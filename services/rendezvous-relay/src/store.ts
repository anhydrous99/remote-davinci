import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import {
  DeleteCommand,
  DynamoDBDocumentClient,
  GetCommand,
  PutCommand,
  QueryCommand,
  TransactWriteCommand,
  type TransactWriteCommandInput,
  UpdateCommand,
} from "@aws-sdk/lib-dynamodb";
import {
  type CloseSessionResult,
  type Connection,
  type Endpoint,
  isExpired,
  type Link,
  linkFromCommits,
  type Pair,
  type PairCommit,
  type Session,
  sameCommit,
  ServiceError,
} from "./model.js";

const META = "META";
const key = (prefix: string, id: string) => ({ pk: `${prefix}#${id}`, sk: META });

type RecordItem<T> = T & { pk: string; sk: typeof META; kind: string };
type PairPointer = { pairId: string; locator: string; expiresAt: number };
type TransactWriteItem = NonNullable<TransactWriteCommandInput["TransactItems"]>[number];

const item = <T extends object>(kind: string, id: string, value: T): RecordItem<T> => ({
  ...key(kind.toUpperCase(), id),
  kind,
  ...value,
}) as RecordItem<T>;

function conditionalFailure(error: unknown): boolean {
  const name = error instanceof Error ? error.name : "";
  return name === "ConditionalCheckFailedException" || name === "TransactionCanceledException";
}

export interface Store {
  getEndpoint(endpointId: string): Promise<Endpoint | undefined>;
  connect(connection: Connection, credentialHash?: string): Promise<void>;
  disconnect(connectionId: string): Promise<Connection | undefined>;
  connection(connectionId: string, now: number): Promise<Connection>;
  rateLimit(sourceKey: string, action: string, limit: number, now: number): Promise<void>;
  createPair(pair: Pair): Promise<void>;
  pairById(pairId: string, now: number): Promise<Pair>;
  pairByLocator(locator: string, now: number): Promise<Pair>;
  joinPair(locator: string, side: { connectionId: string; sideId: string }, now: number): Promise<Pair>;
  commitPair(pairId: string, commit: PairCommit, now: number): Promise<{ pair: Pair; link?: Link }>;
  cancelPair(pairId: string, connectionId: string, now: number): Promise<Pair | undefined>;
  link(linkId: string): Promise<Link | undefined>;
  revokeLink(linkId: string, endpointId: string, now: number): Promise<Link>;
  rotateEndpoint(endpointId: string, credentialHash: string, now: number): Promise<void>;
  revokeEndpoint(endpointId: string, now: number): Promise<{ endpoint: Endpoint; links: Link[]; sessions: Session[] }>;
  openSession(linkId: string, endpointId: string, connectionId: string, sessionId: string, now: number): Promise<Session>;
  session(sessionId: string, now: number): Promise<Session>;
  closeSession(sessionId: string, endpointId: string | undefined, now: number): Promise<CloseSessionResult | undefined>;
}

export class DynamoStore implements Store {
  constructor(
    private readonly tableName: string,
    private readonly db = DynamoDBDocumentClient.from(new DynamoDBClient({}), {
      marshallOptions: { removeUndefinedValues: true },
    }),
  ) {}

  private async get<T>(kind: string, id: string): Promise<T | undefined> {
    const result = await this.db.send(new GetCommand({
      TableName: this.tableName,
      Key: key(kind.toUpperCase(), id),
      ConsistentRead: true,
    }));
    if (!result.Item) return undefined;
    const { pk: _pk, sk: _sk, kind: _kind, ...value } = result.Item;
    return value as T;
  }

  async getEndpoint(endpointId: string): Promise<Endpoint | undefined> {
    return this.get<Endpoint>("endpoint", endpointId);
  }

  async connect(connection: Connection, credentialHash?: string): Promise<void> {
    if (
      (connection.authMode === "endpoint" && (!connection.endpointId || !credentialHash)) ||
      (connection.authMode === "pairing" && connection.endpointId)
    ) throw new ServiceError("UNAUTHENTICATED");
    const put: TransactWriteItem = {
      Put: {
        TableName: this.tableName,
        Item: item("connection", connection.connectionId, connection),
        ConditionExpression: "attribute_not_exists(pk)",
      },
    };
    const operations: TransactWriteItem[] = [put];
    if (connection.endpointId) {
      operations.push({
        Update: {
          TableName: this.tableName,
          Key: key("ENDPOINT", connection.endpointId),
          UpdateExpression: "SET connectionId = :connectionId, updatedAt = :now",
          ConditionExpression: "attribute_exists(pk) AND attribute_not_exists(revokedAt) AND credentialHash = :credentialHash",
          ExpressionAttributeValues: {
            ":connectionId": connection.connectionId,
            ":now": connection.connectedAt,
            ":credentialHash": credentialHash,
          },
        },
      });
    }
    try {
      await this.db.send(new TransactWriteCommand({ TransactItems: operations }));
    } catch (error) {
      if (conditionalFailure(error)) throw new ServiceError("UNAUTHENTICATED");
      throw error;
    }
  }

  async disconnect(connectionId: string): Promise<Connection | undefined> {
    const connection = await this.get<Connection>("connection", connectionId);
    if (!connection) return undefined;
    const cleanup: Promise<unknown>[] = [this.db.send(new DeleteCommand({
      TableName: this.tableName,
      Key: key("CONNECTION", connectionId),
    }))];
    if (connection.endpointId) {
      cleanup.push(this.db.send(new UpdateCommand({
          TableName: this.tableName,
          Key: key("ENDPOINT", connection.endpointId),
          UpdateExpression: "REMOVE connectionId",
          ConditionExpression: "connectionId = :connectionId",
          ExpressionAttributeValues: { ":connectionId": connectionId },
      })));
    }
    // Disconnect cleanup is advisory; returning the record lets durable pair/session cleanup continue.
    await Promise.allSettled(cleanup);
    return connection;
  }

  async connection(connectionId: string, now: number): Promise<Connection> {
    const connection = await this.get<Connection>("connection", connectionId);
    if (!connection || isExpired(connection, now)) throw new ServiceError("UNAUTHENTICATED");
    if (connection.endpointId) {
      const endpoint = await this.getEndpoint(connection.endpointId);
      if (!endpoint || endpoint.revokedAt || endpoint.connectionId !== connectionId) {
        throw new ServiceError("UNAUTHENTICATED");
      }
    }
    return connection;
  }

  async rateLimit(sourceKey: string, action: string, limit: number, now: number): Promise<void> {
    const minute = Math.floor(now / 60);
    const id = `${sourceKey}#${action}#${minute}`;
    try {
      await this.db.send(new UpdateCommand({
        TableName: this.tableName,
        Key: key("RATE", id),
        UpdateExpression: "SET expiresAt = :expiresAt ADD #count :one",
        ConditionExpression: "attribute_not_exists(#count) OR #count < :limit",
        ExpressionAttributeNames: { "#count": "count" },
        ExpressionAttributeValues: { ":expiresAt": (minute + 2) * 60, ":one": 1, ":limit": limit },
      }));
    } catch (error) {
      if (conditionalFailure(error)) throw new ServiceError("RATE_LIMITED", true, 60_000);
      throw error;
    }
  }

  async createPair(pair: Pair): Promise<void> {
    const pointer: PairPointer = { pairId: pair.pairId, locator: pair.locator, expiresAt: pair.expiresAt };
    try {
      await this.db.send(new TransactWriteCommand({ TransactItems: [
        {
          Put: {
            TableName: this.tableName,
            Item: item("pair", pair.locator, pair),
            ConditionExpression: "attribute_not_exists(pk)",
          },
        },
        {
          Put: {
            TableName: this.tableName,
            Item: item("pairid", pair.pairId, pointer),
            ConditionExpression: "attribute_not_exists(pk)",
          },
        },
        {
          Update: {
            TableName: this.tableName,
            Key: key("CONNECTION", pair.sideA.connectionId),
            UpdateExpression: "SET pairingId = :pairId",
            ConditionExpression: "authMode = :pairing AND attribute_not_exists(pairingId)",
            ExpressionAttributeValues: { ":pairId": pair.pairId, ":pairing": "pairing" },
          },
        },
      ] }));
    } catch (error) {
      if (conditionalFailure(error)) throw new ServiceError("CONFLICT", true);
      throw error;
    }
  }

  async pairByLocator(locator: string, now: number): Promise<Pair> {
    const pair = await this.get<Pair>("pair", locator);
    if (!pair || isExpired(pair, now)) throw new ServiceError("PAIR_EXPIRED");
    return pair;
  }

  async pairById(pairId: string, now: number): Promise<Pair> {
    const pointer = await this.get<PairPointer>("pairid", pairId);
    if (!pointer || isExpired(pointer, now)) throw new ServiceError("PAIR_EXPIRED");
    const pair = await this.pairByLocator(pointer.locator, now);
    if (pair.pairId !== pairId) throw new ServiceError("PAIR_UNAVAILABLE");
    return pair;
  }

  async joinPair(locator: string, side: { connectionId: string; sideId: string }, now: number): Promise<Pair> {
    const pair = await this.pairByLocator(locator, now);
    if (pair.status !== "OPEN" || pair.sideB) throw new ServiceError("PAIR_FULL");
    try {
      await this.db.send(new TransactWriteCommand({ TransactItems: [
        {
          Update: {
            TableName: this.tableName,
            Key: key("PAIR", locator),
            UpdateExpression: "SET sideB = :side, #status = :ready, version = :nextVersion",
            ConditionExpression: "#status = :open AND version = :version AND expiresAt > :now AND attribute_not_exists(sideB)",
            ExpressionAttributeNames: { "#status": "status" },
            ExpressionAttributeValues: {
              ":side": side,
              ":ready": "READY",
              ":open": "OPEN",
              ":version": pair.version,
              ":nextVersion": pair.version + 1,
              ":now": now,
            },
          },
        },
        {
          Update: {
            TableName: this.tableName,
            Key: key("CONNECTION", side.connectionId),
            UpdateExpression: "SET pairingId = :pairId",
            ConditionExpression: "authMode = :pairing AND attribute_not_exists(pairingId)",
            ExpressionAttributeValues: { ":pairId": pair.pairId, ":pairing": "pairing" },
          },
        },
      ] }));
    } catch (error) {
      if (conditionalFailure(error)) throw new ServiceError("PAIR_FULL");
      throw error;
    }
    return { ...pair, sideB: side, status: "READY", version: pair.version + 1 };
  }

  private async endpointWrite(endpoint: Endpoint): Promise<TransactWriteItem> {
    const existing = await this.getEndpoint(endpoint.endpointId);
    if (!existing) {
      return {
        Put: {
          TableName: this.tableName,
          Item: item("endpoint", endpoint.endpointId, endpoint),
          ConditionExpression: "attribute_not_exists(pk)",
        },
      };
    }
    if (
      existing.revokedAt ||
      existing.credentialHash !== endpoint.credentialHash ||
      existing.role !== endpoint.role
    ) throw new ServiceError("CONFLICT");
    return {
      ConditionCheck: {
        TableName: this.tableName,
        Key: key("ENDPOINT", endpoint.endpointId),
        ConditionExpression: "credentialHash = :credentialHash AND #role = :role AND attribute_not_exists(revokedAt)",
        ExpressionAttributeNames: { "#role": "role" },
        ExpressionAttributeValues: {
          ":credentialHash": endpoint.credentialHash,
          ":role": endpoint.role,
        },
      },
    };
  }

  async commitPair(pairId: string, commit: PairCommit, now: number): Promise<{ pair: Pair; link?: Link }> {
    const pair = await this.pairById(pairId, now);
    const slot = pair.sideA.sideId === commit.sideId && pair.sideA.connectionId === commit.connectionId
      ? "A"
      : pair.sideB?.sideId === commit.sideId && pair.sideB.connectionId === commit.connectionId
        ? "B"
        : undefined;
    if (!slot) throw new ServiceError("FORBIDDEN");
    const ownField = slot === "A" ? "commitA" : "commitB";
    const other = slot === "A" ? pair.commitB : pair.commitA;
    const own = slot === "A" ? pair.commitA : pair.commitB;
    if (pair.status === "ACTIVE" && own && sameCommit(own, commit)) {
      const activeLink = await this.link(commit.linkId);
      return { pair, ...(activeLink ? { link: activeLink } : {}) };
    }
    if (own) {
      if (!sameCommit(own, commit)) throw new ServiceError("CONFLICT");
      return { pair };
    }
    if (pair.status !== "READY" && pair.status !== "HALF_COMMITTED") throw new ServiceError("PAIR_UNAVAILABLE");

    if (!other) {
      try {
        await this.db.send(new UpdateCommand({
          TableName: this.tableName,
          Key: key("PAIR", pair.locator),
          UpdateExpression: `SET ${ownField} = :commit, #status = :half, version = :nextVersion`,
          ConditionExpression: "version = :version AND (#status = :ready OR #status = :half) AND attribute_not_exists(" + ownField + ")",
          ExpressionAttributeNames: { "#status": "status" },
          ExpressionAttributeValues: {
            ":commit": commit,
            ":half": "HALF_COMMITTED",
            ":ready": "READY",
            ":version": pair.version,
            ":nextVersion": pair.version + 1,
          },
        }));
      } catch (error) {
        if (conditionalFailure(error)) throw new ServiceError("CONFLICT", true);
        throw error;
      }
      return {
        pair: { ...pair, [ownField]: commit, status: "HALF_COMMITTED", version: pair.version + 1 },
      };
    }

    const first = slot === "A" ? commit : other;
    const second = slot === "B" ? commit : other;
    const link = linkFromCommits(first, second, now);
    const commits = [first, second];
    const endpoints = commits.map((value): Endpoint => ({
      endpointId: value.self.endpointId,
      credentialHash: value.self.credentialHash,
      role: value.self.role,
      createdAt: now,
      updatedAt: now,
    }));
    const endpointWrites = await Promise.all(endpoints.map((endpoint) => this.endpointWrite(endpoint)));
    try {
      await this.db.send(new TransactWriteCommand({ TransactItems: [
        {
          Update: {
            TableName: this.tableName,
            Key: key("PAIR", pair.locator),
            UpdateExpression: `SET ${ownField} = :commit, #status = :active, version = :nextVersion`,
            ConditionExpression: "version = :version AND #status = :half AND attribute_not_exists(" + ownField + ")",
            ExpressionAttributeNames: { "#status": "status" },
            ExpressionAttributeValues: {
              ":commit": commit,
              ":active": "ACTIVE",
              ":half": "HALF_COMMITTED",
              ":version": pair.version,
              ":nextVersion": pair.version + 1,
            },
          },
        },
        {
          Put: {
            TableName: this.tableName,
            Item: item("link", link.linkId, link),
            ConditionExpression: "attribute_not_exists(pk)",
          },
        },
        ...[link.controllerId, link.companionId].map((endpointId): TransactWriteItem => ({
          Put: {
            TableName: this.tableName,
            Item: {
              pk: `ENDPOINT#${endpointId}`,
              sk: `LINK#${link.linkId}`,
              kind: "endpoint-link",
              endpointId,
              linkId: link.linkId,
              peerEndpointId: endpointId === link.controllerId ? link.companionId : link.controllerId,
            },
            ConditionExpression: "attribute_not_exists(pk)",
          },
        })),
        ...endpointWrites,
      ] }));
    } catch (error) {
      if (conditionalFailure(error)) throw new ServiceError("CONFLICT", true);
      throw error;
    }
    return {
      pair: { ...pair, [ownField]: commit, status: "ACTIVE", version: pair.version + 1 },
      link,
    };
  }

  async cancelPair(pairId: string, connectionId: string, now: number): Promise<Pair | undefined> {
    let pair: Pair;
    try {
      pair = await this.pairById(pairId, now);
    } catch (error) {
      if (error instanceof ServiceError && error.code === "PAIR_EXPIRED") return undefined;
      throw error;
    }
    if (pair.sideA.connectionId !== connectionId && pair.sideB?.connectionId !== connectionId) {
      throw new ServiceError("FORBIDDEN");
    }
    if (pair.status === "ACTIVE") throw new ServiceError("CONFLICT");
    if (pair.status === "CLOSED") return pair;
    try {
      await this.db.send(new UpdateCommand({
        TableName: this.tableName,
        Key: key("PAIR", pair.locator),
        UpdateExpression: "SET #status = :closed, version = :nextVersion",
        ConditionExpression: "version = :version AND #status <> :active",
        ExpressionAttributeNames: { "#status": "status" },
        ExpressionAttributeValues: {
          ":closed": "CLOSED",
          ":active": "ACTIVE",
          ":version": pair.version,
          ":nextVersion": pair.version + 1,
        },
      }));
    } catch (error) {
      if (!conditionalFailure(error)) throw error;
      const current = await this.pairById(pairId, now);
      if (current.status === "CLOSED") return current;
      throw new ServiceError("CONFLICT");
    }
    return { ...pair, status: "CLOSED", version: pair.version + 1 };
  }

  async link(linkId: string): Promise<Link | undefined> {
    return this.get<Link>("link", linkId);
  }

  async revokeLink(linkId: string, endpointId: string, now: number): Promise<Link> {
    const link = await this.link(linkId);
    if (!link) throw new ServiceError("FORBIDDEN");
    if (link.controllerId !== endpointId && link.companionId !== endpointId) throw new ServiceError("FORBIDDEN");
    if (link.status === "REVOKED") return link;
    try {
      await this.db.send(new UpdateCommand({
        TableName: this.tableName,
        Key: key("LINK", linkId),
        UpdateExpression: "SET #status = :revoked, revokedAt = :now",
        ConditionExpression: "#status = :active",
        ExpressionAttributeNames: { "#status": "status" },
        ExpressionAttributeValues: { ":revoked": "REVOKED", ":active": "ACTIVE", ":now": now },
      }));
    } catch (error) {
      if (!conditionalFailure(error)) throw error;
    }
    return { ...link, status: "REVOKED", revokedAt: now };
  }

  async rotateEndpoint(endpointId: string, credentialHash: string, now: number): Promise<void> {
    try {
      await this.db.send(new UpdateCommand({
        TableName: this.tableName,
        Key: key("ENDPOINT", endpointId),
        UpdateExpression: "SET credentialHash = :credentialHash, updatedAt = :now",
        ConditionExpression: "attribute_exists(pk) AND attribute_not_exists(revokedAt)",
        ExpressionAttributeValues: { ":credentialHash": credentialHash, ":now": now },
      }));
    } catch (error) {
      if (conditionalFailure(error)) throw new ServiceError("UNAUTHENTICATED");
      throw error;
    }
  }

  async revokeEndpoint(endpointId: string, now: number): Promise<{ endpoint: Endpoint; links: Link[]; sessions: Session[] }> {
    const endpoint = await this.getEndpoint(endpointId);
    if (!endpoint) throw new ServiceError("UNAUTHENTICATED");
    if (!endpoint.revokedAt) {
      try {
        await this.db.send(new UpdateCommand({
          TableName: this.tableName,
          Key: key("ENDPOINT", endpointId),
          UpdateExpression: "SET revokedAt = :now, updatedAt = :now REMOVE connectionId, activeSessionId",
          ConditionExpression: "attribute_not_exists(revokedAt)",
          ExpressionAttributeValues: { ":now": now },
        }));
      } catch (error) {
        if (!conditionalFailure(error)) throw error;
      }
    }
    const linkIds: string[] = [];
    let startKey: Record<string, unknown> | undefined;
    do {
      const page = await this.db.send(new QueryCommand({
        TableName: this.tableName,
        KeyConditionExpression: "pk = :pk AND begins_with(sk, :prefix)",
        ExpressionAttributeValues: { ":pk": `ENDPOINT#${endpointId}`, ":prefix": "LINK#" },
        ProjectionExpression: "linkId",
        ConsistentRead: true,
        ExclusiveStartKey: startKey,
      }));
      for (const value of page.Items ?? []) if (typeof value.linkId === "string") linkIds.push(value.linkId);
      startKey = page.LastEvaluatedKey;
    } while (startKey);

    const links: Link[] = [];
    const sessions: Session[] = [];
    // ponytail: sequential cleanup fits device-scale link counts; use a workflow if fan-out grows enough to hit Lambda timeout.
    for (const linkId of linkIds) {
      const link = await this.link(linkId);
      if (!link) continue;
      const sessionId = link.activeSessionId;
      links.push(await this.revokeLink(linkId, endpointId, now));
      if (sessionId) {
        const closed = await this.closeSession(sessionId, undefined, now);
        if (closed?.closedNow) sessions.push(closed.session);
      }
    }

    const { connectionId: _connectionId, activeSessionId: _activeSessionId, ...withoutConnection } = endpoint;
    return {
      endpoint: { ...withoutConnection, revokedAt: endpoint.revokedAt ?? now, updatedAt: now },
      links,
      sessions,
    };
  }

  async openSession(
    linkId: string,
    endpointId: string,
    connectionId: string,
    sessionId: string,
    now: number,
  ): Promise<Session> {
    let link = await this.link(linkId);
    if (!link || link.status !== "ACTIVE" || link.controllerId !== endpointId) throw new ServiceError("FORBIDDEN");
    if (link.activeSessionId) {
      if (await this.repairStaleSession(link.activeSessionId, link, now)) {
        link = await this.link(linkId);
        if (!link || link.status !== "ACTIVE" || link.activeSessionId) throw new ServiceError("PEER_BUSY", true);
      }
    }
    let [controller, companion] = await Promise.all([
      this.getEndpoint(link.controllerId),
      this.getEndpoint(link.companionId),
    ]);
    if (!controller || !companion) throw new ServiceError("UNAUTHENTICATED");
    const connections = await Promise.all([
      controller.connectionId ? this.get<Connection>("connection", controller.connectionId) : undefined,
      companion.connectionId ? this.get<Connection>("connection", companion.connectionId) : undefined,
    ]);
    const staleLocks = new Set([
      companion.activeSessionId,
      connections[0]?.sessionId,
      connections[1]?.sessionId,
    ].filter((value): value is string => Boolean(value)));
    let repaired = false;
    for (const sessionId of staleLocks) repaired = await this.repairStaleSession(sessionId, link, now) || repaired;
    if (repaired) {
      link = await this.link(linkId);
      [controller, companion] = await Promise.all([
        this.getEndpoint(link?.controllerId ?? ""),
        this.getEndpoint(link?.companionId ?? ""),
      ]);
    }
    if (!link || !controller || !companion) throw new ServiceError("UNAUTHENTICATED");
    if (!controller || controller.revokedAt || controller.connectionId !== connectionId) throw new ServiceError("UNAUTHENTICATED");
    if (!companion || companion.revokedAt || !companion.connectionId) throw new ServiceError("PEER_OFFLINE", true);
    const session: Session = {
      sessionId,
      linkId,
      controllerId: controller.endpointId,
      companionId: companion.endpointId,
      controllerConnectionId: connectionId,
      companionConnectionId: companion.connectionId,
      status: "ACTIVE",
      createdAt: now,
      expiresAt: now + 2 * 60 * 60,
    };
    try {
      await this.db.send(new TransactWriteCommand({ TransactItems: [
        {
          Put: {
            TableName: this.tableName,
            Item: item("session", sessionId, session),
            ConditionExpression: "attribute_not_exists(pk)",
          },
        },
        {
          Update: {
            TableName: this.tableName,
            Key: key("LINK", linkId),
            UpdateExpression: "SET activeSessionId = :sessionId",
            ConditionExpression: "#status = :active AND attribute_not_exists(activeSessionId)",
            ExpressionAttributeNames: { "#status": "status" },
            ExpressionAttributeValues: { ":sessionId": sessionId, ":active": "ACTIVE" },
          },
        },
        {
          ConditionCheck: {
            TableName: this.tableName,
            Key: key("ENDPOINT", controller.endpointId),
            ConditionExpression: "connectionId = :connectionId AND attribute_not_exists(revokedAt)",
            ExpressionAttributeValues: { ":connectionId": connectionId },
          },
        },
        {
          Update: {
            TableName: this.tableName,
            Key: key("ENDPOINT", companion.endpointId),
            UpdateExpression: "SET activeSessionId = :sessionId",
            ConditionExpression: "connectionId = :connectionId AND attribute_not_exists(activeSessionId) AND attribute_not_exists(revokedAt)",
            ExpressionAttributeValues: { ":sessionId": sessionId, ":connectionId": companion.connectionId },
          },
        },
        ...[connectionId, companion.connectionId].map((id): TransactWriteItem => ({
          Update: {
            TableName: this.tableName,
            Key: key("CONNECTION", id),
            UpdateExpression: "SET sessionId = :sessionId",
            ConditionExpression: "attribute_exists(pk) AND attribute_not_exists(sessionId)",
            ExpressionAttributeValues: { ":sessionId": sessionId },
          },
        })),
      ] }));
    } catch (error) {
      if (conditionalFailure(error)) throw new ServiceError("PEER_BUSY", true);
      throw error;
    }
    return session;
  }

  private async repairStaleSession(sessionId: string, link: Link, now: number): Promise<boolean> {
    const session = await this.get<Session>("session", sessionId);
    if (session?.status === "ACTIVE" && !isExpired(session, now)) return false;
    if (session) {
      await this.closeSession(sessionId, undefined, now);
      return true;
    }
    const [controller, companion] = await Promise.all([
      this.getEndpoint(link.controllerId),
      this.getEndpoint(link.companionId),
    ]);
    await Promise.all([
      this.clearIfEqual("LINK", link.linkId, "activeSessionId", sessionId),
      this.clearIfEqual("ENDPOINT", link.companionId, "activeSessionId", sessionId),
      ...[controller?.connectionId, companion?.connectionId]
        .filter((value): value is string => Boolean(value))
        .map((connectionId) => this.clearIfEqual("CONNECTION", connectionId, "sessionId", sessionId)),
    ]);
    return true;
  }

  async session(sessionId: string, now: number): Promise<Session> {
    const session = await this.get<Session>("session", sessionId);
    if (!session || session.status !== "ACTIVE" || isExpired(session, now)) {
      throw new ServiceError("SESSION_NOT_FOUND");
    }
    return session;
  }

  async closeSession(sessionId: string, endpointId: string | undefined, now: number): Promise<CloseSessionResult | undefined> {
    let session = await this.get<Session>("session", sessionId);
    if (!session) return undefined;
    if (endpointId && session.controllerId !== endpointId && session.companionId !== endpointId) {
      throw new ServiceError("FORBIDDEN");
    }
    let closedNow = false;
    if (session.status === "ACTIVE") {
      try {
        await this.db.send(new UpdateCommand({
          TableName: this.tableName,
          Key: key("SESSION", sessionId),
          UpdateExpression: "SET #status = :closed, closedAt = :now",
          ConditionExpression: "#status = :active",
          ExpressionAttributeNames: { "#status": "status" },
          ExpressionAttributeValues: { ":closed": "CLOSED", ":active": "ACTIVE", ":now": now },
        }));
        session = { ...session, status: "CLOSED", closedAt: now };
        closedNow = true;
      } catch (error) {
        if (!conditionalFailure(error)) throw error;
        const current = await this.get<Session>("session", sessionId);
        if (!current) return undefined;
        session = current;
      }
    }
    await Promise.all([
      this.clearIfEqual("LINK", session.linkId, "activeSessionId", sessionId),
      this.clearIfEqual("ENDPOINT", session.companionId, "activeSessionId", sessionId),
      this.clearIfEqual("CONNECTION", session.controllerConnectionId, "sessionId", sessionId),
      this.clearIfEqual("CONNECTION", session.companionConnectionId, "sessionId", sessionId),
    ]);
    return { session, closedNow };
  }

  private async clearIfEqual(kind: string, id: string, field: string, expected: string): Promise<void> {
    try {
      await this.db.send(new UpdateCommand({
        TableName: this.tableName,
        Key: key(kind, id),
        UpdateExpression: `REMOVE ${field}`,
        ConditionExpression: `${field} = :expected`,
        ExpressionAttributeValues: { ":expected": expected },
      }));
    } catch (error) {
      if (!conditionalFailure(error)) throw error;
    }
  }
}
