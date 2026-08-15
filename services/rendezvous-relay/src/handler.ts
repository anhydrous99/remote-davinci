import { createHash, randomInt, randomUUID } from "node:crypto";
import {
  ApiGatewayManagementApiClient,
  PostToConnectionCommand,
} from "@aws-sdk/client-apigatewaymanagementapi";
import {
  ERROR_CODES,
  PAIRING_TTL_SECONDS,
  PROTOCOL_NAME,
  PROTOCOL_VERSION,
  ProtocolValidationError,
  parseClientEnvelope,
  type ClientEnvelope,
  type ErrorCode,
  type ServerEnvelope,
} from "@remote-davinci/protocol";
import { type CloseSessionResult, type Connection, type Pair, type PairCommit, ServiceError, type Session } from "./model.js";
import { DynamoStore, type Store } from "./store.js";

interface WebSocketEvent {
  body?: string | null;
  requestContext: {
    routeKey: "$connect" | "$disconnect" | "$default" | string;
    connectionId: string;
    domainName?: string;
    stage?: string;
    identity?: { sourceIp?: string };
    authorizer?: { authMode?: string; endpointId?: string; credentialHash?: string };
  };
}

type Post = (connectionId: string, message: ServerEnvelope, event: WebSocketEvent) => Promise<void>;
type Logger = (entry: Record<string, string | number | boolean | undefined>) => void;

interface Dependencies {
  store: Store;
  post: Post;
  now?: () => number;
  id?: () => string;
  locator?: () => string;
  log?: Logger;
}

const pairingActions = new Set(["system.hello", "system.ping", "pair.create", "pair.join", "pair.commit", "pair.cancel"]);
const endpointActions = new Set(["system.hello", "system.ping", "link.get", "link.revoke", "endpoint.rotate", "endpoint.revoke", "session.open", "session.close"]);
const knownErrors = new Set<string>(ERROR_CODES);

const response = (type: string, body: Record<string, unknown>, id: string, replyTo?: string): ServerEnvelope => ({
  protocol: PROTOCOL_NAME,
  v: PROTOCOL_VERSION,
  type,
  id,
  ...(replyTo ? { replyTo } : {}),
  body,
} as ServerEnvelope);

const ok = (request: ClientEnvelope, result: Record<string, unknown>, id: string): ServerEnvelope =>
  response("ok", { requestType: request.type, result }, id, request.id);

const failure = (replyTo: string, error: unknown, id: string): ServerEnvelope => {
  const protocolError = error instanceof ProtocolValidationError;
  const serviceError = error instanceof ServiceError;
  const candidate = protocolError || serviceError ? error.code : "INTERNAL";
  const code = (knownErrors.has(candidate) ? candidate : "INTERNAL") as ErrorCode;
  const retryable = error instanceof ServiceError ? error.retryable : code === "INTERNAL";
  const retryAfterMs = error instanceof ServiceError ? error.retryAfterMs : undefined;
  return response("error", {
    code,
    retryable,
    ...(retryAfterMs === undefined ? {} : { retryAfterMs }),
  }, id, replyTo);
};

const gone = (error: unknown): boolean => error instanceof Error && (
  error.name === "GoneException" || ("$metadata" in error && (error as { $metadata?: { httpStatusCode?: number } }).$metadata?.httpStatusCode === 410)
);

function peerConnection(pair: Pair, connectionId: string): string | undefined {
  if (pair.sideA.connectionId === connectionId) return pair.sideB?.connectionId;
  if (pair.sideB?.connectionId === connectionId) return pair.sideA.connectionId;
  throw new ServiceError("FORBIDDEN");
}

function sessionPeer(session: Session, connectionId: string): string {
  if (session.controllerConnectionId === connectionId) return session.companionConnectionId;
  if (session.companionConnectionId === connectionId) return session.controllerConnectionId;
  throw new ServiceError("FORBIDDEN");
}

export const sourceKey = (sourceIp: string): string => createHash("sha256").update(sourceIp).digest("base64url");

export function createHandler({
  store,
  post,
  now = () => Math.floor(Date.now() / 1000),
  id = randomUUID,
  locator = () => randomInt(0, 1_000_000).toString().padStart(6, "0"),
  log = (entry) => console.log(JSON.stringify(entry)),
}: Dependencies) {
  const notify = async (connectionId: string | undefined, message: ServerEnvelope, event: WebSocketEvent): Promise<boolean> => {
    if (!connectionId) return false;
    try {
      await post(connectionId, message, event);
      return true;
    } catch (error) {
      if (!gone(error)) throw error;
      await cleanup(connectionId, "peer-disconnected", event, false);
      return false;
    }
  };

  const notifyEndpoint = async (endpointId: string, message: ServerEnvelope, event: WebSocketEvent): Promise<void> => {
    const endpoint = await store.getEndpoint(endpointId);
    if (endpoint?.connectionId && !endpoint.revokedAt) await notify(endpoint.connectionId, message, event);
  };

  const closeAndNotify = async (
    sessionId: string,
    endpointId: string | undefined,
    reason: "requested" | "peer-disconnected" | "expired" | "revoked" | "replaced",
    event: WebSocketEvent,
    skipConnectionId?: string,
  ): Promise<CloseSessionResult | undefined> => {
    const result = await store.closeSession(sessionId, endpointId, now());
    if (!result) return undefined;
    if (result.closedNow) {
      const message = response("session.closed", { sessionId, reason }, id());
      for (const connectionId of [result.session.controllerConnectionId, result.session.companionConnectionId]) {
        if (connectionId !== skipConnectionId) await notify(connectionId, message, event);
      }
    }
    return result;
  };

  const cleanup = async (
    connectionId: string,
    reason: "peer-disconnected",
    event: WebSocketEvent,
    sendEvents = true,
  ): Promise<void> => {
    const connection = await store.disconnect(connectionId);
    if (!connection) return;
    if (connection.pairingId) {
      try {
        const pair = await store.cancelPair(connection.pairingId, connectionId, now());
        if (sendEvents && pair?.status === "CLOSED") {
          await notify(peerConnection(pair, connectionId), response("pair.closed", {
            pairId: pair.pairId,
            reason,
          }, id()), event);
        }
      } catch (error) {
        if (!(error instanceof ServiceError && error.code === "CONFLICT")) throw error;
      }
    }
    if (connection.sessionId) {
      await closeAndNotify(connection.sessionId, undefined, reason, event, connectionId);
    }
  };

  const dispatch = async (message: ClientEnvelope, connection: Connection, event: WebSocketEvent): Promise<Record<string, unknown>> => {
    const timestamp = now();
    const body = message.body as Record<string, unknown>;

    if (message.type === "relay.frame") {
      const frame = message.body;
      if (frame.channel === "pair") {
        if (connection.authMode !== "pairing" || connection.pairingId !== frame.channelId) throw new ServiceError("FORBIDDEN");
        const pair = await store.pairById(frame.channelId, timestamp);
        if (pair.status !== "READY" && pair.status !== "HALF_COMMITTED") throw new ServiceError("PAIR_UNAVAILABLE");
        const delivered = await notify(peerConnection(pair, connection.connectionId), response("relay.frame", frame, id()), event);
        if (!delivered) throw new ServiceError("PEER_OFFLINE", true);
        return { delivered: true };
      }
      if (connection.authMode !== "endpoint" || !connection.endpointId) throw new ServiceError("FORBIDDEN");
      const session = await store.session(frame.channelId, timestamp);
      const expectedEndpoint = session.controllerConnectionId === connection.connectionId
        ? session.controllerId
        : session.companionConnectionId === connection.connectionId
          ? session.companionId
          : undefined;
      if (expectedEndpoint !== connection.endpointId) throw new ServiceError("FORBIDDEN");
      const [controller, companion, link] = await Promise.all([
        store.getEndpoint(session.controllerId),
        store.getEndpoint(session.companionId),
        store.link(session.linkId),
      ]);
      if (
        !link || link.status !== "ACTIVE" || link.activeSessionId !== session.sessionId ||
        link.controllerId !== session.controllerId || link.companionId !== session.companionId ||
        !controller || controller.revokedAt || controller.connectionId !== session.controllerConnectionId ||
        !companion || companion.revokedAt || companion.connectionId !== session.companionConnectionId
      ) {
        await closeAndNotify(
          session.sessionId,
          undefined,
          link?.status === "REVOKED" ? "revoked" : "peer-disconnected",
          event,
          connection.connectionId,
        );
        throw new ServiceError(link?.status === "REVOKED" ? "FORBIDDEN" : "PEER_OFFLINE", link?.status !== "REVOKED");
      }
      const delivered = await notify(sessionPeer(session, connection.connectionId), response("relay.frame", frame, id()), event);
      if (!delivered) throw new ServiceError("PEER_OFFLINE", true);
      return { delivered: true };
    }

    if (connection.authMode === "pairing" && !pairingActions.has(message.type)) throw new ServiceError("FORBIDDEN");
    if (connection.authMode === "endpoint" && !endpointActions.has(message.type)) throw new ServiceError("FORBIDDEN");

    switch (message.type) {
      case "system.hello":
        return { serverTime: timestamp, protocolVersion: PROTOCOL_VERSION };
      case "system.ping":
        return { receivedAt: timestamp };
      case "pair.create": { // Pairing locators are intentionally service-visible; the PAKE words are not.
        await store.rateLimit(connection.sourceKey, message.type, 5, timestamp);
        for (let attempt = 0; attempt < 5; attempt += 1) {
          const pair: Pair = {
            pairId: id(),
            locator: locator(),
            status: "OPEN",
            sideA: { connectionId: connection.connectionId, sideId: id() },
            version: 1,
            expiresAt: timestamp + PAIRING_TTL_SECONDS,
          };
          try {
            await store.createPair(pair);
            return { pairId: pair.pairId, sideId: pair.sideA.sideId, locator: pair.locator, expiresAt: pair.expiresAt };
          } catch (error) {
            if (!(error instanceof ServiceError) || error.code !== "CONFLICT" || attempt === 4) throw error;
          }
        }
        throw new ServiceError("CONFLICT", true);
      }
      case "pair.join": {
        await store.rateLimit(connection.sourceKey, message.type, 20, timestamp);
        const side = { connectionId: connection.connectionId, sideId: id() };
        const pair = await store.joinPair(message.body.locator, side, timestamp);
        const readyForA = response("pair.ready", { pairId: pair.pairId, peerSideId: side.sideId, expiresAt: pair.expiresAt }, id());
        const readyForB = response("pair.ready", { pairId: pair.pairId, peerSideId: pair.sideA.sideId, expiresAt: pair.expiresAt }, id());
        if (!await notify(pair.sideA.connectionId, readyForA, event)) throw new ServiceError("PEER_OFFLINE", true);
        if (!await notify(side.connectionId, readyForB, event)) throw new ServiceError("PEER_OFFLINE", true);
        return { pairId: pair.pairId, sideId: side.sideId, expiresAt: pair.expiresAt };
      }
      case "pair.commit": {
        const commit: PairCommit = { connectionId: connection.connectionId, ...message.body };
        const result = await store.commitPair(message.body.pairId, commit, timestamp);
        if (!result.link) return { pending: true };
        const commits = [result.pair.commitA, result.pair.commitB];
        for (const value of commits) {
          if (!value) continue;
          await notify(value.connectionId, response("pair.completed", {
            pairId: result.pair.pairId,
            linkId: result.link.linkId,
            peerEndpointId: value.peer.endpointId,
            peerRole: value.peer.role,
          }, id()), event);
        }
        return { linkId: result.link.linkId, active: true };
      }
      case "pair.cancel": {
        const pair = await store.cancelPair(message.body.pairId, connection.connectionId, timestamp);
        if (pair?.status === "CLOSED") {
          await notify(peerConnection(pair, connection.connectionId), response("pair.closed", {
            pairId: pair.pairId,
            reason: "cancelled",
          }, id()), event);
        }
        return { cancelled: true };
      }
      case "link.get": {
        const link = await store.link(message.body.linkId);
        if (!link || !connection.endpointId || (link.controllerId !== connection.endpointId && link.companionId !== connection.endpointId)) {
          throw new ServiceError("FORBIDDEN");
        }
        const peerEndpointId = link.controllerId === connection.endpointId ? link.companionId : link.controllerId;
        return {
          linkId: link.linkId,
          peerEndpointId,
          peerRole: link.controllerId === peerEndpointId ? "controller" : "companion",
          status: link.status.toLowerCase(),
          ...(link.revokedAt ? { revokedAt: link.revokedAt } : {}),
        };
      }
      case "link.revoke": {
        if (!connection.endpointId) throw new ServiceError("FORBIDDEN");
        const current = await store.link(message.body.linkId);
        const revoked = await store.revokeLink(message.body.linkId, connection.endpointId, timestamp);
        if (current?.activeSessionId) await closeAndNotify(current.activeSessionId, connection.endpointId, "revoked", event);
        const peerEndpointId = revoked.controllerId === connection.endpointId ? revoked.companionId : revoked.controllerId;
        await notifyEndpoint(peerEndpointId, response("link.revoked", { linkId: revoked.linkId }, id()), event);
        return { revoked: true };
      }
      case "endpoint.rotate":
        if (!connection.endpointId) throw new ServiceError("FORBIDDEN");
        await store.rotateEndpoint(connection.endpointId, message.body.credentialHash, timestamp);
        return { rotated: true };
      case "endpoint.revoke": { // Revocation is an ownership reset for every server-side link.
        if (!connection.endpointId) throw new ServiceError("FORBIDDEN");
        const revoked = await store.revokeEndpoint(connection.endpointId, timestamp);
        for (const session of revoked.sessions) {
          const closed = response("session.closed", { sessionId: session.sessionId, reason: "revoked" }, id());
          await notify(session.controllerConnectionId, closed, event);
          await notify(session.companionConnectionId, closed, event);
        }
        for (const link of revoked.links) {
          const peerEndpointId = link.controllerId === connection.endpointId ? link.companionId : link.controllerId;
          await notifyEndpoint(peerEndpointId, response("link.revoked", { linkId: link.linkId }, id()), event);
        }
        return { revoked: true, linksRevoked: revoked.links.length };
      }
      case "session.open": {
        if (!connection.endpointId) throw new ServiceError("FORBIDDEN");
        const session = await store.openSession(message.body.linkId, connection.endpointId, connection.connectionId, id(), timestamp);
        const controllerNotified = await notify(session.controllerConnectionId, response("session.opened", {
          sessionId: session.sessionId,
          linkId: session.linkId,
          peerEndpointId: session.companionId,
        }, id()), event);
        if (!controllerNotified) {
          await closeAndNotify(session.sessionId, undefined, "peer-disconnected", event);
          throw new ServiceError("PEER_OFFLINE", true);
        }
        const companionNotified = await notify(session.companionConnectionId, response("session.opened", {
          sessionId: session.sessionId,
          linkId: session.linkId,
          peerEndpointId: session.controllerId,
        }, id()), event);
        if (!companionNotified) {
          await closeAndNotify(session.sessionId, undefined, "peer-disconnected", event);
          throw new ServiceError("PEER_OFFLINE", true);
        }
        return { sessionId: session.sessionId };
      }
      case "session.close": {
        if (!connection.endpointId) throw new ServiceError("FORBIDDEN");
        await closeAndNotify(message.body.sessionId, connection.endpointId, "requested", event);
        return { closed: true };
      }
      default:
        throw new ServiceError("INVALID_MESSAGE");
    }
  };

  return async (event: WebSocketEvent): Promise<{ statusCode: number }> => {
    const { routeKey, connectionId } = event.requestContext;
    if (routeKey === "$connect") {
      const authMode = event.requestContext.authorizer?.authMode;
      const endpointId = event.requestContext.authorizer?.endpointId || undefined;
      const credentialHash = event.requestContext.authorizer?.credentialHash || undefined;
      if (authMode !== "pairing" && authMode !== "endpoint") return { statusCode: 401 };
      if (authMode === "endpoint" && (!endpointId || !credentialHash)) return { statusCode: 401 };
      try {
        await store.connect({
          connectionId,
          authMode,
          ...(endpointId ? { endpointId } : {}),
          sourceKey: sourceKey(event.requestContext.identity?.sourceIp ?? "unknown"),
          connectedAt: now(),
          expiresAt: now() + 2 * 60 * 60 + 5 * 60,
        }, credentialHash);
        return { statusCode: 200 };
      } catch (error) {
        log({ level: "warn", event: "connect-rejected", connectionId, error: error instanceof ServiceError ? error.code : "INTERNAL" });
        return { statusCode: error instanceof ServiceError ? 401 : 500 };
      }
    }
    if (routeKey === "$disconnect") {
      await cleanup(connectionId, "peer-disconnected", event);
      return { statusCode: 200 };
    }
    if (routeKey !== "$default") return { statusCode: 400 };

    let requestId = id();
    try {
      const connection = await store.connection(connectionId, now());
      const message = parseClientEnvelope(event.body ?? "");
      requestId = message.id;
      log({ level: "info", event: "message", connectionId, messageType: message.type });
      const result = await dispatch(message, connection, event);
      await notify(connectionId, ok(message, result, id()), event);
    } catch (error) {
      log({ level: "warn", event: "message-rejected", connectionId, error: error instanceof ServiceError || error instanceof ProtocolValidationError ? error.code : "INTERNAL" });
      await notify(connectionId, failure(requestId, error, id()), event);
    }
    return { statusCode: 200 };
  };
}

const store = new DynamoStore(process.env.TABLE_NAME ?? "missing");
const post: Post = async (connectionId, message, event) => {
  const { domainName, stage } = event.requestContext;
  if (!domainName || !stage) throw new Error("Missing WebSocket management endpoint");
  const client = new ApiGatewayManagementApiClient({ endpoint: `https://${domainName}/${stage}` });
  await client.send(new PostToConnectionCommand({
    ConnectionId: connectionId,
    Data: Buffer.from(JSON.stringify(message)),
  }));
};

export const handler = createHandler({ store, post });
