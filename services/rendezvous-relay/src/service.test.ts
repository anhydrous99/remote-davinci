import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import { PROTOCOL_NAME, PROTOCOL_VERSION, parseServerEnvelope, type ServerEnvelope } from "@remote-davinci/protocol";
import { createAuthorizer } from "./authorizer.js";
import { createHandler, sourceKey } from "./handler.js";
import {
  linkFromCommits,
  reciprocalCommits,
  sameCommit,
  ServiceError,
  type Connection,
  type Endpoint,
  type Link,
  type Pair,
  type PairCommit,
  type Session,
} from "./model.js";
import { DynamoStore, type Store } from "./store.js";

const unimplemented = async (): Promise<never> => { throw new Error("unexpected store call"); };
const fakeStore = (overrides: Partial<Store> = {}): Store => ({
  getEndpoint: unimplemented,
  connect: unimplemented,
  disconnect: unimplemented,
  connection: unimplemented,
  rateLimit: unimplemented,
  createPair: unimplemented,
  pairById: unimplemented,
  pairByLocator: unimplemented,
  joinPair: unimplemented,
  commitPair: unimplemented,
  cancelPair: unimplemented,
  link: unimplemented,
  revokeLink: unimplemented,
  rotateEndpoint: unimplemented,
  revokeEndpoint: unimplemented,
  openSession: unimplemented,
  session: unimplemented,
  closeSession: unimplemented,
  ...overrides,
});

const uuid = (tail: number) => `00000000-0000-4000-8000-${tail.toString().padStart(12, "0")}`;
const envelope = (type: string, body: Record<string, unknown>, id = uuid(1)) => JSON.stringify({
  protocol: PROTOCOL_NAME,
  v: PROTOCOL_VERSION,
  type,
  id,
  body,
});
const event = (connectionId: string, body?: string) => ({
  ...(body === undefined ? {} : { body }),
  requestContext: {
    routeKey: body === undefined ? "$connect" as const : "$default" as const,
    connectionId,
    domainName: "example.invalid",
    stage: "v1",
    identity: { sourceIp: "203.0.113.42" },
    authorizer: { authMode: "pairing", endpointId: "" },
  },
});

test("authorizer validates the raw bearer secret against only its SHA-256 hash", async () => {
  const secret = Buffer.alloc(32, 7).toString("base64url");
  const credentialHash = createHash("sha256").update(Buffer.from(secret, "base64url")).digest("base64url");
  const endpointId = uuid(9);
  const authorize = createAuthorizer(fakeStore({
    getEndpoint: async () => ({ endpointId, credentialHash, role: "controller", createdAt: 1, updatedAt: 1 }),
  }));
  const result = await authorize({
    headers: { Authorization: `Bearer rd1.${endpointId}.${secret}` },
    methodArn: "arn:aws:execute-api:region:account:api/stage/$connect",
  });
  assert.equal(result.context.authMode, "endpoint");
  if (result.context.authMode !== "endpoint") assert.fail("expected endpoint authorization");
  assert.equal(result.context.endpointId, endpointId);
  assert.equal(result.context.credentialHash, credentialHash);
  await assert.rejects(() => authorize({
    headers: { Authorization: `Bearer rd1.${endpointId}.${Buffer.alloc(32, 8).toString("base64url")}` },
    methodArn: "arn",
  }), /Unauthorized/);
});

test("connect persists a source hash, never the raw IP", async () => {
  let saved: Connection | undefined;
  const handler = createHandler({
    store: fakeStore({ connect: async (connection) => { saved = connection; } }),
    post: async () => undefined,
    now: () => 100,
    log: () => undefined,
  });
  assert.deepEqual(await handler(event("one")), { statusCode: 200 });
  assert.equal(saved?.sourceKey, sourceKey("203.0.113.42"));
  assert.equal(JSON.stringify(saved).includes("203.0.113.42"), false);
});

test("pair relay forwards ciphertext unchanged and does not store it", async () => {
  const connection: Connection = {
    connectionId: "a",
    authMode: "pairing",
    sourceKey: "source",
    pairingId: uuid(2),
    connectedAt: 1,
    expiresAt: 1_000,
  };
  const pair: Pair = {
    pairId: uuid(2),
    locator: "123456",
    status: "READY",
    sideA: { connectionId: "a", sideId: uuid(3) },
    sideB: { connectionId: "b", sideId: uuid(4) },
    version: 2,
    expiresAt: 1_000,
  };
  const sent: Array<{ connectionId: string; message: ServerEnvelope }> = [];
  const handler = createHandler({
    store: fakeStore({ connection: async () => connection, pairById: async () => pair }),
    post: async (connectionId, message) => { sent.push({ connectionId, message }); },
    now: () => 100,
    id: (() => { let value = 10; return () => uuid(value++); })(),
    log: () => undefined,
  });
  await handler(event("a", envelope("relay.frame", {
    channel: "pair",
    channelId: pair.pairId,
    seq: 1,
    payload: "AQID",
  })));
  assert.equal(sent[0]?.connectionId, "b");
  assert.equal((sent[0]?.message.body as { payload?: string }).payload, "AQID");
  assert.equal(sent.at(-1)?.message.type, "ok");
});

test("reciprocal commits expose only routing metadata and reject self-links", () => {
  const a: PairCommit = {
    connectionId: "a",
    sideId: uuid(3),
    linkId: uuid(5),
    self: { endpointId: uuid(6), role: "controller", credentialHash: "a".repeat(43) },
    peer: { endpointId: uuid(7), role: "companion" },
  };
  const b: PairCommit = {
    connectionId: "b",
    sideId: uuid(4),
    linkId: uuid(5),
    self: { endpointId: uuid(7), role: "companion", credentialHash: "b".repeat(43) },
    peer: { endpointId: uuid(6), role: "controller" },
  };
  assert.equal(reciprocalCommits(a, b), true);
  assert.equal(sameCommit(a, {
    peer: { role: a.peer.role, endpointId: a.peer.endpointId },
    self: { credentialHash: a.self.credentialHash, role: a.self.role, endpointId: a.self.endpointId },
    linkId: a.linkId,
    sideId: a.sideId,
    connectionId: a.connectionId,
  }), true);
  const link = linkFromCommits(a, b, 100);
  assert.deepEqual(Object.keys(link).sort(), ["companionId", "controllerId", "createdAt", "linkId", "status"]);
  assert.equal(reciprocalCommits(a, { ...b, self: { ...b.self, endpointId: a.self.endpointId } }), false);
});

test("connect transaction is bound to the hash validated by the authorizer", async () => {
  let input: Record<string, unknown> | undefined;
  const db = { send: async (command: { input: Record<string, unknown> }) => { input = command.input; return {}; } };
  const store = new DynamoStore("table", db as never);
  await store.connect({
    connectionId: "connection",
    authMode: "endpoint",
    endpointId: uuid(6),
    sourceKey: "source",
    connectedAt: 1,
    expiresAt: 2,
  }, "validated-hash");
  const transaction = input as { TransactItems: Array<{ Update?: { ConditionExpression?: string; ExpressionAttributeValues?: Record<string, unknown> } }> };
  assert.match(transaction.TransactItems[1]?.Update?.ConditionExpression ?? "", /credentialHash = :credentialHash/);
  assert.equal(transaction.TransactItems[1]?.Update?.ExpressionAttributeValues?.[":credentialHash"], "validated-hash");
});

test("pair cancellation rejects activation before and during cancellation", async () => {
  const pair: Pair = {
    pairId: uuid(10),
    locator: "123456",
    status: "ACTIVE",
    sideA: { connectionId: "a", sideId: uuid(11) },
    sideB: { connectionId: "b", sideId: uuid(12) },
    version: 4,
    expiresAt: 1_000,
  };
  const storeWithStates = (states: Pair[]) => {
    let pairRead = 0;
    return new DynamoStore("table", { send: async (command: { input: { Key?: { pk?: string }; UpdateExpression?: string } }) => {
      if (command.input.UpdateExpression) {
        throw Object.assign(new Error("lost race"), { name: "ConditionalCheckFailedException" });
      }
      if (command.input.Key?.pk === `PAIRID#${pair.pairId}`) {
        return { Item: { pk: command.input.Key.pk, sk: "META", kind: "pairid", pairId: pair.pairId, locator: pair.locator, expiresAt: pair.expiresAt } };
      }
      const current = states[Math.min(pairRead++, states.length - 1)];
      return { Item: { pk: `PAIR#${pair.locator}`, sk: "META", kind: "pair", ...current } };
    } } as never);
  };
  const conflict = (error: unknown) => error instanceof ServiceError && error.code === "CONFLICT";

  await assert.rejects(() => storeWithStates([pair]).cancelPair(pair.pairId, "a", 100), conflict);
  await assert.rejects(() => storeWithStates([
    { ...pair, status: "HALF_COMMITTED", version: 3 },
    pair,
  ]).cancelPair(pair.pairId, "a", 100), conflict);
});

test("endpoint revocation is durable before link enumeration", async () => {
  const endpoint: Endpoint = {
    endpointId: uuid(13),
    credentialHash: "a".repeat(43),
    role: "controller",
    createdAt: 1,
    updatedAt: 1,
  };
  const operations: string[] = [];
  const db = { send: async (command: { input: { KeyConditionExpression?: string; UpdateExpression?: string } }) => {
    if (command.input.KeyConditionExpression) {
      operations.push("query");
      return { Items: [] };
    }
    if (command.input.UpdateExpression) {
      operations.push("revoke");
      return {};
    }
    return { Item: { pk: `ENDPOINT#${endpoint.endpointId}`, sk: "META", kind: "endpoint", ...endpoint } };
  } };

  await new DynamoStore("table", db as never).revokeEndpoint(endpoint.endpointId, 100);
  assert.deepEqual(operations, ["revoke", "query"]);
});

test("expired and already-closed sessions retry pointer cleanup", async () => {
  const session: Session = {
    sessionId: uuid(20),
    linkId: uuid(21),
    controllerId: uuid(22),
    companionId: uuid(23),
    controllerConnectionId: "controller",
    companionConnectionId: "companion",
    status: "ACTIVE",
    createdAt: 1,
    expiresAt: 2,
  };
  const updates: string[] = [];
  let stored = session;
  const db = { send: async (command: { input: Record<string, unknown> }) => {
    const input = command.input as { Key?: { pk?: string }; UpdateExpression?: string };
    if (!input.UpdateExpression) return { Item: { pk: `SESSION#${session.sessionId}`, sk: "META", kind: "session", ...stored } };
    updates.push(`${input.Key?.pk}:${input.UpdateExpression}`);
    if (input.Key?.pk === `SESSION#${session.sessionId}`) stored = { ...stored, status: "CLOSED", closedAt: 10 };
    return {};
  } };
  const store = new DynamoStore("table", db as never);
  const first = await store.closeSession(session.sessionId, session.controllerId, 10);
  assert.equal(first?.closedNow, true);
  const second = await store.closeSession(session.sessionId, session.controllerId, 11);
  assert.equal(second?.closedNow, false);
  assert.equal(updates.filter((value) => value.includes("REMOVE activeSessionId")).length, 4);
});

test("session cleanup propagates real Dynamo failures", async () => {
  const session: Session = {
    sessionId: uuid(24),
    linkId: uuid(25),
    controllerId: uuid(26),
    companionId: uuid(27),
    controllerConnectionId: "controller",
    companionConnectionId: "companion",
    status: "CLOSED",
    createdAt: 1,
    expiresAt: 2,
  };
  const db = { send: async (command: { input: { Key?: { pk?: string }; UpdateExpression?: string } }) => {
    if (!command.input.UpdateExpression) return { Item: { pk: `SESSION#${session.sessionId}`, sk: "META", kind: "session", ...session } };
    if (command.input.Key?.pk === `LINK#${session.linkId}`) throw new Error("cleanup failed");
    return {};
  } };
  await assert.rejects(
    () => new DynamoStore("table", db as never).closeSession(session.sessionId, undefined, 10),
    /cleanup failed/,
  );
});

test("revoked links cannot relay through a still-active session", async () => {
  const controllerId = uuid(30);
  const companionId = uuid(31);
  const session: Session = {
    sessionId: uuid(32),
    linkId: uuid(33),
    controllerId,
    companionId,
    controllerConnectionId: "controller",
    companionConnectionId: "companion",
    status: "ACTIVE",
    createdAt: 1,
    expiresAt: 1_000,
  };
  const connection: Connection = {
    connectionId: "controller",
    authMode: "endpoint",
    endpointId: controllerId,
    sourceKey: "source",
    sessionId: session.sessionId,
    connectedAt: 1,
    expiresAt: 1_000,
  };
  const endpoints: Record<string, Endpoint> = {
    [controllerId]: { endpointId: controllerId, credentialHash: "a".repeat(43), role: "controller", connectionId: "controller", createdAt: 1, updatedAt: 1 },
    [companionId]: { endpointId: companionId, credentialHash: "b".repeat(43), role: "companion", connectionId: "companion", createdAt: 1, updatedAt: 1 },
  };
  const sent: Array<{ connectionId: string; message: ServerEnvelope }> = [];
  const handler = createHandler({
    store: fakeStore({
      connection: async () => connection,
      session: async () => session,
      link: async () => ({ linkId: session.linkId, controllerId, companionId, status: "REVOKED", activeSessionId: session.sessionId, createdAt: 1 }),
      getEndpoint: async (endpointId) => endpoints[endpointId],
      closeSession: async () => ({ session: { ...session, status: "CLOSED" }, closedNow: true }),
    }),
    post: async (connectionId, message) => { sent.push({ connectionId, message }); },
    now: () => 100,
    id: (() => { let value = 40; return () => uuid(value++); })(),
    log: () => undefined,
  });
  await handler(event("controller", envelope("relay.frame", {
    channel: "session",
    channelId: session.sessionId,
    seq: 1,
    payload: "AQID",
  })));
  assert.equal(sent.some(({ connectionId, message }) => connectionId === "companion" && message.type === "relay.frame"), false);
  assert.equal((sent.at(-1)?.message.body as { code?: string }).code, "FORBIDDEN");
});

test("pair join reports PEER_OFFLINE when the creator notification is gone", async () => {
  const pair: Pair = {
    pairId: uuid(50),
    locator: "123456",
    status: "READY",
    sideA: { connectionId: "creator", sideId: uuid(51) },
    sideB: { connectionId: "joiner", sideId: uuid(52) },
    version: 2,
    expiresAt: 1_000,
  };
  const joiner: Connection = { connectionId: "joiner", authMode: "pairing", sourceKey: "source", connectedAt: 1, expiresAt: 1_000 };
  const sent: ServerEnvelope[] = [];
  const handler = createHandler({
    store: fakeStore({
      connection: async () => joiner,
      rateLimit: async () => undefined,
      joinPair: async () => pair,
      disconnect: async () => ({ connectionId: "creator", authMode: "pairing", sourceKey: "source", pairingId: pair.pairId, connectedAt: 1, expiresAt: 1_000 }),
      cancelPair: async () => ({ ...pair, status: "CLOSED" }),
    }),
    post: async (connectionId, message) => {
      if (connectionId === "creator") throw Object.assign(new Error("gone"), { name: "GoneException" });
      sent.push(message);
    },
    now: () => 100,
    id: (() => { let value = 60; return () => uuid(value++); })(),
    log: () => undefined,
  });
  await handler(event("joiner", envelope("pair.join", { locator: pair.locator })));
  assert.equal(sent.some(({ type }) => type === "ok"), false);
  assert.equal((sent.at(-1)?.body as { code?: string }).code, "PEER_OFFLINE");
});

test("session open closes and reports PEER_OFFLINE when the companion notification is gone", async () => {
  const controllerId = uuid(61);
  const companionId = uuid(62);
  const session: Session = {
    sessionId: uuid(63),
    linkId: uuid(64),
    controllerId,
    companionId,
    controllerConnectionId: "controller",
    companionConnectionId: "companion",
    status: "ACTIVE",
    createdAt: 1,
    expiresAt: 1_000,
  };
  const sent: ServerEnvelope[] = [];
  let closed = false;
  const handler = createHandler({
    store: fakeStore({
      connection: async () => ({ connectionId: "controller", authMode: "endpoint", endpointId: controllerId, sourceKey: "source", connectedAt: 1, expiresAt: 1_000 }),
      openSession: async () => session,
      disconnect: async () => ({ connectionId: "companion", authMode: "endpoint", endpointId: companionId, sourceKey: "source", sessionId: session.sessionId, connectedAt: 1, expiresAt: 1_000 }),
      closeSession: async () => {
        const closedNow = !closed;
        closed = true;
        return { session: { ...session, status: "CLOSED" }, closedNow };
      },
    }),
    post: async (connectionId, message) => {
      if (connectionId === "companion") throw Object.assign(new Error("gone"), { name: "GoneException" });
      sent.push(message);
    },
    now: () => 100,
    id: (() => { let value = 65; return () => uuid(value++); })(),
    log: () => undefined,
  });
  await handler(event("controller", envelope("session.open", { linkId: session.linkId })));
  assert.equal(closed, true);
  assert.equal(sent.some(({ type }) => type === "ok"), false);
  assert.equal(sent.some(({ type }) => type === "session.closed"), true);
  assert.equal((sent.at(-1)?.body as { code?: string }).code, "PEER_OFFLINE");
});

test("endpoint revocation emits session.closed before link.revoked", async () => {
  const controllerId = uuid(70);
  const companionId = uuid(71);
  const link: Link = { linkId: uuid(72), controllerId, companionId, status: "REVOKED", createdAt: 1, revokedAt: 100 };
  const session: Session = {
    sessionId: uuid(73),
    linkId: link.linkId,
    controllerId,
    companionId,
    controllerConnectionId: "controller",
    companionConnectionId: "companion",
    status: "CLOSED",
    createdAt: 1,
    expiresAt: 1_000,
    closedAt: 100,
  };
  const sent: ServerEnvelope[] = [];
  const handler = createHandler({
    store: fakeStore({
      connection: async () => ({ connectionId: "controller", authMode: "endpoint", endpointId: controllerId, sourceKey: "source", connectedAt: 1, expiresAt: 1_000 }),
      revokeEndpoint: async () => ({
        endpoint: { endpointId: controllerId, credentialHash: "a".repeat(43), role: "controller", revokedAt: 100, createdAt: 1, updatedAt: 100 },
        links: [link],
        sessions: [session],
      }),
      getEndpoint: async (endpointId) => endpointId === companionId
        ? { endpointId, credentialHash: "b".repeat(43), role: "companion", connectionId: "companion", createdAt: 1, updatedAt: 1 }
        : undefined,
    }),
    post: async (_connectionId, message) => { sent.push(message); },
    now: () => 100,
    id: (() => { let value = 80; return () => uuid(value++); })(),
    log: () => undefined,
  });
  await handler(event("controller", envelope("endpoint.revoke", {})));
  assert.equal(sent.some(({ type }) => type === "session.closed"), true);
  assert.equal(sent.some(({ type }) => type === "link.revoked"), true);
});

test("session close keeps the public idempotent success contract", async () => {
  const endpointId = uuid(90);
  const sent: ServerEnvelope[] = [];
  const handler = createHandler({
    store: fakeStore({
      connection: async () => ({
        connectionId: "controller",
        authMode: "endpoint",
        endpointId,
        sourceKey: "source",
        connectedAt: 1,
        expiresAt: 1_000,
      }),
      closeSession: async () => undefined,
    }),
    post: async (_connectionId, message) => { sent.push(message); },
    now: () => 100,
    id: (() => { let value = 91; return () => uuid(value++); })(),
    log: () => undefined,
  });
  await handler(event("controller", envelope("session.close", { sessionId: uuid(99) })));
  const reply = parseServerEnvelope(sent.at(-1));
  assert.equal(reply.type, "ok");
  assert.deepEqual(reply.body, { requestType: "session.close", result: { closed: true } });
});
