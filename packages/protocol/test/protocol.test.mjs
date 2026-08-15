import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  CLIENT_MESSAGE_TYPES,
  CONTROL_MESSAGE_TYPES,
  MAX_CONTROL_PLAINTEXT_BYTES,
  MAX_RELAY_PAYLOAD_BYTES,
  ProtocolValidationError,
  SERVER_MESSAGE_TYPES,
  noiseKeyFingerprint,
  parseAuthorization,
  parseClientEnvelope,
  parseControlEnvelope,
  parsePairingEnvelope,
  parseRendezvousEnvelope,
  parseServerEnvelope,
  parseWormholeMessage,
  sessionNoisePrologue,
} from "../dist/index.js";

const fixtures = JSON.parse(
  await readFile(new URL("../fixtures/conformance-v1.json", import.meta.url), "utf8"),
);

function rejects(code, action) {
  assert.throws(
    action,
    (error) => error instanceof ProtocolValidationError && error.code === code,
  );
}

test("all v1 rendezvous fixtures pass and cover the exported message types", () => {
  assert.deepEqual(
    fixtures.client.map((frame) => parseClientEnvelope(frame).type),
    CLIENT_MESSAGE_TYPES,
  );
  assert.deepEqual(
    fixtures.server.map((frame) => parseServerEnvelope(JSON.stringify(frame)).type),
    SERVER_MESSAGE_TYPES,
  );

  const extended = structuredClone(fixtures.client[2]);
  extended.futureField = { safely: "ignored" };
  assert.equal(parseClientEnvelope(extended).type, "pair.create");
});

test("ok responses correlate every request type with its required result", () => {
  const pairId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
  const sideId = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
  const linkId = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
  const sessionId = "dddddddd-dddd-4ddd-8ddd-dddddddddddd";
  const endpointId = "22222222-2222-4222-8222-222222222222";
  const results = {
    "system.hello": { serverTime: 1786723200, protocolVersion: 1 },
    "system.ping": { receivedAt: 1786723200 },
    "pair.create": { pairId, sideId, locator: "482901", expiresAt: 1786723500 },
    "pair.join": { pairId, sideId, expiresAt: 1786723500 },
    "pair.commit": { pending: true },
    "pair.cancel": { cancelled: true },
    "relay.frame": { delivered: true },
    "link.get": { linkId, peerEndpointId: endpointId, peerRole: "companion", status: "active" },
    "link.revoke": { revoked: true },
    "endpoint.rotate": { rotated: true },
    "endpoint.revoke": { revoked: true, linksRevoked: 1 },
    "session.open": { sessionId },
    "session.close": { closed: true },
  };

  assert.deepEqual(Object.keys(results), CLIENT_MESSAGE_TYPES);
  for (const [requestType, result] of Object.entries(results)) {
    const parsed = parseServerEnvelope({
      protocol: "remote-davinci.rendezvous",
      v: 1,
      type: "ok",
      id: "10000000-0000-4000-8000-000000000010",
      replyTo: "00000000-0000-4000-8000-000000000001",
      body: { requestType, result: { ...result, futureField: true } },
    });
    assert.equal(parsed.body.requestType, requestType);
  }

  const malformed = structuredClone(fixtures.server[0]);
  malformed.body.result = {};
  rejects("INVALID_MESSAGE", () => parseServerEnvelope(malformed));
});

test("pairing and encrypted control fixtures match their independent schemas", () => {
  const identity = parsePairingEnvelope(fixtures.pairingIdentity);
  assert.equal(identity.type, "identity");
  assert.equal(
    Buffer.from(identity.body.noiseKey, "base64url").toString("hex"),
    "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
  );
  assert.equal(noiseKeyFingerprint(identity.body.noiseKey), identity.body.noiseFingerprint);
  assert.deepEqual(
    fixtures.wormhole.map((frame) => parseWormholeMessage(frame).phase),
    ["pake", "version", "0"],
  );
  assert.deepEqual(
    fixtures.control.map((frame) => parseControlEnvelope(frame).type),
    CONTROL_MESSAGE_TYPES,
  );

  const expired = structuredClone(fixtures.control[1]);
  expired.body.expiresAt = expired.body.sentAt - 1;
  rejects("INVALID_MESSAGE", () => parseControlEnvelope(expired));
  rejects("INVALID_MESSAGE", () => parseWormholeMessage({ phase: "00", body: "aa" }));
  rejects("INVALID_MESSAGE", () => parseWormholeMessage({ phase: "0", body: "abc" }));
  rejects("INVALID_MESSAGE", () => parseWormholeMessage({ phase: "version", body: "00".repeat(39) }));
  rejects("INVALID_MESSAGE", () => parseWormholeMessage({
    phase: "pake",
    body: Buffer.from("{}").toString("hex"),
  }));

  const wrongFingerprint = structuredClone(fixtures.pairingIdentity);
  wrongFingerprint.body.noiseFingerprint = `sha256:${"A".repeat(43)}`;
  rejects("INVALID_MESSAGE", () => parsePairingEnvelope(wrongFingerprint));
});

test("authorization grammar is exact and never echoes credentials in errors", () => {
  assert.deepEqual(parseAuthorization(fixtures.authorization.pairing), { scheme: "pairing" });
  const authorization = parseAuthorization(fixtures.authorization.bearer);
  assert.deepEqual(authorization, {
    scheme: "bearer",
    endpointId: "11111111-1111-4111-8111-111111111111",
    secret: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
  });
  assert.equal(
    fixtures.client[4].body.self.credentialHash,
    createHash("sha256").update(Buffer.from(authorization.secret, "base64url")).digest("base64url"),
  );

  const bad = `${fixtures.authorization.bearer}=`;
  assert.throws(
    () => parseAuthorization(bad),
    (error) =>
      error instanceof ProtocolValidationError &&
      error.code === "UNAUTHENTICATED" &&
      !error.message.includes(bad),
  );
  rejects("UNAUTHENTICATED", () => parseAuthorization(
    `Bearer rd1.11111111-1111-4111-8111-111111111111.${"A".repeat(42)}B`,
  ));
});

test("malformed frames fail closed and payload limits report stable errors", () => {
  for (const { name, frame } of fixtures.invalidClient) {
    rejects(name === "unsupported version" ? "UNSUPPORTED_VERSION" : "INVALID_MESSAGE", () => parseClientEnvelope(frame));
  }
  rejects("INVALID_MESSAGE", () => parseClientEnvelope("not json"));

  const oversized = structuredClone(fixtures.client[6]);
  oversized.body.payload = Buffer.alloc(MAX_RELAY_PAYLOAD_BYTES + 1).toString("base64url");
  rejects("PAYLOAD_TOO_LARGE", () => parseClientEnvelope(oversized));

  const nonCanonical = structuredClone(fixtures.client[6]);
  nonCanonical.body.payload = "AB";
  rejects("INVALID_MESSAGE", () => parseClientEnvelope(nonCanonical));

  const metadataLeak = structuredClone(fixtures.client[4]);
  metadataLeak.body.peer.noiseKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
  rejects("INVALID_MESSAGE", () => parseClientEnvelope(metadataLeak));

  const sameRole = structuredClone(fixtures.client[4]);
  sameRole.body.peer.role = sameRole.body.self.role;
  rejects("INVALID_MESSAGE", () => parseClientEnvelope(sameRole));
  rejects("INVALID_MESSAGE", () => parseRendezvousEnvelope(sameRole));

  const millisecondTimestamp = structuredClone(fixtures.client[1]);
  millisecondTimestamp.body.sentAt = 1786723200000;
  rejects("INVALID_MESSAGE", () => parseClientEnvelope(millisecondTimestamp));

  const hugeObject = structuredClone(fixtures.control[3]);
  hugeObject.body.data = "x".repeat(MAX_CONTROL_PLAINTEXT_BYTES);
  rejects("PAYLOAD_TOO_LARGE", () => parseControlEnvelope(hugeObject));
});

test("Noise prologue encoding is deterministic and validates IDs", () => {
  assert.equal(
    new TextDecoder().decode(
      sessionNoisePrologue(
        "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
        "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
      ),
    ),
    "remote-davinci/session/v1\ncccccccc-cccc-4ccc-8ccc-cccccccccccc\ndddddddd-dddd-4ddd-8ddd-dddddddddddd",
  );
  rejects("INVALID_MESSAGE", () =>
    sessionNoisePrologue("not-a-link", "dddddddd-dddd-4ddd-8ddd-dddddddddddd"),
  );
});
