import { createHash } from "node:crypto";
import { Ajv2020, type ErrorObject, type ValidateFunction } from "ajv/dist/2020.js";
import controlSchema from "./schemas/control-v1.schema.json" with { type: "json" };
import pairingSchema from "./schemas/pairing-v1.schema.json" with { type: "json" };
import rendezvousSchema from "./schemas/rendezvous-v1.schema.json" with { type: "json" };

export { controlSchema, pairingSchema, rendezvousSchema };

export const PROTOCOL_NAME = "remote-davinci.rendezvous" as const;
export const PROTOCOL_VERSION = 1 as const;
export const CONTROL_PROTOCOL_NAME = "remote-davinci.control" as const;
export const CONTROL_PROTOCOL_VERSION = 1 as const;
export const PAIRING_PROTOCOL_NAME = "remote-davinci.pairing" as const;
export const PAIRING_PROTOCOL_VERSION = 1 as const;
export const PAIRING_AUTHORIZATION = "Pairing rd1" as const;
export const PAIRING_APP_ID = "remote-davinci/pair/v1" as const;
export const SESSION_NOISE_PROTOCOL = "Noise_IK_25519_ChaChaPoly_SHA256" as const;
export const SESSION_NOISE_PROLOGUE = "remote-davinci/session/v1" as const;

export const MAX_WEBSOCKET_FRAME_BYTES = 32 * 1024;
export const MAX_RELAY_PAYLOAD_BYTES = 16 * 1024;
export const MAX_CONTROL_PLAINTEXT_BYTES = MAX_RELAY_PAYLOAD_BYTES - 16;
export const MAX_PAIRING_PLAINTEXT_BYTES = Math.floor((MAX_RELAY_PAYLOAD_BYTES - 23) / 2) - 40;
export const PAIRING_TTL_SECONDS = 5 * 60;
export const LOCATOR_DIGITS = 6;
export const PAIRING_WORDS = 4;

export const CLIENT_MESSAGE_TYPES = [
  "system.hello",
  "system.ping",
  "pair.create",
  "pair.join",
  "pair.commit",
  "pair.cancel",
  "relay.frame",
  "link.get",
  "link.revoke",
  "endpoint.rotate",
  "endpoint.revoke",
  "session.open",
  "session.close",
] as const;

export const SERVER_MESSAGE_TYPES = [
  "ok",
  "error",
  "pair.ready",
  "pair.completed",
  "pair.closed",
  "relay.frame",
  "session.opened",
  "session.closed",
  "link.revoked",
] as const;

export const CONTROL_MESSAGE_TYPES = ["hello", "request", "response", "event"] as const;

export const ERROR_CODES = [
  "INVALID_MESSAGE",
  "UNSUPPORTED_VERSION",
  "UNAUTHENTICATED",
  "FORBIDDEN",
  "PAIR_UNAVAILABLE",
  "PAIR_FULL",
  "PAIR_EXPIRED",
  "PEER_OFFLINE",
  "PEER_BUSY",
  "SESSION_NOT_FOUND",
  "PAYLOAD_TOO_LARGE",
  "RATE_LIMITED",
  "CONFLICT",
  "INTERNAL",
] as const;

export type ClientMessageType = (typeof CLIENT_MESSAGE_TYPES)[number];
export type ServerMessageType = (typeof SERVER_MESSAGE_TYPES)[number];
export type ControlMessageType = (typeof CONTROL_MESSAGE_TYPES)[number];
export type ErrorCode = (typeof ERROR_CODES)[number];
export type DeviceRole = "controller" | "companion";
export type RelayChannel = "pair" | "session";
export type JsonPrimitive = string | number | boolean | null;
export type JsonValue = JsonPrimitive | JsonValue[] | { [key: string]: JsonValue };
export type JsonObject = { [key: string]: JsonValue };
export type EmptyBody = JsonObject;

export interface RoutingEndpoint {
  endpointId: string;
  role: DeviceRole;
}

export interface EndpointCommit extends RoutingEndpoint {
  credentialHash: string;
}

export interface ClientBodyByType {
  "system.hello": EmptyBody;
  "system.ping": { sentAt: number };
  "pair.create": EmptyBody;
  "pair.join": { locator: string };
  "pair.commit": {
    pairId: string;
    sideId: string;
    linkId: string;
    self: EndpointCommit;
    peer: RoutingEndpoint;
  };
  "pair.cancel": { pairId: string };
  "relay.frame": {
    channel: RelayChannel;
    channelId: string;
    seq: number;
    payload: string;
  };
  "link.get": { linkId: string };
  "link.revoke": { linkId: string };
  "endpoint.rotate": { credentialHash: string };
  "endpoint.revoke": EmptyBody;
  "session.open": { linkId: string };
  "session.close": { sessionId: string };
}

export interface OkResultByRequest {
  "system.hello": { serverTime: number; protocolVersion: typeof PROTOCOL_VERSION };
  "system.ping": { receivedAt: number };
  "pair.create": { pairId: string; sideId: string; locator: string; expiresAt: number };
  "pair.join": { pairId: string; sideId: string; expiresAt: number };
  "pair.commit": { pending: true } | { linkId: string; active: true };
  "pair.cancel": { cancelled: true };
  "relay.frame": { delivered: true };
  "link.get": {
    linkId: string;
    peerEndpointId: string;
    peerRole: DeviceRole;
    status: "active" | "revoked";
    revokedAt?: number;
  };
  "link.revoke": { revoked: true };
  "endpoint.rotate": { rotated: true };
  "endpoint.revoke": { revoked: true; linksRevoked: number };
  "session.open": { sessionId: string };
  "session.close": { closed: true };
}

export type OkBody = {
  [K in ClientMessageType]: { requestType: K; result: OkResultByRequest[K] };
}[ClientMessageType];

export interface ServerBodyByType {
  ok: OkBody;
  error: {
    code: ErrorCode;
    retryable: boolean;
    retryAfterMs?: number;
  };
  "pair.ready": {
    pairId: string;
    peerSideId: string;
    expiresAt: number;
  };
  "pair.completed": {
    pairId: string;
    linkId: string;
    peerEndpointId: string;
    peerRole: DeviceRole;
  };
  "pair.closed": {
    pairId: string;
    reason: "cancelled" | "expired" | "peer-disconnected" | "failed";
  };
  "relay.frame": ClientBodyByType["relay.frame"];
  "session.opened": {
    sessionId: string;
    linkId: string;
    peerEndpointId: string;
  };
  "session.closed": {
    sessionId: string;
    reason: "requested" | "peer-disconnected" | "expired" | "revoked" | "replaced";
  };
  "link.revoked": { linkId: string };
}

export interface BaseEnvelope<T extends string, B> {
  protocol: typeof PROTOCOL_NAME;
  v: typeof PROTOCOL_VERSION;
  type: T;
  id: string;
  body: B;
}

type EnvelopeUnion<M> = {
  [K in keyof M]: K extends string ? BaseEnvelope<K, M[K]> : never;
}[keyof M];

export type ClientEnvelope = EnvelopeUnion<ClientBodyByType>;

type ServerEnvelopeUnion = {
  [K in keyof ServerBodyByType]: K extends "ok" | "error"
    ? BaseEnvelope<K, ServerBodyByType[K]> & { replyTo: string }
    : K extends string
      ? BaseEnvelope<K, ServerBodyByType[K]>
      : never;
}[keyof ServerBodyByType];

export type ServerEnvelope = ServerEnvelopeUnion;
export type RendezvousEnvelope = ClientEnvelope | ServerEnvelope;

export interface PairingIdentityEnvelope {
  protocol: typeof PAIRING_PROTOCOL_NAME;
  v: typeof PAIRING_PROTOCOL_VERSION;
  type: "identity";
  id: string;
  body: {
    linkId: string;
    endpointId: string;
    role: DeviceRole;
    noiseKey: string;
    noiseFingerprint: string;
    deviceLabel: string;
    permissions: string[];
    capabilities: string[];
  };
}

export interface WormholeMessage {
  phase: "pake" | "version" | `${number}`;
  body: string;
}

export interface ControlBodyByType {
  hello: {
    role: DeviceRole;
    capabilities: string[];
    appVersion: string;
  };
  request: {
    operation: string;
    args: JsonObject;
    sentAt: number;
    expiresAt: number;
  };
  response:
    | { ok: true; result: JsonValue }
    | { ok: false; error: { code: string; message?: string; retryable?: boolean } };
  event: { name: string; data: JsonValue };
}

interface BaseControlEnvelope<T extends string, B> {
  protocol: typeof CONTROL_PROTOCOL_NAME;
  v: typeof CONTROL_PROTOCOL_VERSION;
  type: T;
  id: string;
  body: B;
}

export type ControlEnvelope = {
  [K in keyof ControlBodyByType]: K extends "response"
    ? BaseControlEnvelope<K, ControlBodyByType[K]> & { replyTo: string }
    : K extends string
      ? BaseControlEnvelope<K, ControlBodyByType[K]>
      : never;
}[keyof ControlBodyByType];

export type ParsedAuthorization =
  | { scheme: "pairing" }
  | { scheme: "bearer"; endpointId: string; secret: string };

export class ProtocolValidationError extends Error {
  readonly code: ErrorCode;
  readonly issues: readonly string[];

  constructor(code: ErrorCode, message: string, issues: readonly string[] = []) {
    super(message);
    this.name = "ProtocolValidationError";
    this.code = code;
    this.issues = issues;
  }
}

const ajv = new Ajv2020({ allErrors: true, strict: true });
ajv.addSchema(rendezvousSchema);
ajv.addSchema(pairingSchema);
ajv.addSchema(controlSchema);

const RENDEZVOUS_SCHEMA_ID = rendezvousSchema.$id;
const CONTROL_SCHEMA_ID = controlSchema.$id;
const PAIRING_SCHEMA_ID = pairingSchema.$id;

function validator(ref: string): ValidateFunction {
  const found = ajv.getSchema(ref);
  if (!found) throw new Error(`Missing bundled protocol schema: ${ref}`);
  return found;
}

const validateClient = validator(`${RENDEZVOUS_SCHEMA_ID}#/$defs/clientEnvelope`);
const validateServer = validator(`${RENDEZVOUS_SCHEMA_ID}#/$defs/serverEnvelope`);
const validateRendezvous = validator(RENDEZVOUS_SCHEMA_ID);
const validatePairing = validator(PAIRING_SCHEMA_ID);
const validateWormholeMessage = validator(`${PAIRING_SCHEMA_ID}#/$defs/wormholeMessage`);
const validateControl = validator(CONTROL_SCHEMA_ID);
const encoder = new TextEncoder();

function decodeJson(input: string | unknown, maxBytes: number): unknown {
  let json: string;
  if (typeof input === "string") {
    json = input;
  } else {
    try {
      const serialized = JSON.stringify(input);
      if (serialized === undefined) throw new Error("not JSON");
      json = serialized;
    } catch {
      throw new ProtocolValidationError("INVALID_MESSAGE", "Protocol frame is not JSON-serializable");
    }
  }
  if (encoder.encode(json).byteLength > maxBytes) {
    throw new ProtocolValidationError("PAYLOAD_TOO_LARGE", "Protocol frame exceeds its byte limit");
  }
  try {
    return JSON.parse(json) as unknown;
  } catch {
    throw new ProtocolValidationError("INVALID_MESSAGE", "Protocol frame is not valid JSON");
  }
}

function issues(errors: ErrorObject[] | null | undefined): string[] {
  return (errors ?? []).map(({ instancePath, message }) => `${instancePath || "/"} ${message ?? "is invalid"}`);
}

function parsed<T>(input: string | unknown, check: ValidateFunction, maxBytes: number): T {
  const value = decodeJson(input, maxBytes);
  const record = typeof value === "object" && value !== null ? value as Record<string, unknown> : undefined;
  preflightRelayPayload(record);
  if (!check(value)) {
    if (
      record?.v !== undefined && record.v !== PROTOCOL_VERSION &&
      (record.protocol === PROTOCOL_NAME || record.protocol === CONTROL_PROTOCOL_NAME || record.protocol === PAIRING_PROTOCOL_NAME)
    ) {
      throw new ProtocolValidationError("UNSUPPORTED_VERSION", "Protocol version is not supported");
    }
    throw new ProtocolValidationError("INVALID_MESSAGE", "Protocol frame does not match the v1 contract", issues(check.errors));
  }
  return value as T;
}

function canonicalBase64UrlBytes(value: string): Buffer | undefined {
  if (!/^[A-Za-z0-9_-]+$/.test(value) || value.length % 4 === 1) return undefined;
  const bytes = Buffer.from(value, "base64url");
  return bytes.toString("base64url") === value ? bytes : undefined;
}

function preflightRelayPayload(record: Record<string, unknown> | undefined): void {
  if (record?.protocol !== PROTOCOL_NAME || record.type !== "relay.frame") return;
  const body = typeof record.body === "object" && record.body !== null
    ? record.body as Record<string, unknown>
    : undefined;
  if (typeof body?.payload !== "string") return;
  const bytes = canonicalBase64UrlBytes(body.payload);
  if (!bytes) {
    throw new ProtocolValidationError("INVALID_MESSAGE", "Relay payload must be canonical unpadded base64url");
  }
  if (bytes.byteLength > MAX_RELAY_PAYLOAD_BYTES) {
    throw new ProtocolValidationError("PAYLOAD_TOO_LARGE", "Decoded relay payload exceeds 16 KiB");
  }
}

function enforceRelayLimit(envelope: RendezvousEnvelope): void {
  if (envelope.type !== "relay.frame") return;
  const bytes = canonicalBase64UrlBytes(envelope.body.payload);
  if (!bytes) {
    throw new ProtocolValidationError("INVALID_MESSAGE", "Relay payload must be canonical unpadded base64url");
  }
  if (bytes.byteLength > MAX_RELAY_PAYLOAD_BYTES) {
    throw new ProtocolValidationError("PAYLOAD_TOO_LARGE", "Decoded relay payload exceeds 16 KiB");
  }
}

function enforceRendezvousSemantics(envelope: RendezvousEnvelope): void {
  if (
    envelope.type === "pair.commit" &&
    (envelope.body.self.endpointId === envelope.body.peer.endpointId || envelope.body.self.role === envelope.body.peer.role)
  ) {
    throw new ProtocolValidationError("INVALID_MESSAGE", "Pairing endpoints must be distinct and have opposite roles");
  }
  enforceRelayLimit(envelope);
}

export function parseClientEnvelope(input: string | unknown): ClientEnvelope {
  const envelope = parsed<ClientEnvelope>(input, validateClient, MAX_WEBSOCKET_FRAME_BYTES);
  enforceRendezvousSemantics(envelope);
  return envelope;
}

export function parseServerEnvelope(input: string | unknown): ServerEnvelope {
  const envelope = parsed<ServerEnvelope>(input, validateServer, MAX_WEBSOCKET_FRAME_BYTES);
  enforceRendezvousSemantics(envelope);
  return envelope;
}

export function parseRendezvousEnvelope(input: string | unknown): RendezvousEnvelope {
  const envelope = parsed<RendezvousEnvelope>(input, validateRendezvous, MAX_WEBSOCKET_FRAME_BYTES);
  enforceRendezvousSemantics(envelope);
  return envelope;
}

export function parseControlEnvelope(input: string | unknown): ControlEnvelope {
  const envelope = parsed<ControlEnvelope>(input, validateControl, MAX_CONTROL_PLAINTEXT_BYTES);
  if (envelope.type === "request" && envelope.body.expiresAt < envelope.body.sentAt) {
    throw new ProtocolValidationError("INVALID_MESSAGE", "Request expiresAt must not precede sentAt");
  }
  return envelope;
}

export function parsePairingEnvelope(input: string | unknown): PairingIdentityEnvelope {
  const envelope = parsed<PairingIdentityEnvelope>(input, validatePairing, MAX_PAIRING_PLAINTEXT_BYTES);
  if (envelope.body.noiseFingerprint !== noiseKeyFingerprint(envelope.body.noiseKey)) {
    throw new ProtocolValidationError("INVALID_MESSAGE", "Noise fingerprint does not match the public key");
  }
  return envelope;
}

export function parseWormholeMessage(input: string | unknown): WormholeMessage {
  const message = parsed<WormholeMessage>(input, validateWormholeMessage, MAX_RELAY_PAYLOAD_BYTES);
  const body = Buffer.from(message.body, "hex");
  if (message.phase === "pake") {
    try {
      const wrapper = JSON.parse(body.toString("utf8")) as unknown;
      const pake = typeof wrapper === "object" && wrapper !== null && "pake_v1" in wrapper
        ? (wrapper as { pake_v1?: unknown }).pake_v1
        : undefined;
      if (typeof pake !== "string" || !/^(?:[0-9a-f]{2})+$/.test(pake)) throw new Error("invalid pake");
    } catch {
      throw new ProtocolValidationError("INVALID_MESSAGE", "PAKE phase does not contain a valid pake_v1 wrapper");
    }
  } else if (body.byteLength < 40) {
    throw new ProtocolValidationError("INVALID_MESSAGE", "Encrypted Wormhole phases require a SecretBox nonce and tag");
  }
  return message;
}

const UUID = "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}";
const UUID_PATTERN = new RegExp(`^${UUID}$`);
const BEARER = new RegExp(`^Bearer rd1\\.(${UUID})\\.([A-Za-z0-9_-]{43})$`);

export function sessionNoisePrologue(linkId: string, sessionId: string): Uint8Array {
  if (!UUID_PATTERN.test(linkId) || !UUID_PATTERN.test(sessionId)) {
    throw new ProtocolValidationError("INVALID_MESSAGE", "Noise prologue IDs must be lowercase UUIDs");
  }
  return encoder.encode(`${SESSION_NOISE_PROLOGUE}\n${linkId}\n${sessionId}`);
}

export function noiseKeyFingerprint(noiseKey: string): string {
  const key = canonicalBase64UrlBytes(noiseKey);
  if (!key || key.byteLength !== 32) {
    throw new ProtocolValidationError("INVALID_MESSAGE", "Noise public key must be 32 canonical base64url bytes");
  }
  return `sha256:${createHash("sha256").update(key).digest("base64url")}`;
}

export function parseAuthorization(header: string | undefined): ParsedAuthorization {
  if (header === PAIRING_AUTHORIZATION) return { scheme: "pairing" };
  const match = header?.match(BEARER);
  if (!match?.[1] || !match[2] || canonicalBase64UrlBytes(match[2])?.byteLength !== 32) {
    throw new ProtocolValidationError("UNAUTHENTICATED", "Authorization header is missing or invalid");
  }
  return { scheme: "bearer", endpointId: match[1], secret: match[2] };
}
