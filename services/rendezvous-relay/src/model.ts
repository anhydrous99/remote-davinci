import { isDeepStrictEqual } from "node:util";

export type Role = "controller" | "companion";
export type PairStatus = "OPEN" | "READY" | "HALF_COMMITTED" | "ACTIVE" | "CLOSED";

export interface Connection {
  connectionId: string;
  authMode: "pairing" | "endpoint";
  endpointId?: string;
  sourceKey: string;
  pairingId?: string;
  sessionId?: string;
  connectedAt: number;
  expiresAt: number;
}

export interface Endpoint {
  endpointId: string;
  credentialHash: string;
  role: Role;
  connectionId?: string;
  activeSessionId?: string;
  revokedAt?: number;
  createdAt: number;
  updatedAt: number;
}

export interface PairSide {
  connectionId: string;
  sideId: string;
}

export interface PairIdentity {
  endpointId: string;
  role: Role;
}

export interface PairCommit {
  connectionId: string;
  sideId: string;
  linkId: string;
  self: PairIdentity & { credentialHash: string };
  peer: PairIdentity;
}

export interface Pair {
  pairId: string;
  locator: string;
  status: PairStatus;
  sideA: PairSide;
  sideB?: PairSide;
  commitA?: PairCommit;
  commitB?: PairCommit;
  version: number;
  expiresAt: number;
}

export interface Link {
  linkId: string;
  controllerId: string;
  companionId: string;
  status: "ACTIVE" | "REVOKED";
  activeSessionId?: string;
  createdAt: number;
  revokedAt?: number;
}

export interface Session {
  sessionId: string;
  linkId: string;
  controllerId: string;
  companionId: string;
  controllerConnectionId: string;
  companionConnectionId: string;
  status: "ACTIVE" | "CLOSED";
  createdAt: number;
  expiresAt: number;
  closedAt?: number;
}

export interface CloseSessionResult {
  session: Session;
  closedNow: boolean;
}

export class ServiceError extends Error {
  constructor(
    readonly code: string,
    readonly retryable = false,
    readonly retryAfterMs?: number,
  ) {
    super(code);
  }
}

export const isExpired = (record: { expiresAt: number }, now: number): boolean =>
  record.expiresAt <= now;

export const sameCommit = (a: PairCommit, b: PairCommit): boolean => isDeepStrictEqual(a, b);

export function reciprocalCommits(a: PairCommit, b: PairCommit): boolean {
  return (
    a.linkId === b.linkId &&
    a.self.endpointId !== a.peer.endpointId &&
    a.self.endpointId === b.peer.endpointId &&
    a.peer.endpointId === b.self.endpointId &&
    a.self.role === b.peer.role &&
    a.peer.role === b.self.role &&
    a.self.role !== a.peer.role
  );
}

export function linkFromCommits(a: PairCommit, b: PairCommit, now: number): Link {
  if (!reciprocalCommits(a, b)) throw new ServiceError("CONFLICT");
  const controller = a.self.role === "controller" ? a.self : b.self;
  const companion = a.self.role === "companion" ? a.self : b.self;
  return {
    linkId: a.linkId,
    controllerId: controller.endpointId,
    companionId: companion.endpointId,
    status: "ACTIVE",
    createdAt: now,
  };
}
