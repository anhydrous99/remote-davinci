import { createHash, timingSafeEqual } from "node:crypto";
import { parseAuthorization } from "@remote-davinci/protocol";
import { DynamoStore, type Store } from "./store.js";

interface AuthorizerEvent {
  headers?: Record<string, string | undefined>;
  methodArn?: string;
  routeArn?: string;
}

interface AuthorizerResult {
  principalId: string;
  policyDocument: {
    Version: "2012-10-17";
    Statement: [{ Action: "execute-api:Invoke"; Effect: "Allow"; Resource: string }];
  };
  context:
    | { authMode: "pairing" }
    | { authMode: "endpoint"; endpointId: string; credentialHash: string };
}

const unauthorized = (): never => { throw new Error("Unauthorized"); };
const digest = (secret: string): string => createHash("sha256").update(Buffer.from(secret, "base64url")).digest("base64url");
const equal = (a: string, b: string): boolean => {
  const left = Buffer.from(a);
  const right = Buffer.from(b);
  return left.length === right.length && timingSafeEqual(left, right);
};

export function createAuthorizer(store: Pick<Store, "getEndpoint">) {
  return async (event: AuthorizerEvent): Promise<AuthorizerResult> => {
    const header = Object.entries(event.headers ?? {}).find(([name]) => name.toLowerCase() === "authorization")?.[1];
    let authorization;
    try {
      authorization = parseAuthorization(header);
    } catch {
      return unauthorized();
    }

    let endpointId = "";
    if (authorization.scheme === "bearer") {
      endpointId = authorization.endpointId;
      const endpoint = await store.getEndpoint(endpointId);
      if (!endpoint || endpoint.revokedAt || !equal(endpoint.credentialHash, digest(authorization.secret))) {
        return unauthorized();
      }
    }

    const resource = event.methodArn ?? event.routeArn;
    if (!resource) return unauthorized();
    const context = authorization.scheme === "bearer"
      ? { authMode: "endpoint" as const, endpointId, credentialHash: digest(authorization.secret) }
      : { authMode: "pairing" as const };
    return {
      principalId: endpointId || "pairing",
      policyDocument: {
        Version: "2012-10-17",
        Statement: [{ Action: "execute-api:Invoke", Effect: "Allow", Resource: resource }],
      },
      context,
    };
  };
}

const store = new DynamoStore(process.env.TABLE_NAME ?? "missing");
export const handler = createAuthorizer(store);
