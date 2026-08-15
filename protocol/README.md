# `protocol`

Language-neutral v1 contracts and Go trust-boundary validators for the Remote DaVinci rendezvous, pairing, relay, and control protocols.

The JSON Schemas in `schemas` are the wire-format source of truth. The public Go package exports the corresponding message types, constants, and parsers. Unknown fields on a known message are ignored for forward compatibility, except for the deliberately closed `pair.commit` identity objects. Unknown message types, missing fields, invalid field values, and unsupported protocol versions fail closed.

## Scope and trust boundary

The AWS service is an availability and routing intermediary. It may learn endpoint IDs, roles, link IDs, credential hashes, pairing locators, IP addresses, connection times, and traffic volume. It must not receive or store Noise keys or fingerprints, device labels, permissions, capabilities, pairing words, private keys, decrypted control messages, or relay plaintext.

V1 is single-region, relay-only, and live-only. It has no mailbox, offline queue, push channel, direct-connect negotiation, account, or arbitrary script transport.

## Common encoding

- WebSocket messages are UTF-8 JSON text. Binary WebSocket frames are invalid.
- IDs are canonical lowercase UUID strings.
- Binary fields are unpadded RFC 4648 base64url unless a field explicitly says hexadecimal.
- Outer rendezvous timestamps are Unix epoch seconds (matching DynamoDB TTL). Inner control `sentAt` and `expiresAt` are Unix epoch milliseconds.
- The outer API Gateway frame is at most 32 KiB. A decoded relay `payload` is at most 16 KiB.
- Every sent message gets a fresh `id`. A response copies that ID to `replyTo`.

Outer envelope:

```json
{
  "protocol": "remote-davinci.rendezvous",
  "v": 1,
  "type": "pair.join",
  "id": "10000000-0000-4000-8000-000000000001",
  "body": { "locator": "482901" }
}
```

`ok` and `error` responses add `replyTo`. An `ok` body is `{ "requestType": "<original type>", "result": {} }`. An error body is `{ "code": "<stable code>", "retryable": false, "retryAfterMs": 1000 }`, with `retryAfterMs` present only when useful.

## WebSocket authentication

The upgrade request has exactly one of these headers:

```text
Authorization: Pairing rd1
Authorization: Bearer rd1.<endpointId>.<secret>
```

`secret` is 32 cryptographically random bytes encoded as 43 unpadded base64url characters. `credentialHash` is unpadded base64url of `SHA-256(raw secret bytes)`, not a hash of the encoded string. Clients store the secret in platform secure storage. AWS stores only the hash.

A pairing connection may call `system.*`, pairing lifecycle messages, and `pair.frame` for its assigned pair. A bearer connection may call `system.*`, `link.*`, `endpoint.*`, session lifecycle messages, and `session.frame` for its assigned session. Lifecycle operations recheck the current endpoint and link records. Session forwarding strongly reads the authoritative session route; revocation and connection replacement close that route transactionally before they return.

## Outer messages

| Client type | Body | Successful `result` |
| --- | --- | --- |
| `system.hello` | `{}` | `{ serverTime, protocolVersion }` |
| `system.ping` | `{ sentAt }` | `{ receivedAt }` |
| `pair.create` | `{}` | `{ pairId, sideId, locator, expiresAt }` |
| `pair.join` | `{ locator }` | `{ pairId, sideId, expiresAt }` |
| `pair.commit` | `{ pairId, sideId, linkId, self, peer }` | `{ pending: true }` or `{ linkId, active: true }` |
| `pair.cancel` | `{ pairId }` | `{ cancelled: true }` |
| `pair.frame` | `{ pairId, seq, payload }` | None (one-way) |
| `link.get` | `{ linkId }` | `{ linkId, peerEndpointId, peerRole, status, revokedAt? }` |
| `link.revoke` | `{ linkId }` | `{ revoked: true }` |
| `endpoint.rotate` | `{ credentialHash }` | `{ rotated: true }` |
| `endpoint.revoke` | `{}` | `{ revoked: true }` |
| `session.open` | `{ linkId }` | `{ sessionId }` |
| `session.close` | `{ sessionId }` | `{ closed: true }` |
| `session.frame` | `{ sessionId, seq, payload }` | None (one-way) |

`pair.commit.self` is `{ endpointId, role, credentialHash }`; `peer` is only `{ endpointId, role }`. These three objects reject extra fields so peer keys, labels, permissions, and capabilities cannot be persisted accidentally. The two commits must use the same `pairId`, `linkId`, opposite roles, and cross-matching endpoint IDs and roles. Each side supplies only its own credential hash.

Server events are:

- `pair.ready { pairId, peerSideId, expiresAt }`
- `pair.completed { pairId, linkId, peerEndpointId, peerRole }`
- `pair.closed { pairId, reason }`
- `pair.frame { pairId, seq, payload }`
- `session.opened { sessionId, linkId, peerEndpointId }`
- `session.closed { sessionId, reason }`
- `session.frame { sessionId, seq, payload }`
- `link.revoked { linkId }`

The stable outer errors are exported as `ErrorCodes`. Successful frame forwarding has no correlated `ok` response. A correlated `error` reports that AWS rejected or could not forward the frame; it says nothing about whether a peer decrypted or applied ciphertext already posted successfully.

## One-time pairing profile

### Human code

`pair.create` allocates a random six-digit routing locator for five minutes. The creator locally generates four random bytes and maps them to four words from the PGP Word List: word `0` uses the odd column, word `1` uses the even column, and the remaining words continue alternating. Both clients canonicalize the words to lowercase ASCII.

The displayed and QR-transferred code is exactly:

```text
<six digits>-<word 0>-<word 1>-<word 2>-<word 3>
```

The joining client sends only the six digits to `pair.join`. Both clients use the complete canonical string, including the locator, as the PAKE password. The service never receives the four words. A code is single-use; a wrong code, a third participant, expiry, cancellation, disconnect before activation, or any cryptographic failure closes the slot without creating a link.

### Magic Wormhole client-to-client compatibility

Use a reviewed implementation compatible with Magic Wormhole's `python-spake2==0.9` client-to-client profile; do not independently invent the curve or point encoding.

1. Run symmetric SPAKE2 with password bytes equal to NFC UTF-8 of the canonical code and `idSymmetric` equal to UTF-8 `remote-davinci/pair/v1`.
2. A client-to-client wire message is compact UTF-8 JSON `{ "phase": "...", "body": "..." }`. Encode those bytes as the outer `pair.frame` base64url `payload`. `phase` is `pake`, `version`, or a canonical decimal application sequence beginning at `0`; `body` is lowercase, even-length hexadecimal.
3. For `pake`, `body` decodes to UTF-8 JSON `{ "pake_v1": "<lowercase hex SPAKE message>" }`.
4. Let the SPAKE output be `K`. For every encrypted message derive a 32-byte phase key with RFC 5869 HKDF-SHA256: input key `K`, no salt, and info `ASCII("wormhole:phase:") || SHA256(ASCII(senderSideId)) || SHA256(ASCII(phase))`.
5. Encrypt `version` and numeric phases with NaCl SecretBox (XSalsa20-Poly1305), using a fresh random 24-byte nonce prepended to the authenticated ciphertext, then lowercase-hex encode the result into `body`.
6. The `version` plaintext is UTF-8 JSON containing `{ "app_versions": { "remote-davinci": { "v": 1 } } }`. Successfully decrypting any peer encrypted phase proves key possession; failure immediately closes the pairing. The optional 32-byte verifier is HKDF-SHA256(`K`, no salt, info `wormhole:verifier`).
7. After key confirmation, each side sends one numeric phase `0` whose decrypted plaintext matches `pairing-v1.schema.json`. The creator generates `linkId`; the joiner echoes it. `noiseFingerprint` is exactly `"sha256:" + base64url(SHA-256(raw 32-byte noiseKey))`; receivers recompute it and reject a mismatch. The Noise implementation also rejects invalid or low-order X25519 public keys. Noise keys, fingerprints, labels, permissions, and capabilities stay inside this encrypted document and local storage.
8. The controller's permissions are its request. The companion's permissions are its grant; both persist only the intersection after local user approval. Each then sends the minimal outer `pair.commit`.

The compact phase-`0` wrapper plus SecretBox and hex overhead limits the decrypted pairing identity document to `MAX_PAIRING_PLAINTEXT_BYTES` (8,140 bytes). Pairing state is `OPEN -> READY -> HALF_COMMITTED -> ACTIVE`; any non-active state can become `CLOSED`.

## Durable link and session profile

Private service credentials and the local Noise static private key belong in Keychain or the platform credential store. Normal local app storage holds the peer endpoint ID, peer Noise static public key and fingerprint, local display name, negotiated permissions/capabilities, protocol version, and revocation state. Credential loss or an unexpected peer key requires pairing again; a changed peer key is never silently accepted.

An authenticated controller opens a live session by link ID. The service permits one active session per endpoint and link and emits `session.opened` to both sides. Each direction starts outer `seq` at `1`. API Gateway may deliver concurrent relay invocations out of order, so a receiver buffers at most the next 8 frames (128 KiB decoded total) and drains only contiguous sequences into Noise. An old or duplicate sequence, or a gap beyond that bound, closes the session.

Use `Noise_IK_25519_ChaChaPoly_SHA256`, controller as initiator and companion as responder. The exact prologue bytes are:

```text
UTF8("remote-davinci/session/v1\n" + linkId + "\n" + sessionId)
```

`SessionNoisePrologue()` produces those bytes. Each endpoint must compare the authenticated remote static key to the key stored during pairing before enabling controls. One Noise handshake or transport message occupies one `session.frame` payload. After the handshake, each transport plaintext is one compact UTF-8 control envelope; its maximum is 16,368 bytes to leave room for the 16-byte ChaChaPoly tag.

## Encrypted control protocol

The independently versioned inner envelope is:

```json
{
  "protocol": "remote-davinci.control",
  "v": 1,
  "type": "request",
  "id": "20000000-0000-4000-8000-000000000001",
  "body": {
    "operation": "resolve.transport.play",
    "args": {},
    "sentAt": 1786723200000,
    "expiresAt": 1786723205000
  }
}
```

- `hello { role, capabilities, appVersion }` is the first transport message from each peer.
- `request { operation, args, sentAt, expiresAt }` uses semantic operation names. Expired requests are not executed.
- `response` adds `replyTo` and contains either `{ ok: true, result }` or `{ ok: false, error }`.
- `event { name, data }` is best effort.

Raw keystrokes, arbitrary scripts, and direct Resolve network access are not protocol operations. The companion checks each operation against the authenticated peer and locally stored grant. Within a session, duplicate request IDs return the cached response without executing twice.

## Delivery and lifecycle semantics

- Relay forwarding is ordered only by explicit `seq`; AWS stores no payloads. Receivers apply the bounded reorder rule above before processing `pair.frame` or `session.frame` payloads.
- Outer `id` values correlate responses; the service does not persist them as idempotency records. After an uncertain `pair.create` or `pair.join`, close the socket and start a new pairing. After an uncertain `session.open`, accept a received `session.opened` event or reconnect and open a fresh session.
- Socket loss closes the session and discards in-memory frames and response cache.
- Reconnect uses full-jitter exponential backoff from one second to 15 minutes, then creates a fresh service session and fresh Noise keys.
- No session frame or Resolve command is replayed into a replacement session.
- Native WebSocket ping/pong every five minutes avoids the ten-minute idle timeout without an application message. `system.ping` is only an explicit health/clock diagnostic. Reconnect at a randomized age from 90 to 110 minutes to stay below API Gateway's two-hour connection limit.
- Mobile suspension may make the controller unavailable. V1 reports offline state honestly and has no wake or deferred-delivery path.

## Runtime use

```go
import "github.com/anhydrous99/remote-davinci/protocol"

auth, err := protocol.ParseAuthorization(request.Headers["Authorization"])
command, err := protocol.ParseClient(request.Body)
```

The parsers return `ValidationError` without embedding input values, credentials, or payloads in the message. Logs may include the stable error code and schema paths only.
