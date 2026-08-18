# End-to-end test plan

This is the release-validation matrix, not the basic setup guide. To build,
pair, and run the two apps, start with [Run the Mac companion and iPhone
app](../README.md#run-the-mac-companion-and-iphone-app).

This plan validates the complete live path:

```text
iPhone/iPad controller -> deployed WSS relay -> macOS companion -> Resolve/macOS
```

It separates repeatable automation from tests that require a signed physical
device or visible host effects. Passing unit tests or a no-op live canary alone
is not release readiness.

## Safety rules

- Use a disposable `RemoteDavinci-dev` stack for provisioning, revocation,
  replay, and failure-path tests. The live canary refuses to run without the
  disposable opt-in or an explicit dangerous production override.
- Never copy QR invitations, enrollment JSON, bearer headers, Noise keys,
  ciphertext, pairing secrets, or the companion launch token into test evidence
  or shared logs. The native app
  captures the helper's launch record privately. The development CLI
  prints a single-use browser-bootstrap URL to the local console; capture it
  privately and record only stable operation/error codes and pass/fail results.
- Give every test a timeout. Do not replay commands into a replacement session.
- Use a uniquely named disposable Resolve project. Delete only that exact
  project after closing it.
- Before changing host audio, record the exact output device and mute state.
  Restore both and verify them, including after a failed assertion.
- Revoke the link before endpoints. Destroy the exact disposable stack after
  inspecting its logs, metrics, and state. Never bulk-delete shared AWS data.

## Required test environments

| Environment | Purpose | Required state |
| --- | --- | --- |
| Local Go/Node | contracts, relay, companion, CDK | Go version from `go.mod`; Node 24; npm; clean test caches are optional |
| Mac Catalyst | fast Swift/Noise regression | current Xcode |
| Native macOS app | SwiftUI host, helper lifecycle, Keychain migration | Apple Silicon; macOS 14+; full Xcode; Go version from `go.mod`; stable signing identity for release checks |
| iPhone simulator | phone build, launch, layout | full Xcode; installed iOS 17+ runtime |
| iPad simulator | tablet build, launch, layout | full Xcode; installed iOS 17+ runtime |
| Disposable AWS stack | real API Gateway/Lambda/DynamoDB ordering and lifecycle | account credentials; stack tagged `Project=remote-davinci`, `Environment=dev` |
| Physical iPhone and iPad | Keychain, suspension, Wi-Fi/cellular roaming, signing | trusted devices, development provisioning, passcodes enabled |
| Host Mac | real control effects | companion running; Resolve scripting enabled; mute-capable output for mute test |

## Phase 0: immutable evidence record

Before a test run, record without secrets:

- Git commit plus `git status --short`.
- macOS, Xcode, iOS runtime/device, Go, Node, and Resolve versions.
- Production stack status and alarm state.
- Whether Resolve is running and whether a user project is open.
- Current default audio output and mute state.

Pass: the exact code and environment under test can be identified, production
has no active alarm, and cleanup targets are unambiguous.

## Phase 1: deterministic local gates

Run:

```sh
make bootstrap
make check
go test -race -count=1 ./...
make companion-app-check
make controller-check
```

Also run the controller test target with warnings as errors on one iPhone and
one iPad simulator. Inspect each `.xcresult` summary and require zero failures,
skips, or expected failures.

Coverage required:

- Rendezvous/control schema validation and frame byte limits.
- Official Noise IK and Noise NNpsk0 interoperability vectors, peer-static-key
  validation, and cross-language pairing-handshake coverage.
- Strict QR invitation parsing, relay pinning, expiry, independent secret
  validation, pairing prologue binding, legacy enrollment response validation,
  and device-only Keychain coding.
- Token-only pair creation/join, hash-only admission storage, wrong/missing/
  reused token rejection, and no downgrade to the legacy locator profile.
- Eight-frame/128 KiB bounded reordering, contiguous drain, and rejection of
  duplicates, stale sequences, oversized gaps, and oversized payloads.
- One-command-in-flight, expiration, deduplication, and late-response handling.
- Four fixed Resolve page mappings, initial/change-only page observation,
  unsupported-page handling, and no request echo from an inbound page event.
- Full-jitter reconnect ceiling, randomized connection rotation, and no replay.
- Config atomic write, mode `0600`, rejection of symlink/non-regular/weak-mode
  files, standalone insecure-storage opt-in, one-time browser bootstrap,
  localhost token, Host/Origin/media-type checks, reset checkpoints, and stale
  callback protection.
- Native readiness validation, terminal startup errors, parent-death shutdown,
  bounded helper restart, and verified file-to-Keychain migration.
- CDK synthesis assertions for routes, permissions, retention, TTL, alarms,
  throttles, tags, and production deletion protection.

Pass: every command exits zero and the working tree changes only by expected
source or ignored build artifacts.

## Phase 2: signed simulator launch and layout

For both an iPhone and iPad simulator:

1. Build normally for the simulator so the app receives an ad-hoc signature;
   do not use an unsigned build for Keychain launch validation.
2. Uninstall any prior app, install the fresh product, and cold launch it.
3. Verify the initial state says `Not enrolled`, shows **Scan Mac QR Code**, and
   leaves connection and host controls disabled.
4. Because the simulator camera cannot prove scanning, exercise the paste-invite
   fallback with valid, malformed, expired, and wrong-relay invitations. Verify
   no pending credential is promoted before reciprocal activation.
5. Verify all four page bodies are blank, then inspect portrait phone plus
   portrait and landscape tablet layouts, Dynamic Type, tab VoiceOver labels,
   and destructive confirmation dialogs.
6. Exercise explicit local-forget recovery with a deliberately invalid pending
   enrollment; verify it requires its own warning and confirmation.

Pass: no crash, truncation that hides an action, Keychain error, secret-bearing
log, accidental enabled control, or unconfirmed destructive action.

## Phase 3: disposable relay deployment

Deploy the exact CDK synthesis under test as `RemoteDavinci-dev`. If WebSocket
access logging is enabled (the default), first configure the account-level API
Gateway CloudWatch Logs role. Set `accessLogs=false` only as an explicit
exception for the disposable test stack.

Verify:

- CloudFormation reaches `CREATE_COMPLETE`.
- A post-deploy CDK diff reports zero differences.
- The WSS output performs a real HTTP 101 upgrade with pairing authorization.
- Lambda is active, DynamoDB is active with `expiresAt` TTL enabled, and no
  alarm is in `ALARM`.
- Production stack resources and outputs did not change.

Pass: the disposable endpoint is live and attributable to the current build,
with production unchanged.

## Phase 4: automated live relay canary

Run only against the confirmed disposable URL:

```sh
REMOTE_DAVINCI_E2E=1 \
REMOTE_DAVINCI_E2E_DISPOSABLE=1 \
REMOTE_DAVINCI_RELAY_URL='wss://DISPOSABLE_HOST/v1' \
go test -count=1 -run '^TestLiveRelayLifecycle$' ./internal/companion
```

The canary must prove:

1. Provisioning creates opposite controller/companion endpoints and one link.
2. A controller-only session open returns `PEER_OFFLINE`.
3. Both bearer sockets connect and receive one consistent session.
4. Noise IK authenticates the stored static keys and exchanges encrypted hello.
5. One encrypted page request executes exactly once and gets a correlated
   encrypted response; one companion-originated page event traverses the same
   opaque relay path in the reverse direction.
6. Frames arriving as sequence 2 then 1 drain in order within the bounded
   window.
7. A closed session is not reused; an old encrypted frame sent to it returns
   `SESSION_NOT_FOUND` and does not execute.
8. A replacement session uses fresh Noise state and receives no queued command.
9. Link and both endpoints are revoked using fresh cleanup sockets.
10. Both revoked bearer credentials fail a new upgrade with HTTP 401.

Pass: all assertions succeed, cleanup succeeds, and no secret appears in test,
Lambda, API, or terminal output.

## Phase 5: native companion and loopback boundary

Build a signed native app with the same identity intended for release and cold
launch it. Separately start the development CLI with a temporary config path
when direct HTTP boundary probing is required:

```sh
go run ./cmd/companion -config /absolute/private/temp/companion.json -allow-insecure-file-config
```

For a confirmed disposable or self-hosted relay, add the same canonical
`REMOTE_DAVINCI_RELAY_URL` to both apps under **Product > Scheme > Edit Scheme >
Run > Arguments > Environment Variables** before creating either side's
enrollment, then run both apps from Xcode. Omit it when testing the default
production relay.

For the development CLI run only, capture its single-use bootstrap URL
privately. The native app receives a separate launch record internally and does
not display it.

Verify:

- The native app opens no browser, its embedded helper uses an ephemeral
  loopback port, and the tokenized readiness record is never logged or shown.
- Normal Quit terminates the helper; forced parent death closes its stdin and
  the helper exits without becoming an orphan. Unexpected helper exits use
  bounded restart, while deterministic storage failures require manual retry.
- A valid legacy mode-0600 configuration migrates only after Keychain readback
  matches. Conflicts and Keychain failures preserve the legacy file and fail
  closed before the API binds.
- It binds only to an explicit loopback IP.
- `/api/*` rejects a missing or wrong launch token.
- Non-loopback/DNS-rebinding Host values, cross-origin POSTs, non-JSON POSTs,
  oversized bodies, unknown fields, and trailing JSON are rejected.
- Pairing start returns its invitation only once; state polling exposes only
  sanitized phase/expiry/controller data. Approve, reject, and cancel require
  the current pair ID and the launch-scoped API token.
- A scan hides the QR before approval. Reject, cancel, expiry, helper shutdown,
  malformed identity, and cryptographic failure close the slot and erase its
  in-memory join token and PSK without creating configuration.
- The current-enrollment guard blocks replacement until reset or explicit
  separately confirmed local forget; the latter warns that the remote identity
  may remain.
- Link confirmation and a correlated relay acknowledgment are required for
  reset. A failed reset retains credentials and restores the relay connection.
- Once link revocation is durably checkpointed, endpoint revocation is
  best-effort and a lost endpoint acknowledgment cannot strand local cleanup.
- The CLI bootstrap succeeds once, replay fails, and the API token delivered to
  port-scoped session storage does not enter the process arguments, startup
  URL, application logs, or error bodies; config secrets and enrollment
  material never do.
- A corrupt temporary config fails closed before the GUI or native API binds.
  Recovery is an explicit move-aside of that exact file and a fresh enrollment;
  record that the old remote identity may remain.

Pass: an unauthenticated browser or native localhost caller cannot read state or
mutate the host, and every supported runtime failure leaves a recoverable state.

## Phase 6: physical-device live matrix

Repeat QR pairing separately on a physical iPhone and iPad using fresh
endpoints. For each device:

1. Test camera permission allow, deny, re-enable in Settings, low light,
   portrait/landscape, Dynamic Type, VoiceOver, and repeated scanner callbacks.
   The scanner must stop after one valid invite.
2. Tamper the QR relay, pair ID, join token, PSK, expiry, and one unknown field
   separately. Require rejection or cryptographic failure with no saved link;
   also reject an expired screenshot and reuse of a successfully scanned QR.
3. Scan a fresh QR, verify the Mac hides it, compare the displayed controller
   label/fingerprint and five requested controls, then approve. Reject a separate
   fresh attempt once and verify neither device persists it.
4. Verify both sides report a secure session and matching peer, and that the
   controller connects automatically only after activation.
5. Tap each page tab and use the host mute control once. Require remote actions
   to remain unavailable while disconnected or handshaking, and page commands
   to remain bounded to one in flight.
6. Confirm success, stable failure code, and unknown-result UI states are
   distinguishable.
7. Background while scanning, authenticating, awaiting approval, and after
   activation. Pre-activation cases require a fresh code; after activation,
   foreground and reconnect with no prior command replay.
8. Disable/restore Wi-Fi, switch Wi-Fi to cellular and back, restart the
   companion, and replace the bearer socket. Confirm bounded backoff and fresh
   sessions without stale-session teardown.
9. Inject a delayed response beyond command expiry. It may update an expired
   result policy but must not close an otherwise healthy secure session.
10. Revoke and re-enroll. Verify the old link stops immediately, both old bearer
    credentials fail, exact Keychain data is removed, and the new identity is
    different.
11. Test the separately confirmed local-forget path with a deliberately stale
    credential; record any intentionally orphaned inert endpoint for stack
    teardown.

Pass: both form factors complete the matrix over a real signed Keychain and
real suspension/network behavior, with zero replay or unauthorized execution.

## Phase 7: real Resolve and host effects

### Resolve

1. Confirm Resolve is not already in use, then launch the installed exact app.
2. Through the documented scripting API, create a uniquely named disposable
   project with no media.
3. Put Resolve on Cut before connecting. Connect and verify the initial
   `resolve.page.changed` snapshot selects Cut in the app without asking Resolve
   to change pages.
4. Tap Cut, Edit, Fusion, and Color in the app. For each tab, verify
   `GetCurrentPage()` returns the matching lowercase page and the correlated
   success result contains that page.
5. Select Cut, Edit, Fusion, and Color inside Resolve. For each change, verify
   the app follows within two 500 ms polls plus relay latency (target under 1.5
   seconds on a healthy connection) and sends no echo request.
6. Select Media, Fairlight, and Deliver inside Resolve. Verify the app retains
   its last supported tab and sends no corrective command. Return to a
   supported page and verify synchronization resumes.
7. Exercise rapid app and Resolve page changes. Verify one command remains in
   flight, the final state converges to Resolve, and no event/request loop or
   stale selection appears.
8. Close Resolve. A page request must return `resolve.unavailable` without
   relaunch, focus stealing, keystrokes, or fallback shell execution. Reopen
   Resolve and verify page observation reattaches and emits a fresh supported
   snapshot.
9. Close and delete only the disposable project; verify it no longer exists.

### Host mute

1. Record the exact default output device and boolean mute state.
2. Send `host.volume.toggle-mute` once and verify the value inverted.
3. Send it again and verify the exact baseline was restored.
4. On an output without a mute property, require `host.mute-unsupported` and
   verify no output device or volume setting changed.

Pass: both effects are observed and fully restored; no existing Resolve project,
media, preference, output selection, or unrelated host state changes.

## Phase 8: resilience and soak

Run a bounded two-hour soak on a disposable link:

- One native ping/pong interval and one forced 90–110 minute rotation.
- Periodic no-op encrypted requests below 60 frames/second.
- Alternating supported Resolve pages plus occasional unsupported pages to
  exercise observer deduplication and resumption without command echo.
- Network loss during handshake, during idle read, before request send, after
  execution but before response, and during revocation.
- Back-to-back frames to exercise real relay reordering.
- Duplicate request IDs and 257 unique requests to prove deduplication and the
  per-session request bound.
- Companion and controller process restarts with persisted credentials.

Pass: memory remains bounded, no command executes twice, reconnect delay resets
after a stable connection, ping failure wakes a blocked read, rotation creates a
fresh session, and terminal revocation never reconnects indefinitely.

## Phase 9: observability and cleanup

Before teardown, inspect the disposable stack:

- Lambda errors/throttles and API execution errors.
- DynamoDB throttles, TTL status, and only expected active/tombstoned records.
- Sanitized logs for validation codes; search explicitly for bearer prefixes,
  enrollment/invitation field names, join tokens, PSKs, Noise material, and full
  payloads.

Then:

1. Revoke any remaining test link/endpoints.
2. Stop the companion and simulators; remove only temporary config/build output.
3. Destroy exactly `RemoteDavinci-dev` with matching environment, region, app,
   and access-log context.
4. Verify CloudFormation reports the dev stack absent and no tagged dev table,
   API, Lambda, log group, or alarm remains.
5. Recheck production status, WSS output, Lambda health, table status, and alarms.

Final release evidence must list every phase as passed, failed, or externally
blocked. Simulator proof cannot substitute for physical-device Keychain,
suspension, roaming, or real Resolve/host-effect proof.
