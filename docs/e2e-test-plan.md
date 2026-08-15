# End-to-end test plan

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
- Never copy enrollment JSON, bearer headers, Noise keys, ciphertext, or the
  companion launch token into test evidence or shared logs. The CLI necessarily
  prints its launch-scoped tokenized URL to the local console; capture it
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
| Local Go/Node | contracts, relay, companion, CDK | supported Go and Node versions; clean test caches are optional |
| Mac Catalyst | fast Swift/Noise regression | current Xcode |
| iPhone simulator | phone build, launch, layout | installed iOS runtime |
| iPad simulator | tablet build, launch, layout | installed iOS runtime |
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
make check
go test -count=1 ./...
go test -race -count=1 ./...
go vet ./...
make controller-check
```

Also run the controller test target with warnings as errors on one iPhone and
one iPad simulator. Inspect each `.xcresult` summary and require zero failures,
skips, or expected failures.

Coverage required:

- Rendezvous/control schema validation and frame byte limits.
- Official Noise IK interoperability vector and peer-static-key validation.
- Enrollment response validation and device-only Keychain coding.
- Eight-frame/128 KiB bounded reordering, contiguous drain, and rejection of
  duplicates, stale sequences, oversized gaps, and oversized payloads.
- One-command-in-flight, expiration, deduplication, and late-response handling.
- Full-jitter reconnect ceiling, randomized connection rotation, and no replay.
- Config atomic write, mode `0600`, localhost token, Host/Origin/media-type
  checks, reset checkpoints, and stale callback protection.
- CDK synthesis assertions for routes, permissions, retention, TTL, alarms,
  throttles, tags, and production deletion protection.

Pass: every command exits zero and the working tree changes only by expected
source or ignored build artifacts.

## Phase 2: signed simulator launch and layout

For both an iPhone and iPad simulator:

1. Build normally for the simulator so the app receives an ad-hoc signature;
   do not use an unsigned build for Keychain launch validation.
2. Uninstall any prior app, install the fresh product, and cold launch it.
3. Verify the initial state says `Not enrolled`, with Connect and both controls
   disabled.
4. Create an enrollment request, terminate and relaunch, and verify the pending
   request survives in Keychain without exposing its secret in logs.
5. Inspect portrait phone plus portrait and landscape tablet layouts, Dynamic
   Type, VoiceOver labels/hints/values, and destructive confirmation dialogs.
6. Exercise explicit local-forget recovery with a deliberately invalid pending
   enrollment; verify it requires its own warning and confirmation.

Pass: no crash, truncation that hides an action, Keychain error, secret-bearing
log, accidental enabled control, or unconfirmed destructive action.

## Phase 3: disposable relay deployment

Deploy the exact CDK synthesis under test as `RemoteDavinci-dev`. If WebSocket
access logging is enabled, first configure the account-level API Gateway
CloudWatch Logs role; otherwise explicitly set `accessLogs=false` for the
disposable test stack.

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
5. One encrypted semantic request executes exactly once and gets a correlated
   encrypted response.
6. Frames arriving as sequence 2 then 1 drain in order within the bounded
   window.
7. A closed session is not reused; an old encrypted frame sent to it returns
   `SESSION_NOT_FOUND` and does not execute.
8. A replacement session uses fresh Noise state and receives no queued command.
9. Link and both endpoints are revoked using fresh cleanup sockets.
10. Both revoked bearer credentials fail a new upgrade with HTTP 401.

Pass: all assertions succeed, cleanup succeeds, and no secret appears in test,
Lambda, API, or terminal output.

## Phase 5: companion loopback boundary

Start a fresh companion process with a temporary config path and capture its
launch URL privately.

Verify:

- It binds only to an explicit loopback IP.
- `/api/*` rejects a missing or wrong launch token.
- Non-loopback/DNS-rebinding Host values, cross-origin POSTs, non-JSON POSTs,
  oversized bodies, unknown fields, and trailing JSON are rejected.
- The current-enrollment guard blocks replacement until reset or explicit
  separately confirmed local forget; the latter warns that the remote identity
  may remain.
- Link confirmation and a correlated relay acknowledgment are required for
  reset. A failed reset retains credentials and restores the relay connection.
- Once link revocation is durably checkpointed, endpoint revocation is
  best-effort and a lost endpoint acknowledgment cannot strand local cleanup.
- Beyond the one local startup URL, the launch token does not enter application
  logs or error bodies; config secrets and enrollment material never do.
- A corrupt temporary config fails closed before the GUI binds. For this
  unsigned slice, recovery is an explicit move-aside of that exact file and a
  fresh enrollment; record that the old remote identity may remain.

Pass: an unauthenticated browser or native localhost caller cannot read state or
mutate the host, and every supported runtime failure leaves a recoverable state.

## Phase 6: physical-device live matrix

Repeat the manual enrollment ceremony separately on an iPhone and iPad using
fresh endpoints. For each device:

1. Confirm controller request details on the trusted Mac and import the returned
   response only on the originating device.
2. Connect and verify both sides report a secure session and matching peer.
3. Send each shipped semantic operation once. Require disabled controls while
   disconnected, handshaking, or another command is in flight.
4. Confirm success, stable failure code, and unknown-result UI states are
   distinguishable.
5. Background for 30 seconds, foreground, and reconnect; confirm no prior
   command is replayed.
6. Disable/restore Wi-Fi, switch Wi-Fi to cellular and back, restart the
   companion, and replace the bearer socket. Confirm bounded backoff and fresh
   sessions without stale-session teardown.
7. Inject a delayed response beyond command expiry. It may update an expired
   result policy but must not close an otherwise healthy secure session.
8. Revoke and re-enroll. Verify the old link stops immediately, both old bearer
   credentials fail, exact Keychain data is removed, and the new identity is
   different.
9. Test the separately confirmed local-forget path with a deliberately stale
   credential; record any intentionally orphaned inert endpoint for stack
   teardown.

Pass: both form factors complete the matrix over a real signed Keychain and
real suspension/network behavior, with zero replay or unauthorized execution.

## Phase 7: real Resolve and host effects

### Resolve

1. Confirm Resolve is not already in use, then launch the installed exact app.
2. Through the documented scripting API, create a uniquely named disposable
   project with no media.
3. Send `resolve.page.edit` through the encrypted controller path.
4. Verify `GetCurrentPage()` is `edit` and the response is correlated success.
5. Close and delete only the disposable project; verify it no longer exists.
6. Repeat with Resolve closed and require `resolve.unavailable` without launch,
   focus stealing, keystrokes, or fallback shell execution.

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
  enrollment field names, Noise material, and full payloads.

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
