# Customer-readiness roadmap

This is the implementation handoff for customer usability, synchronization,
security, performance, and latency. It keeps the V1 boundary intact: one
controller, one Mac companion, single-region relay, and live-only delivery. It
does not add accounts, offline queues, push wake-up, direct-connect negotiation,
media transfer, or arbitrary scripting.

## Release outcomes

| Area | Release outcome | Evidence |
| --- | --- | --- |
| Customer usability | A new customer can install, pair by QR or pasted one-time code, understand status, use every granted control from the main screen, and recover without handling protocol JSON. | Fresh-device walkthrough, accessibility pass, support notes, completion rate. |
| Synchronization | An enrolled controller connects on cold launch, resumes with a fresh secure session, wakes a pending retry when the network returns, detects a half-open socket, and never replays an interrupted command. | Lifecycle tests plus physical background, sleep/wake, and network-transition matrix. |
| Security | Pair activation is abuse-limited, fixed grants remain enforced, revocation removes active endpoint credentials, and logs contain only allowlisted metadata. | Unit/CDK tests, log review, destructive disposable-stack canary, signed-app Keychain test. |
| Performance | The relay remains error- and throttle-free at the accepted beta workload, and Lambda memory is selected from measurements rather than intuition. | Dated load report, CloudWatch metrics, memory sweep, cost record. |
| Latency | Foreground recovery, network recovery, control RTT, relay integration, host execution, and Resolve-event propagation have separate percentile measurements. | Dated p50/p95/p99 report from devices and an isolated AWS stack. |

## Implemented in this worktree

### Customer usability

- Replaced the seven blank controller tabs with an adaptive, grant-aware page
  grid; moved connection recovery and Mac mute onto the main screen.
- Added cold-launch auto-connect, clearer operation-specific recovery messages,
  and a nonblocking notice when a newer companion offers controls missing from
  the stored grant.
- Made authenticated QR pairing the only customer-facing enrollment flow. A
  customer without camera access copies the same expiring Mac pairing code and
  pastes it into the iOS scanner; the lower-level legacy protocol remains only
  for compatibility and tests.
- Moved Mac pairing ahead of technical connection details, collapsed raw relay
  identifiers, and kept destructive remote revoke separate from emergency local
  forget.
- Added native iOS/iPadOS and macOS app icons.

### Synchronization and reliability

- Preserved connection intent across background suspension and opens a fresh
  Noise session on foreground. Explicit Disconnect remains disconnected.
- Added a native network-path wake-up that only short-circuits an existing
  reconnect delay on an unsatisfied-to-satisfied transition.
- Added a ten-second watchdog around the five-minute native WebSocket ping and
  routes failure through the normal fresh-session reconnect path.
- Resets controller and companion retry backoff only after a continuous
  30-second secure session, avoiding rapid loops on unstable connections.
- Propagates the controller's absolute command expiry into companion host
  execution. Interrupted or expired commands are not queued or replayed.

### Security

- Limits successful pair activations by the already-hashed IPv4 or IPv6 `/64`
  source key. The beta default is 10 per source per hour, tunable from 1 through
  10,000, and remains atomic with the existing global daily circuit breaker and
  link activation.
- Emits metadata-only lifecycle audit events and a `PairActivations` metric.
  Production relay application logs are retained at `INFO` so those events
  reach the configured log group.
- Atomically removes `credentialHash`, connection ownership, and active-session
  state when an endpoint is revoked. A later proof-free revoke retry remains
  unauthenticated by design.
- Converts native helper operation logs into bounded JSON, then reconstructs
  only allowlisted operation, outcome, and duration fields in macOS unified
  logging. Raw helper stderr is discarded.
- Retains the login-Keychain implementation for the embedded Go helper. Moving
  a bare helper to the Data Protection Keychain is blocked until it has
  app-like packaging and authorized access-group entitlements.

### Performance and latency evidence

- Added API Gateway integration latency to metadata-only access logs.
- Expanded the gated disposable live canary to sample 1 through 100 sequential
  encrypted control round trips (20 by default) and report nearest-rank p50,
  p95, and p99.
- Added a dated performance-results template for workload, percentiles,
  capacity signals, Lambda memory sweep, cost, and the final tuning decision.
- Added unsigned Release and real iOS-SDK builds to local and CI checks.

## Acceptance targets

These are candidate gates, not claims about the current deployment.

| Signal | Initial beta gate |
| --- | ---: |
| Foreground to secure session | at most 3 seconds |
| Network restored to secure session | at most 5 seconds |
| Controller tap to correlated response | p95 at most 1.5 seconds |
| Relay integration latency | p95 at most 150 ms; p99 at most 300 ms |
| Resolve page change to controller | p95 at most 1.5 seconds |
| Unexpected steady-state errors | below 0.1% |
| Valid-request API/Lambda/DynamoDB throttles | zero |
| Interrupted commands replayed | zero |
| Credentials, pairing secrets, or plaintext payloads in logs | zero |

## Remaining release gates

1. Produce signed candidates. Archive the controller for TestFlight; sign the
   nested Mac helper and outer app with Developer ID, notarize, staple, and
   verify both signatures using [`release-checklist.md`](release-checklist.md).
2. On clean devices, complete QR and pasted-code onboarding, VoiceOver,
   Dynamic Type, iPhone/iPad rotation, camera-denied recovery, explicit
   disconnect, background/foreground, Mac sleep/wake, and network-loss tests.
3. Against a disposable AWS stack and supported Resolve Studio installation,
   run every phase in [`e2e-test-plan.md`](e2e-test-plan.md), including
   revocation, half-open connection, rotation, and secret-free log inspection.
4. Run the staged workload and Lambda memory sweep in
   [`performance-results-template.md`](performance-results-template.md). Change
   route limits, Lambda memory, region strategy, or the Resolve worker model
   only when a measured segment misses its gate.
5. Start an internal beta, review activation limiter false positives and support
   failures, then expand gradually with the previous signed artifact and relay
   commit retained for rollback.

## Scaling triggers

- Raise the per-source activation limit only when legitimate shared-NAT beta
  evidence shows false rejection; retain the global circuit breaker.
- Raise API Gateway route limits only after the staged workload approaches the
  configured rate with no downstream Lambda or DynamoDB throttling.
- Change Lambda memory only when the memory sweep improves latency or cost.
- Add another region only when measured user geography dominates relay RTT and
  the revocation/state model for multi-region operation is designed first.
- Replace the persistent 500 ms Resolve page poll only if the Resolve SDK adds a
  reliable callback or host measurements show it is the limiting segment.
