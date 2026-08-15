# Remote DaVinci

Accountless rendezvous and live encrypted relay for an iPhone/iPad controller
and a macOS DaVinci Resolve companion.

## What is here

- `protocol`: the versioned, language-neutral wire contract and Go validators.
- `services/rendezvous-relay`: WebSocket authorization, pairing, routing, and
  live ciphertext forwarding in one Lambda.
- `apps/controller/RemoteDavinciController.swiftpm`: the native iOS 17+
  SwiftUI controller for iPhone and iPad.
- `cmd/companion` and `internal/companion`: the macOS Go companion and its
  loopback-only browser GUI.
- `infra/cdk`: the TypeScript CDK stack for API Gateway, Lambda, DynamoDB, and
  operational alarms.
- `docs/capacity.md`: the capacity envelope, quota prerequisites, and cost
  model.

The relay sees routing metadata and opaque ciphertext. It does not queue
commands, terminate the peer-to-peer secure channel, or connect to Resolve.

## AWS architecture

```mermaid
flowchart LR
  IOS["iPhone / iPad<br/>controller"]
  MAC["macOS<br/>Resolve companion"]

  subgraph AWS["RemoteDavinci-{dev|prod} AWS stack"]
    subgraph APIGW["API Gateway WebSocket API"]
      STAGE["v1 stage<br/>auto-deploy"]
      ROUTES["5 routes + 1 route response<br/>$connect · $disconnect · $default<br/>pair.frame · session.frame"]
    end

    WIRING["5 Lambda integrations<br/>5 invoke permissions"]
    RELAY["RelayHandler Lambda<br/>Go · ARM64 · provided.al2023<br/>256 MiB · 10-second timeout"]
    STATE[("DynamoDB State table<br/>on-demand · AWS-managed encryption<br/>pk + sk · expiresAt TTL")]
    IAM["Lambda execution role/policy<br/>DynamoDB item operations<br/>execute-api:ManageConnections"]

    RELAY_LOGS["CloudWatch RelayLogs"]
    ACCESS_LOGS["CloudWatch AccessLogs<br/>optional; enabled for dev by default"]

    LAMBDA_ALARMS["RelayErrors<br/>RelayThrottles"]
    API_ALARM["ApiExecutionErrors"]
    TABLE_ALARM["TableThrottles"]
  end

  IOS <-->|"WSS JSON"| STAGE
  MAC <-->|"WSS JSON"| STAGE

  STAGE --> ROUTES
  ROUTES --> WIRING --> RELAY
  RELAY <-->|"Get / Put / Update / Delete"| STATE
  RELAY -->|"POST @connections<br/>opaque ciphertext"| STAGE

  IAM -. "permissions" .-> RELAY
  RELAY -. "JSON logs" .-> RELAY_LOGS
  STAGE -. "request metadata" .-> ACCESS_LOGS

  RELAY -. "metrics" .-> LAMBDA_ALARMS
  STAGE -. "metrics" .-> API_ALARM
  STATE -. "metrics" .-> TABLE_ALARM
```

## Local validation

```sh
make bootstrap
make check
```

Synthesize the development stack with `npm --prefix infra/cdk run synth`. It
targets `us-east-1` by default; pass CDK context `region` to the infrastructure
workspace to select another region. Deployment requires an AWS account
bootstrapped for CDK and is intentionally not performed by the test suite.

## Run the vertical slice

Build and start the macOS companion:

```sh
make companion
.build/remote-davinci-companion
```

It prints and opens a launch-scoped URL at `http://127.0.0.1:7314`; keep that
URL private because its query token authorizes the loopback GUI for this
process. For Resolve control, launch DaVinci Resolve Studio and allow
command-line scripting in Resolve Preferences. The host-volume control does
not require Resolve.

Open `apps/controller/RemoteDavinciController.swiftpm` in Xcode, select a
development team and an iPhone or iPad running iOS 17 or later, and Run. Then:

1. Create an enrollment request on iOS.
2. Paste it into the companion GUI and create the link.
3. Paste the returned response into iOS and import it.
4. Keep the companion running, tap Connect, then use either control.

The two shipped operations are deliberately fixed: `resolve.page.edit` opens
Resolve's Edit page through the documented scripting API, and
`host.volume.toggle-mute` toggles macOS output mute. Remote raw keys, shell
commands, and user-authored scripts are not accepted.

Enrollment is a trusted, manual, one-operator ceremony for this slice. The iOS
bearer secret and Noise private key use the device-only Keychain; the unsigned
Go CLI uses a mode-0600 configuration file. Add PAKE/QR enrollment and macOS
Keychain storage before onboarding anyone outside that boundary.
Both apps offer separately confirmed local-only recovery when remote revocation
cannot complete; it warns that the old relay identity may remain.

On macOS with Xcode installed, run the controller's Noise/enrollment tests with:

```sh
make controller-check
```

The complete deployment, device, failure-path, host-effect, and cleanup matrix
is in [`docs/e2e-test-plan.md`](docs/e2e-test-plan.md).

## V1 boundary

V1 is single-region, relay-only, and live-only. Direct peer connectivity,
offline command queues, accounts, push wake-up, media transfer, and arbitrary
Resolve scripting are deferred until a measured requirement justifies them.

Passing local tests proves the contract and infrastructure logic, not physical
iPhone/iPad pairing, mobile network roaming, or live Resolve control.

## Client transport requirements

Clients use WebSocket ping/pong control frames every five minutes, reconnect at
a randomized age between 90 and 110 minutes, and use full-jitter retry capped at
15 minutes after failures. Each side limits an active session to 60 encrypted
frames per second and may coalesce only supersedable controls such as jog or
scrub updates.

Successful `pair.frame` and `session.frame` messages are intentionally silent.
The relay returns a correlated protocol error when it rejects a frame; an
application response from the encrypted peer is the only end-to-end delivery
confirmation.
