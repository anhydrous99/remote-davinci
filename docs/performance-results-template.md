# Performance results: YYYY-MM-DD

Performance targets are hypotheses until this record contains live measurements.
Use an isolated stack and disposable identities; never load-test production
customer pairings.

The gated canary prints encrypted control RTT percentiles when run with `-v`:

```sh
REMOTE_DAVINCI_E2E=1 \
REMOTE_DAVINCI_E2E_DISPOSABLE=1 \
REMOTE_DAVINCI_E2E_LATENCY_SAMPLES=20 \
REMOTE_DAVINCI_RELAY_URL='wss://DISPOSABLE_HOST/v1' \
go test -v -count=1 -run '^TestLiveRelayLifecycle$' ./internal/companion
```

## Candidate

- Commit:
- Environment and AWS region:
- Relay stack version:
- Lambda architecture and memory:
- API Gateway route throttle:
- DynamoDB mode:
- Controller device and OS:
- Companion Mac and OS:
- Resolve version and project state:
- Tester and date:

## Workload

- Cold or warm:
- Connections:
- Control round trips per second:
- Inbound frames per second:
- Duration:
- Command mix:
- Network/geography:
- Failure injection:

## Results

| Segment | Samples | p50 | p95 | p99 | Maximum | Target | Pass |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | :---: |
| Enrolled cold launch to secure | | | | | | | |
| Foreground to secure | | | | | | 3 s | |
| Network restored to secure | | | | | | 5 s | |
| Controller tap to response | | | | | | 1.5 s | |
| Relay integration latency | | | | | | 150 ms p95 / 300 ms p99 | |
| Companion operation | | | | | | | |
| Resolve change to controller | | | | | | 1.5 s | |

| Capacity signal | Result | Accepted value | Pass |
| --- | ---: | ---: | :---: |
| API Gateway throttles | | 0 | |
| Lambda errors | | 0 | |
| Lambda throttles | | 0 | |
| DynamoDB throttles | | 0 | |
| Rejected valid frames | | 0 | |
| Replayed commands | | 0 | |
| Estimated relay cost | | | |

## Memory sweep

| Lambda memory | p95 | p99 | Average billed duration | Estimated cost | Decision |
| ---: | ---: | ---: | ---: | ---: | --- |
| 128 MB | | | | | |
| 256 MB | | | | | |
| 512 MB | | | | | |

## Observations and decision

- Measured bottleneck:
- Smallest proposed change:
- Expected improvement:
- Security or revocation invariant affected:
- Re-test required:
- Decision and approver:
