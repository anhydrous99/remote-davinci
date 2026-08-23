# Performance results: YYYY-MM-DD

This file is an intentionally blank release record. Performance targets remain
hypotheses until a dated copy contains live measurements. Use an isolated stack
and disposable identities; never load-test production customer pairings.

The gated canary prints encrypted control RTT percentiles when run with `-v`:

```sh
REMOTE_DAVINCI_E2E=1 \
REMOTE_DAVINCI_E2E_DISPOSABLE=1 \
REMOTE_DAVINCI_E2E_LATENCY_SAMPLES=100 \
REMOTE_DAVINCI_RELAY_URL='wss://DISPOSABLE_HOST/v1' \
go test -v -count=1 -run '^TestLiveRelayLifecycle$' ./internal/companion
```

That canary proves the encrypted session path at modest sequential volume. The
separate load probe below forwards opaque payloads because API Gateway, Lambda,
and DynamoDB do not inspect Noise ciphertext. Do not use the load probe as
cryptographic, controller, host-operation, or Resolve evidence.

## Executable isolated-stack workflow

### 1. Confirm and deploy one memory candidate

Use a dedicated AWS account or an otherwise empty, quota-approved region. The
commands below always select the development stack, but that label is not a
safety boundary: inspect the identity and CDK diff before approving deployment.
Run one memory value at a time and repeat unchanged for `128`, `256`, and `512`.

```sh
mkdir -p .build/performance
PERF_REGION='us-east-1'
PERF_STACK='RemoteDavinci-dev'
PERF_MEMORY='128'

aws sts get-caller-identity
npm --prefix infra/cdk run build
npm --prefix infra/cdk exec -- cdk diff "$PERF_STACK" \
  --app 'node infra/cdk/dist/bin/remote-davinci.js' \
  -c environment=dev \
  -c region="$PERF_REGION" \
  -c lambdaMemory="$PERF_MEMORY" \
  -c performanceMode=true \
  -c pairActivationsPerSourceHour=10000
npm --prefix infra/cdk exec -- cdk deploy "$PERF_STACK" \
  --app 'node infra/cdk/dist/bin/remote-davinci.js' \
  -c environment=dev \
  -c region="$PERF_REGION" \
  -c lambdaMemory="$PERF_MEMORY" \
  -c performanceMode=true \
  -c pairActivationsPerSourceHour=10000
```

The CDK app accepts only the three documented memory values and otherwise keeps
the 256 MiB default. Dev-only `performanceMode=true` raises `session.frame` to
4,000 frames/s with a 5,000-frame burst; production rejects that context. The
elevated per-source activation limit is for this disposable stack only; the
10,000-activation global daily circuit breaker still applies.

Resolve the exact deployed endpoint from the confirmed stack rather than
copying another environment's URL:

```sh
PERF_RELAY_URL="$(aws cloudformation describe-stacks \
  --region "$PERF_REGION" \
  --stack-name "$PERF_STACK" \
  --query 'Stacks[0].Outputs[?OutputKey==`WebSocketUrl`].OutputValue | [0]' \
  --output text)"
case "$PERF_RELAY_URL" in
  wss://*) ;;
  *) echo 'Disposable WebSocket output is missing' >&2; exit 1 ;;
esac
```

### 2. Run the relay workload

`relay-perf` refuses the repository's configured production relay, requires the
explicit disposable opt-in, creates unique pairs through the normal protocol,
holds two authenticated sockets per pair, and attempts link plus endpoint
revocation on every normal, error, interrupt, and SIGTERM path. It emits
only aggregate JSON; bearer credentials never enter its output. A hard process
kill cannot run application cleanup, so destroy the disposable stack if the
probe reports cleanup failure or the load host is lost.

The following checked selector covers warm-up plus sustained and peak smoke
shapes for the memory comparison. Choose exactly one shape, run it, and
complete Step 3 immediately before changing `PERF_SHAPE`; the shape is included
in every interval artifact name.

```sh
PERF_SHAPE='sustained' # warmup, sustained, or peak
case "$PERF_SHAPE" in
  warmup)    PERF_PAIRS=4;  PERF_RPS=20;  PERF_DURATION=2m ;;
  sustained) PERF_PAIRS=20; PERF_RPS=100; PERF_DURATION=60m ;;
  peak)      PERF_PAIRS=40; PERF_RPS=200; PERF_DURATION=5m ;;
  *) echo 'Unknown PERF_SHAPE' >&2; exit 1 ;;
esac
PERF_START_EPOCH="$(date -u +%s)"
PERF_METRIC_START_ISO="$(date -u +%Y-%m-%dT%H:%M:00Z)"
REMOTE_DAVINCI_PERF_DISPOSABLE=1 \
go run ./cmd/relay-perf \
  -relay "$PERF_RELAY_URL" -pairs "$PERF_PAIRS" \
  -rps "$PERF_RPS" -duration "$PERF_DURATION" \
  > ".build/performance/${PERF_MEMORY}-${PERF_SHAPE}-relay.json"
PERF_END_EPOCH="$(date -u +%s)"
PERF_METRIC_END_ISO="$(date -u +%Y-%m-%dT%H:%M:59Z)"
```

Provisioning is deliberately paced to the relay's existing five
`pair.create` requests per source per minute. Thus 20- and 40-pair setup take at
least 3m48s and 7m48s respectively, plus protocol time; this is outside the
driver's reported measurement duration, while the AWS interval below covers the
full process lifecycle. A process is capped at 60 pairs so admission spacing
alone remains within its 15-minute setup bound.

Each pair is capped at 60 round trips/s so the probe cannot exceed the product's
per-endpoint frame limit. The probe is closed-loop per pair and rejects a
nonzero workload unless its observed rate reaches at least 95% of the selected
smoke target; do not use percentiles from a rejected run. A run retains at most
ten million exact latency samples; shorten or shard a larger workload. This
bounded probe compares Lambda memory and catches regressions, but it does not
prove the 1,000 sustained or 2,000 peak round-trip beta targets because it has
only one in-flight round trip per pair. Those targets and the 200,000-socket
envelope require reviewed open-loop, distributed load hosts, approved quotas,
and an isolated-stack fixture plan and remain external execution-only release
gates.

### 3. Collect AWS signals for the exact interval

Run this step immediately after the selected Step 2 shape. Do not change
`PERF_SHAPE` or its start/end variables until every shape-specific artifact is
saved.

Resolve resource names from the same stack:

```sh
PERF_ACCESS_LOG_GROUP="$(aws cloudformation list-stack-resources \
  --region "$PERF_REGION" --stack-name "$PERF_STACK" \
  --query 'StackResourceSummaries[?ResourceType==`AWS::Logs::LogGroup` && contains(LogicalResourceId, `AccessLogs`)].PhysicalResourceId | [0]' \
  --output text)"
PERF_RELAY_LOG_GROUP="$(aws cloudformation list-stack-resources \
  --region "$PERF_REGION" --stack-name "$PERF_STACK" \
  --query 'StackResourceSummaries[?ResourceType==`AWS::Logs::LogGroup` && contains(LogicalResourceId, `RelayLogs`)].PhysicalResourceId | [0]' \
  --output text)"
PERF_FUNCTION="$(aws cloudformation list-stack-resources \
  --region "$PERF_REGION" --stack-name "$PERF_STACK" \
  --query 'StackResourceSummaries[?ResourceType==`AWS::Lambda::Function`].PhysicalResourceId | [0]' \
  --output text)"
PERF_TABLE="$(aws cloudformation list-stack-resources \
  --region "$PERF_REGION" --stack-name "$PERF_STACK" \
  --query 'StackResourceSummaries[?ResourceType==`AWS::DynamoDB::Table`].PhysicalResourceId | [0]' \
  --output text)"
```

Aggregate API Gateway integration latency from metadata-only access logs. The
arithmetic expression converts the JSON string field to milliseconds. The
helper retries completed queries with no samples so delayed log ingestion
cannot create an empty evidence artifact:

```sh
run_sampled_logs_query() {
  PERF_QUERY_LOG_GROUP="$1"
  PERF_QUERY_STRING="$2"
  PERF_QUERY_OUTPUT="$3"
  PERF_QUERY_ATTEMPT=1
  while [ "$PERF_QUERY_ATTEMPT" -le 20 ]; do
    PERF_LAST_QUERY_ID="$(aws logs start-query \
      --region "$PERF_REGION" \
      --log-group-name "$PERF_QUERY_LOG_GROUP" \
      --start-time "$PERF_START_EPOCH" \
      --end-time "$PERF_END_EPOCH" \
      --query-string "$PERF_QUERY_STRING" \
      --query queryId --output text)" || return
    while :; do
      PERF_QUERY_STATUS="$(aws logs get-query-results \
        --region "$PERF_REGION" --query-id "$PERF_LAST_QUERY_ID" \
        --query status --output text)" || return
      case "$PERF_QUERY_STATUS" in
        Complete) break ;;
        Failed|Cancelled|Timeout|Unknown)
          echo "Logs query: $PERF_QUERY_STATUS" >&2
          return 1
          ;;
      esac
      sleep 1
    done
    PERF_QUERY_SAMPLES="$(aws logs get-query-results \
      --region "$PERF_REGION" --query-id "$PERF_LAST_QUERY_ID" \
      --query 'results[0][?field==`samples`].value | [0]' \
      --output text)" || return
    case "$PERF_QUERY_SAMPLES" in
      ''|None|*[!0-9]*) ;;
      *)
        if [ "$PERF_QUERY_SAMPLES" -gt 0 ]; then
          aws logs get-query-results \
            --region "$PERF_REGION" --query-id "$PERF_LAST_QUERY_ID" \
            > "$PERF_QUERY_OUTPUT" || return
          return
        fi
        ;;
    esac
    sleep 15
    PERF_QUERY_ATTEMPT=$((PERF_QUERY_ATTEMPT + 1))
  done
  echo "No Logs Insights samples for $PERF_QUERY_OUTPUT" >&2
  return 1
}

PERF_INTEGRATION_QUERY='fields integrationLatency * 1 as latencyMs
  | filter routeKey = "session.frame" and latencyMs >= 0
  | stats count(latencyMs) as samples, pct(latencyMs, 50) as p50Milliseconds, pct(latencyMs, 95) as p95Milliseconds, pct(latencyMs, 99) as p99Milliseconds, max(latencyMs) as maximumMilliseconds'
run_sampled_logs_query \
  "$PERF_ACCESS_LOG_GROUP" "$PERF_INTEGRATION_QUERY" \
  ".build/performance/${PERF_MEMORY}-${PERF_SHAPE}-integration-latency.json" \
  || exit 1
PERF_INTEGRATION_QUERY_ID="$PERF_LAST_QUERY_ID"
```

Run the error query and require no `429` or `5xx` result rows:

```sh
PERF_ERROR_QUERY_ID="$(aws logs start-query \
  --region "$PERF_REGION" \
  --log-group-name "$PERF_ACCESS_LOG_GROUP" \
  --start-time "$PERF_START_EPOCH" \
  --end-time "$PERF_END_EPOCH" \
  --query-string 'fields status * 1 as statusCode
    | filter statusCode = 429 or statusCode >= 500
    | stats count(*) as responses by statusCode' \
  --query queryId --output text)" || exit 1
while :; do
  PERF_ERROR_QUERY_STATUS="$(aws logs get-query-results \
    --region "$PERF_REGION" --query-id "$PERF_ERROR_QUERY_ID" \
    --query status --output text)" || exit 1
  case "$PERF_ERROR_QUERY_STATUS" in
    Complete) break ;;
    Failed|Cancelled|Timeout|Unknown) echo "Logs query: $PERF_ERROR_QUERY_STATUS" >&2; exit 1 ;;
  esac
  sleep 1
done
PERF_ERROR_OUTPUT=".build/performance/${PERF_MEMORY}-${PERF_SHAPE}-api-errors.json"
aws logs get-query-results \
  --region "$PERF_REGION" --query-id "$PERF_ERROR_QUERY_ID" \
  > "$PERF_ERROR_OUTPUT" || exit 1
PERF_ERROR_ROWS="$(aws logs get-query-results \
  --region "$PERF_REGION" --query-id "$PERF_ERROR_QUERY_ID" \
  --query 'length(results)' --output text)" || exit 1
[ "$PERF_ERROR_ROWS" -eq 0 ] || { echo "API error rows: $PERF_ERROR_ROWS" >&2; exit 1; }
```

CloudWatch error metrics are sparse and can legitimately return no datapoints
when zero. First poll positive Lambda and DynamoDB usage metrics to prove that
the exact interval is available, then save and reject any nonzero error or
throttle datapoint:

```sh
collect_metric_with_data() {
  PERF_OUTPUT="$1"
  shift
  PERF_ATTEMPT=1
  while [ "$PERF_ATTEMPT" -le 20 ]; do
    PERF_POINT_COUNT="$(aws cloudwatch get-metric-statistics "$@" \
      --query 'length(Datapoints)' --output text)" || return
    if [ "$PERF_POINT_COUNT" -gt 0 ]; then
      aws cloudwatch get-metric-statistics "$@" > "$PERF_OUTPUT"
      return
    fi
    sleep 15
    PERF_ATTEMPT=$((PERF_ATTEMPT + 1))
  done
  echo "No CloudWatch datapoints for $PERF_OUTPUT" >&2
  return 1
}

collect_zero_metric() {
  PERF_OUTPUT="$1"
  shift
  aws cloudwatch get-metric-statistics \
    "$@" > "$PERF_OUTPUT" || return
  PERF_NONZERO_POINTS="$(aws cloudwatch get-metric-statistics "$@" \
    --query 'length(Datapoints[?Sum > `0`])' --output text)" || return
  [ "$PERF_NONZERO_POINTS" -eq 0 ] || {
    echo "Nonzero error or throttle datapoints in $PERF_OUTPUT" >&2
    return 1
  }
}

collect_metric_with_data \
  ".build/performance/${PERF_MEMORY}-${PERF_SHAPE}-lambda-Invocations.json" \
  --region "$PERF_REGION" --namespace AWS/Lambda --metric-name Invocations \
  --dimensions Name=FunctionName,Value="$PERF_FUNCTION" \
  --start-time "$PERF_METRIC_START_ISO" --end-time "$PERF_METRIC_END_ISO" \
  --period 60 --statistics Sum || exit 1
for PERF_METRIC in ConsumedReadCapacityUnits ConsumedWriteCapacityUnits; do
  collect_metric_with_data \
    ".build/performance/${PERF_MEMORY}-${PERF_SHAPE}-dynamodb-${PERF_METRIC}.json" \
    --region "$PERF_REGION" --namespace AWS/DynamoDB \
    --metric-name "$PERF_METRIC" \
    --dimensions Name=TableName,Value="$PERF_TABLE" \
    --start-time "$PERF_METRIC_START_ISO" --end-time "$PERF_METRIC_END_ISO" \
    --period 60 --statistics Sum || exit 1
done
for PERF_METRIC in Errors Throttles; do
  collect_zero_metric \
    ".build/performance/${PERF_MEMORY}-${PERF_SHAPE}-lambda-${PERF_METRIC}.json" \
    --region "$PERF_REGION" --namespace AWS/Lambda \
    --metric-name "$PERF_METRIC" \
    --dimensions Name=FunctionName,Value="$PERF_FUNCTION" \
    --start-time "$PERF_METRIC_START_ISO" --end-time "$PERF_METRIC_END_ISO" \
    --period 60 --statistics Sum || exit 1
done
for PERF_METRIC in ReadThrottleEvents WriteThrottleEvents; do
  collect_zero_metric \
    ".build/performance/${PERF_MEMORY}-${PERF_SHAPE}-dynamodb-${PERF_METRIC}.json" \
    --region "$PERF_REGION" --namespace AWS/DynamoDB \
    --metric-name "$PERF_METRIC" \
    --dimensions Name=TableName,Value="$PERF_TABLE" \
    --start-time "$PERF_METRIC_START_ISO" --end-time "$PERF_METRIC_END_ISO" \
    --period 60 --statistics Sum || exit 1
done
```

Query and save the relay log group's Lambda REPORT records for the memory sweep:

```sh
PERF_LAMBDA_QUERY='filter @type = "REPORT"
  | stats count(*) as samples, pct(@duration, 95) as p95Milliseconds, pct(@duration, 99) as p99Milliseconds, avg(@billedDuration) as averageBilledMilliseconds, max(@maxMemoryUsed) as maximumMemoryMegabytes'
run_sampled_logs_query \
  "$PERF_RELAY_LOG_GROUP" "$PERF_LAMBDA_QUERY" \
  ".build/performance/${PERF_MEMORY}-${PERF_SHAPE}-lambda-report.json" \
  || exit 1
PERF_LAMBDA_QUERY_ID="$PERF_LAST_QUERY_ID"
```

After the `Project=remote-davinci` cost-allocation tag is active and charges have
settled, use an end date after the test date (Cost Explorer end dates are
exclusive):

```sh
PERF_COST_START='YYYY-MM-DD'
PERF_COST_END='YYYY-MM-DD'
aws ce get-cost-and-usage \
  --time-period Start="$PERF_COST_START",End="$PERF_COST_END" \
  --granularity DAILY \
  --metrics UnblendedCost UsageQuantity \
  --filter '{"Tags":{"Key":"Project","Values":["remote-davinci"],"MatchOptions":["EQUALS"]}}' \
  > ".build/performance/${PERF_MEMORY}-${PERF_SHAPE}-cost.json"
```

Keep every raw driver, metric, cost, and query result with the report; do not
transcribe only the winning memory value.

### 4. Collect each user-visible latency segment

For the five cross-process/device rows, record both relevant displays with one
shared-clock camera at a known frame rate. Independent iOS and macOS screen
recordings do not share a trustworthy clock. For every trial, divide the frame
count by capture frames/second and write one positive duration in milliseconds
per line:

- **Enrolled cold launch to secure:** terminated app begins launch to the green
  **Connected** state with controls enabled.
- **Foreground to secure:** selection of the suspended app begins to the same
  ready state after a fresh secure session.
- **Network restored to secure:** visible restoration of the test network begins
  to that ready state.
- **Controller tap to response:** touch-down on an enabled control to the visible
  operation-success feedback.
- **Resolve change to controller:** Resolve visibly enters the new page to the
  matching selected page on the controller.

Summarize each file with the checked helper, changing the segment and filename:

```sh
go run ./cmd/latency-summary \
  -segment 'Foreground to secure' -unit ms \
  .build/performance/foreground-to-secure.ms
```

Collect real host execution separately from macOS unified logging after running
the signed companion against Resolve. This extracts only the already-allowlisted
duration field:

```sh
/usr/bin/log show --style compact --last 30m \
  --predicate 'subsystem == "dev.remote-davinci.companion" AND category == "HelperOperations"' \
  | /usr/bin/sed -En 's/.* duration_ns=([0-9]+).*/\1/p' \
  > .build/performance/companion-operation.ns
go run ./cmd/latency-summary \
  -segment 'Companion operation' -unit ns \
  .build/performance/companion-operation.ns
```

Use the gated encrypted canary output for its synthetic control-RTT row, the
load-probe aggregate for opaque relay RTT under load, the access-log query for
relay integration, and the same-clock files plus unified-log extraction for the
remaining rows. Record sample count and method with every percentile. Twenty
canary samples are useful smoke evidence; use 100 for the release record and
state that p99 is still based on a single upper-tail order statistic. Neither
probe substitutes for the physical controller-tap row.

### 5. Cleanup

After all three memory candidates are recorded, destroy only the confirmed
disposable stack. If any driver cleanup failed, destruction is the mandatory
fallback because its bearer credentials are intentionally never printed.

```sh
npm --prefix infra/cdk exec -- cdk destroy "$PERF_STACK" \
  --app 'node infra/cdk/dist/bin/remote-davinci.js' \
  -c environment=dev -c region="$PERF_REGION" \
  -c lambdaMemory="$PERF_MEMORY" -c performanceMode=true \
  -c pairActivationsPerSourceHour=10000 --force
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
- Probe command, shard count, and aggregate JSON files:
- UTC start/end and CloudWatch query IDs:
- Same-clock capture frame rate and raw sample files:

## Results

| Segment | Samples | p50 | p95 | p99 | Maximum | Target | Pass |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | :---: |
| Enrolled cold launch to secure | | | | | | | |
| Foreground to secure | | | | | | 3 s | |
| Network restored to secure | | | | | | 5 s | |
| Controller tap to response | | | | | | 1.5 s | |
| Encrypted synthetic control RTT | | | | | | | |
| Opaque relay RTT under load | | | | | | | |
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
