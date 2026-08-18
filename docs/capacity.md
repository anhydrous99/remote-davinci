# Relay capacity and cost

This is the operating envelope for the single-region managed relay. It is a
quota and load-test target, not a claim that local unit tests prove AWS service
capacity.

## Target envelope

- 100,000 simultaneous pairs and 200,000 WebSocket connections.
- At most 1,000 control round trips per second sustained.
- A five-minute peak of 10,000 control round trips per second.
- Backend forwarding latency below 150 ms p95 and 300 ms p99.
- Unexpected steady-state errors below 0.1% and no service throttles.

One control round trip is two one-way session frames. A one-way frame performs
strong DynamoDB Connection and Session reads, one rate-limit update, one Lambda
invocation, one inbound API Gateway request, and one callback to the peer. The
relay stores no ciphertext. The figures below assume the authority items remain
at most 4 KiB and each rate-limit item remains at most 1 KiB.

| Load | Frames/s | API requests/s | Lambda invokes/s | Strong reads/s | Writes/s |
|---|---:|---:|---:|---:|---:|
| Sustained | 2,000 | 4,000 | 2,000 | 4,000 | 2,000 |
| Peak | 20,000 | 40,000 | 20,000 | 40,000 | 20,000 |

The default production profile caps the on-demand table at 30,000 reads and
8,000 writes per second, reserves 200 Lambda concurrency, and throttles
`session.frame` at 4,000 messages per second with a 5,000-message burst. This
profile leaves write headroom for connection, pairing, default, and disconnect
routes alongside the frame limiter. Obtain at least 300 regional Lambda
concurrency before deployment so the reservation can leave the service-required
100 concurrency unreserved.

The opt-in peak profile reserves 4,500 Lambda concurrency, pre-warms the table
for 60,000 reads and 30,000 writes per second, and raises `session.frame` to
25,000 messages per second with a 50,000-message burst. The 20% headroom covers
the route's two strong reads and one rate-limit write per frame. Enable it with
CDK context `peakCapacity=true` only after AWS has approved at least 60,000
regional API Gateway requests per second, 6,000 regional Lambda concurrency,
60,000 DynamoDB reads per second, and 30,000 DynamoDB writes per second, before
deployment. API Gateway counts inbound WebSocket requests and management
callbacks against its regional throttle; current quotas are documented in the
[API Gateway quota guide](https://docs.aws.amazon.com/apigateway/latest/developerguide/limits.html).
The effective account burst is service-determined, so obtain written
confirmation for the 50,000-message burst as part of that approval. If AWS
approves less, change the configured peak profile to that approved value and
retain the required 60-second client/load-test ramp.

API Gateway permits a 500-new-connections-per-second default and closes a
connection after two hours. Clients therefore reconnect after a randomized
90–110 minutes. After an outage, exponential full-jitter retry is capped at 15
minutes; 200,000 clients uniformly spread over that interval average about 222
new connections per second.

## Cost model

Always refresh prices from the official [API Gateway](https://aws.amazon.com/api-gateway/pricing/),
[Lambda](https://aws.amazon.com/lambda/pricing/), [DynamoDB](https://aws.amazon.com/dynamodb/pricing/),
and [CloudWatch](https://aws.amazon.com/cloudwatch/pricing/) pages before making
a purchasing decision. The reference profile below excludes free tiers, taxes,
Internet transfer, lifecycle writes, DynamoDB storage and point-in-time
recovery, CloudWatch alarms and log ingestion (including default access logs),
and the peak profile's one-time DynamoDB pre-warm charge.

For `F` one-way frames and `C` connection-minutes:

```text
WebSocket messages = 2F
Lambda requests     = F
Lambda GB-seconds   = F * configured_GB * measured_average_seconds
DynamoDB read units = F                 (Session items must remain <= 4 KiB)
                      + F               (Connection items must remain <= 4 KiB)
DynamoDB write units = F                (Rate-limit items must remain <= 1 KiB)
Connection minutes  = C
```

The reference workload is 1,000 pairs connected eight hours per day and 500
control round trips per pair per day, over a 30-day month. At 256 MiB and a
measured 30 ms average Lambda duration, that is 30 million one-way frames,
60 million WebSocket messages, 30 million Lambda requests, 225,000 GB-seconds,
60 million strong read units, 30 million write units, and 28.8 million
connection-minutes. At August 2026 us-east-1 list prices, the components are
approximately $60.00 for messages, $7.20 for connection-minutes, $6.00 for
Lambda requests, $3.00 for Lambda compute, $7.50 for DynamoDB reads, and $18.75
for DynamoDB writes: $102.45/month before the exclusions above.

The pre-redesign implementation used three WebSocket messages and six strong
reads per frame, plus metered application-level keepalives, for an estimated
$146/month at the same workload. Recalculate either estimate from actual
CloudWatch usage and Cost Explorer tags after every load test.

Use native WebSocket ping/pong for keepalive; API Gateway documents control
frames as unmetered. Production suppresses successful per-frame logs and
detailed route metrics. Metadata-only API Gateway access logs are enabled by
default with seven-day retention; include their ingestion in the deployment
budget.

Each session frame strongly reads its current connection and session authority,
then updates an endpoint-scoped one-minute rate bucket. The bucket enforces the
documented 60-frame-per-second client cap, and a violating socket is physically
disconnected. A frame whose authority read starts after replacement or
revocation is rejected; an already-read callback may still arrive later and is
discarded by the receiver's local revocation gate. Relay rejection,
Lambda/DynamoDB throttle, Lambda error, and API execution alarms all notify the
required production SNS topic.

## Scaling decision

Keep API Gateway, Lambda, and DynamoDB while they meet the SLO. Start a measured
ECS/NLB connection-fleet study only when one of these conditions is true:

- the tagged relay platform exceeds a $5,000 trailing-30-day run rate for two
  consecutive months;
- AWS will not grant a required quota; or
- the accepted serverless design misses the latency SLO under the target load.

Migrate only if the complete alternative, including a distributed ephemeral
connection registry, is at least 40% cheaper with 30% capacity headroom. Do not
add cache, DAX, Redis, SQS, Step Functions, multi-region coordination, or a
second protocol in anticipation of that result.

## Performance acceptance

Run these only in an isolated, quota-approved performance stack:

1. Verify native ping keeps a connection alive for more than 12 idle minutes,
   followed by a 130-minute reconnect soak.
2. Hold 200,000 simultaneous sockets.
3. Sustain 1,000 round trips per second for 60 minutes.
4. Ramp from 1,000 to 10,000 round trips per second over 60 seconds and hold for
   five minutes.
5. Spread a 200,000-client recovery over 15 minutes.
6. Inject Gone peers and race session opening/forwarding against link and
   endpoint revocation.

Record p50/p95/p99 duration, concurrency, throttles, errors, consumed table
capacity, API message count, and tagged cost. Benchmark the relay at 128, 256,
and 512 MiB; use the cheapest setting that meets the SLO, preferring lower
memory when modeled costs are within 5%.
