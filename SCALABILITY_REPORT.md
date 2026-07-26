# Phase 3 system design and scalability

## What is implemented

The demo remains intentionally deployable by one person, but its state and ordering boundaries now match a distributed design:

- HTTP scoring runs in worker threads instead of blocking the FastAPI event loop.
- SQLite uses WAL mode, a 30-second busy timeout, and foreign-key enforcement.
- Every event exposes `stream_partition_key=entity_id` and a stable local partition number.
- Event-GRU history is read through `SequenceStateStore` from durable prediction rows; it is not worker memory.
- Entity/device/peer/global profiles and 20/20 concept-drift windows are durable database records.
- The read-only model bundle is the only worker-local cache; losing a worker loses no entity state.
- `/api/system/design` exposes the current state, partition, and production-substitution contract.

Direct HTTP cannot guarantee ordering if a client sends the same entity concurrently. The benchmark and production design solve that at ingestion: one sequential queue per entity-keyed partition, with parallelism only across partitions.

## Complete HTTP benchmark

Reproduce with:

```bash
python backend/scripts/benchmark_system.py --events 60 --concurrency 1,4,8
```

Each run starts a real one-process Uvicorn server and a fresh temporary SQLite-WAL database. The measured path is:

```text
TCP HTTP → bearer authentication → Pydantic validation → persistent history/profile reads
→ 32-feature extraction → global/domain IF + event GRU + calibrated RF
→ risk/explanation → event/feature/prediction/incident/profile/drift transaction
→ response serialization
```

Model `v20260726-073744`, 60 production-shaped events per run:

| Entity-partition queues | HTTP P50 | HTTP P95 | HTTP P99 | Pipeline P50 | Throughput | Failures |
|---:|---:|---:|---:|---:|---:|---:|
| 1 | 193.66 ms | 229.36 ms | 242.33 ms | 185.25 ms | 5.10 events/s | 0/60 |
| 4 | 912.78 ms | 1,152.62 ms | 1,232.23 ms | 778.94 ms | 4.30 events/s | 0/60 |
| 8 | 1,483.76 ms | 2,705.00 ms | 4,511.24 ms | 1,171.75 ms | 4.26 events/s | 0/60 |

Expected failure probes passed in every run:

| Failure | Expected response | Result |
|---|---:|---:|
| Duplicate `event_id` | 409 Conflict | Passed |
| Invalid schema/range | 422 Unprocessable Entity | Passed |
| Missing authentication | 401 Unauthorized | Passed |
| Unexpected server errors | 0 | Passed |

The exact machine-readable output is stored in `data/models/system_benchmark.json`.
The workload contains 59 unique entities; all partition loads are recorded and every run reports zero per-entity ordering violations.

## Model-only control

`benchmark_inference.py` isolates the precomputed-feature model path and reports 135.30/158.84/186.77 ms P50/P95/P99 with 7.28 sequential events/s. Comparing it with the single-queue HTTP result shows the cost of authentication, history queries, feature extraction, persistence, and serialization.

## Interpretation

Thread concurrency does not increase throughput on the demo host. CPU-heavy Python inference competes within one process and SQLite still serializes writes, so queueing raises P95/P99. This is an honest capacity boundary—not a basis for multiplying the single-worker rate into an unsupported production claim.

The application therefore scales by partition workers, not by allowing unordered concurrent work on one identity:

```text
Collectors / API gateway
          │
          ▼
Kafka or Redpanda topic: telemetry.v3
key = entity_id, 32+ partitions, replication ≥ 3
          │
          ▼
Consumer group: one ordered consumer per assigned partition
          │
    ┌─────┴──────────────┐
    ▼                    ▼
Redis Cluster       Signed model server
hot 1m/5m/24h/30d   stateless IF/GRU/RF
windows + 12-event        │
sequence state            ▼
    └──────────────► PostgreSQL transaction
                         │
               ┌─────────┴──────────┐
               ▼                    ▼
       findings/notification    ClickHouse/object store
       topic + WebSocket tier   analytics and retention
```

## Production substitutions

| Demo component | Production component | Responsibility |
|---|---|---|
| Direct authenticated HTTP | API gateway → Kafka/Redpanda | Durable buffering, backpressure, replay and entity ordering |
| Stable local hash | Broker message key `entity_id` | Keep every identity on one ordered partition |
| SQLite sequence/profile reads | Redis Cluster or online feature store | Low-latency rolling windows, GRU history and profile snapshots with TTL |
| SQLite transactions | Partitioned PostgreSQL | Idempotent events, predictions, incidents, feedback and drift governance |
| SQLite dashboard queries | ClickHouse plus object storage | High-volume time-series analytics and long-term immutable retention |
| Process-local SSE | Durable findings topic + WebSocket gateway | Multi-instance analyst updates without lost notifications |
| Local joblib | Signed model registry/object store | Versioning, checksum validation, canary activation and rollback |

## Failure and scaling policy

- Commit stream offsets only after the PostgreSQL transaction succeeds.
- Preserve the unique `event_id` constraint so replay is idempotent.
- Retry transient Redis/PostgreSQL failures with bounded exponential backoff and jitter.
- Send invalid or repeatedly failing records to a dead-letter topic with reason, schema and source metadata.
- Monitor consumer lag, HTTP/worker P50/P95/P99, event age, 5xx rate, database saturation, Redis misses, model latency, alert volume and drift backlog.
- Autoscale consumers on partition lag; maximum active ordering parallelism is the Kafka partition count.
- Snapshot Redis state to PostgreSQL/object storage so hot-state loss can be rebuilt by replay.
- Use OpenTelemetry trace IDs from ingestion through feature extraction, inference, persistence and notification.

## Known demo boundaries

The benchmark uses 60 events per level on one local machine and synthetic telemetry. It proves the full path, concurrency behavior, persistence, ordering contract, and failure handling; it does not claim SIEM-scale capacity. A production load test must use representative event sizes, network distance, multi-node Kafka/Redis/PostgreSQL, sustained soak traffic, broker failover, consumer rebalance, database failover, dead-letter replay and recovery-time objectives.
