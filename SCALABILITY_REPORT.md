# Scalability report

## Reproducible baseline

Command:

```bash
python backend/scripts/benchmark_inference.py --events 1000 --warmup 100
```

Environment: one local Python process, feature vectors precomputed, one event scored at a time through the scaler, one global plus four domain Isolation Forests, GRU recurrence, and the calibrated validation-selected Random Forest. Model `v20260725-125955`, schema 2.0.0.

| Measure | Result |
|---|---:|
| Median model latency | 106.85 ms |
| P95 model latency | 116.42 ms |
| P99 model latency | 125.98 ms |
| Mean model latency | 106.40 ms |
| Sequential throughput | 9.39 events/second |

The measured path is comfortably interactive for the solo demonstration but is not a high-volume SIEM benchmark. It excludes HTTP, database, feature extraction, network, and queue time, so production capacity must be measured end to end.

## Why the design can scale

Events are naturally partitionable by `entity_id`. Each partition preserves sequence order while independent partitions can be processed in parallel. The model bundle is read-only, and the API/service boundaries separate state, inference, persistence, and live delivery.

A production topology would use:

```text
collectors → durable stream → entity-partitioned feature workers
           → model-serving workers → incident/risk topic
           → analytical store + SOC API + notification tier
```

At the measured single-worker rate, 100 identical inference workers imply roughly 939 events/second before orchestration overhead; this is a planning estimate, not a measured claim. Batch scoring can improve tree-model efficiency, while per-entity micro-batches retain short-window ordering.

## Required production work

- Benchmark full ingestion with representative event sizes, concurrency, and persistent state.
- Use Kafka/Redpanda partitions keyed by entity and dead-letter/replay handling.
- Move rolling windows and entity profiles to Redis or a feature store.
- Store immutable events in partitioned PostgreSQL/ClickHouse/object storage.
- Run signed artifacts behind horizontally scaled model servers with canary rollback.
- Add backpressure, queue-lag and P95/P99 SLOs, tracing, autoscaling, and capacity tests.
- Replace process-local SSE with a durable pub/sub notification layer.
- Measure drift, alert rate, and analyst workload as first-class capacity signals.

The benchmark JSON is regenerated at `data/models/benchmark.json` and is intentionally separate from model-quality metrics.
