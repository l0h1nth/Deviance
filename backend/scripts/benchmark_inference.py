#!/usr/bin/env python3
"""Repeatable single-process latency/throughput benchmark for the active artifact."""
import argparse
import json
import sys
from collections import defaultdict, deque
from pathlib import Path
from time import perf_counter

import numpy as np

BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))

from app.config import get_settings
from app.ml.feature_pipeline import FeaturePipeline
from app.ml.model_bundle import ModelBundle
from app.ml.training import MemoryProfiles, load_split


def run(count: int = 1000, warmup: int = 100) -> dict:
    settings = get_settings()
    rows = load_split(settings.data_dir / "processed" / "test.jsonl",
                      settings.data_dir / "processed" / "test_labels.jsonl")[:count]
    bundle = ModelBundle.load(settings.model_dir / "current.joblib", settings.model_dir)
    bundle.validate(FeaturePipeline.names)
    pipeline, profiles, history = FeaturePipeline(), MemoryProfiles(), []
    vectors = []
    for row in rows:
        vector, _ = pipeline.transform_one(row.event, history, profiles.baseline(row.event))
        vectors.append((row.event.entity_id, vector)); profiles.update(row.event, row.label); history.append(row.event)
    entity_history: dict[str, deque] = defaultdict(lambda: deque(maxlen=bundle.sequence_detector.window_size))
    latencies = []
    started = perf_counter()
    for index, (entity, vector) in enumerate(vectors):
        prior = np.asarray(entity_history[entity])
        tick = perf_counter(); bundle.infer(vector, prior); elapsed = (perf_counter() - tick) * 1000
        entity_history[entity].append(vector)
        if index >= warmup: latencies.append(elapsed)
    wall = perf_counter() - started
    measured = np.asarray(latencies or [0.0])
    result = {
        "model_version": bundle.version, "feature_schema_version": bundle.feature_schema_version,
        "events": len(vectors), "warmup_events": min(warmup, len(vectors)),
        "latency_ms": {"p50": float(np.percentile(measured, 50)), "p95": float(np.percentile(measured, 95)),
                       "p99": float(np.percentile(measured, 99)), "mean": float(np.mean(measured))},
        "sequential_throughput_events_per_second": len(vectors) / max(wall, 1e-9),
        "environment": "single Python process; feature vectors precomputed; per-event scaler + IF + GRU + RF",
    }
    (settings.model_dir / "benchmark.json").write_text(json.dumps(result, indent=2))
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(); parser.add_argument("--events", type=int, default=1000); parser.add_argument("--warmup", type=int, default=100)
    args = parser.parse_args(); print(json.dumps(run(args.events, args.warmup), indent=2))
