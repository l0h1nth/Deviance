#!/usr/bin/env python3
"""Benchmark authenticated concurrent HTTP ingestion through the complete stack."""

import argparse
import asyncio
import json
import os
import socket
import subprocess
import sys
import tempfile
from collections import Counter, defaultdict
from pathlib import Path
from time import perf_counter
from uuid import uuid4

import httpx
import numpy as np

BACKEND = Path(__file__).resolve().parents[1]
ROOT = BACKEND.parent
sys.path.insert(0, str(BACKEND))

from app.config import get_settings  # noqa: E402
from app.services.partitioning import partition_for_entity  # noqa: E402


def percentile_summary(values: list[float]) -> dict[str, float]:
    measured = np.asarray(values or [0.0], dtype=float)
    return {
        "p50": float(np.percentile(measured, 50)),
        "p95": float(np.percentile(measured, 95)),
        "p99": float(np.percentile(measured, 99)),
        "mean": float(np.mean(measured)),
        "minimum": float(np.min(measured)),
        "maximum": float(np.max(measured)),
    }


def available_port() -> int:
    with socket.socket() as candidate:
        candidate.bind(("127.0.0.1", 0))
        return int(candidate.getsockname()[1])


def load_payloads(count: int) -> list[dict]:
    settings = get_settings(); path = settings.data_dir / "processed" / "test.jsonl"
    if not path.exists():
        raise FileNotFoundError(f"{path} is missing; run generate_data.py first")
    payloads = []
    with path.open() as handle:
        for line in handle:
            if line.strip():
                payload = json.loads(line); payload["event_id"] = f"system-benchmark-{uuid4().hex}"
                payloads.append(payload)
                if len(payloads) >= count: break
    if len(payloads) < count:
        raise ValueError(f"requested {count} events but only loaded {len(payloads)}")
    return payloads


async def wait_until_ready(base_url: str, process: subprocess.Popen, timeout: float = 30) -> None:
    deadline = perf_counter() + timeout
    async with httpx.AsyncClient(base_url=base_url, timeout=1) as client:
        while perf_counter() < deadline:
            if process.poll() is not None:
                raise RuntimeError(f"benchmark server exited early with code {process.returncode}")
            try:
                if (await client.get("/api/health")).status_code == 200: return
            except httpx.HTTPError:
                pass
            await asyncio.sleep(.1)
    raise TimeoutError("benchmark server did not become ready")


async def exercise(base_url: str, payloads: list[dict], concurrency: int) -> dict:
    limits = httpx.Limits(max_connections=concurrency, max_keepalive_connections=concurrency)
    async with httpx.AsyncClient(base_url=base_url, timeout=90, limits=limits) as client:
        login = await client.post("/api/auth/login", json={"username": "admin", "password": "admin"})
        login.raise_for_status(); headers = {"Authorization": f"Bearer {login.json()['access_token']}"}
        warmup = dict(payloads[0]); warmup["event_id"] = f"system-benchmark-warmup-{uuid4().hex}"
        warmup_response = await client.post("/api/events/ingest", json=warmup, headers=headers)
        warmup_response.raise_for_status(); model_version = warmup_response.json()["model_version"]

        queues: list[list[tuple[int, dict]]] = [[] for _ in range(concurrency)]
        for sequence, payload in enumerate(payloads):
            queues[partition_for_entity(payload["entity_id"], concurrency)].append((sequence, payload))
        results: list[dict] = []

        async def worker(partition: int, items: list[tuple[int, dict]]):
            for sequence, payload in items:
                started = perf_counter()
                try:
                    response = await client.post("/api/events/ingest", json=payload, headers=headers)
                    elapsed = (perf_counter() - started) * 1000
                    body = response.json()
                    results.append({"sequence": sequence, "partition": partition, "entity_id": payload["entity_id"],
                                    "status": response.status_code, "latency_ms": elapsed,
                                    "server_latency_ms": body.get("latency_ms"), "event_id": body.get("event_id"),
                                    "detail": body.get("detail")})
                except Exception as exc:
                    results.append({"sequence": sequence, "partition": partition, "entity_id": payload["entity_id"],
                                    "status": 0, "latency_ms": (perf_counter() - started) * 1000,
                                    "server_latency_ms": None, "event_id": None, "detail": str(exc)})

        started = perf_counter()
        await asyncio.gather(*(worker(index, queue) for index, queue in enumerate(queues)))
        wall_seconds = perf_counter() - started

        duplicate = await client.post("/api/events/ingest", json=warmup, headers=headers)
        invalid = dict(warmup); invalid["event_id"] = f"system-benchmark-invalid-{uuid4().hex}"; invalid["latitude"] = 999
        malformed = await client.post("/api/events/ingest", json=invalid, headers=headers)
        unauthorized = await client.post("/api/events/ingest", json=invalid)

    successes = [item for item in results if item["status"] == 200]
    client_latencies = [item["latency_ms"] for item in successes]
    server_latencies = [item["server_latency_ms"] for item in successes if item["server_latency_ms"] is not None]
    status_counts = Counter(str(item["status"]) for item in results)
    observed_order: dict[str, list[int]] = defaultdict(list)
    for item in results: observed_order[item["entity_id"]].append(item["sequence"])
    ordering_violations = sum(values != sorted(values) for values in observed_order.values())
    return {
        "model_version": model_version,
        "requested_events": len(payloads), "successful_events": len(successes),
        "failed_events": len(results) - len(successes), "concurrency": concurrency,
        "unique_entities": len({payload["entity_id"] for payload in payloads}),
        "wall_seconds": wall_seconds,
        "throughput_events_per_second": len(successes) / max(wall_seconds, 1e-9),
        "http_latency_ms": percentile_summary(client_latencies),
        "server_pipeline_latency_ms": percentile_summary(server_latencies),
        "status_counts": dict(status_counts),
        "entity_ordering": {"strategy": "one sequential queue per entity-keyed partition",
                            "partition_queues": concurrency,
                            "partition_loads": [len(queue) for queue in queues],
                            "violations": ordering_violations},
        "failure_handling": {
            "duplicate_event": {"expected": 409, "observed": duplicate.status_code,
                                "passed": duplicate.status_code == 409},
            "schema_validation": {"expected": 422, "observed": malformed.status_code,
                                  "passed": malformed.status_code == 422},
            "authentication": {"expected": 401, "observed": unauthorized.status_code,
                               "passed": unauthorized.status_code == 401},
            "server_errors": int(status_counts.get("500", 0)),
        },
    }


def run(event_count: int, concurrency: int, port: int = 0) -> dict:
    if event_count < 1 or concurrency < 1: raise ValueError("events and concurrency must be positive")
    payloads = load_payloads(event_count); port = port or available_port(); base_url = f"http://127.0.0.1:{port}"
    with tempfile.TemporaryDirectory(prefix="deviance-system-benchmark-") as temporary:
        environment = dict(os.environ)
        environment.update(DATABASE_URL=f"sqlite:///{Path(temporary) / 'benchmark.db'}",
                           PYTHONPATH=str(BACKEND), ENVIRONMENT="benchmark",
                           PYTHONWARNINGS="ignore::DeprecationWarning")
        command = [sys.executable, "-m", "uvicorn", "app.main:app", "--app-dir", str(BACKEND),
                   "--host", "127.0.0.1", "--port", str(port), "--log-level", "warning"]
        process = subprocess.Popen(command, cwd=ROOT, env=environment, stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL, text=True)
        try:
            asyncio.run(wait_until_ready(base_url, process))
            measured = asyncio.run(exercise(base_url, payloads, concurrency))
        finally:
            process.terminate()
            try: process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill(); process.wait(timeout=5)
    settings = get_settings()
    result = {
        "path": "real TCP HTTP -> authentication -> validation -> feature extraction -> IF/GRU/RF inference -> SQLite WAL transaction -> response",
        "server": "one Uvicorn process; scoring offloaded to worker threads",
        "state": "persistent SQLite profiles, prediction sequence history, and drift windows",
        **measured,
    }
    output = settings.model_dir / "system_benchmark.json"
    output.write_text(json.dumps(result, indent=2) + "\n")
    return result


def run_matrix(event_count: int, concurrency_levels: list[int]) -> dict:
    runs = [run(event_count, concurrency) for concurrency in concurrency_levels]
    result = {
        "benchmark": "Concurrent end-to-end HTTP ingestion",
        "events_per_run": event_count,
        "concurrency_levels": concurrency_levels,
        "runs": runs,
        "interpretation": (
            "SQLite is intentionally retained for the demo; concurrency results expose its serialized-write "
            "and single-host limits rather than being extrapolated as production capacity."
        ),
    }
    output = get_settings().model_dir / "system_benchmark.json"
    output.write_text(json.dumps(result, indent=2) + "\n")
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--events", type=int, default=100)
    parser.add_argument("--concurrency", default="1,4,8",
                        help="comma-separated concurrent entity-partition workers")
    parser.add_argument("--port", type=int, default=0)
    arguments = parser.parse_args()
    levels = [int(value) for value in arguments.concurrency.split(",") if value.strip()]
    measured = run(arguments.events, levels[0], arguments.port) if len(levels) == 1 else run_matrix(arguments.events, levels)
    print(json.dumps(measured, indent=2))
