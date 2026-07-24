#!/usr/bin/env python3
import argparse
import json
import sys
from pathlib import Path

import numpy as np

BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))

from app.config import get_settings
from app.synthetic.attack_generator import generate_attacks
from app.synthetic.normal_generator import build_users, generate_normal


def write_jsonl(path: Path, rows: list) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as handle:
        for row in rows: handle.write(json.dumps(row.model_dump(mode="json")) + "\n")


def generate(seed: int = 42, users_count: int = 120, events_per_user: int = 40, scenarios_per_type: int = 20) -> dict:
    settings = get_settings(); rng = np.random.default_rng(seed)
    users = build_users(users_count, rng)
    normal = generate_normal(users, events_per_user, rng)
    attacks = generate_attacks(users, normal, scenarios_per_type, rng)
    all_events = sorted(normal + attacks, key=lambda e: e.timestamp)
    t1, t2 = int(len(all_events) * .65), int(len(all_events) * .82)
    splits = {"train": all_events[:t1], "validation": all_events[t1:t2], "test": all_events[t2:]}
    stream = sorted(attacks[-100:] + normal[-200:], key=lambda e: e.timestamp)
    for name, rows in {**splits, "demo_stream": stream}.items(): write_jsonl(settings.data_dir / "processed" / f"{name}.jsonl", rows)
    write_jsonl(settings.data_dir / "raw" / "all_events.jsonl", all_events)
    return {name: len(rows) for name, rows in {**splits, "demo_stream": stream}.items()}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(); parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--users", type=int, default=120); parser.add_argument("--events-per-user", type=int, default=40)
    parser.add_argument("--scenarios-per-type", type=int, default=20); args = parser.parse_args()
    print(json.dumps(generate(args.seed, args.users, args.events_per_user, args.scenarios_per_type), indent=2))

