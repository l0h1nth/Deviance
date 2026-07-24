#!/usr/bin/env python3
import argparse
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import numpy as np

BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))

from app.config import get_settings
from app.schemas.events import LabeledEvent
from app.synthetic.attack_generator import generate_attacks
from app.synthetic.normal_generator import build_users, generate_normal


def write_split(directory: Path, name: str, rows: list[LabeledEvent]) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    with (directory / f"{name}.jsonl").open("w") as events, (directory / f"{name}_labels.jsonl").open("w") as labels:
        for row in sorted(rows, key=lambda item: item.event.timestamp):
            events.write(json.dumps(row.event.model_dump(mode="json")) + "\n")
            labels.write(json.dumps(row.sidecar().model_dump(mode="json")) + "\n")


def generate(seed: int = 42, users_count: int = 240, events_per_user: int = 120,
             scenarios_per_type: int | None = None, attack_rate: float = .025) -> dict:
    if not .005 <= attack_rate <= .03:
        raise ValueError("attack_rate must be between 0.005 and 0.03")
    settings = get_settings(); rng = np.random.default_rng(seed)
    entities = build_users(users_count, rng); rng.shuffle(entities)
    train_end, validation_end = int(len(entities) * .70), int(len(entities) * .85)
    groups = {"train": entities[:train_end], "validation": entities[train_end:validation_end], "test": entities[validation_end:]}
    splits: dict[str, list[LabeledEvent]] = {}
    starts = {"train": datetime.now(timezone.utc) - timedelta(days=390),
              "validation": datetime.now(timezone.utc) - timedelta(days=260),
              "test": datetime.now(timezone.utc) - timedelta(days=130)}
    for name, group in groups.items():
        normal = generate_normal(group, events_per_user, rng, start=starts[name])
        attacks = generate_attacks(group, normal, scenarios_per_type, rng, attack_rate)
        splits[name] = sorted(normal + attacks, key=lambda row: row.event.timestamp)

    test_attacks = [row for row in splits["test"] if row.label != "normal"]
    test_normal = [row for row in splits["test"] if row.label == "normal"]
    stream = sorted(test_attacks[-180:] + test_normal[-320:], key=lambda row: row.event.timestamp)
    for name, rows in {**splits, "demo_stream": stream}.items(): write_split(settings.data_dir / "processed", name, rows)
    all_rows = sorted([row for rows in splits.values() for row in rows], key=lambda row: row.event.timestamp)
    write_split(settings.data_dir / "raw", "all_events", all_rows)
    return {
        name: {"events": len(rows), "attacks": sum(row.label != "normal" for row in rows),
               "attack_rate": round(sum(row.label != "normal" for row in rows) / max(len(rows), 1), 4),
               "entities": len(groups.get(name, []))}
        for name, rows in {**splits, "demo_stream": stream}.items()
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--users", type=int, default=240)
    parser.add_argument("--events-per-user", type=int, default=120)
    parser.add_argument("--scenarios-per-type", type=int)
    parser.add_argument("--attack-rate", type=float, default=.025)
    args = parser.parse_args()
    print(json.dumps(generate(args.seed, args.users, args.events_per_user, args.scenarios_per_type, args.attack_rate), indent=2))
