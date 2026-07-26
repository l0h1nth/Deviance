"""Reproducible benchmark for the trusted-window drift detector."""

import argparse
import json
import sys
import tempfile
from pathlib import Path

import numpy as np
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))

from app.database.session import Base  # noqa: E402
from app.services.drift_service import DriftService  # noqa: E402


def vector(hour: float) -> dict[str, float]:
    return {
        "access_hour": hour, "location_novelty_score": 0, "new_device_score": 0,
        "download_volume_zscore": 0, "resource_novelty_score": 0,
        "privilege_expansion_score": 0, "sequence_anomaly_score": 0, "anomaly_score": 0,
    }


def evaluate(seed: int = 42, stable_entities: int = 100, drift_entities: int = 100) -> dict:
    rng = np.random.default_rng(seed)
    with tempfile.TemporaryDirectory(prefix="deviance-drift-") as directory:
        engine = create_engine(f"sqlite:///{Path(directory)/'benchmark.db'}")
        Base.metadata.create_all(engine)
        factory = sessionmaker(bind=engine)
        false_positives = true_positives = 0
        delays: list[int] = []
        with factory() as db:
            service = DriftService(db)
            for subject in range(stable_entities):
                found = []
                center = rng.uniform(7.5, 10.5)
                for hour in rng.normal(center, .45, 40):
                    found.extend(service.observe(f"stable-{subject:04d}", vector(float(hour))))
                false_positives += int(any(row.feature == "access_hour" for row in found))
            for subject in range(drift_entities):
                found = []
                center = rng.uniform(7.5, 10.5)
                stream = [*rng.normal(center, .45, 20), *rng.normal(center + 8, .55, 20)]
                for index, hour in enumerate(stream, start=1):
                    new = service.observe(f"drift-{subject:04d}", vector(float(hour)))
                    found.extend(new)
                    if any(row.feature == "access_hour" for row in new): delays.append(index - 20)
                true_positives += int(any(row.feature == "access_hour" for row in found))
            db.commit()
        precision = true_positives / max(true_positives + false_positives, 1)
        recall = true_positives / max(drift_entities, 1)
        fpr = false_positives / max(stable_entities, 1)
        return {
            "seed": seed, "stable_entities": stable_entities, "drift_entities": drift_entities,
            "true_positive_entities": true_positives, "false_positive_entities": false_positives,
            "entity_precision": precision, "entity_recall": recall, "stable_entity_false_positive_rate": fpr,
            "mean_detection_delay_events": float(np.mean(delays)) if delays else None,
            "window_contract": {"reference_events": 20, "current_events": 20},
            "safety_contract": {"trusted_events_only": True, "automatic_retraining": False,
                                "analyst_approval_required_for_adaptation": True},
        }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--stable-entities", type=int, default=100)
    parser.add_argument("--drift-entities", type=int, default=100)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    metrics = evaluate(args.seed, args.stable_entities, args.drift_entities)
    rendered = json.dumps(metrics, indent=2)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n")
    print(rendered)
