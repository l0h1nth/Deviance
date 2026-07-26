#!/usr/bin/env python3
"""Re-evaluate the two event GRUs and calibrate the daily drift-day boundary."""

import json
import sys
from pathlib import Path

import numpy as np

BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))

from app.config import get_settings  # noqa: E402
from app.ml.enriched_features import enrich_scaled  # noqa: E402
from app.ml.entity_behavior import aggregate_daily, daily_evaluation, tune_daily_threshold  # noqa: E402
from app.ml.model_bundle import ModelBundle  # noqa: E402
from app.ml.training import featurize_splits, load_split  # noqa: E402


def evaluate(save: bool = False) -> dict:
    settings = get_settings(); artifact_path = settings.model_dir / "current.joblib"
    bundle = ModelBundle.load(artifact_path, settings.model_dir)
    detector = getattr(bundle, "entity_behavior_detector", None)
    daily_scaler = getattr(bundle, "entity_behavior_scaler", None)
    if detector is None or daily_scaler is None:
        raise ValueError("The active artifact has no EntityBehaviorGRU; retrain it first")
    detector.normalization = "bounded_exp"
    paths = {name: (settings.data_dir / "processed" / f"{name}.jsonl",
                    settings.data_dir / "processed" / f"{name}_labels.jsonl")
             for name in ("train", "validation", "test")}
    raw = {name: load_split(*pair) for name, pair in paths.items()}
    featured = featurize_splits(raw)
    daily = {}
    for name in ("validation", "test"):
        x, labels, entities, *_ = featured[name]
        scaled = bundle.scaler.transform(x)
        enriched = enrich_scaled(scaled, bundle.anomaly_detector, bundle.attack_classifier)
        ordered = sorted(raw[name], key=lambda item: item.event.timestamp)
        daily[name] = aggregate_daily(enriched, labels, entities,
            np.asarray([row.event.timestamp for row in ordered], dtype=object))
    validation_scores = detector.score_stream(daily_scaler.transform(daily["validation"].vectors),
                                               daily["validation"].entities)
    threshold, validation = tune_daily_threshold(validation_scores, daily["validation"].labels)
    test_scores = detector.score_stream(daily_scaler.transform(daily["test"].vectors), daily["test"].entities)
    test = daily_evaluation(test_scores, daily["test"], threshold)
    bundle.entity_behavior_threshold = threshold
    bundle.metrics["entity_behavior"]["validation_threshold"] = validation
    bundle.metrics["entity_behavior"]["test"] = test
    if save:
        bundle.save(artifact_path)
        (settings.model_dir / "metrics.json").write_text(json.dumps(bundle.metrics, indent=2) + "\n")
    compact_test = {key: value for key, value in test.items() if key != "rankings"}
    return {"model_version": bundle.version,
            "event_sequence_comparison": bundle.metrics["event_sequence_comparison"],
            "entity_behavior_validation": validation, "entity_behavior_test": compact_test,
            "saved": save}


if __name__ == "__main__":
    save = "--save" in sys.argv
    print(json.dumps(evaluate(save), indent=2))
