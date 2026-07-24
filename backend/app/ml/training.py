from __future__ import annotations

import json
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from time import perf_counter

import numpy as np
from sklearn.metrics import (classification_report, confusion_matrix, f1_score, precision_recall_fscore_support,
                             average_precision_score, roc_auc_score)
from sklearn.utils.class_weight import compute_sample_weight

from app.ml.anomaly_model import IsolationForestDetector
from app.ml.attack_classifier import AttackClassifier
from app.ml.feature_pipeline import FeaturePipeline
from app.ml.feature_registry import FEATURE_SCHEMA_VERSION
from app.ml.model_bundle import ModelBundle
from app.ml.preprocessing import build_scaler
from app.schemas.events import AccessEvent
from app.services.profile_service import Baseline, EMPTY_PROFILE


class MemoryProfiles:
    """Leakage-safe trusted profiles used while walking events in timestamp order."""
    def __init__(self, user_min: int = 12, peer_min: int = 25):
        self.user_min, self.peer_min = user_min, peer_min
        self.profiles: dict[str, dict] = defaultdict(lambda: {**{k: [] for k in EMPTY_PROFILE}, "count": 0})

    def _key(self, kind: str, event: AccessEvent) -> str:
        return f"user:{event.user_id}" if kind == "user" else f"peer:{event.department}:{event.user_role}" if kind == "peer" else "global:organization"

    def baseline(self, event: AccessEvent) -> Baseline:
        user, peer, glob = (self.profiles[self._key(kind, event)] for kind in ("user", "peer", "global"))
        if user["count"] >= self.user_min: data, kind, minimum = user, "user", self.user_min
        elif peer["count"] >= self.peer_min: data, kind, minimum = peer, "peer", self.peer_min
        else: data, kind, minimum = glob, "global" if glob["count"] else "global_default", self.peer_min
        clean = {k: v for k, v in data.items() if k != "count"}
        confidence = min(1.0, .25 + .75 * data["count"] / max(minimum * 2, 1)) if data["count"] else .1
        return Baseline(kind, data["count"], confidence, data["count"], datetime.now(timezone.utc).isoformat(), clean)

    def update(self, event: AccessEvent) -> None:
        if event.ground_truth_label != "normal": return
        for kind in ("user", "peer", "global"):
            data = self.profiles[self._key(kind, event)]; data["count"] += 1
            if event.event_type == "login" and event.authentication_result == "success":
                data["login_hours"] = (data["login_hours"] + [event.timestamp.hour + event.timestamp.minute / 60])[-500:]
                for key, value, limit in [("devices", event.device_id, 50), ("fingerprints", event.device_fingerprint, 50),
                                          ("locations", f"{event.country}|{event.city}", 50)]:
                    data[key] = list(dict.fromkeys(data[key] + [value]))[-limit:]
            data["downloads"] = (data["downloads"] + [event.bytes_downloaded])[-500:]
            data["session_durations"] = (data["session_durations"] + [event.session_duration_seconds])[-500:]
            data["resources"] = list(dict.fromkeys(data["resources"] + [event.resource_id]))[-100:]


def load_jsonl(path: Path) -> list[AccessEvent]:
    with path.open() as handle: return [AccessEvent.model_validate_json(line) for line in handle if line.strip()]


def featurize_splits(splits: dict[str, list[AccessEvent]]) -> dict[str, tuple[np.ndarray, np.ndarray]]:
    pipeline, profiles, history = FeaturePipeline(), MemoryProfiles(), []
    result = {}
    for split_name in ("train", "validation", "test"):
        vectors, labels = [], []
        for event in sorted(splits[split_name], key=lambda e: e.timestamp):
            vector, _ = pipeline.transform_one(event, history, profiles.baseline(event))
            vectors.append(vector); labels.append(event.ground_truth_label or "normal")
            profiles.update(event); history.append(event)
            if len(history) > 5000: history = history[-5000:]
        result[split_name] = (np.asarray(vectors), np.asarray(labels))
    return result


def evaluation_metrics(bundle: ModelBundle, x: np.ndarray, y: np.ndarray) -> dict:
    started = perf_counter(); scaled = bundle.scaler.transform(x); predicted, _ = bundle.attack_classifier.predict(scaled)
    report = classification_report(y, predicted, output_dict=True, zero_division=0)
    labels = sorted(set(y) | set(predicted)); matrix = confusion_matrix(y, predicted, labels=labels)
    normal = y == "normal"; pred_normal = predicted == "normal"
    fp = int(np.sum(normal & ~pred_normal)); tn = int(np.sum(normal & pred_normal)); fn = int(np.sum(~normal & pred_normal)); tp = int(np.sum(~normal & ~pred_normal))
    anomaly_scores = bundle.anomaly_detector.score(scaled)
    try:
        binary = (y != "normal").astype(int); roc_auc = float(roc_auc_score(binary, anomaly_scores))
        pr_auc = float(average_precision_score(binary, anomaly_scores))
    except ValueError: roc_auc = pr_auc = 0.0
    latency_ms = (perf_counter() - started) * 1000 / max(len(y), 1)
    return {
        "classes": labels, "confusion_matrix": matrix.tolist(), "classification_report": report,
        "macro_f1": float(f1_score(y, predicted, average="macro")), "weighted_f1": float(f1_score(y, predicted, average="weighted")),
        "false_positive_rate": fp / max(fp + tn, 1), "false_negative_rate": fn / max(fn + tp, 1),
        "anomaly_roc_auc": roc_auc, "anomaly_pr_auc": pr_auc, "sample_count": len(y),
        "average_detection_latency_ms": latency_ms, "threshold": bundle.alert_threshold,
    }


def train(data_dir: Path, model_dir: Path, contamination: float = .03, seed: int = 42,
          artifact_name: str = "current.joblib") -> ModelBundle:
    paths = {name: data_dir / "processed" / f"{name}.jsonl" for name in ("train", "validation", "test")}
    missing = [str(path) for path in paths.values() if not path.exists()]
    if missing: raise FileNotFoundError(f"Missing datasets: {missing}. Run generate_data.py first.")
    featured = featurize_splits({name: load_jsonl(path) for name, path in paths.items()})
    x_train, y_train = featured["train"]
    scaler = build_scaler().fit(x_train); scaled_train = scaler.transform(x_train)
    anomaly = IsolationForestDetector(contamination, seed).fit(scaled_train[y_train == "normal"])
    classifier = AttackClassifier(seed).fit(scaled_train, y_train, compute_sample_weight("balanced", y_train))
    version = datetime.now(timezone.utc).strftime("v%Y%m%d-%H%M%S")
    bundle = ModelBundle(version, FEATURE_SCHEMA_VERSION, FeaturePipeline.names, scaler, anomaly, classifier, 50.0, {})
    validation_metrics = evaluation_metrics(bundle, *featured["validation"])
    # Conservative risk threshold selection: high normal-score quantile mapped into the risk scale.
    val_x, val_y = featured["validation"]; normal_scores = anomaly.score(scaler.transform(val_x[val_y == "normal"]))
    if len(normal_scores): bundle.alert_threshold = float(np.clip(np.quantile(normal_scores, .98) * 45 + 20, 45, 70))
    bundle.metrics = {"validation": validation_metrics, "test": evaluation_metrics(bundle, *featured["test"]),
                      "trained_at": datetime.now(timezone.utc).isoformat(), "feature_count": 12}
    bundle.save(model_dir / artifact_name)
    (model_dir / "metrics.json").write_text(json.dumps(bundle.metrics, indent=2))
    return bundle
