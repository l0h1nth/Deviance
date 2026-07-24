from __future__ import annotations

import json
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from time import perf_counter

import numpy as np
from sklearn.metrics import average_precision_score, classification_report, confusion_matrix, f1_score, roc_auc_score

from app.ml.anomaly_model import IsolationForestDetector
from app.ml.attack_classifier import AttackClassifier
from app.ml.feature_pipeline import FeaturePipeline
from app.ml.feature_registry import FEATURE_SCHEMA_VERSION
from app.ml.model_bundle import ModelBundle
from app.ml.preprocessing import build_scaler
from app.ml.sequence_model import GRUSequenceDetector
from app.schemas.events import AccessEvent, LabeledEvent, TrainingLabel
from app.services.profile_service import Baseline, EMPTY_PROFILE


class MemoryProfiles:
    """Leakage-safe normal-only profiles used while walking events chronologically."""
    def __init__(self, entity_min: int = 12, peer_min: int = 25):
        self.entity_min, self.peer_min = entity_min, peer_min
        self.profiles: dict[str, dict] = defaultdict(lambda: {**{key: [] for key in EMPTY_PROFILE}, "count": 0})

    def _key(self, kind: str, event: AccessEvent) -> str:
        if kind == "entity": return f"entity:{event.entity_id}"
        if kind == "device": return f"device:{event.device_id}"
        if kind == "peer": return f"peer:{event.entity_type}:{event.department}:{event.user_role}"
        return "global:organization"

    def baseline(self, event: AccessEvent) -> Baseline:
        entity, device, peer, glob = (self.profiles[self._key(kind, event)] for kind in ("entity", "device", "peer", "global"))
        if entity["count"] >= self.entity_min: data, kind, minimum = entity, "entity", self.entity_min
        elif event.entity_type == "edge_device" and device["count"] >= self.entity_min: data, kind, minimum = device, "device", self.entity_min
        elif peer["count"] >= self.peer_min: data, kind, minimum = peer, "peer", self.peer_min
        else: data, kind, minimum = glob, "global" if glob["count"] else "global_default", self.peer_min
        clean = {key: value for key, value in data.items() if key != "count"}
        confidence = min(1.0, .25 + .75 * data["count"] / max(minimum * 2, 1)) if data["count"] else .1
        return Baseline(kind, data["count"], confidence, data["count"], datetime.now(timezone.utc).isoformat(), clean)

    def update(self, event: AccessEvent, label: str) -> None:
        if label != "normal": return
        for kind in ("entity", "device", "peer", "global"):
            data = self.profiles[self._key(kind, event)]; data["count"] += 1
            if event.authentication_result == "success":
                data["login_hours"] = (data["login_hours"] + [event.timestamp.hour + event.timestamp.minute / 60])[-500:]
                for key, value, limit in [("devices", event.device_id, 50), ("fingerprints", event.device_fingerprint, 50),
                                          ("locations", f"{event.country}|{event.city}", 50), ("auth_methods", event.auth_method, 10)]:
                    data[key] = list(dict.fromkeys(data[key] + [value]))[-limit:]
            data["downloads"] = (data["downloads"] + [event.bytes_downloaded])[-500:]
            data["uploads"] = (data["uploads"] + [event.bytes_uploaded])[-500:]
            data["session_durations"] = (data["session_durations"] + [event.session_duration_seconds])[-500:]
            data["resources"] = list(dict.fromkeys(data["resources"] + [event.resource_id]))[-150:]
            if event.is_privileged_action:
                data["privileged_resources"] = list(dict.fromkeys(data["privileged_resources"] + [event.resource_id]))[-100:]
            data["commands"] = list(dict.fromkeys(data["commands"] + event.command_sequence))[-200:]
            data["protocol_ports"] = list(dict.fromkeys(data["protocol_ports"] + [f"{event.network_protocol}:{event.destination_port}"]))[-50:]


def load_split(event_path: Path, label_path: Path) -> list[LabeledEvent]:
    labels = {}
    with label_path.open() as handle:
        for line in handle:
            if line.strip():
                label = TrainingLabel.model_validate_json(line); labels[label.event_id] = label
    rows = []
    with event_path.open() as handle:
        for line in handle:
            if not line.strip(): continue
            event = AccessEvent.model_validate_json(line); label = labels.get(event.event_id)
            if not label: raise ValueError(f"Missing training label for {event.event_id}")
            rows.append(LabeledEvent(event=event, label=label.label, scenario_id=label.scenario_id, sequence_id=label.sequence_id))
    if len(rows) != len(labels): raise ValueError(f"Event/label count mismatch for {event_path.name}")
    return rows


def featurize_splits(splits: dict[str, list[LabeledEvent]]) -> dict[str, tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]]:
    pipeline, profiles, history = FeaturePipeline(), MemoryProfiles(), []
    result = {}
    for split_name in ("train", "validation", "test"):
        vectors, labels, entities, sequences = [], [], [], []
        for row in sorted(splits[split_name], key=lambda item: item.event.timestamp):
            event = row.event; vector, _ = pipeline.transform_one(event, history, profiles.baseline(event))
            vectors.append(vector); labels.append(row.label); entities.append(event.entity_id); sequences.append(row.sequence_id)
            profiles.update(event, row.label); history.append(event)
            if len(history) > 3000: history = history[-3000:]
        result[split_name] = (np.asarray(vectors), np.asarray(labels), np.asarray(entities), np.asarray(sequences))
    return result


def risk_scores(bundle: ModelBundle, x: np.ndarray, entities: np.ndarray) -> np.ndarray:
    scaled = bundle.scaler.transform(x); anomaly = bundle.anomaly_detector.score(scaled)
    sequence = bundle.sequence_detector.score_stream(scaled, entities)
    probabilities = bundle.attack_classifier.probabilities(scaled)
    malicious_indices = [index for index, name in enumerate(bundle.attack_classifier.classes_) if name != "normal"]
    malicious = probabilities[:, malicious_indices].max(axis=1) if malicious_indices else np.zeros(len(x))
    deviation = np.clip(np.mean(np.minimum(np.abs(scaled), 5), axis=1) / 3, 0, 1)
    criticality = np.clip(x[:, 8], 0, 1)
    return 100 * (.35 * anomaly + .25 * sequence + .25 * malicious + .10 * deviation + .05 * criticality)


def budget_metrics(scores: np.ndarray, labels: np.ndarray, fraction: float = .01) -> dict:
    count = max(1, int(np.ceil(len(scores) * fraction))); order = np.argsort(scores)[::-1]; selected = order[:count]
    attacks = labels != "normal"; tp = int(np.sum(attacks[selected])); fp = count - tp
    return {"budget_fraction": fraction, "budget_count": count, "precision": tp / count,
            "recall": tp / max(int(np.sum(attacks)), 1), "false_positives": fp,
            "threshold": float(scores[selected[-1]]), "alert_rate": count / max(len(scores), 1)}


def evaluation_metrics(bundle: ModelBundle, x: np.ndarray, y: np.ndarray, entities: np.ndarray) -> dict:
    started = perf_counter(); scaled = bundle.scaler.transform(x); predicted, _ = bundle.attack_classifier.predict(scaled)
    anomaly = bundle.anomaly_detector.score(scaled); sequence = bundle.sequence_detector.score_stream(scaled, entities)
    probabilities = bundle.attack_classifier.probabilities(scaled)
    malicious_indices = [index for index, name in enumerate(bundle.attack_classifier.classes_) if name != "normal"]
    malicious = probabilities[:, malicious_indices].max(axis=1) if malicious_indices else np.zeros(len(x))
    predicted = np.asarray(["unknown_anomaly" if max(a, s) >= .85 and m < .55 else p
                            for p, a, s, m in zip(predicted, anomaly, sequence, malicious)])
    report = classification_report(y, predicted, output_dict=True, zero_division=0)
    labels = sorted(set(y) | set(predicted)); matrix = confusion_matrix(y, predicted, labels=labels)
    normal = y == "normal"; pred_normal = predicted == "normal"
    fp, tn = int(np.sum(normal & ~pred_normal)), int(np.sum(normal & pred_normal))
    fn, tp = int(np.sum(~normal & pred_normal)), int(np.sum(~normal & ~pred_normal))
    binary = (y != "normal").astype(int)
    try:
        anomaly_roc = float(roc_auc_score(binary, anomaly)); anomaly_pr = float(average_precision_score(binary, anomaly))
        sequence_roc = float(roc_auc_score(binary, sequence)); sequence_pr = float(average_precision_score(binary, sequence))
    except ValueError: anomaly_roc = anomaly_pr = sequence_roc = sequence_pr = 0.0
    risk = risk_scores(bundle, x, entities); alerted = risk >= bundle.alert_threshold
    alert_tp, alert_fp = int(np.sum((y != "normal") & alerted)), int(np.sum(normal & alerted))
    alert_fn, alert_tn = int(np.sum((y != "normal") & ~alerted)), int(np.sum(normal & ~alerted))
    return {
        "classes": labels, "confusion_matrix": matrix.tolist(), "classification_report": report,
        "macro_f1": float(f1_score(y, predicted, average="macro")), "weighted_f1": float(f1_score(y, predicted, average="weighted")),
        "false_positive_rate": fp / max(fp + tn, 1), "false_negative_rate": fn / max(fn + tp, 1),
        "anomaly_roc_auc": anomaly_roc, "anomaly_pr_auc": anomaly_pr,
        "sequence_roc_auc": sequence_roc, "sequence_pr_auc": sequence_pr,
        "sample_count": len(y), "attack_prevalence": float(np.mean(y != "normal")),
        "average_detection_latency_ms": (perf_counter() - started) * 1000 / max(len(y), 1),
        "threshold": bundle.alert_threshold, "alert_count": int(np.sum(alerted)), "alert_rate": float(np.mean(alerted)),
        "alert_precision": alert_tp / max(alert_tp + alert_fp, 1), "alert_recall": alert_tp / max(alert_tp + alert_fn, 1),
        "alert_false_positive_rate": alert_fp / max(alert_fp + alert_tn, 1),
        "top_1_percent": budget_metrics(risk, y, .01), "alerts_per_10000": float(np.mean(alerted) * 10000),
    }


def tune_threshold(bundle: ModelBundle, x: np.ndarray, y: np.ndarray, entities: np.ndarray) -> dict:
    scores = risk_scores(bundle, x, entities); budget = budget_metrics(scores, y, .01)
    bundle.alert_threshold = budget["threshold"]
    alerted = scores >= bundle.alert_threshold; attacks = y != "normal"
    tp, fp = int(np.sum(attacks & alerted)), int(np.sum(~attacks & alerted))
    fn, tn = int(np.sum(attacks & ~alerted)), int(np.sum(~attacks & ~alerted))
    return {"selected_threshold": bundle.alert_threshold, "validation_precision": tp / max(tp + fp, 1),
            "validation_recall": tp / max(tp + fn, 1), "validation_false_positive_rate": fp / max(fp + tn, 1),
            "validation_alert_rate": float(np.mean(alerted)),
            "selection_method": "validation risk cutoff constrained to the top 1% analyst alert budget", "top_1_percent": budget}


def train(data_dir: Path, model_dir: Path, contamination: float = .03, seed: int = 42,
          artifact_name: str = "current.joblib") -> ModelBundle:
    paths = {name: (data_dir / "processed" / f"{name}.jsonl", data_dir / "processed" / f"{name}_labels.jsonl")
             for name in ("train", "validation", "test")}
    missing = [str(path) for pair in paths.values() for path in pair if not path.exists()]
    if missing: raise FileNotFoundError(f"Missing datasets: {missing}. Run generate_data.py first.")
    raw_splits = {name: load_split(*pair) for name, pair in paths.items()}
    featured = featurize_splits(raw_splits)
    x_train, y_train, train_entities, _ = featured["train"]; normal_mask = y_train == "normal"
    if not np.any(normal_mask): raise ValueError("Training data must contain normal events")
    scaler = build_scaler().fit(x_train[normal_mask]); scaled_train = scaler.transform(x_train)
    anomaly = IsolationForestDetector(contamination, seed).fit(scaled_train[normal_mask])
    sequence = GRUSequenceDetector(len(FeaturePipeline.names), random_state=seed).fit(scaled_train, y_train, train_entities)
    classifier = AttackClassifier(seed).fit(scaled_train, y_train)
    val_x, val_y, val_entities, _ = featured["validation"]
    calibration_indices, threshold_indices = [], []
    for label in np.unique(val_y):
        indices = np.flatnonzero(val_y == label); cut = max(1, len(indices) // 2)
        calibration_indices.extend(indices[:cut]); threshold_indices.extend(indices[cut:])
    calibration_indices = np.asarray(sorted(calibration_indices)); threshold_indices = np.asarray(sorted(threshold_indices))
    classifier.calibrate(scaler.transform(val_x[calibration_indices]), val_y[calibration_indices])
    version = datetime.now(timezone.utc).strftime("v%Y%m%d-%H%M%S")
    bootstrap_memory = MemoryProfiles()
    for row in sorted(raw_splits["train"], key=lambda item: item.event.timestamp):
        bootstrap_memory.update(row.event, row.label)
    bootstrap_profiles = {}
    for key, profile in bootstrap_memory.profiles.items():
        if key.startswith("peer:") or key == "global:organization":
            bootstrap_profiles[key] = {"count": profile["count"],
                                       "data": {name: list(profile.get(name, [])) for name in EMPTY_PROFILE}}
    bundle = ModelBundle(version, FEATURE_SCHEMA_VERSION, FeaturePipeline.names, scaler, anomaly, sequence, classifier,
                         50.0, {}, bootstrap_profiles)
    threshold_selection = tune_threshold(bundle, val_x[threshold_indices], val_y[threshold_indices], val_entities[threshold_indices])
    validation_metrics = evaluation_metrics(bundle, val_x, val_y, val_entities)
    test_x, test_y, test_entities, _ = featured["test"]
    bundle.metrics = {
        "validation": validation_metrics, "test": evaluation_metrics(bundle, test_x, test_y, test_entities),
        "threshold_selection": threshold_selection,
        "training_population": {"total_rows": int(len(y_train)), "normal_rows": int(np.sum(normal_mask)),
            "attack_rows": int(np.sum(~normal_mask)), "preprocessor_fit": "normal_only",
            "anomaly_detector_fit": "normal_only", "sequence_detector_fit": "normal_sequences_only",
            "classifier_fit": "normal_and_attack", "classifier_probability_calibration": "validation_sigmoid"},
        "bootstrap_profiles": {"source": "normal_training_rows_only", "profile_count": len(bootstrap_profiles)},
        "trained_at": datetime.now(timezone.utc).isoformat(), "feature_count": len(FeaturePipeline.names),
    }
    bundle.save(model_dir / artifact_name)
    if artifact_name == "current.joblib":
        (model_dir / "metrics.json").write_text(json.dumps(bundle.metrics, indent=2))
    return bundle
