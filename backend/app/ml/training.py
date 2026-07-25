from __future__ import annotations

import json
from copy import deepcopy
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from time import perf_counter

import numpy as np
from sklearn.metrics import accuracy_score, average_precision_score, classification_report, confusion_matrix, f1_score, roc_auc_score

from app.ml.anomaly_model import IsolationForestDetector
from app.ml.attack_classifier import AttackClassifier
from app.ml.feature_pipeline import FeaturePipeline
from app.ml.feature_registry import FEATURE_SCHEMA_VERSION
from app.ml.model_bundle import ModelBundle
from app.ml.preprocessing import build_scaler
from app.ml.risk_policy import DEFAULT_RISK_WEIGHTS, RiskWeights, behavioral_score, combine_risk
from app.ml.sequence_model import GRUSequenceDetector
from app.schemas.events import AccessEvent, LabeledEvent, TrainingLabel
from app.services.profile_service import Baseline, EMPTY_PROFILE, empty_profile_data, update_profile_data


class MemoryProfiles:
    """Leakage-safe normal-only profiles used while walking events chronologically."""
    def __init__(self, entity_min: int = 12, peer_min: int = 25):
        self.entity_min, self.peer_min = entity_min, peer_min
        self.profiles: dict[str, dict] = defaultdict(lambda: {**empty_profile_data(), "count": 0})

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

    def update(self, event: AccessEvent, trusted: bool) -> None:
        if not trusted: return
        for kind in ("entity", "device", "peer", "global"):
            key = self._key(kind, event); current = self.profiles[key]; count = int(current.get("count", 0))
            updated = update_profile_data(current, event); updated["count"] = count + 1; self.profiles[key] = updated


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


def featurize_splits(splits: dict[str, list[LabeledEvent]]) -> dict[str, tuple[np.ndarray, ...]]:
    pipeline, training_profiles = FeaturePipeline(), MemoryProfiles()
    result = {}
    for split_name in ("train", "validation", "test"):
        # Validation and test each begin from the same training-only priors, then
        # evolve chronologically without consulting labels. This models online
        # adaptation while allowing anomalous traffic to contaminate the profile.
        profiles = training_profiles if split_name == "train" else deepcopy(training_profiles)
        history = []
        vectors, labels, entities, sequences, scenarios, criticalities = [], [], [], [], [], []
        for row in sorted(splits[split_name], key=lambda item: item.event.timestamp):
            event = row.event; vector, _ = pipeline.transform_one(event, history, profiles.baseline(event))
            vectors.append(vector); labels.append(row.label); entities.append(event.entity_id)
            sequences.append(row.sequence_id); scenarios.append(row.scenario_id)
            criticalities.append(float(np.clip(.75 * event.resource_sensitivity + .25 * event.is_privileged_action, 0, 1)))
            profiles.update(event, trusted=(row.label == "normal") if split_name == "train" else True)
            history.append(event)
            if len(history) > 3000: history = history[-3000:]
        result[split_name] = (
            np.asarray(vectors), np.asarray(labels), np.asarray(entities), np.asarray(sequences),
            np.asarray(scenarios), np.asarray(criticalities),
        )
    return result


def score_components(bundle: ModelBundle, x: np.ndarray, entities: np.ndarray) -> tuple[np.ndarray, ...]:
    scaled = bundle.scaler.transform(x); anomaly = bundle.anomaly_detector.score(scaled)
    sequence = bundle.sequence_detector.score_stream(scaled, entities)
    probabilities = bundle.attack_classifier.probabilities(scaled)
    malicious_indices = [index for index, name in enumerate(bundle.attack_classifier.classes_) if name != "normal"]
    malicious = probabilities[:, malicious_indices].max(axis=1) if malicious_indices else np.zeros(len(x))
    deviation = np.clip(np.mean(np.minimum(np.abs(scaled), 5), axis=1) / 3, 0, 1)
    return anomaly, sequence, malicious, deviation


def risk_scores(bundle: ModelBundle, x: np.ndarray, entities: np.ndarray, criticality: np.ndarray) -> np.ndarray:
    anomaly, sequence, malicious, deviation = score_components(bundle, x, entities)
    return combine_risk(
        anomaly, sequence, malicious, deviation, criticality, RiskWeights(**bundle.risk_weights))


def budget_metrics(scores: np.ndarray, labels: np.ndarray, fraction: float = .01) -> dict:
    count = max(1, int(np.ceil(len(scores) * fraction))); order = np.argsort(scores)[::-1]; selected = order[:count]
    attacks = labels != "normal"; tp = int(np.sum(attacks[selected])); fp = count - tp
    return {"budget_fraction": fraction, "budget_count": count, "precision": tp / count,
            "recall": tp / max(int(np.sum(attacks)), 1), "false_positives": fp,
            "threshold": float(scores[selected[-1]]), "alert_rate": count / max(len(scores), 1)}


def binary_alert_metrics(alerted: np.ndarray, labels: np.ndarray) -> dict:
    attacks, normal = labels != "normal", labels == "normal"
    tp, fp = int(np.sum(attacks & alerted)), int(np.sum(normal & alerted))
    fn, tn = int(np.sum(attacks & ~alerted)), int(np.sum(normal & ~alerted))
    return {
        "alert_count": int(np.sum(alerted)), "alert_rate": float(np.mean(alerted)),
        "precision": tp / max(tp + fp, 1), "recall": tp / max(tp + fn, 1),
        "false_positive_rate": fp / max(fp + tn, 1), "false_positives": fp,
    }


def grouped_recall(alerted: np.ndarray, y: np.ndarray, groups: np.ndarray) -> dict:
    attack_mask = y != "normal"; true_groups = set(groups[attack_mask]); found_groups = set(groups[attack_mask & alerted])
    by_class = {}
    for label in sorted(set(y) - {"normal"}):
        class_groups = set(groups[y == label]); detected = set(groups[(y == label) & alerted])
        by_class[str(label)] = len(detected) / max(len(class_groups), 1)
    return {"detected": len(found_groups), "total": len(true_groups),
            "recall": len(found_groups) / max(len(true_groups), 1), "recall_by_class": by_class}


def evaluation_metrics(bundle: ModelBundle, x: np.ndarray, y: np.ndarray, entities: np.ndarray,
                       scenarios: np.ndarray, criticality: np.ndarray) -> dict:
    started = perf_counter(); scaled = bundle.scaler.transform(x); classifier_predicted, _ = bundle.attack_classifier.predict(scaled)
    anomaly = bundle.anomaly_detector.score(scaled); sequence = bundle.sequence_detector.score_stream(scaled, entities)
    probabilities = bundle.attack_classifier.probabilities(scaled)
    malicious_indices = [index for index, name in enumerate(bundle.attack_classifier.classes_) if name != "normal"]
    malicious = probabilities[:, malicious_indices].max(axis=1) if malicious_indices else np.zeros(len(x))
    deviation = np.clip(np.mean(np.minimum(np.abs(scaled), 5), axis=1) / 3, 0, 1)
    behavior = behavioral_score(anomaly, sequence, deviation, RiskWeights(**bundle.risk_weights))
    report = classification_report(y, classifier_predicted, output_dict=True, zero_division=0)
    labels = sorted(set(y) | set(classifier_predicted)); matrix = confusion_matrix(y, classifier_predicted, labels=labels)
    normal = y == "normal"
    binary = (y != "normal").astype(int)
    try:
        anomaly_roc = float(roc_auc_score(binary, anomaly)); anomaly_pr = float(average_precision_score(binary, anomaly))
        sequence_roc = float(roc_auc_score(binary, sequence)); sequence_pr = float(average_precision_score(binary, sequence))
    except ValueError: anomaly_roc = anomaly_pr = sequence_roc = sequence_pr = 0.0
    risk = risk_scores(bundle, x, entities, criticality); alerted = risk >= bundle.alert_threshold
    priority = risk >= bundle.priority_threshold
    alert_tp, alert_fp = int(np.sum((y != "normal") & alerted)), int(np.sum(normal & alerted))
    alert_fn, alert_tn = int(np.sum((y != "normal") & ~alerted)), int(np.sum(normal & ~alerted))
    behavior_flagged = behavior >= bundle.behavioral_threshold
    insider_drift = np.asarray([str(value).startswith("insider_drift-") for value in scenarios])
    attacked_entities = set(entities[y != "normal"]); alerted_attacked_entities = set(entities[(y != "normal") & alerted])
    return {
        "classes": labels, "confusion_matrix": matrix.tolist(), "classification_report": report,
        "classifier_accuracy": float(accuracy_score(y, classifier_predicted)),
        "macro_f1": float(f1_score(y, classifier_predicted, average="macro")),
        "weighted_f1": float(f1_score(y, classifier_predicted, average="weighted")),
        "anomaly_roc_auc": anomaly_roc, "anomaly_pr_auc": anomaly_pr,
        "sequence_roc_auc": sequence_roc, "sequence_pr_auc": sequence_pr,
        "classifier_pr_auc": float(average_precision_score(binary, malicious)),
        "behavioral_pr_auc": float(average_precision_score(binary, behavior)),
        "behavioral_threshold": bundle.behavioral_threshold,
        "behavioral_recall": float(np.sum((y != "normal") & behavior_flagged) / max(np.sum(y != "normal"), 1)),
        "behavioral_false_positive_rate": float(np.sum(normal & behavior_flagged) / max(np.sum(normal), 1)),
        "behavioral_insider_drift_false_positive_rate": float(
            np.mean(behavior_flagged[insider_drift]) if np.any(insider_drift) else 0.0),
        "behavioral_recall_by_attack_class": {
            str(label): float(np.mean(behavior_flagged[y == label])) for label in sorted(set(y) - {"normal"})},
        "sample_count": len(y), "attack_prevalence": float(np.mean(y != "normal")),
        "average_detection_latency_ms": (perf_counter() - started) * 1000 / max(len(y), 1),
        "threshold": bundle.alert_threshold, "alert_count": int(np.sum(alerted)), "alert_rate": float(np.mean(alerted)),
        "alert_precision": alert_tp / max(alert_tp + alert_fp, 1), "alert_recall": alert_tp / max(alert_tp + alert_fn, 1),
        "alert_false_positive_rate": alert_fp / max(alert_fp + alert_tn, 1),
        "insider_drift_false_positive_rate": float(
            np.mean(alerted[insider_drift]) if np.any(insider_drift) else 0.0),
        "scenario_detection": grouped_recall(alerted, y, scenarios),
        "attacked_entity_recall": len(alerted_attacked_entities) / max(len(attacked_entities), 1),
        "priority_threshold": bundle.priority_threshold,
        "priority_queue": binary_alert_metrics(priority, y),
        "top_1_percent": budget_metrics(risk, y, .01), "alerts_per_10000": float(np.mean(alerted) * 10000),
    }


def tune_threshold(bundle: ModelBundle, x: np.ndarray, y: np.ndarray, entities: np.ndarray,
                   criticality: np.ndarray, max_normal_fpr: float = .001) -> dict:
    scores = risk_scores(bundle, x, entities, criticality); budget = budget_metrics(scores, y, .01)
    bundle.priority_threshold = budget["threshold"]
    normal, attacks = y == "normal", y != "normal"; candidates = []
    for threshold in np.unique(scores):
        alerted = scores >= threshold
        tp, fp = int(np.sum(attacks & alerted)), int(np.sum(normal & alerted))
        fn, tn = int(np.sum(attacks & ~alerted)), int(np.sum(normal & ~alerted))
        fpr = fp / max(fp + tn, 1)
        if fpr <= max_normal_fpr:
            candidates.append((tp / max(tp + fn, 1), tp / max(tp + fp, 1), -fpr, float(threshold)))
    if not candidates: raise ValueError("No validation threshold satisfies the false-positive constraint")
    _, _, _, bundle.alert_threshold = max(candidates)
    alerted = scores >= bundle.alert_threshold; attacks = y != "normal"
    tp, fp = int(np.sum(attacks & alerted)), int(np.sum(~attacks & alerted))
    fn, tn = int(np.sum(attacks & ~alerted)), int(np.sum(~attacks & ~alerted))
    return {"selected_threshold": bundle.alert_threshold, "validation_precision": tp / max(tp + fp, 1),
            "validation_recall": tp / max(tp + fn, 1), "validation_false_positive_rate": fp / max(fp + tn, 1),
            "validation_alert_rate": float(np.mean(alerted)),
            "max_validation_normal_fpr": max_normal_fpr,
            "priority_threshold": bundle.priority_threshold,
            "selection_method": "maximize validation attack recall subject to <=0.10% normal-event FPR; keep a separate top-1% priority queue",
            "top_1_percent": budget}


def tune_behavioral_threshold(bundle: ModelBundle, x: np.ndarray, y: np.ndarray, entities: np.ndarray,
                              max_normal_fpr: float = .0025) -> dict:
    anomaly, sequence, _, deviation = score_components(bundle, x, entities)
    scores = behavioral_score(anomaly, sequence, deviation, RiskWeights(**bundle.risk_weights))
    attacks, normal = y != "normal", y == "normal"
    if not np.any(normal): raise ValueError("Normal validation events are required")
    candidates = []
    for threshold in np.unique(scores):
        flagged = scores >= threshold
        tp, fp = int(np.sum(attacks & flagged)), int(np.sum(normal & flagged))
        fn, tn = int(np.sum(attacks & ~flagged)), int(np.sum(normal & ~flagged))
        fpr = fp / max(fp + tn, 1)
        if fpr <= max_normal_fpr:
            candidates.append((tp / max(tp + fn, 1), tp / max(tp + fp, 1), -fpr, float(threshold)))
    if not candidates: raise ValueError("No behavioral threshold satisfies the false-positive constraint")
    _, _, _, bundle.behavioral_threshold = max(candidates)
    flagged = scores >= bundle.behavioral_threshold
    tp, fp = int(np.sum(attacks & flagged)), int(np.sum(normal & flagged))
    fn, tn = int(np.sum(attacks & ~flagged)), int(np.sum(normal & ~flagged))
    return {"selected_threshold": bundle.behavioral_threshold,
            "validation_recall": tp / max(tp + fn, 1), "validation_precision": tp / max(tp + fp, 1),
            "validation_false_positive_rate": fp / max(fp + tn, 1),
            "max_validation_normal_fpr": max_normal_fpr,
            "selection_method": "maximize validation attack recall using normal-only evidence subject to <=0.25% normal-event FPR"}


def validation_partitions(labels: np.ndarray) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    calibration, selection, threshold = [], [], []
    for label in np.unique(labels):
        indices = np.flatnonzero(labels == label)
        if len(indices) < 3:
            calibration.extend(indices); selection.extend(indices); threshold.extend(indices)
            continue
        first = max(1, len(indices) // 3); second = min(len(indices) - 1, max(first + 1, 2 * len(indices) // 3))
        calibration.extend(indices[:first]); selection.extend(indices[first:second]); threshold.extend(indices[second:])
    return tuple(np.asarray(sorted(part), dtype=int) for part in (calibration, selection, threshold))


def classifier_metrics(classifier: AttackClassifier, x: np.ndarray, y: np.ndarray) -> dict:
    predicted, _ = classifier.predict(x); probabilities = classifier.probabilities(x)
    malicious_indices = [index for index, name in enumerate(classifier.classes_) if name != "normal"]
    malicious = probabilities[:, malicious_indices].max(axis=1)
    return {"accuracy": float(accuracy_score(y, predicted)),
            "macro_f1": float(f1_score(y, predicted, average="macro")),
            "malicious_pr_auc": float(average_precision_score(y != "normal", malicious))}


def train(data_dir: Path, model_dir: Path, contamination: float = .03, seed: int = 42,
          artifact_name: str = "current.joblib") -> ModelBundle:
    paths = {name: (data_dir / "processed" / f"{name}.jsonl", data_dir / "processed" / f"{name}_labels.jsonl")
             for name in ("train", "validation", "test")}
    missing = [str(path) for pair in paths.values() for path in pair if not path.exists()]
    if missing: raise FileNotFoundError(f"Missing datasets: {missing}. Run generate_data.py first.")
    raw_splits = {name: load_split(*pair) for name, pair in paths.items()}
    featured = featurize_splits(raw_splits)
    x_train, y_train, train_entities, _, _, _ = featured["train"]; normal_mask = y_train == "normal"
    if not np.any(normal_mask): raise ValueError("Training data must contain normal events")
    scaler = build_scaler().fit(x_train[normal_mask]); scaled_train = scaler.transform(x_train)
    anomaly = IsolationForestDetector(contamination, seed).fit(scaled_train[normal_mask])
    sequence = GRUSequenceDetector(
        len(FeaturePipeline.names), random_state=seed, feature_indices=FeaturePipeline.sequence_feature_indices,
    ).fit(scaled_train, y_train, train_entities)
    val_x, val_y, val_entities, _, val_scenarios, val_criticality = featured["validation"]
    calibration_indices, selection_indices, threshold_indices = validation_partitions(val_y)
    scaled_val = scaler.transform(val_x); candidate_models, candidate_results = {}, {}
    class_names, class_counts = np.unique(y_train, return_counts=True)
    count_by_class = dict(zip(class_names, class_counts)); class_total = len(y_train) / len(class_names)
    xgb_weights = np.asarray([np.sqrt(class_total / count_by_class[label]) for label in y_train])
    xgb_weights = np.clip(xgb_weights / np.mean(xgb_weights), .2, 12)
    for kind in ("random_forest", "xgboost"):
        candidate = AttackClassifier(seed, kind).fit(
            scaled_train, y_train, sample_weight=xgb_weights if kind == "xgboost" else None)
        candidate.calibrate(scaled_val[calibration_indices], val_y[calibration_indices])
        candidate_models[kind] = candidate
        candidate_results[kind] = classifier_metrics(candidate, scaled_val[selection_indices], val_y[selection_indices])
    selected_kind = max(candidate_results, key=lambda name: (
        candidate_results[name]["macro_f1"], candidate_results[name]["malicious_pr_auc"]))
    classifier = candidate_models[selected_kind]
    version = datetime.now(timezone.utc).strftime("v%Y%m%d-%H%M%S")
    bootstrap_memory = MemoryProfiles()
    for row in sorted(raw_splits["train"], key=lambda item: item.event.timestamp):
        bootstrap_memory.update(row.event, trusted=row.label == "normal")
    bootstrap_profiles = {}
    for key, profile in bootstrap_memory.profiles.items():
        if key.startswith("peer:") or key == "global:organization":
            bootstrap_profiles[key] = {"count": profile["count"],
                                       "data": {name: list(profile.get(name, [])) for name in EMPTY_PROFILE}}
    bundle = ModelBundle(version, FEATURE_SCHEMA_VERSION, FeaturePipeline.names, scaler, anomaly, sequence, classifier,
                         50.0, {}, bootstrap_profiles, DEFAULT_RISK_WEIGHTS.as_dict(), .85, 70.0,
                         {"selected": selected_kind, "validation": candidate_results})
    behavioral_threshold_selection = tune_behavioral_threshold(
        bundle, val_x[threshold_indices], val_y[threshold_indices], val_entities[threshold_indices])
    threshold_selection = tune_threshold(
        bundle, val_x[threshold_indices], val_y[threshold_indices], val_entities[threshold_indices],
        val_criticality[threshold_indices])
    validation_metrics = evaluation_metrics(bundle, val_x, val_y, val_entities, val_scenarios, val_criticality)
    test_x, test_y, test_entities, _, test_scenarios, test_criticality = featured["test"]
    bundle.metrics = {
        "validation": validation_metrics,
        "test": evaluation_metrics(bundle, test_x, test_y, test_entities, test_scenarios, test_criticality),
        "threshold_selection": threshold_selection,
        "behavioral_threshold_selection": behavioral_threshold_selection,
        "classifier_selection": {"selected": selected_kind, "selection_partition": candidate_results,
                                  "policy": "highest validation macro F1; malicious PR-AUC tie-break"},
        "risk_weights": bundle.risk_weights,
        "training_population": {"total_rows": int(len(y_train)), "normal_rows": int(np.sum(normal_mask)),
            "attack_rows": int(np.sum(~normal_mask)), "preprocessor_fit": "normal_only",
            "anomaly_detector_fit": "normal_only", "sequence_detector_fit": "normal_sequences_only",
            "classifier_fit": "normal_and_attack", "classifier_probability_calibration": "validation_sigmoid",
            "holdout_profile_policy": "training-seeded online profiles; validation/test labels never consulted"},
        "dataset": json.loads((data_dir / "processed" / "manifest.json").read_text())
            if (data_dir / "processed" / "manifest.json").exists() else {},
        "bootstrap_profiles": {"source": "normal_training_rows_only", "profile_count": len(bootstrap_profiles)},
        "trained_at": datetime.now(timezone.utc).isoformat(), "feature_count": len(FeaturePipeline.names),
    }
    bundle.save(model_dir / artifact_name)
    if artifact_name == "current.joblib":
        (model_dir / "metrics.json").write_text(json.dumps(bundle.metrics, indent=2))
    return bundle
