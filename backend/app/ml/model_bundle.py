from dataclasses import dataclass, field
from pathlib import Path

import joblib
import numpy as np

from app.ml.anomaly_model import IsolationForestDetector
from app.ml.attack_classifier import AttackClassifier
from app.ml.enriched_features import enrich_scaled, enriched_names
from app.ml.feature_registry import FEATURE_SCHEMA_VERSION
from app.ml.risk_policy import DEFAULT_RISK_WEIGHTS, RiskWeights, behavioral_score
from app.ml.sequence_model import GRUSequenceDetector


@dataclass
class ModelBundle:
    version: str
    feature_schema_version: str
    feature_names: list[str]
    scaler: object
    anomaly_detector: IsolationForestDetector
    sequence_detector: GRUSequenceDetector
    attack_classifier: AttackClassifier
    alert_threshold: float
    metrics: dict
    bootstrap_profiles: dict = field(default_factory=dict)
    risk_weights: dict = field(default_factory=lambda: DEFAULT_RISK_WEIGHTS.as_dict())
    behavioral_threshold: float = .85
    priority_threshold: float = 70.0
    classifier_candidates: dict = field(default_factory=dict)
    event_sequence_scaler: object | None = None
    entity_behavior_scaler: object | None = None
    entity_behavior_detector: GRUSequenceDetector | None = None
    entity_behavior_threshold: float = .85
    enriched_feature_names: list[str] = field(default_factory=list)

    def validate(self, expected_names: list[str]) -> None:
        if self.feature_schema_version != FEATURE_SCHEMA_VERSION:
            raise ValueError(f"Feature schema mismatch: model={self.feature_schema_version}, runtime={FEATURE_SCHEMA_VERSION}")
        if self.feature_names != expected_names: raise ValueError("Feature order mismatch")

    def infer(self, vector: np.ndarray, previous_vectors: np.ndarray | None = None) -> dict:
        scaled = self.scaler.transform(vector.reshape(1, -1))
        anomaly_score = float(self.anomaly_detector.score(scaled)[0])
        domain_anomaly_scores = {
            name: float(values[0]) for name, values in self.anomaly_detector.domain_scores(scaled).items()
        }
        probabilities = self.attack_classifier.probabilities(scaled)[0]
        class_probabilities = {str(name): float(value) for name, value in zip(self.attack_classifier.classes_, probabilities)}
        previous_scaled = self.scaler.transform(previous_vectors) if previous_vectors is not None and len(previous_vectors) else np.empty((0, len(vector)))
        sequence_width = getattr(self.sequence_detector, "source_input_size", len(vector))
        if sequence_width > len(vector):
            current_sequence = enrich_scaled(scaled, self.anomaly_detector, self.attack_classifier,
                                             probabilities.reshape(1, -1))[0]
            previous_sequence = enrich_scaled(previous_scaled, self.anomaly_detector, self.attack_classifier) if len(previous_scaled) else np.empty((0, sequence_width))
            sequence_scaler = getattr(self, "event_sequence_scaler", None)
            if sequence_scaler is not None:
                current_sequence = sequence_scaler.transform(current_sequence.reshape(1, -1))[0]
                previous_sequence = sequence_scaler.transform(previous_sequence) if len(previous_sequence) else previous_sequence
        else:
            current_sequence, previous_sequence = scaled[0], previous_scaled
        sequence_anomaly_score = self.sequence_detector.score_one(previous_sequence, current_sequence)
        predicted = str(self.attack_classifier.classes_[int(probabilities.argmax())])
        confidence = float(probabilities.max())
        malicious = max((value for name, value in class_probabilities.items() if name != "normal"), default=0.0)
        deviation = float(np.clip(np.mean(np.minimum(np.abs(scaled[0]), 5)) / 3, 0, 1))
        behavior = float(behavioral_score(
            anomaly_score, sequence_anomaly_score, deviation, RiskWeights(**self.risk_weights)))
        # The required taxonomy has no extra output class. Once the normal-only layer
        # establishes an anomaly, route a classifier-normal result to the closest
        # required attack class and retain its honest (possibly low) confidence.
        if behavior >= self.behavioral_threshold and predicted == "normal":
            malicious_indices = [
                index for index, name in enumerate(self.attack_classifier.classes_) if name != "normal"
            ]
            if malicious_indices:
                selected = max(malicious_indices, key=lambda index: probabilities[index])
                predicted = str(self.attack_classifier.classes_[selected])
                confidence = float(probabilities[selected])
        return {"anomaly_score": anomaly_score, "sequence_anomaly_score": sequence_anomaly_score, "predicted_attack": predicted,
                "classifier_confidence": confidence, "class_probabilities": class_probabilities,
                "behavioral_score": behavior, "domain_anomaly_scores": domain_anomaly_scores,
                "scaled_vector": scaled[0], "enriched_vector": current_sequence,
                "enriched_feature_names": getattr(self, "enriched_feature_names", None) or enriched_names(self.feature_names)}

    def save(self, path: Path) -> None:
        path = path.resolve(); path.parent.mkdir(parents=True, exist_ok=True); joblib.dump(self, path)

    @classmethod
    def load(cls, path: Path, allowed_dir: Path | None = None):
        resolved = path.resolve()
        if allowed_dir and allowed_dir.resolve() not in resolved.parents: raise ValueError("Model path is outside configured artifact directory")
        if not resolved.is_file(): raise FileNotFoundError(f"Model bundle not found at {resolved}. Run train_models.py first.")
        bundle = joblib.load(resolved)
        if not isinstance(bundle, cls): raise ValueError("Artifact is not a Deviance model bundle")
        return bundle
