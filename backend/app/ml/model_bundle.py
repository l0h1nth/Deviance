from dataclasses import dataclass
from pathlib import Path

import joblib
import numpy as np

from app.ml.anomaly_model import IsolationForestDetector
from app.ml.attack_classifier import AttackClassifier
from app.ml.feature_registry import FEATURE_SCHEMA_VERSION


@dataclass
class ModelBundle:
    version: str
    feature_schema_version: str
    feature_names: list[str]
    scaler: object
    anomaly_detector: IsolationForestDetector
    attack_classifier: AttackClassifier
    alert_threshold: float
    metrics: dict

    def validate(self, expected_names: list[str]) -> None:
        if self.feature_schema_version != FEATURE_SCHEMA_VERSION:
            raise ValueError(f"Feature schema mismatch: model={self.feature_schema_version}, runtime={FEATURE_SCHEMA_VERSION}")
        if self.feature_names != expected_names: raise ValueError("Feature order mismatch")

    def infer(self, vector: np.ndarray) -> dict:
        scaled = self.scaler.transform(vector.reshape(1, -1))
        anomaly_score = float(self.anomaly_detector.score(scaled)[0])
        probabilities = self.attack_classifier.probabilities(scaled)[0]
        class_probabilities = {str(name): float(value) for name, value in zip(self.attack_classifier.classes_, probabilities)}
        predicted = str(self.attack_classifier.classes_[int(probabilities.argmax())])
        confidence = float(probabilities.max())
        return {"anomaly_score": anomaly_score, "predicted_attack": predicted,
                "classifier_confidence": confidence, "class_probabilities": class_probabilities,
                "scaled_vector": scaled[0]}

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

