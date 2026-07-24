from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression


class AttackClassifier:
    def __init__(self, random_state: int = 42):
        self.model = RandomForestClassifier(n_estimators=240, class_weight="balanced_subsample", min_samples_leaf=2,
                                            max_features="sqrt", random_state=random_state, n_jobs=-1)
        self.calibrators = []

    def fit(self, features: np.ndarray, labels: np.ndarray, sample_weight=None):
        self.model.fit(features, labels, sample_weight=sample_weight); return self

    def calibrate(self, features: np.ndarray, labels: np.ndarray):
        raw = self.model.predict_proba(features); self.calibrators = []
        for index, class_name in enumerate(self.model.classes_):
            target = (labels == class_name).astype(int)
            if len(np.unique(target)) < 2: self.calibrators.append(None)
            else: self.calibrators.append(LogisticRegression(random_state=42, class_weight="balanced").fit(raw[:, [index]], target))
        return self

    def probabilities(self, features: np.ndarray) -> np.ndarray:
        raw = self.model.predict_proba(features)
        if not self.calibrators: return raw
        calibrated = np.column_stack([
            model.predict_proba(raw[:, [index]])[:, 1] if model is not None else raw[:, index]
            for index, model in enumerate(self.calibrators)
        ])
        return calibrated / np.maximum(calibrated.sum(axis=1, keepdims=True), 1e-12)

    def predict(self, features: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
        probabilities = self.probabilities(features); indices = probabilities.argmax(axis=1)
        return self.classes_[indices], probabilities[np.arange(len(indices)), indices]

    @property
    def classes_(self): return self.model.classes_
    @property
    def feature_importances_(self): return self.model.feature_importances_
    def save(self, path: Path) -> None: joblib.dump(self, path)
    @classmethod
    def load(cls, path: Path): return joblib.load(path)
