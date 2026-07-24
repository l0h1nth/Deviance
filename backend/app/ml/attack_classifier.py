from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier


class AttackClassifier:
    def __init__(self, random_state: int = 42):
        self.model = RandomForestClassifier(n_estimators=240, class_weight="balanced_subsample", min_samples_leaf=2,
                                            max_features="sqrt", random_state=random_state, n_jobs=-1)

    def fit(self, features: np.ndarray, labels: np.ndarray, sample_weight=None):
        self.model.fit(features, labels, sample_weight=sample_weight); return self

    def probabilities(self, features: np.ndarray) -> np.ndarray: return self.model.predict_proba(features)

    def predict(self, features: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
        probabilities = self.probabilities(features); indices = probabilities.argmax(axis=1)
        return self.model.classes_[indices], probabilities[np.arange(len(indices)), indices]

    @property
    def classes_(self): return self.model.classes_
    @property
    def feature_importances_(self): return self.model.feature_importances_
    def save(self, path: Path) -> None: joblib.dump(self, path)
    @classmethod
    def load(cls, path: Path): return joblib.load(path)

