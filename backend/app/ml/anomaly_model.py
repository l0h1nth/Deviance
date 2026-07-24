from abc import ABC, abstractmethod
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest


class AnomalyDetector(ABC):
    @abstractmethod
    def fit(self, features: np.ndarray): ...
    @abstractmethod
    def score(self, features: np.ndarray) -> np.ndarray: ...
    @abstractmethod
    def predict(self, features: np.ndarray, threshold: float = .5) -> np.ndarray: ...
    @abstractmethod
    def model_metadata(self) -> dict: ...


class IsolationForestDetector(AnomalyDetector):
    def __init__(self, contamination: float = .03, random_state: int = 42):
        self.contamination = contamination
        self.model = IsolationForest(n_estimators=180, contamination=contamination, random_state=random_state, n_jobs=-1)
        self.score_low = 0.0; self.score_high = 1.0

    def fit(self, features: np.ndarray):
        self.model.fit(features)
        raw = -self.model.score_samples(features)
        self.score_low, self.score_high = float(np.quantile(raw, .02)), float(np.quantile(raw, .995))
        return self


    def score(self, features: np.ndarray) -> np.ndarray:
        raw = -self.model.score_samples(features)
        return np.clip((raw - self.score_low) / max(self.score_high - self.score_low, 1e-9), 0, 1)

    def predict(self, features: np.ndarray, threshold: float = .5) -> np.ndarray: return self.score(features) >= threshold
    def save(self, path: Path) -> None: joblib.dump(self, path)
    @classmethod
    def load(cls, path: Path): return joblib.load(path)
    def model_metadata(self) -> dict: return {"type": "IsolationForest", "contamination": self.contamination, "estimators": 180}

