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
        self.random_state = random_state
        self.model = IsolationForest(n_estimators=280, contamination=contamination, max_samples=2048,
                                     random_state=random_state, n_jobs=-1)
        self.score_low = 0.0; self.score_high = 1.0
        self.domain_indices = {
            "authentication": np.asarray([0, 1, 2, 11, 12, 13, 14, 15, 23]),
            "identity_device_geo": np.asarray([3, 4, 5, 6, 16]),
            "resource_network": np.asarray([7, 8, 17, 18, 19, 20]),
            "volume_timing": np.asarray([9, 10, 21, 22]),
        }
        self.domain_models: dict[str, IsolationForest] = {}
        self.domain_ranges: dict[str, tuple[float, float]] = {}

    def fit(self, features: np.ndarray):
        self.model.set_params(max_samples=min(2048, len(features)))
        self.model.fit(features)
        raw = -self.model.score_samples(features)
        self.score_low, self.score_high = float(np.quantile(raw, .02)), float(np.quantile(raw, .995))
        self.domain_models = {}; self.domain_ranges = {}
        for offset, (name, indices) in enumerate(self.domain_indices.items(), start=1):
            valid = indices[indices < features.shape[1]]
            if not len(valid):
                continue
            model = IsolationForest(
                n_estimators=180, contamination=self.contamination, max_samples=min(2048, len(features)),
                random_state=self.random_state + offset, n_jobs=-1,
            ).fit(features[:, valid])
            domain_raw = -model.score_samples(features[:, valid])
            self.domain_models[name] = model
            self.domain_ranges[name] = (float(np.quantile(domain_raw, .02)), float(np.quantile(domain_raw, .995)))
        return self

    @staticmethod
    def _normalize(raw: np.ndarray, low: float, high: float) -> np.ndarray:
        return np.clip((raw - low) / max(high - low, 1e-9), 0, 1)

    def domain_scores(self, features: np.ndarray) -> dict[str, np.ndarray]:
        scores = {}
        for name, model in self.domain_models.items():
            indices = self.domain_indices[name]
            low, high = self.domain_ranges[name]
            scores[name] = self._normalize(-model.score_samples(features[:, indices]), low, high)
        return scores

    def score(self, features: np.ndarray) -> np.ndarray:
        raw = -self.model.score_samples(features)
        global_score = self._normalize(raw, self.score_low, self.score_high)
        domain = self.domain_scores(features)
        if not domain:
            return global_score
        matrix = np.column_stack(list(domain.values()))
        return np.clip(.35 * global_score + .45 * matrix.max(axis=1) + .20 * matrix.mean(axis=1), 0, 1)

    def predict(self, features: np.ndarray, threshold: float = .5) -> np.ndarray: return self.score(features) >= threshold
    def save(self, path: Path) -> None: joblib.dump(self, path)
    @classmethod
    def load(cls, path: Path): return joblib.load(path)
    def model_metadata(self) -> dict:
        return {"type": "DomainIsolationForestEnsemble", "contamination": self.contamination,
                "global_estimators": 280, "domain_estimators": 180,
                "domains": list(self.domain_models)}
