from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import LabelEncoder
from xgboost import XGBClassifier


class AttackClassifier:
    def __init__(self, random_state: int = 42, model_kind: str = "random_forest"):
        self.model_kind = model_kind
        self.label_encoder = LabelEncoder() if model_kind == "xgboost" else None
        if model_kind == "random_forest":
            self.model = RandomForestClassifier(
                n_estimators=320, class_weight="balanced_subsample", min_samples_leaf=2,
                max_features="sqrt", random_state=random_state, n_jobs=-1,
            )
        elif model_kind == "xgboost":
            self.model = XGBClassifier(
                objective="multi:softprob", n_estimators=360, max_depth=5,
                learning_rate=.045, min_child_weight=3, subsample=.82,
                colsample_bytree=.82, reg_alpha=.08, reg_lambda=1.4,
                random_state=random_state, n_jobs=-1, tree_method="hist",
                eval_metric="mlogloss",
            )
        else:
            raise ValueError(f"Unsupported classifier: {model_kind}")
        self.calibrators = []

    def fit(self, features: np.ndarray, labels: np.ndarray, sample_weight=None):
        target = self.label_encoder.fit_transform(labels) if self.label_encoder is not None else labels
        self.model.fit(features, target, sample_weight=sample_weight); return self

    def calibrate(self, features: np.ndarray, labels: np.ndarray):
        raw = self.model.predict_proba(features); self.calibrators = []
        for index, class_name in enumerate(self.classes_):
            target = (labels == class_name).astype(int)
            if len(np.unique(target)) < 2: self.calibrators.append(None)
            else: self.calibrators.append(LogisticRegression(random_state=42).fit(raw[:, [index]], target))
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
    def classes_(self):
        return self.label_encoder.classes_ if self.label_encoder is not None else self.model.classes_
    @property
    def feature_importances_(self): return self.model.feature_importances_
    def model_metadata(self) -> dict:
        return {"type": self.model_kind, "classes": [str(item) for item in self.classes_]}
    def save(self, path: Path) -> None: joblib.dump(self, path)
    @classmethod
    def load(cls, path: Path): return joblib.load(path)
