from __future__ import annotations

import numpy as np

from app.ml.anomaly_model import IsolationForestDetector
from app.ml.attack_classifier import AttackClassifier


IF_DOMAIN_NAMES = ["authentication_api", "identity_device_geo", "resource_network", "volume_timing"]
RF_ATTACK_NAMES = [
    "brute_force", "credential_stuffing", "lateral_movement",
    "impossible_travel", "device_spoofing", "low_slow_exfiltration",
]


def enriched_names(base_names: list[str]) -> list[str]:
    return [*base_names, *[f"if_{name}_score" for name in IF_DOMAIN_NAMES],
            *[f"rf_{name}_probability" for name in RF_ATTACK_NAMES]]


def aligned_attack_probabilities(classifier: AttackClassifier, scaled: np.ndarray,
                                 probabilities: np.ndarray | None = None) -> np.ndarray:
    values = classifier.probabilities(scaled) if probabilities is None else np.asarray(probabilities, dtype=float)
    class_index = {str(name): index for index, name in enumerate(classifier.classes_)}
    return np.column_stack([
        values[:, class_index[name]] if name in class_index else np.zeros(len(scaled))
        for name in RF_ATTACK_NAMES
    ])


def enrich_scaled(scaled: np.ndarray, anomaly: IsolationForestDetector, classifier: AttackClassifier,
                  probabilities: np.ndarray | None = None) -> np.ndarray:
    scaled = np.atleast_2d(np.asarray(scaled, dtype=float))
    domains = anomaly.domain_scores(scaled)
    domain_matrix = np.column_stack([domains.get(name, np.zeros(len(scaled))) for name in IF_DOMAIN_NAMES])
    attacks = aligned_attack_probabilities(classifier, scaled, probabilities)
    return np.column_stack([scaled, domain_matrix, attacks])
