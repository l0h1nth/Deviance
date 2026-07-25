from __future__ import annotations

from dataclasses import asdict, dataclass

import numpy as np


@dataclass(frozen=True)
class RiskWeights:
    """Shared training/serving policy for independently scaled evidence."""

    anomaly: float = .30
    sequence: float = .05
    classifier: float = .25
    deviation: float = .35
    criticality: float = .05

    def validate(self) -> "RiskWeights":
        values = np.asarray(list(asdict(self).values()), dtype=float)
        if np.any(values < 0) or not np.isclose(values.sum(), 1.0):
            raise ValueError("Risk weights must be non-negative and total 1.0")
        return self

    def as_dict(self) -> dict[str, float]:
        return asdict(self.validate())


DEFAULT_RISK_WEIGHTS = RiskWeights()


def combine_risk(anomaly, sequence, malicious, deviation, criticality, weights: RiskWeights):
    weights.validate()
    return 100 * (
        weights.anomaly * np.asarray(anomaly)
        + weights.sequence * np.asarray(sequence)
        + weights.classifier * np.asarray(malicious)
        + weights.deviation * np.asarray(deviation)
        + weights.criticality * np.asarray(criticality)
    )


def behavioral_score(anomaly, sequence, deviation, weights: RiskWeights):
    """Normal-only evidence normalized independently from known-attack confidence."""
    total = weights.anomaly + weights.sequence + weights.deviation
    if total <= 0:
        raise ValueError("Behavioral risk requires at least one normal-only component")
    return np.clip(
        (weights.anomaly * np.asarray(anomaly)
         + weights.sequence * np.asarray(sequence)
         + weights.deviation * np.asarray(deviation)) / total,
        0,
        1,
    )
