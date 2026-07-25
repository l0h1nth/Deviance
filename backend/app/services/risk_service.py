import numpy as np

from app.ml.risk_policy import DEFAULT_RISK_WEIGHTS, RiskWeights, combine_risk
from app.schemas.events import AccessEvent


class RiskService:
    def __init__(self, weights: dict | RiskWeights | None = None, priority_threshold: float = 70.0):
        self.weights = weights if isinstance(weights, RiskWeights) else RiskWeights(**(weights or DEFAULT_RISK_WEIGHTS.as_dict()))
        self.priority_threshold = priority_threshold
        self.weights.validate()

    def score(self, inference: dict, scaled_vector: np.ndarray, event: AccessEvent, baseline_confidence: float) -> dict:
        malicious = max((value for name, value in inference["class_probabilities"].items() if name != "normal"), default=0.0)
        deviation = float(np.clip(np.mean(np.minimum(np.abs(scaled_vector), 5)) / 3, 0, 1))
        criticality = float(np.clip(.75 * event.resource_sensitivity + .25 * event.is_privileged_action, 0, 1))
        anomaly_weight, sequence_weight = self.weights.anomaly, self.weights.sequence
        classifier_weight, deviation_weight = self.weights.classifier, self.weights.deviation
        criticality_weight = self.weights.criticality
        components = {
            "behavioral_anomaly": 100 * anomaly_weight * inference["anomaly_score"],
            "sequence_anomaly": 100 * sequence_weight * inference["sequence_anomaly_score"],
            "attack_classifier": 100 * classifier_weight * malicious,
            "profile_deviation": 100 * deviation_weight * deviation,
            "resource_criticality": 100 * criticality_weight * criticality,
        }
        risk = float(np.clip(combine_risk(
            inference["anomaly_score"], inference["sequence_anomaly_score"], malicious,
            deviation, criticality, self.weights,
        ), 0, 100))
        severity = "low" if risk < 30 else "medium" if risk < 50 else "high" if risk < self.priority_threshold else "critical"
        model_confidence = float(np.clip((inference["classifier_confidence"] + baseline_confidence) / 2, 0, 1))
        return {"risk_score": round(risk, 2), "severity": severity, "model_confidence": model_confidence,
                "baseline_deviation": deviation, "criticality": criticality,
                "risk_composition": {key: round(value, 2) for key, value in components.items()}}

    @staticmethod
    def actions(predicted: str, severity: str) -> list[str]:
        base = ["Review the complete entity sequence", "Validate the activity with the system or account owner"]
        specific = {
            "brute_force": "Rate-limit authentication and inspect the source session",
            "credential_stuffing": "Block the source campaign and identify all targeted entities",
            "lateral_movement": "Isolate the device and inspect destination hosts and commands",
            "impossible_travel": "Verify travel/VPN context and compare overlapping sessions",
            "device_spoofing": "Challenge device trust and re-enrol the endpoint",
            "low_slow_exfiltration": "Review cumulative sensitive transfers and destination ownership",
            "normal": "Monitor for corroborating activity",
        }
        if severity == "critical": base.insert(0, "Escalate immediately to incident response")
        return [specific.get(predicted, specific["normal"]), *base]
