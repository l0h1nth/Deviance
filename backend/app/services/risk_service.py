import numpy as np

from app.schemas.events import AccessEvent


class RiskService:
    def __init__(self, anomaly_weight=.45, classifier_weight=.35, deviation_weight=.10, criticality_weight=.10):
        self.weights = (anomaly_weight, classifier_weight, deviation_weight, criticality_weight)

    def score(self, inference: dict, scaled_vector: np.ndarray, event: AccessEvent, baseline_confidence: float) -> dict:
        malicious = max((v for k, v in inference["class_probabilities"].items() if k != "normal"), default=0.0)
        deviation = float(np.clip(np.mean(np.minimum(np.abs(scaled_vector), 5)) / 3, 0, 1))
        criticality = float(np.clip(.75 * event.resource_sensitivity + .25 * event.is_privileged_action, 0, 1))
        a, c, d, r = self.weights
        raw = 100 * (a * inference["anomaly_score"] + c * malicious + d * deviation + r * criticality)
        # Cold start affects confidence, not the evidence/risk itself.
        risk = float(np.clip(raw, 0, 100))
        severity = "low" if risk < 30 else "medium" if risk < 50 else "high" if risk < 70 else "critical"
        model_confidence = float(np.clip((inference["classifier_confidence"] + baseline_confidence) / 2, 0, 1))
        return {"risk_score": round(risk, 2), "severity": severity, "model_confidence": model_confidence,
                "baseline_deviation": deviation, "criticality": criticality}

    @staticmethod
    def actions(predicted: str, severity: str) -> list[str]:
        base = ["Review the user and device timeline", "Validate the activity with the account owner"]
        specific = {
            "brute_force": "Rate-limit authentication and inspect the source session",
            "credential_misuse": "Revoke active sessions and rotate credentials",
            "lateral_movement": "Isolate the device and inspect destination hosts",
            "impossible_travel": "Verify travel/VPN context and compare session overlap",
            "device_spoofing": "Challenge device trust and re-enrol the endpoint",
            "normal": "Monitor for corroborating activity",
        }
        if severity == "critical": base.insert(0, "Escalate immediately to incident response")
        return [specific.get(predicted, specific["normal"]), *base]

