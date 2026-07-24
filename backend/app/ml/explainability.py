import numpy as np

from app.ml.feature_registry import registry


def explain_features(values: dict[str, float], scaled_vector: np.ndarray, importances: np.ndarray | None = None,
                     limit: int = 4) -> list[dict]:
    importances = importances if importances is not None else np.ones(len(scaled_vector))
    strength = np.abs(scaled_vector) * (.5 + importances / max(float(importances.max()), 1e-9))
    indices = np.argsort(strength)[::-1][:limit]
    definitions = registry.definitions
    return [{
        "feature": definitions[i].name, "value": float(values[definitions[i].name]), "expected": 0.0,
        "deviation": float(abs(scaled_vector[i])), "description": definitions[i].description,
    } for i in indices]


def human_explanation(contributions: list[dict], baseline_type: str, cold_start: bool) -> str:
    readable = [f"{item['feature'].replace('_', ' ')} was {item['value']:.2f}" for item in contributions[:3]]
    prefix = "Cold-start scoring used a peer/global baseline. " if cold_start else ""
    return prefix + "Risk increased because " + ", ".join(readable) + f" relative to the {baseline_type} behavioral baseline."

