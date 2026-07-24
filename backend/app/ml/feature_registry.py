from dataclasses import dataclass
from typing import Any, Callable


FEATURE_SCHEMA_VERSION = "1.0.0"


@dataclass(frozen=True)
class FeatureDefinition:
    name: str
    description: str
    data_type: str
    default: float
    required_history: str
    extractor: Callable[[Any], float]
    version: str = FEATURE_SCHEMA_VERSION
    anomaly_model: bool = True
    attack_classifier: bool = True


class FeatureRegistry:
    def __init__(self) -> None:
        self._features: list[FeatureDefinition] = []

    def register(self, feature: FeatureDefinition) -> None:
        if any(item.name == feature.name for item in self._features):
            raise ValueError(f"Duplicate feature: {feature.name}")
        self._features.append(feature)

    @property
    def definitions(self) -> tuple[FeatureDefinition, ...]: return tuple(self._features)

    @property
    def names(self) -> list[str]: return [feature.name for feature in self._features]

    def extract(self, context: Any) -> dict[str, float]:
        values: dict[str, float] = {}
        for feature in self._features:
            try:
                value = float(feature.extractor(context))
                values[feature.name] = value if value == value and abs(value) != float("inf") else feature.default
            except (KeyError, TypeError, ValueError, ZeroDivisionError):
                values[feature.name] = feature.default
        return values


registry = FeatureRegistry()

