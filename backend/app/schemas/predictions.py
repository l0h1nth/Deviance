from pydantic import BaseModel, Field


class FeatureContribution(BaseModel):
    feature: str
    value: float
    expected: float
    deviation: float
    description: str


class PredictionResponse(BaseModel):
    event_id: str
    anomaly_score: float = Field(ge=0, le=1)
    predicted_attack: str
    display_attack: str
    class_probabilities: dict[str, float]
    classifier_confidence: float = Field(ge=0, le=1)
    model_confidence: float = Field(ge=0, le=1)
    baseline_confidence: float = Field(ge=0, le=1)
    risk_score: float = Field(ge=0, le=100)
    severity: str
    top_contributing_features: list[FeatureContribution]
    explanation: str
    recommended_actions: list[str]
    baseline_type: str
    historical_events: int
    cold_start: bool
    model_version: str
    feature_schema_version: str
    alert_id: int | None = None
    latency_ms: float
    drift_detected: bool
    user_id: str
    device_id: str
    timestamp: str
    event_type: str
    location: dict
    authentication_result: str
    features: dict[str, float]
    feature_evidence: list[dict]
    risk_composition: dict[str, float]
    event: dict
    trusted: bool
    trust_source: str | None = None
