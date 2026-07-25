from typing import Literal

from pydantic import BaseModel, Field, model_validator


SimulationScenario = Literal[
    "mixed", "brute_force", "credential_stuffing", "lateral_movement",
    "impossible_travel", "device_spoofing", "low_slow_exfiltration", "cold_start",
    "cold_start_benign", "cold_start_attack",
    "concept_drift", "insider_drift",
]


class SimulationStart(BaseModel):
    scenario: SimulationScenario = "mixed"
    interval_ms: Literal[500, 1000, 2000] = 1000
    event_count: int = Field(default=30, ge=1, le=500)

    @model_validator(mode="after")
    def drift_requires_two_windows(self):
        if self.scenario in {"concept_drift", "insider_drift"} and self.event_count < 40:
            raise ValueError("drift scenarios require at least 40 events to fill both rolling windows")
        return self
