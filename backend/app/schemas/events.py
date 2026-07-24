from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


AttackLabel = Literal[
    "normal", "brute_force", "credential_misuse", "lateral_movement",
    "impossible_travel", "device_spoofing",
]


class AccessEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_id: str = Field(min_length=1, max_length=100)
    timestamp: datetime
    user_id: str = Field(min_length=1, max_length=100)
    user_role: str = Field(min_length=1, max_length=80)
    department: str = Field(min_length=1, max_length=80)
    device_id: str = Field(min_length=1, max_length=100)
    claimed_device_id: str = Field(min_length=1, max_length=100)
    operating_system: str = Field(min_length=1, max_length=100)
    browser: str = Field(min_length=1, max_length=100)
    user_agent: str = Field(min_length=1, max_length=500)
    device_fingerprint: str = Field(min_length=4, max_length=256)
    source_ip: str = Field(min_length=3, max_length=64)
    country: str = Field(min_length=2, max_length=80)
    city: str = Field(min_length=1, max_length=100)
    latitude: float = Field(ge=-90, le=90)
    longitude: float = Field(ge=-180, le=180)
    event_type: Literal["login", "resource_access", "file_download", "admin_action"]
    authentication_result: Literal["success", "failure", "not_applicable"]
    resource_id: str = Field(min_length=1, max_length=120)
    resource_type: str = Field(min_length=1, max_length=80)
    resource_sensitivity: float = Field(ge=0, le=1)
    destination_host: str = Field(min_length=1, max_length=180)
    bytes_uploaded: int = Field(ge=0, le=10_000_000_000)
    bytes_downloaded: int = Field(ge=0, le=10_000_000_000)
    session_id: str = Field(min_length=1, max_length=100)
    session_duration_seconds: int = Field(ge=0, le=604800)
    is_vpn: bool
    is_privileged_action: bool
    ground_truth_label: AttackLabel | None = None

    @field_validator("timestamp")
    @classmethod
    def validate_timestamp(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("timestamp must include a timezone")
        now = datetime.now(timezone.utc)
        if value.astimezone(timezone.utc) > now.replace(microsecond=0) and (value - now).total_seconds() > 300:
            raise ValueError("timestamp cannot be more than five minutes in the future")
        return value.astimezone(timezone.utc)


class EventBatch(BaseModel):
    events: list[AccessEvent] = Field(min_length=1, max_length=500)

