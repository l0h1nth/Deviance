from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


REQUIRED_ATTACK_TYPES = (
    "brute_force", "credential_stuffing", "lateral_movement",
    "impossible_travel", "device_spoofing", "low_slow_exfiltration",
)

AttackLabel = Literal[
    "normal", "brute_force", "credential_stuffing",
    "lateral_movement", "impossible_travel", "device_spoofing", "low_slow_exfiltration",
]
EntityType = Literal["user", "service_account", "edge_device"]


class AccessEvent(BaseModel):
    """Production telemetry contract. Ground-truth labels never cross this boundary."""

    model_config = ConfigDict(extra="forbid")

    event_id: str = Field(min_length=1, max_length=100)
    timestamp: datetime
    entity_id: str = Field(min_length=1, max_length=100)
    entity_type: EntityType
    user_id: str = Field(min_length=1, max_length=100)  # compatibility/correlation alias
    user_role: str = Field(min_length=1, max_length=80)
    department: str = Field(min_length=1, max_length=80)
    device_id: str = Field(min_length=1, max_length=100)
    claimed_device_id: str = Field(min_length=1, max_length=100)
    operating_system: str = Field(min_length=1, max_length=100)
    firmware_version: str = Field(min_length=1, max_length=100)
    browser: str = Field(min_length=1, max_length=100)
    user_agent: str = Field(min_length=1, max_length=500)
    device_fingerprint: str = Field(min_length=4, max_length=256)
    device_mac_hash: str = Field(min_length=4, max_length=128)
    source_ip: str = Field(min_length=3, max_length=64)
    country: str = Field(min_length=2, max_length=80)
    city: str = Field(min_length=1, max_length=100)
    latitude: float = Field(ge=-90, le=90)
    longitude: float = Field(ge=-180, le=180)
    event_type: Literal["login", "resource_access", "file_download", "admin_action", "api_call", "device_connection"]
    action: Literal[
        "authenticate", "read", "write", "delete", "execute", "list", "connect", "disconnect", "invoke",
        "not_applicable",
    ] = "not_applicable"
    access_outcome: Literal["allowed", "denied", "error", "not_applicable"] = "not_applicable"
    authentication_result: Literal["success", "failure", "not_applicable"]
    auth_method: Literal["password", "token", "certificate", "biometric", "not_applicable"]
    mfa_result: Literal["success", "failure", "not_used", "not_applicable"] = "not_applicable"
    api_route: str | None = Field(default=None, min_length=1, max_length=200)
    http_method: Literal["GET", "POST", "PUT", "PATCH", "DELETE"] | None = None
    http_status_code: int | None = Field(default=None, ge=100, le=599)
    api_latency_ms: float | None = Field(default=None, ge=0, le=600_000)
    credential_id_hash: str | None = Field(default=None, min_length=4, max_length=128)
    token_scopes: list[str] = Field(default_factory=list, max_length=20)
    resource_id: str = Field(min_length=1, max_length=120)
    resource_type: str = Field(min_length=1, max_length=80)
    resource_sensitivity: float = Field(ge=0, le=1)
    destination_host: str = Field(min_length=1, max_length=180)
    source_network_zone: Literal["corporate", "vpn", "internet", "partner", "ot", "unknown"] = "unknown"
    destination_network_zone: Literal["internal", "restricted", "external", "ot", "cloud", "unknown"] = "unknown"
    is_external_destination: bool = False
    network_protocol: Literal["https", "ssh", "rdp", "smb", "mqtt", "opcua", "database", "internal"]
    destination_port: int = Field(ge=1, le=65535)
    command_sequence: list[str] = Field(default_factory=list, max_length=50)
    bytes_uploaded: int = Field(ge=0, le=10_000_000_000)
    bytes_downloaded: int = Field(ge=0, le=10_000_000_000)
    session_id: str = Field(min_length=1, max_length=100)
    session_duration_seconds: int = Field(ge=0, le=604800)
    parent_auth_event_id: str | None = Field(default=None, min_length=1, max_length=100)
    device_connection_action: Literal["connect", "disconnect", "heartbeat", "not_applicable"] = "not_applicable"
    device_class: Literal["workstation", "server", "mobile", "edge_gateway", "iot", "pos", "unknown"] = "unknown"
    is_vpn: bool
    is_privileged_action: bool

    @field_validator("timestamp")
    @classmethod
    def validate_timestamp(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("timestamp must include a timezone")
        now = datetime.now(timezone.utc)
        if value.astimezone(timezone.utc) > now.replace(microsecond=0) and (value - now).total_seconds() > 300:
            raise ValueError("timestamp cannot be more than five minutes in the future")
        return value.astimezone(timezone.utc)

    @model_validator(mode="after")
    def validate_event_specific_fields(self):
        if self.event_type == "api_call":
            missing = [name for name in ("api_route", "http_method", "http_status_code")
                       if getattr(self, name) is None]
            if missing:
                raise ValueError(f"api_call requires {', '.join(missing)}")
        if self.event_type == "device_connection" and self.device_connection_action == "not_applicable":
            raise ValueError("device_connection requires device_connection_action")
        return self


class TrainingLabel(BaseModel):
    """Offline-only label sidecar joined by event_id during training/evaluation."""

    event_id: str
    label: AttackLabel
    scenario_id: str
    sequence_id: str


class LabeledEvent(BaseModel):
    event: AccessEvent
    label: AttackLabel
    scenario_id: str
    sequence_id: str

    def sidecar(self) -> TrainingLabel:
        return TrainingLabel(event_id=self.event.event_id, label=self.label,
                             scenario_id=self.scenario_id, sequence_id=self.sequence_id)


class EventBatch(BaseModel):
    events: list[AccessEvent] = Field(min_length=1, max_length=500)
