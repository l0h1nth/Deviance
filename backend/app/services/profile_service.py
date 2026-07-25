from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from statistics import mean, pstdev

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.database.models import ProfileRecord
from app.schemas.events import AccessEvent


@dataclass
class Baseline:
    baseline_type: str
    event_count: int
    confidence: float
    profile_version: int
    last_updated: str
    data: dict


MATURE_BASELINE_TYPES = frozenset({"entity", "device"})


def is_cold_start_baseline(baseline_type: str) -> bool:
    """Return whether scoring still relies on a fallback rather than a mature subject profile."""
    return baseline_type not in MATURE_BASELINE_TYPES


EMPTY_PROFILE = {
    "login_hours": [], "devices": [], "fingerprints": [], "locations": [], "downloads": [], "uploads": [],
    "session_durations": [], "resources": [], "privileged_resources": [], "auth_methods": [], "commands": [],
    "protocol_ports": [], "activity_hours": [], "source_ips": [], "device_postures": [], "vpn_usage": [],
    "event_actions": [], "api_endpoint_methods": [], "api_credentials": [], "api_scopes": [],
    "resource_sensitivities": [], "external_transfers": [], "sensitive_flags": [], "command_transitions": [],
    "event_epochs": [], "inter_event_seconds": [], "api_events": [], "resource_events": [],
    "sensitive_events": [], "external_transfer_events": [],
}


def empty_profile_data() -> dict[str, list]:
    return {key: [] for key in EMPTY_PROFILE}


def update_profile_data(source: dict | None, event: AccessEvent) -> dict[str, list]:
    """Apply one trusted event to the bounded behavioral profile contract."""
    data = {key: list((source or {}).get(key, [])) for key in EMPTY_PROFILE}

    def append(key: str, value, limit: int = 500) -> None:
        data[key] = (data[key] + [value])[-limit:]

    def unique(key: str, value, limit: int) -> None:
        data[key] = list(dict.fromkeys(data[key] + [value]))[-limit:]

    hour = event.timestamp.hour + event.timestamp.minute / 60
    append("activity_hours", hour)
    unique("source_ips", event.source_ip, 100)
    unique("devices", event.device_id, 50)
    unique("fingerprints", event.device_fingerprint, 50)
    unique("locations", f"{event.country}|{event.city}", 50)
    unique("device_postures", f"{event.operating_system}|{event.firmware_version}|{event.browser}|{event.device_mac_hash}", 80)
    append("vpn_usage", float(event.is_vpn))
    unique("event_actions", f"{event.event_type}:{event.action}", 100)
    append("resource_sensitivities", float(event.resource_sensitivity))
    sensitive = float(event.resource_sensitivity >= .7 or event.is_privileged_action)
    append("sensitive_flags", sensitive)
    append("downloads", event.bytes_downloaded)
    append("uploads", event.bytes_uploaded)
    append("session_durations", event.session_duration_seconds)
    unique("resources", event.resource_id, 150)
    unique("protocol_ports", f"{event.network_protocol}:{event.destination_port}", 50)
    epoch = event.timestamp.timestamp()
    append("resource_events", [epoch, event.resource_id], 1000)
    append("sensitive_events", [epoch, sensitive], 1000)
    if event.is_external_destination:
        transfer = event.bytes_uploaded + event.bytes_downloaded
        append("external_transfers", transfer)
        append("external_transfer_events", [epoch, transfer], 1000)
    if event.is_privileged_action:
        unique("privileged_resources", event.resource_id, 100)
    if event.authentication_result == "success":
        append("login_hours", hour)
    if event.auth_method != "not_applicable":
        unique("auth_methods", event.auth_method, 10)
    if event.command_sequence:
        for command in event.command_sequence:
            unique("commands", command, 200)
        ordered = ["__start__", *event.command_sequence]
        for left, right in zip(ordered, ordered[1:]):
            unique("command_transitions", f"{left}->{right}", 300)
    if event.event_type == "api_call":
        endpoint = f"{event.http_method}:{event.api_route}"
        unique("api_endpoint_methods", endpoint, 150)
        append("api_events", [epoch, endpoint], 1000)
        if event.credential_id_hash:
            unique("api_credentials", event.credential_id_hash, 50)
        for scope in event.token_scopes:
            unique("api_scopes", scope, 100)

    if data["event_epochs"]:
        append("inter_event_seconds", max(0.0, epoch - float(data["event_epochs"][-1])))
    append("event_epochs", epoch)
    return data


class ProfileService:
    def __init__(self, db: Session, bootstrap_profiles: dict | None = None):
        self.db = db; self.settings = get_settings(); self.bootstrap_profiles = bootstrap_profiles or {}

    @staticmethod
    def _key(profile_type: str, subject: str) -> str: return f"{profile_type}:{subject}"

    def _record(self, profile_type: str, subject: str) -> ProfileRecord | None:
        return self.db.scalar(select(ProfileRecord).where(ProfileRecord.profile_key == self._key(profile_type, subject)))

    def baseline_for(self, event: AccessEvent) -> Baseline:
        entity = self._record("entity", event.entity_id)
        device = self._record("device", event.device_id)
        peer_subject = f"{event.entity_type}:{event.department}:{event.user_role}"
        peer = self._record("peer", peer_subject); global_record = self._record("global", "organization")
        if entity and entity.event_count >= self.settings.minimum_user_history:
            chosen, kind, needed = entity, "entity", self.settings.minimum_user_history
        elif device and device.event_count >= self.settings.minimum_user_history:
            chosen, kind, needed = device, "device", self.settings.minimum_user_history
        elif peer and peer.event_count >= self.settings.minimum_peer_history:
            chosen, kind, needed = peer, "peer", self.settings.minimum_peer_history
        elif global_record and global_record.event_count >= self.settings.minimum_peer_history:
            chosen, kind, needed = global_record, "global", self.settings.minimum_peer_history
        else:
            prior = self.bootstrap_profiles.get(f"peer:{peer_subject}")
            prior_kind = "peer_prior"
            if not prior:
                prior = self.bootstrap_profiles.get("global:organization"); prior_kind = "global_prior"
            if prior:
                return Baseline(prior_kind, int(prior.get("count", 0)), .55, 0,
                                datetime.now(timezone.utc).isoformat(), prior.get("data", empty_profile_data()))
            return Baseline("global_default", 0, .1, 0, datetime.now(timezone.utc).isoformat(), empty_profile_data())
        confidence = min(1.0, .25 + .75 * chosen.event_count / max(needed * 2, 1))
        return Baseline(kind, chosen.event_count, confidence, chosen.version, chosen.updated_at.isoformat(), chosen.profile_data)

    def update_trusted(self, event: AccessEvent) -> None:
        subjects = [("entity", event.entity_id), ("device", event.device_id),
                    ("peer", f"{event.entity_type}:{event.department}:{event.user_role}"), ("global", "organization")]
        for profile_type, subject in subjects:
            record = self._record(profile_type, subject)
            if not record:
                record = ProfileRecord(profile_key=self._key(profile_type, subject), profile_type=profile_type,
                                       subject_id=subject, event_count=0, profile_data=empty_profile_data(), version=1)
                self.db.add(record)
            data = update_profile_data(record.profile_data, event)
            record.profile_data, record.event_count, record.version = data, record.event_count + 1, record.version + 1

    @staticmethod
    def summary(baseline: Baseline) -> dict:
        data = baseline.data
        def stats(values: list[float]) -> dict:
            return {"mean": mean(values) if values else 0.0, "std": pstdev(values) if len(values) > 1 else 0.0}
        return {
            "baseline_type": baseline.baseline_type, "event_count": baseline.event_count,
            "confidence": baseline.confidence, "profile_version": baseline.profile_version,
            "last_updated": baseline.last_updated, "cold_start": is_cold_start_baseline(baseline.baseline_type),
            "normal_login_hours": stats(data.get("login_hours", [])), "known_devices": data.get("devices", []),
            "common_locations": data.get("locations", []), "common_resources": data.get("resources", []),
            "auth_methods": data.get("auth_methods", []), "protocol_ports": data.get("protocol_ports", []),
            "download_baseline": stats(data.get("downloads", [])), "session_baseline": stats(data.get("session_durations", [])),
        }
