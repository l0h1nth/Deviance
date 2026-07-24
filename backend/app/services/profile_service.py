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


EMPTY_PROFILE = {
    "login_hours": [], "devices": [], "fingerprints": [], "locations": [], "downloads": [], "uploads": [],
    "session_durations": [], "resources": [], "privileged_resources": [], "auth_methods": [], "commands": [],
    "protocol_ports": [],
}


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
        elif event.entity_type == "edge_device" and device and device.event_count >= self.settings.minimum_user_history:
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
                                datetime.now(timezone.utc).isoformat(), prior.get("data", dict(EMPTY_PROFILE)))
            return Baseline("global_default", 0, .1, 0, datetime.now(timezone.utc).isoformat(), dict(EMPTY_PROFILE))
        confidence = min(1.0, .25 + .75 * chosen.event_count / max(needed * 2, 1))
        return Baseline(kind, chosen.event_count, confidence, chosen.version, chosen.updated_at.isoformat(), chosen.profile_data)

    def update_trusted(self, event: AccessEvent) -> None:
        subjects = [("entity", event.entity_id), ("device", event.device_id),
                    ("peer", f"{event.entity_type}:{event.department}:{event.user_role}"), ("global", "organization")]
        for profile_type, subject in subjects:
            record = self._record(profile_type, subject)
            if not record:
                record = ProfileRecord(profile_key=self._key(profile_type, subject), profile_type=profile_type,
                                       subject_id=subject, event_count=0, profile_data=dict(EMPTY_PROFILE), version=1)
                self.db.add(record)
            source = record.profile_data or EMPTY_PROFILE
            data = {key: list(source.get(key, [])) for key in EMPTY_PROFILE}
            if event.authentication_result == "success":
                data["login_hours"] = (data["login_hours"] + [event.timestamp.hour + event.timestamp.minute / 60])[-500:]
                data["devices"] = list(dict.fromkeys(data["devices"] + [event.device_id]))[-50:]
                data["fingerprints"] = list(dict.fromkeys(data["fingerprints"] + [event.device_fingerprint]))[-50:]
                data["locations"] = list(dict.fromkeys(data["locations"] + [f"{event.country}|{event.city}"]))[-50:]
                if event.auth_method != "not_applicable": data["auth_methods"] = list(dict.fromkeys(data["auth_methods"] + [event.auth_method]))[-10:]
            data["downloads"] = (data["downloads"] + [event.bytes_downloaded])[-500:]
            data["uploads"] = (data["uploads"] + [event.bytes_uploaded])[-500:]
            data["session_durations"] = (data["session_durations"] + [event.session_duration_seconds])[-500:]
            data["resources"] = list(dict.fromkeys(data["resources"] + [event.resource_id]))[-150:]
            if event.is_privileged_action:
                data["privileged_resources"] = list(dict.fromkeys(data["privileged_resources"] + [event.resource_id]))[-100:]
            data["commands"] = list(dict.fromkeys(data["commands"] + event.command_sequence))[-200:]
            protocol_port = f"{event.network_protocol}:{event.destination_port}"
            data["protocol_ports"] = list(dict.fromkeys(data["protocol_ports"] + [protocol_port]))[-50:]
            record.profile_data, record.event_count, record.version = data, record.event_count + 1, record.version + 1

    @staticmethod
    def summary(baseline: Baseline) -> dict:
        data = baseline.data
        def stats(values: list[float]) -> dict:
            return {"mean": mean(values) if values else 0.0, "std": pstdev(values) if len(values) > 1 else 0.0}
        return {
            "baseline_type": baseline.baseline_type, "event_count": baseline.event_count,
            "confidence": baseline.confidence, "profile_version": baseline.profile_version,
            "last_updated": baseline.last_updated, "cold_start": baseline.baseline_type != "entity",
            "normal_login_hours": stats(data.get("login_hours", [])), "known_devices": data.get("devices", []),
            "common_locations": data.get("locations", []), "common_resources": data.get("resources", []),
            "auth_methods": data.get("auth_methods", []), "protocol_ports": data.get("protocol_ports", []),
            "download_baseline": stats(data.get("downloads", [])), "session_baseline": stats(data.get("session_durations", [])),
        }
