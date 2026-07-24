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
    "login_hours": [], "devices": [], "fingerprints": [], "locations": [],
    "downloads": [], "session_durations": [], "resources": [],
}


class ProfileService:
    def __init__(self, db: Session):
        self.db = db
        self.settings = get_settings()

    @staticmethod
    def _key(profile_type: str, subject: str) -> str: return f"{profile_type}:{subject}"

    def _record(self, profile_type: str, subject: str) -> ProfileRecord | None:
        return self.db.scalar(select(ProfileRecord).where(ProfileRecord.profile_key == self._key(profile_type, subject)))

    def baseline_for(self, event: AccessEvent) -> Baseline:
        user = self._record("user", event.user_id)
        peer_subject = f"{event.department}:{event.user_role}"
        peer = self._record("peer", peer_subject)
        global_record = self._record("global", "organization")
        if user and user.event_count >= self.settings.minimum_user_history:
            chosen, kind, needed = user, "user", self.settings.minimum_user_history
        elif peer and peer.event_count >= self.settings.minimum_peer_history:
            chosen, kind, needed = peer, "peer", self.settings.minimum_peer_history
        elif global_record:
            chosen, kind, needed = global_record, "global", self.settings.minimum_peer_history
        else:
            return Baseline("global_default", 0, 0.1, 0, datetime.now(timezone.utc).isoformat(), dict(EMPTY_PROFILE))
        confidence = min(1.0, 0.25 + 0.75 * chosen.event_count / max(needed * 2, 1))
        return Baseline(kind, chosen.event_count, confidence, chosen.version, chosen.updated_at.isoformat(), chosen.profile_data)

    def update_trusted(self, event: AccessEvent) -> None:
        subjects = [("user", event.user_id), ("peer", f"{event.department}:{event.user_role}"), ("global", "organization")]
        for profile_type, subject in subjects:
            record = self._record(profile_type, subject)
            if not record:
                record = ProfileRecord(profile_key=self._key(profile_type, subject), profile_type=profile_type,
                                       subject_id=subject, event_count=0, profile_data=dict(EMPTY_PROFILE), version=1)
                self.db.add(record)
            data = {key: list(value) for key, value in (record.profile_data or EMPTY_PROFILE).items()}
            if event.event_type == "login" and event.authentication_result == "success":
                data["login_hours"] = (data["login_hours"] + [event.timestamp.hour + event.timestamp.minute / 60])[-500:]
                data["devices"] = list(dict.fromkeys(data["devices"] + [event.device_id]))[-50:]
                data["fingerprints"] = list(dict.fromkeys(data["fingerprints"] + [event.device_fingerprint]))[-50:]
                data["locations"] = list(dict.fromkeys(data["locations"] + [f"{event.country}|{event.city}"]))[-50:]
            data["downloads"] = (data["downloads"] + [event.bytes_downloaded])[-500:]
            data["session_durations"] = (data["session_durations"] + [event.session_duration_seconds])[-500:]
            data["resources"] = list(dict.fromkeys(data["resources"] + [event.resource_id]))[-100:]
            record.profile_data, record.event_count, record.version = data, record.event_count + 1, record.version + 1

    @staticmethod
    def summary(baseline: Baseline) -> dict:
        data = baseline.data
        def stats(values: list[float]) -> dict:
            return {"mean": mean(values) if values else 0.0, "std": pstdev(values) if len(values) > 1 else 0.0}
        return {
            "baseline_type": baseline.baseline_type, "event_count": baseline.event_count,
            "confidence": baseline.confidence, "profile_version": baseline.profile_version,
            "last_updated": baseline.last_updated, "cold_start": baseline.baseline_type != "user",
            "normal_login_hours": stats(data.get("login_hours", [])), "known_devices": data.get("devices", []),
            "common_locations": data.get("locations", []), "common_resources": data.get("resources", []),
            "download_baseline": stats(data.get("downloads", [])), "session_baseline": stats(data.get("session_durations", [])),
        }

