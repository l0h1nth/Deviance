from dataclasses import dataclass
from datetime import timedelta
from statistics import mean, pstdev

import numpy as np

from app.ml.feature_registry import FEATURE_SCHEMA_VERSION, FeatureDefinition, registry
from app.schemas.events import AccessEvent
from app.services.profile_service import Baseline
from app.utils.geo import required_speed_kmph
from app.utils.time import circular_hour_distance


@dataclass
class FeatureContext:
    event: AccessEvent
    history: list[AccessEvent]
    baseline: Baseline


def recent(context: FeatureContext, minutes: int) -> list[AccessEvent]:
    floor = context.event.timestamp - timedelta(minutes=minutes)
    return [e for e in context.history if floor <= e.timestamp < context.event.timestamp]


def zscore(value: float, values: list[float]) -> float:
    if len(values) < 2: return 0.0
    sd = pstdev(values)
    return float(np.clip((value - mean(values)) / max(sd, 1.0), -20, 20))


def fingerprint_distance(value: str, known: list[str]) -> float:
    if not known: return 0.35
    distances = []
    for other in known:
        width = max(len(value), len(other), 1)
        left, right = value.ljust(width), other.ljust(width)
        distances.append(sum(a != b for a, b in zip(left, right)) / width)
    return min(distances)


def _last_success(context: FeatureContext) -> AccessEvent | None:
    matches = [e for e in context.history if e.user_id == context.event.user_id and e.authentication_result == "success" and e.timestamp < context.event.timestamp]
    return max(matches, key=lambda e: e.timestamp) if matches else None


def _failed_1m(c): return sum(e.authentication_result == "failure" and (e.user_id == c.event.user_id or e.source_ip == c.event.source_ip) for e in recent(c, 1))
def _attempts_5m(c): return sum(e.event_type == "login" and (e.user_id == c.event.user_id or e.source_ip == c.event.source_ip) for e in recent(c, 5))
def _hour_dev(c):
    values = c.baseline.data.get("login_hours", [])
    return circular_hour_distance(c.event.timestamp.hour + c.event.timestamp.minute / 60, mean(values)) if values else 1.5
def _new_device(c):
    known = c.baseline.data.get("devices", [])
    return 0.35 if not known else float(c.event.device_id not in known)
def _fp_distance(c): return fingerprint_distance(c.event.device_fingerprint, c.baseline.data.get("fingerprints", []))
def _location(c):
    known = c.baseline.data.get("locations", [])
    return 0.3 if not known else float(f"{c.event.country}|{c.event.city}" not in known)
def _travel(c):
    previous = _last_success(c)
    if not previous: return 0.0
    hours = (c.event.timestamp - previous.timestamp).total_seconds() / 3600
    return required_speed_kmph(previous.latitude, previous.longitude, c.event.latitude, c.event.longitude, hours)
def _hosts(c): return len({e.destination_host for e in recent(c, 5) if e.user_id == c.event.user_id} | {c.event.destination_host})
def _sensitive_ratio(c):
    events = [e for e in recent(c, 5) if e.user_id == c.event.user_id] + [c.event]
    return sum(e.resource_sensitivity >= .7 or e.is_privileged_action for e in events) / len(events)
def _download(c): return zscore(c.event.bytes_downloaded, c.baseline.data.get("downloads", []))
def _duration(c): return zscore(c.event.session_duration_seconds, c.baseline.data.get("session_durations", []))
def _success_after_failures(c):
    failures = sum(e.authentication_result == "failure" and (e.user_id == c.event.user_id or e.source_ip == c.event.source_ip) for e in recent(c, 5))
    return min(1.0, failures / 5) if c.event.authentication_result == "success" else 0.0


_FEATURES = [
    ("failed_login_count_1m", "Failed authentications by user or IP in the prior minute", "1 minute", _failed_1m),
    ("login_attempt_count_5m", "Authentication attempts in the prior five minutes", "5 minutes", _attempts_5m),
    ("login_hour_deviation", "Circular-hour distance from normal login time", "profile", _hour_dev),
    ("new_device_score", "Unfamiliarity of the device", "profile", _new_device),
    ("device_fingerprint_distance", "Distance from trusted device fingerprints", "profile", _fp_distance),
    ("location_novelty_score", "Novelty of country and city", "profile", _location),
    ("required_travel_speed_kmph", "Speed required since previous successful location", "previous success", _travel),
    ("unique_destination_hosts_5m", "Distinct destination hosts in five minutes", "5 minutes", _hosts),
    ("sensitive_resource_access_ratio", "Sensitive access ratio in current window", "5 minutes", _sensitive_ratio),
    ("download_volume_zscore", "Download deviation from baseline", "profile", _download),
    ("session_duration_zscore", "Session duration deviation from baseline", "profile", _duration),
    ("successful_login_after_failures_score", "Successful login following failures", "5 minutes", _success_after_failures),
]
if not registry.definitions:
    for name, description, history, extractor in _FEATURES:
        registry.register(FeatureDefinition(name, description, "float", 0.0, history, extractor))


class FeaturePipeline:
    schema_version = FEATURE_SCHEMA_VERSION
    names = registry.names

    def transform_one(self, event: AccessEvent, history: list[AccessEvent], baseline: Baseline) -> tuple[np.ndarray, dict]:
        values = registry.extract(FeatureContext(event, history, baseline))
        vector = np.asarray([values[name] for name in registry.names], dtype=float)
        metadata = {
            "values": values, "baseline_type": baseline.baseline_type, "historical_events": baseline.event_count,
            "baseline_confidence": baseline.confidence, "profile_version": baseline.profile_version,
            "last_updated": baseline.last_updated, "feature_schema_version": self.schema_version,
        }
        return vector, metadata
