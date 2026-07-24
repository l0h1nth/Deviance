from dataclasses import dataclass
from datetime import timedelta
from math import log1p
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
    return [event for event in context.history if floor <= event.timestamp < context.event.timestamp]


def zscore(value: float, values: list[float]) -> float:
    if len(values) < 2: return 0.0
    return float(np.clip((value - mean(values)) / max(pstdev(values), 1.0), -20, 20))


def fingerprint_distance(value: str, known: list[str]) -> float:
    if not known: return .35
    distances = []
    for other in known:
        width = max(len(value), len(other), 1); left, right = value.ljust(width), other.ljust(width)
        distances.append(sum(a != b for a, b in zip(left, right)) / width)
    return min(distances)


def _entity_history(context: FeatureContext) -> list[AccessEvent]:
    return [event for event in context.history if event.entity_id == context.event.entity_id]


def _last_entity_event(context: FeatureContext) -> AccessEvent | None:
    matches = [event for event in context.history if event.entity_id == context.event.entity_id and event.timestamp < context.event.timestamp]
    return max(matches, key=lambda event: event.timestamp) if matches else None


def _last_success(context: FeatureContext) -> AccessEvent | None:
    matches = [event for event in context.history if event.entity_id == context.event.entity_id
               and event.authentication_result == "success" and event.timestamp < context.event.timestamp]
    return max(matches, key=lambda event: event.timestamp) if matches else None


def _failed_1m(c): return sum(event.authentication_result == "failure" and (event.entity_id == c.event.entity_id or event.source_ip == c.event.source_ip) for event in recent(c, 1))
def _attempts_5m(c): return sum(event.event_type == "login" and (event.entity_id == c.event.entity_id or event.source_ip == c.event.source_ip) for event in recent(c, 5))
def _hour_dev(c):
    values = c.baseline.data.get("login_hours", [])
    return circular_hour_distance(c.event.timestamp.hour + c.event.timestamp.minute / 60, mean(values)) if values else 1.5
def _new_device(c):
    known = c.baseline.data.get("devices", [])
    return .35 if not known else float(c.event.device_id not in known)
def _fp_distance(c): return fingerprint_distance(c.event.device_fingerprint, c.baseline.data.get("fingerprints", []))
def _location(c):
    known = c.baseline.data.get("locations", [])
    return .3 if not known else float(f"{c.event.country}|{c.event.city}" not in known)
def _travel(c):
    previous = _last_success(c)
    if not previous: return 0.0
    hours = (c.event.timestamp - previous.timestamp).total_seconds() / 3600
    return required_speed_kmph(previous.latitude, previous.longitude, c.event.latitude, c.event.longitude, hours)
def _hosts(c): return len({event.destination_host for event in recent(c, 5) if event.entity_id == c.event.entity_id} | {c.event.destination_host})
def _sensitive_ratio(c):
    events = [event for event in recent(c, 5) if event.entity_id == c.event.entity_id] + [c.event]
    return sum(event.resource_sensitivity >= .7 or event.is_privileged_action for event in events) / len(events)
def _download(c): return zscore(c.event.bytes_downloaded, c.baseline.data.get("downloads", []))
def _duration(c): return zscore(c.event.session_duration_seconds, c.baseline.data.get("session_durations", []))
def _success_after_failures(c):
    failures = sum(event.authentication_result == "failure" and (event.entity_id == c.event.entity_id or event.source_ip == c.event.source_ip) for event in recent(c, 5))
    return min(1.0, failures / 5) if c.event.authentication_result == "success" else 0.0
def _source_entities(c): return len({event.entity_id for event in recent(c, 5) if event.source_ip == c.event.source_ip} | {c.event.entity_id})
def _source_failure_ratio(c):
    events = [event for event in recent(c, 5) if event.source_ip == c.event.source_ip] + [c.event]
    auth = [event for event in events if event.authentication_result != "not_applicable"]
    return sum(event.authentication_result == "failure" for event in auth) / max(len(auth), 1)
def _auth_novelty(c):
    known = c.baseline.data.get("auth_methods", [])
    return .25 if not known else float(c.event.auth_method not in known and c.event.auth_method != "not_applicable")
def _time_since(c):
    previous = _last_entity_event(c)
    return log1p(max(0, (c.event.timestamp - previous.timestamp).total_seconds())) if previous else log1p(86400)
def _concurrent(c):
    sessions = {event.session_id for event in recent(c, 5) if event.entity_id == c.event.entity_id}
    return len(sessions | {c.event.session_id})
def _command_novelty(c):
    if not c.event.command_sequence: return 0.0
    known = set(c.baseline.data.get("commands", []))
    return .3 if not known else sum(command not in known for command in c.event.command_sequence) / len(c.event.command_sequence)
def _resource_novelty(c):
    known = c.baseline.data.get("resources", [])
    return .25 if not known else float(c.event.resource_id not in known)
def _privilege_expansion(c):
    if not c.event.is_privileged_action: return 0.0
    return float(c.event.resource_id not in c.baseline.data.get("privileged_resources", []))
def _protocol_novelty(c):
    value = f"{c.event.network_protocol}:{c.event.destination_port}"
    known = c.baseline.data.get("protocol_ports", [])
    return .25 if not known else float(value not in known)
def _upload(c): return zscore(c.event.bytes_uploaded, c.baseline.data.get("uploads", []))
def _sensitive_downloads_30d(c):
    floor = c.event.timestamp - timedelta(days=30)
    prior = [event for event in c.history if floor <= event.timestamp < c.event.timestamp and event.entity_id == c.event.entity_id
             and event.event_type == "file_download" and event.resource_sensitivity >= .55]
    return len(prior) + int(c.event.event_type == "file_download" and c.event.resource_sensitivity >= .55)
def _off_hours(c):
    values = c.baseline.data.get("login_hours", [])
    if not values: return .25
    return min(1.0, circular_hour_distance(c.event.timestamp.hour + c.event.timestamp.minute / 60, mean(values)) / 6)


_FEATURES = [
    ("failed_login_count_1m", "Failed authentications by entity or IP in one minute", "1 minute", _failed_1m),
    ("login_attempt_count_5m", "Authentication attempts in five minutes", "5 minutes", _attempts_5m),
    ("login_hour_deviation", "Circular-hour distance from normal access time", "profile", _hour_dev),
    ("new_device_score", "Unfamiliarity of the observed device", "profile", _new_device),
    ("device_fingerprint_distance", "Distance from trusted fingerprints", "profile", _fp_distance),
    ("location_novelty_score", "Novelty of country and city", "profile", _location),
    ("required_travel_speed_kmph", "Speed required since previous successful location", "previous success", _travel),
    ("unique_destination_hosts_5m", "Destination breadth in five minutes", "5 minutes", _hosts),
    ("sensitive_resource_access_ratio", "Sensitive access ratio in current window", "5 minutes", _sensitive_ratio),
    ("download_volume_zscore", "Download deviation from entity baseline", "profile", _download),
    ("session_duration_zscore", "Session duration deviation from baseline", "profile", _duration),
    ("successful_login_after_failures_score", "Successful login following failures", "5 minutes", _success_after_failures),
    ("source_ip_unique_entities_5m", "Distinct entities accessed by one source IP", "5 minutes", _source_entities),
    ("source_ip_failure_ratio_5m", "Authentication failure ratio for source IP", "5 minutes", _source_failure_ratio),
    ("auth_method_novelty_score", "Novel authentication method", "profile", _auth_novelty),
    ("time_since_previous_event_log_seconds", "Log time since previous entity event", "previous event", _time_since),
    ("concurrent_session_count_5m", "Distinct active sessions in five minutes", "5 minutes", _concurrent),
    ("command_sequence_novelty_score", "Novel command ratio in privileged sequence", "profile", _command_novelty),
    ("resource_novelty_score", "Resource absent from trusted footprint", "profile", _resource_novelty),
    ("privilege_expansion_score", "Privileged access beyond trusted footprint", "profile", _privilege_expansion),
    ("protocol_port_novelty_score", "Novel protocol and port combination", "profile", _protocol_novelty),
    ("upload_volume_zscore", "Upload deviation from entity baseline", "profile", _upload),
    ("sensitive_download_count_30d", "Sensitive downloads over thirty days", "30 days", _sensitive_downloads_30d),
    ("off_hours_activity_score", "Distance from normal access hours", "profile", _off_hours),
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
