from dataclasses import dataclass
from datetime import timedelta
from collections import Counter
from math import log, sqrt
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


def _window(c: FeatureContext, minutes: int) -> list[AccessEvent]:
    return [*recent(c, minutes), c.event]


def _auth_events(c: FeatureContext, minutes: int) -> list[AccessEvent]:
    return [event for event in _window(c, minutes) if event.authentication_result != "not_applicable"
            and (event.entity_id == c.event.entity_id or event.source_ip == c.event.source_ip)]


def _failed_auth_1m(c): return sum(event.authentication_result == "failure" for event in _auth_events(c, 1))
def _auth_attempts_5m(c): return len(_auth_events(c, 5))
def _success_after_failures(c):
    failures = sum(event.authentication_result == "failure" for event in _auth_events(c, 5)[:-1])
    return min(1.0, failures / 5) if c.event.authentication_result == "success" else 0.0
def _source_entities(c): return len({event.entity_id for event in _window(c, 5) if event.source_ip == c.event.source_ip})
def _source_failure_ratio(c):
    auth = [event for event in _window(c, 5) if event.source_ip == c.event.source_ip
            and event.authentication_result != "not_applicable"]
    return sum(event.authentication_result == "failure" for event in auth) / max(len(auth), 1)
def _auth_novelty(c):
    known = c.baseline.data.get("auth_methods", [])
    return .25 if not known else float(c.event.auth_method not in known and c.event.auth_method != "not_applicable")
def _api_rate(c):
    count = sum(event.event_type == "api_call" and event.entity_id == c.event.entity_id for event in _window(c, 1))
    return float(np.clip(count - 1, 0, 20)) if c.event.event_type == "api_call" else 0.0
def _api_error_ratio(c):
    events = [event for event in _window(c, 5) if event.entity_id == c.event.entity_id and event.event_type == "api_call"]
    failures = sum((event.http_status_code or 0) >= 400 or event.access_outcome in {"denied", "error"} for event in events)
    return failures / max(len(events), 1)
def _api_endpoint_method_novelty(c):
    if c.event.event_type != "api_call": return 0.0
    known = c.baseline.data.get("api_endpoint_methods", [])
    value = f"{c.event.http_method}:{c.event.api_route}"
    return .25 if not known else float(value not in known)
def _source_ip_novelty(c):
    if c.baseline.baseline_type not in {"entity", "device"}: return .25
    known = c.baseline.data.get("source_ips", [])
    return .25 if not known else float(c.event.source_ip not in known)
def _new_device(c):
    if c.baseline.baseline_type not in {"entity", "device"}: return .35
    known = c.baseline.data.get("devices", [])
    return .35 if not known else float(c.event.device_id not in known)
def _fp_distance(c):
    if c.baseline.baseline_type not in {"entity", "device"}: return .35
    return fingerprint_distance(c.event.device_fingerprint, c.baseline.data.get("fingerprints", []))
def _device_mismatch(c): return float(c.event.device_id != c.event.claimed_device_id)
def _device_posture_novelty(c):
    if c.baseline.baseline_type not in {"entity", "device"}: return .3
    known = c.baseline.data.get("device_postures", [])
    value = f"{c.event.operating_system}|{c.event.firmware_version}|{c.event.browser}|{c.event.device_mac_hash}"
    return .3 if not known else float(value not in known)
def _location(c):
    known = c.baseline.data.get("locations", [])
    return .3 if not known else float(f"{c.event.country}|{c.event.city}" not in known)
def _travel(c):
    previous = _last_success(c)
    if not previous: return 0.0
    hours = (c.event.timestamp - previous.timestamp).total_seconds() / 3600
    speed = required_speed_kmph(previous.latitude, previous.longitude, c.event.latitude, c.event.longitude, hours)
    reliability = .35 if c.event.is_vpn or previous.is_vpn else 1.0
    return float(np.clip((speed - 250) / 750, 0, 1) * reliability)
def _access_hour_deviation(c):
    values = c.baseline.data.get("activity_hours", [])
    if not values: return .25
    distance = circular_hour_distance(c.event.timestamp.hour + c.event.timestamp.minute / 60, mean(values))
    return min(1.0, distance / 6)
def _hosts(c): return len({event.destination_host for event in recent(c, 5) if event.entity_id == c.event.entity_id} | {c.event.destination_host})
def _resource_novelty(c):
    known = c.baseline.data.get("resources", [])
    return .25 if not known else float(c.event.resource_id not in known)
def _event_action_novelty(c):
    known = c.baseline.data.get("event_actions", [])
    value = f"{c.event.event_type}:{c.event.action}"
    return .25 if not known else float(value not in known)
def _resource_entropy_24h(c):
    floor = c.event.timestamp.timestamp() - 86400
    stored = [str(value) for epoch, value in c.baseline.data.get("resource_events", []) if float(epoch) >= floor]
    values = [*stored, c.event.resource_id]
    counts = Counter(values)
    if len(counts) <= 1: return 0.0
    total = len(values); entropy = -sum((count / total) * log(count / total) for count in counts.values()) / log(len(counts))
    return float(entropy * min(1.0, (len(counts) - 1) / 5))
def _sensitivity_deviation(c):
    score = zscore(c.event.resource_sensitivity, c.baseline.data.get("resource_sensitivities", []))
    return float(np.clip(max(0.0, score) / 5, 0, 1))
def _privilege_expansion(c):
    if not c.event.is_privileged_action: return 0.0
    return float(c.event.resource_id not in c.baseline.data.get("privileged_resources", []))
def _protocol_novelty(c):
    value = f"{c.event.network_protocol}:{c.event.destination_port}"
    known = c.baseline.data.get("protocol_ports", [])
    return .25 if not known else float(value not in known)
def _command_transition_novelty(c):
    if not c.event.command_sequence: return 0.0
    known = set(c.baseline.data.get("command_transitions", [])); ordered = ["__start__", *c.event.command_sequence]
    transitions = [f"{left}->{right}" for left, right in zip(ordered, ordered[1:])]
    return .3 if not known else sum(item not in known for item in transitions) / len(transitions)
def _download(c): return zscore(c.event.bytes_downloaded, c.baseline.data.get("downloads", []))
def _upload(c): return zscore(c.event.bytes_uploaded, c.baseline.data.get("uploads", []))
def _external_transfer_24h(c):
    floor = c.event.timestamp.timestamp() - 86400
    recent_values = [float(value) for epoch, value in c.baseline.data.get("external_transfer_events", []) if float(epoch) >= floor]
    if c.event.is_external_destination:
        recent_values.append(float(c.event.bytes_uploaded + c.event.bytes_downloaded))
    if not recent_values: return 0.0
    baseline = [float(value) for value in c.baseline.data.get("external_transfers", [])]
    if len(baseline) < 2: return float(np.clip(log(1 + sum(recent_values)) / log(1 + 10_000_000), 0, 1))
    expected = mean(baseline) * len(recent_values); spread = max(pstdev(baseline) * sqrt(len(recent_values)), 1000.0)
    return float(np.clip((sum(recent_values) - expected) / spread, -20, 20))
def _duration(c): return zscore(c.event.session_duration_seconds, c.baseline.data.get("session_durations", []))
def _inter_event(c):
    if c.baseline.baseline_type not in {"entity", "device"}: return 0.0
    previous = _last_entity_event(c)
    if not previous: return 0.0
    seconds = max(0.0, (c.event.timestamp - previous.timestamp).total_seconds())
    return zscore(seconds, c.baseline.data.get("inter_event_seconds", []))
def _active_sessions(c):
    active = {c.event.session_id}
    for event in c.history:
        if event.entity_id != c.event.entity_id or event.session_id == c.event.session_id: continue
        if event.timestamp <= c.event.timestamp < event.timestamp + timedelta(seconds=event.session_duration_seconds):
            active.add(event.session_id)
    return len(active)
def _sensitive_rate_30d(c):
    floor = c.event.timestamp.timestamp() - 30 * 86400
    values = [float(value) for epoch, value in c.baseline.data.get("sensitive_events", []) if float(epoch) >= floor]
    values.append(float(c.event.resource_sensitivity >= .7 or c.event.is_privileged_action))
    rate = mean(values); baseline = [float(value) for value in c.baseline.data.get("sensitive_flags", [])]
    if len(baseline) < 2: return .25 if values[-1] else 0.0
    return float(np.clip((rate - mean(baseline)) / max(pstdev(baseline), .1), -20, 20))


_FEATURES = [
    ("failed_auth_count_1m", "Failed authentications by entity or source IP in one minute", "1 minute", _failed_auth_1m),
    ("auth_attempt_count_5m", "Login, API, and device authentication attempts in five minutes", "5 minutes", _auth_attempts_5m),
    ("successful_auth_after_failures_score", "Successful authentication following recent failures", "5 minutes", _success_after_failures),
    ("source_ip_unique_entities_5m", "Distinct entities accessed by one source IP", "5 minutes", _source_entities),
    ("source_ip_failure_ratio_5m", "Authentication failure ratio for source IP", "5 minutes", _source_failure_ratio),
    ("auth_method_novelty_score", "Authentication method outside the trusted profile", "profile", _auth_novelty),
    ("api_call_rate_1m_zscore", "API call burst above the normal single-call window", "1 minute", _api_rate),
    ("api_error_ratio_5m", "Denied or failed API calls in five minutes", "5 minutes", _api_error_ratio),
    ("api_endpoint_method_novelty_score", "Novel API route and HTTP method combination", "profile", _api_endpoint_method_novelty),
    ("source_ip_novelty_score", "Source IP absent from the trusted footprint", "profile", _source_ip_novelty),
    ("new_device_score", "Unfamiliarity of the observed device", "profile", _new_device),
    ("device_fingerprint_distance", "Distance from trusted fingerprints", "profile", _fp_distance),
    ("claimed_observed_device_mismatch_score", "Observed device differs from its claimed identity", "current event", _device_mismatch),
    ("device_posture_novelty_score", "Novel OS, firmware, browser, or MAC posture", "profile", _device_posture_novelty),
    ("location_novelty_score", "Novelty of country and city", "profile", _location),
    ("vpn_aware_travel_anomaly_score", "Bounded impossible-travel evidence adjusted for VPN reliability", "previous success", _travel),
    ("access_hour_deviation_score", "Distance from normal entity activity hours", "profile", _access_hour_deviation),
    ("unique_destination_hosts_5m", "Destination breadth in five minutes", "5 minutes", _hosts),
    ("resource_novelty_score", "Resource absent from trusted footprint", "profile", _resource_novelty),
    ("event_action_novelty_score", "Novel event type and action combination", "profile", _event_action_novelty),
    ("resource_access_entropy_24h", "Resource-access diversity over twenty-four hours", "24 hours", _resource_entropy_24h),
    ("resource_sensitivity_deviation_score", "Positive sensitivity deviation from normal resource access", "profile", _sensitivity_deviation),
    ("privilege_expansion_score", "Privileged access beyond trusted footprint", "profile", _privilege_expansion),
    ("protocol_port_novelty_score", "Novel protocol and port combination", "profile", _protocol_novelty),
    ("command_transition_novelty_score", "Novel ordered command transitions", "profile", _command_transition_novelty),
    ("download_volume_zscore", "Download deviation from entity baseline", "profile", _download),
    ("upload_volume_zscore", "Upload deviation from entity baseline", "profile", _upload),
    ("cumulative_external_transfer_24h_zscore", "External transfer deviation accumulated over twenty-four hours", "24 hours", _external_transfer_24h),
    ("session_duration_zscore", "Session duration deviation from baseline", "profile", _duration),
    ("inter_event_time_zscore", "Inter-event timing deviation from the entity profile", "previous event", _inter_event),
    ("active_concurrent_session_count", "Sessions whose activity intervals overlap", "active sessions", _active_sessions),
    ("sensitive_access_rate_30d_zscore", "Thirty-day sensitive-access rate deviation", "30 days", _sensitive_rate_30d),
]
if not registry.definitions:
    for name, description, history, extractor in _FEATURES:
        registry.register(FeatureDefinition(name, description, "float", 0.0, history, extractor))


class FeaturePipeline:
    schema_version = FEATURE_SCHEMA_VERSION
    names = registry.names
    domain_feature_names = {
        "authentication_api": names[0:9],
        "identity_device_geo": names[9:17],
        "resource_network": names[17:25],
        "volume_timing": names[25:32],
    }
    sequence_feature_names = [
        "failed_auth_count_1m", "auth_attempt_count_5m", "successful_auth_after_failures_score",
        "source_ip_unique_entities_5m", "source_ip_failure_ratio_5m", "api_call_rate_1m_zscore",
        "api_error_ratio_5m", "vpn_aware_travel_anomaly_score", "unique_destination_hosts_5m",
        "event_action_novelty_score", "resource_access_entropy_24h", "command_transition_novelty_score",
        "cumulative_external_transfer_24h_zscore", "inter_event_time_zscore",
        "active_concurrent_session_count", "sensitive_access_rate_30d_zscore",
    ]
    sequence_feature_indices = [registry.names.index(name) for name in sequence_feature_names]

    def transform_one(self, event: AccessEvent, history: list[AccessEvent], baseline: Baseline) -> tuple[np.ndarray, dict]:
        values = registry.extract(FeatureContext(event, history, baseline))
        vector = np.asarray([values[name] for name in registry.names], dtype=float)
        metadata = {
            "values": values, "baseline_type": baseline.baseline_type, "historical_events": baseline.event_count,
            "baseline_confidence": baseline.confidence, "profile_version": baseline.profile_version,
            "last_updated": baseline.last_updated, "feature_schema_version": self.schema_version,
        }
        return vector, metadata
