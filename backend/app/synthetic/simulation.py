from datetime import datetime, timedelta, timezone
from collections import defaultdict
from pathlib import Path
from uuid import uuid4

from app.ml.training import load_split
from app.schemas.events import AccessEvent, LabeledEvent


SCENARIOS = [
    "mixed", "brute_force", "credential_stuffing", "lateral_movement",
    "impossible_travel", "device_spoofing", "low_slow_exfiltration", "cold_start",
    "cold_start_benign", "cold_start_attack",
    "concept_drift", "insider_drift",
]


def load_demo_stream(path: Path) -> list[LabeledEvent]:
    return load_split(path, path.with_name(f"{path.stem}_labels.jsonl"))


def _replay_copy(row: LabeledEvent, scenario: str, timestamp: datetime) -> LabeledEvent:
    payload = row.event.model_dump()
    payload.update(event_id=f"sim-{scenario}-{uuid4().hex[:16]}", timestamp=timestamp)
    return row.model_copy(update={"event": AccessEvent.model_validate(payload)})


def _normal_copy(row: LabeledEvent, event: AccessEvent, scenario_id: str, sequence_id: str) -> LabeledEvent:
    return row.model_copy(update={"event": event, "label": "normal",
                                  "scenario_id": scenario_id, "sequence_id": sequence_id})


def _benign_context_event(template: LabeledEvent, anchor: AccessEvent,
                          timestamp: datetime, index: int) -> AccessEvent:
    """Create a stable, low-risk habit for the attacked identity around sparse transfers."""
    login = index % 4 == 0
    auth_method = "token" if anchor.entity_type == "service_account" else "password"
    return template.event.model_copy(update={
        "timestamp": timestamp, "entity_id": anchor.entity_id, "entity_type": anchor.entity_type,
        "user_id": anchor.entity_id, "user_role": anchor.user_role, "department": anchor.department,
        "device_id": anchor.device_id, "claimed_device_id": anchor.claimed_device_id,
        "operating_system": anchor.operating_system, "firmware_version": anchor.firmware_version,
        "browser": anchor.browser, "user_agent": anchor.user_agent,
        "device_fingerprint": anchor.device_fingerprint, "device_mac_hash": anchor.device_mac_hash,
        "source_ip": anchor.source_ip, "country": anchor.country, "city": anchor.city,
        "latitude": anchor.latitude, "longitude": anchor.longitude,
        "event_type": "login" if login else "resource_access",
        "action": "authenticate" if login else "read", "access_outcome": "allowed",
        "authentication_result": "success" if login else "not_applicable",
        "auth_method": auth_method if login else "not_applicable",
        "mfa_result": "success" if login and anchor.entity_type == "user" else "not_used" if login else "not_applicable",
        "api_route": None, "http_method": None, "http_status_code": None, "api_latency_ms": None,
        "credential_id_hash": anchor.credential_id_hash if login else None, "token_scopes": [],
        "resource_id": "wiki", "resource_type": "application", "resource_sensitivity": .2,
        "destination_host": "wiki.internal", "source_network_zone": "corporate",
        "destination_network_zone": "internal", "is_external_destination": False,
        "network_protocol": "https", "destination_port": 443, "command_sequence": [],
        "bytes_uploaded": 2_000 + index * 31, "bytes_downloaded": 8_000 + index * 73,
        "session_id": f"low-slow-benign-{index}", "session_duration_seconds": 240 + index * 3,
        "parent_auth_event_id": None, "device_connection_action": "not_applicable",
        "device_class": anchor.device_class, "is_vpn": False, "is_privileged_action": False,
    })


def _low_slow_timeline(source: list[LabeledEvent], event_count: int) -> list[LabeledEvent]:
    """Build one sparse exfiltration sequence with benign events between transfers."""
    groups: dict[str, list[LabeledEvent]] = defaultdict(list)
    for row in source:
        if row.label == "low_slow_exfiltration":
            groups[row.sequence_id].append(row)
    if not groups:
        raise ValueError("No generated events are available for scenario low_slow_exfiltration")

    sequence = min(groups.values(), key=lambda rows: min(row.event.timestamp for row in rows))
    attacks = sorted(sequence, key=lambda row: row.event.timestamp)[:event_count]
    if len(attacks) >= event_count:
        return attacks

    normal_count = event_count - len(attacks)
    normal = [row for row in source if row.label == "normal"]
    if not normal:
        raise ValueError("Low-slow replay requires benign context events")

    template, anchor = normal[0], attacks[0].event
    first, last = attacks[0].event.timestamp, attacks[-1].event.timestamp
    if last <= first:
        last = first + timedelta(days=max(len(attacks) - 1, 1) * 7)
    contextual = []
    warmup_count = min(12, normal_count)
    interleaved_count = normal_count - warmup_count
    warmup_start = first - timedelta(days=max(warmup_count, 1))
    for index in range(warmup_count):
        fraction = (index + 1) / (warmup_count + 1)
        stamp = warmup_start + (first - warmup_start) * fraction
        event = _benign_context_event(template, anchor, stamp, index)
        contextual.append(_normal_copy(template, event, f"simulation-warmup-{attacks[0].scenario_id}",
                                       f"simulation-warmup-{attacks[0].sequence_id}"))
    for index in range(interleaved_count):
        fraction = (index + 1) / (interleaved_count + 1)
        stamp = first + (last - first) * fraction
        event = _benign_context_event(template, anchor, stamp, warmup_count + index)
        contextual.append(_normal_copy(template, event, f"simulation-context-{attacks[0].scenario_id}",
                                       f"simulation-context-{attacks[0].sequence_id}"))
    namespace = f"ls-{uuid4().hex[:8]}"
    device_ids: dict[str, str] = {}
    namespaced = []
    for row in sorted([*attacks, *contextual], key=lambda item: item.event.timestamp):
        device_ids.setdefault(row.event.device_id, f"{namespace}-{row.event.device_id}")
        device_ids.setdefault(row.event.claimed_device_id, f"{namespace}-{row.event.claimed_device_id}")
        event = row.event.model_copy(update={
            "entity_id": f"{namespace}-{row.event.entity_id}",
            "user_id": f"{namespace}-{row.event.entity_id}",
            "device_id": device_ids[row.event.device_id],
            "claimed_device_id": device_ids[row.event.claimed_device_id],
            "session_id": f"{namespace}-{row.event.session_id}"[:100],
        })
        namespaced.append(row.model_copy(update={"event": event}))
    return namespaced


def _schedule_replay(rows: list[LabeledEvent], scenario: str, event_count: int,
                     now: datetime) -> list[LabeledEvent]:
    """Shift an event-time timeline to now without changing its internal gaps."""
    ordered = sorted(rows, key=lambda row: row.event.timestamp)
    if not ordered:
        raise ValueError(f"No generated events are available for scenario {scenario}")
    origin = ordered[0].event.timestamp
    span = max((ordered[-1].event.timestamp - origin).total_seconds(), 0.0)
    gaps = [(right.event.timestamp - left.event.timestamp).total_seconds()
            for left, right in zip(ordered, ordered[1:])
            if right.event.timestamp > left.event.timestamp]
    cycle_gap = sorted(gaps)[len(gaps) // 2] if gaps else 60.0
    cycle_width = max(span + cycle_gap, 60.0)
    selected: list[tuple[LabeledEvent, float]] = []
    for index in range(event_count):
        cycle_index, row_index = divmod(index, len(ordered))
        row = ordered[row_index]
        offset = (row.event.timestamp - origin).total_seconds() + cycle_index * cycle_width
        selected.append((row, offset))
    replay_start = now - timedelta(seconds=selected[-1][1])
    return [_replay_copy(row, scenario, replay_start + timedelta(seconds=offset))
            for row, offset in selected]


def build_simulation_run(path: Path, scenario: str, event_count: int,
                         interval_ms: int) -> list[LabeledEvent]:
    """Build labeled replay rows; labels remain simulator-only and never enter inference."""
    source = load_demo_stream(path)
    if not source: raise FileNotFoundError("Demo stream is empty. Run generate_data.py first.")
    normal = [row for row in source if row.label == "normal"]
    template_row = normal[0] if normal else source[0]
    template = template_row.event
    now = datetime.now(timezone.utc).replace(microsecond=0)

    if scenario in {"cold_start", "cold_start_benign"}:
        event = template.model_copy(update={
            "entity_id": "usr-cold-start", "entity_type": "user", "user_id": "usr-cold-start",
            "user_role": "analyst", "department": "Security", "device_id": "dev-cold-start",
            "claimed_device_id": "dev-cold-start", "device_fingerprint": "coldstart-safe-device-001",
            "device_mac_hash": "coldstart-safe-mac-001",
        })
        selected = [_normal_copy(template_row, event, "simulation-cold-start-benign", "simulation-cold-start-benign")]
    elif scenario == "cold_start_attack":
        # Preserve each attack's relationships (including credential-stuffing fan-out
        # and claimed/observed device mismatch) while moving every subject into a new
        # namespace that cannot already have a runtime profile.
        attack_rows = [row for row in source if row.label != "normal"]
        selected = [row.model_copy(update={"event": row.event.model_copy(update={
            "entity_id": f"cold-{row.event.entity_id}", "user_id": f"cold-{row.event.entity_id}",
            "device_id": f"cold-{row.event.device_id}",
            "claimed_device_id": f"cold-{row.event.claimed_device_id}",
            "device_fingerprint": f"cold-{row.event.device_fingerprint}",
            "device_mac_hash": f"cold-{row.event.device_mac_hash}",
        })}) for row in attack_rows]
        if not selected:
            raise ValueError("No attack events are available for cold-start attack simulation")
    elif scenario == "concept_drift":
        selected = []
        for index in range(max(event_count, 40)):
            shifted = index >= max(event_count, 40) // 2
            day = now - timedelta(days=max(event_count, 40) - index)
            stamp = day.replace(hour=19 if shifted else 9, minute=(index * 7) % 60)
            event = template.model_copy(update={
                "entity_id": "usr-shift-demo", "entity_type": "user", "user_id": "usr-shift-demo",
                "user_role": "analyst", "department": "Security", "event_type": "login",
                "authentication_result": "success", "auth_method": "password", "timestamp": stamp,
                "device_id": "dev-shift-demo", "claimed_device_id": "dev-shift-demo",
                "device_fingerprint": "trusted-shift-demo-device", "device_mac_hash": "trusted-shift-demo-mac",
                "is_vpn": False,
            })
            selected.append(_normal_copy(template_row, event, "simulation-concept-drift", "simulation-concept-drift"))
    elif scenario == "insider_drift":
        selected = []
        resources = [("wiki", .2), ("git", .5), ("files", .6), ("payroll", .85), ("prod-console", .95)]
        for index in range(max(event_count, 40)):
            resource, sensitivity = resources[min(len(resources) - 1, index * len(resources) // max(event_count, 40))]
            day = now - timedelta(days=max(event_count, 40) - index)
            event = template.model_copy(update={
                "entity_id": "usr-insider-drift", "entity_type": "user", "user_id": "usr-insider-drift",
                "event_type": "admin_action" if index > max(event_count, 40) * .75 else "resource_access",
                "authentication_result": "not_applicable", "auth_method": "not_applicable",
                "resource_id": resource, "resource_sensitivity": sensitivity,
                "destination_host": f"{resource}.internal", "is_privileged_action": index > max(event_count, 40) * .75,
                "command_sequence": ["list_resources", "read_config"] if index > max(event_count, 40) * .6 else [],
                "timestamp": day.replace(hour=9 + min(index // 10, 8), minute=(index * 11) % 60),
            })
            selected.append(_normal_copy(template_row, event, "simulation-insider-drift", "simulation-insider-drift"))
    elif scenario == "mixed": selected = source
    elif scenario == "low_slow_exfiltration": selected = _low_slow_timeline(source, event_count)
    else:
        selected = [row for row in source if row.label == scenario]
        if not selected: raise ValueError(f"No generated events are available for scenario {scenario}")

    # interval_ms controls wall-clock playback in SimulationManager. It must never
    # rewrite security-event time, which is model input for temporal features.
    _ = interval_ms
    return _schedule_replay(selected, scenario, event_count, now)


def build_simulation_events(path: Path, scenario: str, event_count: int,
                            interval_ms: int) -> list[AccessEvent]:
    """Compatibility helper for the CLI and existing callers."""
    return [row.event for row in build_simulation_run(path, scenario, event_count, interval_ms)]
