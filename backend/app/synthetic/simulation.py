from datetime import datetime, timedelta, timezone
from itertools import cycle, islice
from pathlib import Path
from uuid import uuid4

from app.ml.training import load_split
from app.schemas.events import AccessEvent, LabeledEvent


SCENARIOS = [
    "mixed", "brute_force", "credential_stuffing", "lateral_movement",
    "impossible_travel", "device_spoofing", "low_slow_exfiltration", "cold_start",
    "concept_drift", "insider_drift",
]


def load_demo_stream(path: Path) -> list[LabeledEvent]:
    return load_split(path, path.with_name(f"{path.stem}_labels.jsonl"))


def _live_copy(event: AccessEvent, scenario: str, timestamp: datetime) -> AccessEvent:
    payload = event.model_dump(); payload.update(event_id=f"sim-{scenario}-{uuid4().hex[:16]}", timestamp=timestamp)
    return AccessEvent.model_validate(payload)


def build_simulation_events(path: Path, scenario: str, event_count: int, interval_ms: int) -> list[AccessEvent]:
    source = load_demo_stream(path)
    if not source: raise FileNotFoundError("Demo stream is empty. Run generate_data.py first.")
    normal = [row.event for row in source if row.label == "normal"]
    template = normal[0] if normal else source[0].event
    now = datetime.now(timezone.utc).replace(microsecond=0)

    if scenario == "cold_start":
        selected = [template.model_copy(update={
            "entity_id": "usr-cold-start", "entity_type": "user", "user_id": "usr-cold-start",
            "user_role": "analyst", "department": "Security", "device_id": "dev-cold-start",
            "claimed_device_id": "dev-cold-start", "device_fingerprint": "coldstart-safe-device-001",
            "device_mac_hash": "coldstart-safe-mac-001",
        })]
    elif scenario == "concept_drift":
        selected = []
        for index in range(max(event_count, 40)):
            shifted = index >= max(event_count, 40) // 2
            day = now - timedelta(days=max(event_count, 40) - index)
            stamp = day.replace(hour=19 if shifted else 9, minute=(index * 7) % 60)
            selected.append(template.model_copy(update={
                "entity_id": "usr-shift-demo", "entity_type": "user", "user_id": "usr-shift-demo",
                "user_role": "analyst", "department": "Security", "event_type": "login",
                "authentication_result": "success", "auth_method": "password", "timestamp": stamp,
                "device_id": "dev-shift-demo", "claimed_device_id": "dev-shift-demo",
                "device_fingerprint": "trusted-shift-demo-device", "device_mac_hash": "trusted-shift-demo-mac",
                "is_vpn": False,
            }))
    elif scenario == "insider_drift":
        selected = []
        resources = [("wiki", .2), ("git", .5), ("files", .6), ("payroll", .85), ("prod-console", .95)]
        for index in range(max(event_count, 40)):
            resource, sensitivity = resources[min(len(resources) - 1, index * len(resources) // max(event_count, 40))]
            selected.append(template.model_copy(update={
                "entity_id": "usr-insider-drift", "entity_type": "user", "user_id": "usr-insider-drift",
                "event_type": "admin_action" if index > max(event_count, 40) * .75 else "resource_access",
                "authentication_result": "not_applicable", "auth_method": "not_applicable",
                "resource_id": resource, "resource_sensitivity": sensitivity,
                "destination_host": f"{resource}.internal", "is_privileged_action": index > max(event_count, 40) * .75,
                "command_sequence": ["list_resources", "read_config"] if index > max(event_count, 40) * .6 else [],
            }))
    elif scenario == "mixed": selected = [row.event for row in source]
    else:
        selected = [row.event for row in source if row.label == scenario]
        if not selected: raise ValueError(f"No generated events are available for scenario {scenario}")

    requested = list(islice(cycle(selected), event_count))
    if scenario == "concept_drift": return [_live_copy(event, scenario, event.timestamp) for event in selected[:event_count]]
    start = now - timedelta(milliseconds=max(event_count - 1, 0) * interval_ms)
    return [_live_copy(event, scenario, start + timedelta(milliseconds=index * interval_ms)) for index, event in enumerate(requested)]
