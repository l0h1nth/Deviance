from datetime import datetime, timedelta, timezone
from itertools import cycle, islice
from pathlib import Path
from uuid import uuid4

from app.schemas.events import AccessEvent


SCENARIOS = [
    "mixed", "brute_force", "credential_misuse", "lateral_movement",
    "impossible_travel", "device_spoofing", "cold_start", "concept_drift",
]


def load_demo_stream(path: Path) -> list[AccessEvent]:
    with path.open() as handle:
        return [AccessEvent.model_validate_json(line) for line in handle if line.strip()]


def _live_copy(event: AccessEvent, scenario: str, index: int, timestamp: datetime) -> AccessEvent:
    payload = event.model_dump(exclude={"ground_truth_label"})
    payload.update(event_id=f"sim-{scenario}-{uuid4().hex[:16]}", timestamp=timestamp)
    return AccessEvent.model_validate(payload)


def build_simulation_events(path: Path, scenario: str, event_count: int, interval_ms: int) -> list[AccessEvent]:
    source = load_demo_stream(path)
    if not source:
        raise FileNotFoundError("Demo stream is empty. Run generate_data.py first.")
    normal = [event for event in source if event.ground_truth_label == "normal"]
    template = normal[0] if normal else source[0]
    now = datetime.now(timezone.utc).replace(microsecond=0)

    if scenario == "cold_start":
        selected = [template.model_copy(update={
            "user_id": "usr-cold-start", "user_role": "analyst", "department": "Security",
            "device_id": "dev-cold-start", "claimed_device_id": "dev-cold-start",
            "device_fingerprint": "coldstart-safe-device-001", "ground_truth_label": None,
        })]
    elif scenario == "concept_drift":
        # A legitimate identity gradually moves from a day shift to an evening shift.
        selected = []
        for index in range(max(event_count, 40)):
            shifted = index >= max(event_count, 40) // 2
            day = now - timedelta(days=max(event_count, 40) - index)
            stamp = day.replace(hour=19 if shifted else 9, minute=(index * 7) % 60)
            selected.append(template.model_copy(update={
                "user_id": "usr-shift-demo", "user_role": "analyst", "department": "Security",
                "event_type": "login", "authentication_result": "success", "timestamp": stamp,
                "device_id": "dev-shift-demo", "claimed_device_id": "dev-shift-demo",
                "device_fingerprint": "trusted-shift-demo-device", "is_vpn": False,
                "ground_truth_label": None,
            }))
    elif scenario == "mixed":
        selected = source
    else:
        selected = [event for event in source if event.ground_truth_label == scenario]
        if not selected:
            raise ValueError(f"No generated events are available for scenario {scenario}")

    requested = list(islice(cycle(selected), event_count))
    if scenario == "concept_drift":
        requested = selected[:event_count]
        return [_live_copy(event, scenario, index, event.timestamp) for index, event in enumerate(requested)]
    start = now - timedelta(milliseconds=max(event_count - 1, 0) * interval_ms)
    return [_live_copy(event, scenario, index, start + timedelta(milliseconds=index * interval_ms))
            for index, event in enumerate(requested)]
