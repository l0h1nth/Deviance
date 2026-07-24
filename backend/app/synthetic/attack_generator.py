from datetime import timedelta

import numpy as np

from app.schemas.events import AccessEvent
from app.synthetic.entities import OFFICES, SyntheticUser
from app.synthetic.normal_generator import RESOURCES, fingerprint


def _copy(base: AccessEvent, *, suffix: str, label: str, seconds: int, **changes) -> AccessEvent:
    data = base.model_dump()
    data.update(changes)
    data.update(event_id=f"evt-{label}-{suffix}", timestamp=base.timestamp + timedelta(seconds=seconds), ground_truth_label=label)
    return AccessEvent(**data)


def brute_force(user: SyntheticUser, base: AccessEvent, scenario: int) -> list[AccessEvent]:
    events = []
    for i in range(6):
        events.append(_copy(base, suffix=f"{scenario}-{i}", label="brute_force", seconds=i * 8,
                            event_type="login", authentication_result="failure" if i < 5 else "success",
                            source_ip=f"198.51.100.{scenario % 240 + 1}", session_duration_seconds=2,
                            device_id=f"unknown-bf-{scenario}", device_fingerprint=fingerprint(f"bf-{scenario}")))
    return events


def credential_misuse(user: SyntheticUser, base: AccessEvent, scenario: int) -> list[AccessEvent]:
    office = OFFICES[(OFFICES.index(user.office) + 3) % len(OFFICES)]
    return [
        _copy(base, suffix=f"{scenario}-0", label="credential_misuse", seconds=0, event_type="login", authentication_result="success",
              device_id=f"foreign-{scenario}", claimed_device_id=user.devices[0]["id"], operating_system="Kali Linux", browser="Firefox",
              device_fingerprint=fingerprint(f"stolen-{scenario}"), country=office.country, city=office.city, latitude=office.latitude,
              longitude=office.longitude, source_ip=f"203.0.113.{scenario % 240 + 1}"),
        _copy(base, suffix=f"{scenario}-1", label="credential_misuse", seconds=45, event_type="file_download",
              device_id=f"foreign-{scenario}", claimed_device_id=user.devices[0]["id"], device_fingerprint=fingerprint(f"stolen-{scenario}"),
              country=office.country, city=office.city, latitude=office.latitude, longitude=office.longitude,
              resource_id="payroll", resource_type="database", resource_sensitivity=.9, destination_host="payroll.internal",
              bytes_downloaded=25_000_000, session_duration_seconds=90),
    ]


def lateral_movement(user: SyntheticUser, base: AccessEvent, scenario: int) -> list[AccessEvent]:
    events = []
    for i in range(6):
        events.append(_copy(base, suffix=f"{scenario}-{i}", label="lateral_movement", seconds=i * 35,
                            event_type="admin_action" if i > 3 else "resource_access", authentication_result="not_applicable",
                            resource_id=f"server-{i}", resource_type="infrastructure", resource_sensitivity=.75 + i * .04,
                            destination_host=f"srv-{i}.security.internal", is_privileged_action=i > 3,
                            bytes_uploaded=200_000 + i * 60_000, device_fingerprint=fingerprint(f"compromised-{scenario}")))
    return events


def impossible_travel(user: SyntheticUser, base: AccessEvent, scenario: int) -> list[AccessEvent]:
    office = OFFICES[(OFFICES.index(user.office) + 4) % len(OFFICES)]
    return [
        _copy(base, suffix=f"{scenario}-0", label="impossible_travel", seconds=0, event_type="login", authentication_result="success"),
        _copy(base, suffix=f"{scenario}-1", label="impossible_travel", seconds=180, event_type="login", authentication_result="success",
              country=office.country, city=office.city, latitude=office.latitude, longitude=office.longitude,
              source_ip=f"192.0.2.{scenario % 240 + 1}", is_vpn=False, session_id=f"overlap-{scenario}"),
    ]


def device_spoofing(user: SyntheticUser, base: AccessEvent, scenario: int) -> list[AccessEvent]:
    return [
        _copy(base, suffix=f"{scenario}-0", label="device_spoofing", seconds=0, event_type="login", authentication_result="success",
              device_id=f"spoof-{scenario}", claimed_device_id=user.devices[0]["id"], operating_system="Android 15", browser="Mobile Safari",
              user_agent="Mobile Safari/18 (Android)", device_fingerprint=fingerprint(f"spoof-{scenario}")),
        _copy(base, suffix=f"{scenario}-1", label="device_spoofing", seconds=50, event_type="resource_access",
              device_id=f"spoof-{scenario}", claimed_device_id=user.devices[0]["id"], operating_system="Android 15", browser="Mobile Safari",
              device_fingerprint=fingerprint(f"spoof-{scenario}"), resource_id="prod-console", resource_type="infrastructure",
              resource_sensitivity=.95, destination_host="prod-console.internal", is_privileged_action=True),
    ]


GENERATORS = {
    "brute_force": brute_force, "credential_misuse": credential_misuse, "lateral_movement": lateral_movement,
    "impossible_travel": impossible_travel, "device_spoofing": device_spoofing,
}


def generate_attacks(users: list[SyntheticUser], normal: list[AccessEvent], scenarios_per_type: int,
                     rng: np.random.Generator) -> list[AccessEvent]:
    attacks = []
    # Attacks span earlier and later periods so every time-aware split contains
    # representative scenarios while later holdouts still reflect future behavior.
    late = normal[int(len(normal) * .15):]
    for label, generator in GENERATORS.items():
        for scenario in range(scenarios_per_type):
            user = users[int(rng.integers(0, len(users)))]
            candidates = [e for e in late if e.user_id == user.user_id]
            base = candidates[int(rng.integers(0, len(candidates)))]
            attacks.extend(generator(user, base, scenario))
    return sorted(attacks, key=lambda e: e.timestamp)
