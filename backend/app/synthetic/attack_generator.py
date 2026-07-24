from datetime import datetime, timedelta, timezone

import numpy as np

from app.schemas.events import AccessEvent, LabeledEvent
from app.synthetic.entities import OFFICES, SyntheticEntity
from app.synthetic.normal_generator import RESOURCES, fingerprint


ATTACK_TYPES = [
    "brute_force", "credential_misuse", "credential_stuffing", "lateral_movement",
    "impossible_travel", "device_spoofing", "low_slow_exfiltration",
]


def _copy(base: AccessEvent, *, label: str, scenario: int, index: int, seconds: int, **changes) -> LabeledEvent:
    payload = base.model_dump(); payload.update(changes)
    sequence_id = f"seq-{label}-{scenario:05d}"
    payload.update(event_id=f"evt-{label}-{scenario:05d}-{index:02d}",
                   timestamp=base.timestamp + timedelta(seconds=seconds), session_id=sequence_id)
    event = AccessEvent(**payload)
    return LabeledEvent(event=event, label=label, scenario_id=f"scenario-{label}-{scenario:05d}", sequence_id=sequence_id)


def brute_force(entity: SyntheticEntity, base: AccessEvent, scenario: int,
                rng: np.random.Generator | None = None) -> list[LabeledEvent]:
    rng = rng or np.random.default_rng(scenario)
    failures = int(rng.integers(4, 13)); spacing = int(rng.integers(4, 26)); successful = bool(rng.random() < .55)
    source = f"198.51.{scenario % 250}.{int(rng.integers(1, 250))}"
    records = []
    for index in range(failures + int(successful)):
        records.append(_copy(base, label="brute_force", scenario=scenario, index=index, seconds=index * spacing,
            event_type="login", authentication_result="success" if successful and index == failures else "failure",
            auth_method="password", source_ip=source, session_duration_seconds=int(rng.integers(1, 8)),
            device_id=f"unknown-{scenario % 97}", claimed_device_id=base.device_id,
            device_fingerprint=fingerprint(f"bf:{scenario}:{index % 2}"), device_mac_hash=fingerprint(f"bfmac:{scenario}")))
    return records


def credential_misuse(entity: SyntheticEntity, base: AccessEvent, scenario: int,
                       rng: np.random.Generator | None = None) -> list[LabeledEvent]:
    rng = rng or np.random.default_rng(scenario)
    office = OFFICES[(OFFICES.index(entity.office) + int(rng.integers(2, len(OFFICES)))) % len(OFFICES)]
    device = f"foreign-{scenario}-{int(rng.integers(10, 999))}"
    fp = fingerprint(f"stolen:{scenario}:{rng.integers(9999)}")
    return [
        _copy(base, label="credential_misuse", scenario=scenario, index=0, seconds=0,
              event_type="login", authentication_result="success", auth_method="password", device_id=device,
              claimed_device_id=base.device_id, operating_system=rng.choice(["Linux", "Android", "Windows 11"]).item(),
              device_fingerprint=fp, device_mac_hash=fingerprint(f"foreignmac:{scenario}"), country=office.country,
              city=office.city, latitude=office.latitude, longitude=office.longitude,
              source_ip=f"203.0.113.{int(rng.integers(1, 250))}", is_vpn=False),
        _copy(base, label="credential_misuse", scenario=scenario, index=1, seconds=int(rng.integers(35, 150)),
              event_type="file_download", authentication_result="not_applicable", auth_method="not_applicable",
              device_id=device, claimed_device_id=base.device_id, device_fingerprint=fp,
              device_mac_hash=fingerprint(f"foreignmac:{scenario}"), country=office.country, city=office.city,
              latitude=office.latitude, longitude=office.longitude, resource_id="payroll", resource_type="database",
              resource_sensitivity=.9, destination_host="payroll.internal", network_protocol="database",
              destination_port=5432, bytes_downloaded=int(rng.integers(8_000_000, 35_000_000)),
              session_duration_seconds=int(rng.integers(45, 240))),
    ]


def credential_stuffing(entities: list[SyntheticEntity], bases: list[AccessEvent], scenario: int,
                        rng: np.random.Generator) -> list[LabeledEvent]:
    attempts = int(rng.integers(6, 15)); spacing = int(rng.integers(5, 20))
    sources = [f"192.0.2.{int(rng.integers(1, 250))}" for _ in range(int(rng.integers(1, 4)))]
    records = []
    for index in range(attempts):
        base = bases[index % len(bases)]
        source = sources[index % len(sources)]
        records.append(_copy(base, label="credential_stuffing", scenario=scenario, index=index, seconds=index * spacing,
            event_type="login", authentication_result="success" if index == attempts - 1 and rng.random() < .25 else "failure",
            auth_method="password", source_ip=source, session_duration_seconds=int(rng.integers(1, 7))))
    return records


def lateral_movement(entity: SyntheticEntity, base: AccessEvent, scenario: int,
                     rng: np.random.Generator | None = None) -> list[LabeledEvent]:
    rng = rng or np.random.default_rng(scenario); count = int(rng.integers(4, 9)); spacing = int(rng.integers(18, 70))
    records = []
    for index in range(count):
        protocol, port = rng.choice([("ssh", 22), ("rdp", 3389), ("smb", 445)]).tolist()
        records.append(_copy(base, label="lateral_movement", scenario=scenario, index=index, seconds=index * spacing,
            event_type="admin_action" if index >= count - 2 else "resource_access", authentication_result="not_applicable",
            auth_method="not_applicable", resource_id=f"server-{scenario % 31}-{index}", resource_type="infrastructure",
            resource_sensitivity=float(rng.uniform(.65, .98)), destination_host=f"srv-{scenario}-{index}.internal",
            network_protocol=str(protocol), destination_port=int(port), is_privileged_action=index >= count - 2,
            command_sequence=list(rng.choice(["whoami", "net_view", "list_shares", "remote_exec", "dump_config"],
                                             size=min(3, index + 1), replace=False)),
            bytes_uploaded=int(rng.integers(100_000, 900_000))))
    return records


def impossible_travel(entity: SyntheticEntity, base: AccessEvent, scenario: int,
                      rng: np.random.Generator | None = None) -> list[LabeledEvent]:
    rng = rng or np.random.default_rng(scenario)
    office = OFFICES[(OFFICES.index(entity.office) + int(rng.integers(2, len(OFFICES)))) % len(OFFICES)]
    gap = int(rng.integers(90, 1200))
    return [
        _copy(base, label="impossible_travel", scenario=scenario, index=0, seconds=0,
              event_type="login", authentication_result="success", auth_method=entity.auth_methods[0]),
        _copy(base, label="impossible_travel", scenario=scenario, index=1, seconds=gap,
              event_type="login", authentication_result="success", auth_method=entity.auth_methods[0],
              country=office.country, city=office.city, latitude=office.latitude, longitude=office.longitude,
              source_ip=f"203.0.113.{int(rng.integers(1, 250))}", is_vpn=False),
    ]


def device_spoofing(entity: SyntheticEntity, base: AccessEvent, scenario: int,
                    rng: np.random.Generator | None = None) -> list[LabeledEvent]:
    rng = rng or np.random.default_rng(scenario); count = int(rng.integers(2, 5)); claimed = base.device_id
    spoof_fp = fingerprint(f"spoof:{scenario}:{rng.integers(10000)}")
    records = []
    for index in range(count):
        records.append(_copy(base, label="device_spoofing", scenario=scenario, index=index, seconds=index * int(rng.integers(25, 80)),
            event_type="login" if index == 0 else "resource_access", authentication_result="success" if index == 0 else "not_applicable",
            auth_method=entity.auth_methods[0] if index == 0 else "not_applicable", device_id=claimed,
            claimed_device_id=claimed, operating_system=rng.choice(["Android", "Embedded Linux", "Windows 10"]).item(),
            firmware_version=f"{int(rng.integers(8, 20))}.0.0", browser=rng.choice(["Mobile Safari", "curl", "Chrome"]).item(),
            device_fingerprint=spoof_fp, device_mac_hash=fingerprint(f"spoofmac:{scenario}"),
            resource_sensitivity=float(.4 + .15 * index), is_privileged_action=index == count - 1))
    return records


def low_slow_exfiltration(entity: SyntheticEntity, base: AccessEvent, scenario: int,
                          rng: np.random.Generator | None = None) -> list[LabeledEvent]:
    rng = rng or np.random.default_rng(scenario); count = int(rng.integers(5, 11)); records = []
    available = max(3600, int((datetime.now(timezone.utc) - timedelta(minutes=5) - base.timestamp).total_seconds()))
    desired_interval = int(rng.integers(7, 22)) * 86400
    interval = max(3600, min(desired_interval, available // max(count, 1)))
    for index in range(count):
        seconds = min(available, index * interval + int(rng.integers(0, min(7200, interval))))
        records.append(_copy(base, label="low_slow_exfiltration", scenario=scenario, index=index, seconds=seconds,
            event_type="file_download", authentication_result="not_applicable", auth_method="not_applicable",
            resource_id=rng.choice(["files", "payroll", "git"]).item(), resource_type="storage",
            resource_sensitivity=float(rng.uniform(.55, .9)), destination_host=f"archive-{scenario % 17}.internal",
            network_protocol="https", destination_port=443, bytes_downloaded=int(rng.integers(150_000, 800_000)),
            session_duration_seconds=int(rng.integers(120, 700))))
    return records


GENERATORS = {
    "brute_force": brute_force, "credential_misuse": credential_misuse,
    "lateral_movement": lateral_movement, "impossible_travel": impossible_travel,
    "device_spoofing": device_spoofing, "low_slow_exfiltration": low_slow_exfiltration,
}


def generate_attacks(entities: list[SyntheticEntity], normal: list[LabeledEvent], scenarios_per_type: int | None,
                     rng: np.random.Generator, attack_rate: float = .025) -> list[LabeledEvent]:
    """Inject complete scenarios until attacks are approximately attack_rate of sessions."""
    normal_by_entity: dict[str, list[AccessEvent]] = {}
    for row in normal: normal_by_entity.setdefault(row.event.entity_id, []).append(row.event)
    target = max(len(ATTACK_TYPES) * 3, int(len(normal) * attack_rate))
    if scenarios_per_type is not None: target = max(target, scenarios_per_type * len(ATTACK_TYPES) * 3)
    attacks: list[LabeledEvent] = []; scenario = 0
    while len(attacks) < target or scenario < len(ATTACK_TYPES):
        label = ATTACK_TYPES[scenario % len(ATTACK_TYPES)]
        entity = entities[int(rng.integers(0, len(entities)))]
        candidates = normal_by_entity[entity.entity_id]
        base = candidates[int(rng.integers(max(1, len(candidates) // 5), max(2, int(len(candidates) * .65))))]
        if label == "credential_stuffing":
            selected = list(rng.choice(entities, size=min(8, len(entities)), replace=False))
            bases = [normal_by_entity[item.entity_id][int(rng.integers(0, len(normal_by_entity[item.entity_id])))] for item in selected]
            generated = credential_stuffing(selected, bases, scenario, rng)
        else:
            generated = GENERATORS[label](entity, base, scenario, rng)
        attacks.extend(generated); scenario += 1
    return sorted(attacks, key=lambda row: row.event.timestamp)
