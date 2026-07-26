from datetime import datetime, timedelta, timezone

import numpy as np

from app.schemas.events import AccessEvent, LabeledEvent
from app.synthetic.entities import OFFICES, SyntheticEntity
from app.synthetic.normal_generator import RESOURCES, fingerprint


ATTACK_TYPES = [
    "brute_force", "credential_stuffing", "lateral_movement",
    "impossible_travel", "device_spoofing", "low_slow_exfiltration",
]


def _copy(base: AccessEvent, *, label: str, scenario: int, index: int, seconds: int, **changes) -> LabeledEvent:
    payload = base.model_dump(); payload.update(changes)
    event_type = payload["event_type"]
    if "action" not in changes:
        payload["action"] = {"login": "authenticate", "resource_access": "read", "file_download": "read",
                             "admin_action": "execute", "api_call": "invoke", "device_connection": "connect"}[event_type]
    if "access_outcome" not in changes:
        payload["access_outcome"] = "denied" if payload.get("authentication_result") == "failure" else "allowed"
    if event_type != "api_call":
        payload.update(api_route=None, http_method=None, http_status_code=None, api_latency_ms=None,
                       credential_id_hash=None, token_scopes=[])
    else:
        payload["api_route"] = payload.get("api_route") or "/api/v1/unknown"
        payload["http_method"] = payload.get("http_method") or "GET"
        payload["http_status_code"] = payload.get("http_status_code") or (
            401 if payload.get("authentication_result") == "failure" else 200)
        payload["api_latency_ms"] = payload.get("api_latency_ms") or 75.0
    if event_type != "device_connection":
        payload["device_connection_action"] = "not_applicable"
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
    api_channel = bool(rng.random() < .35)
    records = []
    for index in range(failures + int(successful)):
        success = successful and index == failures
        records.append(_copy(base, label="brute_force", scenario=scenario, index=index, seconds=index * spacing,
            event_type="api_call" if api_channel else "login", action="invoke" if api_channel else "authenticate",
            access_outcome="allowed" if success else "denied", authentication_result="success" if success else "failure",
            auth_method="token" if api_channel else "password", mfa_result="not_used", source_ip=source,
            source_network_zone="internet", api_route="/api/v1/auth/token" if api_channel else None,
            http_method="POST" if api_channel else None, http_status_code=200 if api_channel and success else 401 if api_channel else None,
            api_latency_ms=float(rng.integers(15, 90)) if api_channel else None,
            credential_id_hash=fingerprint(f"bf-credential:{scenario}") if api_channel else None,
            token_scopes=[] if api_channel else [], device_connection_action="not_applicable",
            session_duration_seconds=int(rng.integers(1, 8)),
            device_id=f"unknown-{scenario % 97}", claimed_device_id=base.device_id,
            device_fingerprint=fingerprint(f"bf:{scenario}:{index % 2}"), device_mac_hash=fingerprint(f"bfmac:{scenario}")))
    return records


def credential_stuffing(entities: list[SyntheticEntity], bases: list[AccessEvent], scenario: int,
                        rng: np.random.Generator) -> list[LabeledEvent]:
    attempts = int(rng.integers(6, 15)); spacing = int(rng.integers(5, 20))
    sources = [f"192.0.2.{int(rng.integers(1, 250))}" for _ in range(int(rng.integers(1, 4)))]
    records = []
    api_channel = bool(rng.random() < .4)
    for index in range(attempts):
        base = bases[index % len(bases)]
        source = sources[index % len(sources)]
        success = index == attempts - 1 and rng.random() < .25
        records.append(_copy(base, label="credential_stuffing", scenario=scenario, index=index, seconds=index * spacing,
            event_type="api_call" if api_channel else "login", action="invoke" if api_channel else "authenticate",
            access_outcome="allowed" if success else "denied", authentication_result="success" if success else "failure",
            auth_method="token" if api_channel else "password", mfa_result="not_used", source_ip=source,
            source_network_zone="internet", api_route="/api/v1/auth/token" if api_channel else None,
            http_method="POST" if api_channel else None, http_status_code=200 if api_channel and success else 401 if api_channel else None,
            api_latency_ms=float(rng.integers(10, 80)) if api_channel else None,
            credential_id_hash=fingerprint(f"stuff:{scenario}:{index}") if api_channel else None,
            token_scopes=[], device_connection_action="not_applicable", session_duration_seconds=int(rng.integers(1, 7))))
    return records


def lateral_movement(entity: SyntheticEntity, base: AccessEvent, scenario: int,
                     rng: np.random.Generator | None = None) -> list[LabeledEvent]:
    rng = rng or np.random.default_rng(scenario); count = int(rng.integers(4, 9)); spacing = int(rng.integers(18, 70))
    records = []
    for index in range(count):
        protocol, port = rng.choice([("ssh", 22), ("rdp", 3389), ("smb", 445)]).tolist()
        api_channel = entity.entity_type == "service_account" and index < count - 1
        records.append(_copy(base, label="lateral_movement", scenario=scenario, index=index, seconds=index * spacing,
            event_type="api_call" if api_channel else "admin_action" if index >= count - 2 else "resource_access",
            action="invoke" if api_channel else "execute" if index >= count - 2 else "read", access_outcome="allowed",
            authentication_result="success" if api_channel else "not_applicable", auth_method="token" if api_channel else "not_applicable",
            mfa_result="not_used" if api_channel else "not_applicable", api_route=f"/api/v1/admin/hosts/{index}" if api_channel else None,
            http_method="POST" if api_channel else None, http_status_code=200 if api_channel else None,
            api_latency_ms=float(rng.integers(30, 200)) if api_channel else None,
            credential_id_hash=entity.credential_id_hash if api_channel else None,
            token_scopes=["admin:execute"] if api_channel else [], device_connection_action="not_applicable",
            resource_id=f"server-{scenario % 31}-{index}", resource_type="infrastructure",
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
            action="authenticate" if index == 0 else "read", access_outcome="allowed",
            auth_method=entity.auth_methods[0] if index == 0 else "not_applicable",
            mfa_result="not_used" if index == 0 else "not_applicable", api_route=None, http_method=None,
            http_status_code=None, api_latency_ms=None, credential_id_hash=None, token_scopes=[],
            device_connection_action="not_applicable", device_id=claimed,
            claimed_device_id=claimed, operating_system=rng.choice(["Android", "Embedded Linux", "Windows 10"]).item(),
            firmware_version=f"{int(rng.integers(8, 20))}.0.0", browser=rng.choice(["Mobile Safari", "curl", "Chrome"]).item(),
            device_fingerprint=spoof_fp, device_mac_hash=fingerprint(f"spoofmac:{scenario}"),
            resource_sensitivity=float(.4 + .15 * index), is_privileged_action=index == count - 1))
    return records


def low_slow_exfiltration(entity: SyntheticEntity, base: AccessEvent, scenario: int,
                          rng: np.random.Generator | None = None,
                          horizon_end: datetime | None = None) -> list[LabeledEvent]:
    rng = rng or np.random.default_rng(scenario); count = int(rng.integers(5, 11)); records = []
    end = horizon_end or datetime.now(timezone.utc) - timedelta(minutes=5)
    available = max(3600, int((end - base.timestamp).total_seconds()))
    desired_interval = int(rng.integers(7, 22)) * 86400
    interval = max(3600, min(desired_interval, available // max(count, 1)))
    for index in range(count):
        seconds = min(available, index * interval + int(rng.integers(0, min(7200, interval))))
        api_channel = entity.entity_type == "service_account" or index % 3 == 0
        records.append(_copy(base, label="low_slow_exfiltration", scenario=scenario, index=index, seconds=seconds,
            event_type="api_call" if api_channel else "file_download", action="invoke" if api_channel else "read",
            access_outcome="allowed", authentication_result="success" if api_channel else "not_applicable",
            auth_method="token" if api_channel else "not_applicable", mfa_result="not_used" if api_channel else "not_applicable",
            api_route="/api/v1/archive/export" if api_channel else None, http_method="GET" if api_channel else None,
            http_status_code=200 if api_channel else None, api_latency_ms=250.0 if api_channel else None,
            credential_id_hash=entity.credential_id_hash if api_channel else None,
            token_scopes=["archive:read"] if api_channel else [], device_connection_action="not_applicable",
            resource_id=rng.choice(["files", "payroll", "git"]).item(), resource_type="storage",
            resource_sensitivity=float(rng.uniform(.55, .9)), destination_host=f"archive-{scenario % 17}.internal",
            destination_network_zone="external", is_external_destination=True,
            network_protocol="https", destination_port=443, bytes_downloaded=int(rng.integers(150_000, 800_000)),
            session_duration_seconds=int(rng.integers(120, 700))))
    return records


GENERATORS = {
    "brute_force": brute_force,
    "lateral_movement": lateral_movement, "impossible_travel": impossible_travel,
    "device_spoofing": device_spoofing, "low_slow_exfiltration": low_slow_exfiltration,
}


def generate_attacks(entities: list[SyntheticEntity], normal: list[LabeledEvent], scenarios_per_type: int | None,
                     rng: np.random.Generator, attack_rate: float = .01) -> list[LabeledEvent]:
    """Inject complete scenarios at a controlled fraction of normal sessions."""
    normal_by_entity: dict[str, list[AccessEvent]] = {}
    for row in normal: normal_by_entity.setdefault(row.event.entity_id, []).append(row.event)
    normal_sessions = len({row.event.session_id for row in normal})
    target_scenarios = max(len(ATTACK_TYPES), int(round(normal_sessions * attack_rate)))
    if scenarios_per_type is not None: target_scenarios = max(target_scenarios, scenarios_per_type * len(ATTACK_TYPES))
    attacks: list[LabeledEvent] = []; scenario = 0
    while scenario < target_scenarios:
        label = ATTACK_TYPES[scenario % len(ATTACK_TYPES)]
        entity = entities[int(rng.integers(0, len(entities)))]
        candidates = normal_by_entity[entity.entity_id]
        base = candidates[int(rng.integers(max(1, len(candidates) // 5), max(2, int(len(candidates) * .65))))]
        if label == "credential_stuffing":
            selected = list(rng.choice(entities, size=min(8, len(entities)), replace=False))
            bases = [normal_by_entity[item.entity_id][int(rng.integers(
                0, max(1, int(len(normal_by_entity[item.entity_id]) * .65))))] for item in selected]
            generated = credential_stuffing(selected, bases, scenario, rng)
        elif label == "low_slow_exfiltration":
            generated = low_slow_exfiltration(entity, base, scenario, rng, max(row.event.timestamp for row in normal))
        else:
            generated = GENERATORS[label](entity, base, scenario, rng)
        attacks.extend(generated); scenario += 1
    return sorted(attacks, key=lambda row: row.event.timestamp)
