from datetime import datetime, timedelta, timezone
from hashlib import sha256

import numpy as np

from app.schemas.events import AccessEvent, LabeledEvent
from app.synthetic.entities import OFFICES, SyntheticEntity


DEPARTMENTS = ["Engineering", "Finance", "Sales", "HR", "Operations", "Security"]
ROLES = ["analyst", "engineer", "manager", "administrator", "support"]
RESOURCES = [
    ("wiki", "application", .2, "https", 443), ("crm", "application", .45, "https", 443),
    ("git", "repository", .5, "ssh", 22), ("payroll", "database", .85, "database", 5432),
    ("prod-console", "infrastructure", .95, "ssh", 22), ("files", "storage", .4, "smb", 445),
    ("iot-hub", "device_function", .65, "mqtt", 8883), ("edge-control", "device_function", .9, "opcua", 4840),
]


def fingerprint(seed: str) -> str:
    return sha256(seed.encode()).hexdigest()[:24]


def build_users(count: int, rng: np.random.Generator) -> list[SyntheticEntity]:
    entities = []
    for i in range(count):
        kind_roll = rng.random()
        entity_type = "user" if kind_roll < .76 else "service_account" if kind_roll < .91 else "edge_device"
        office = OFFICES[i % len(OFFICES)]
        if entity_type == "user":
            role, department = ROLES[i % len(ROLES)], DEPARTMENTS[i % len(DEPARTMENTS)]
            auth_methods = ["password", "biometric"] if i % 4 == 0 else ["password"]
            prefix = "usr"
        elif entity_type == "service_account":
            role, department, auth_methods, prefix = "service", ["Engineering", "Operations", "Security"][i % 3], ["token", "certificate"], "svc"
        else:
            role, department, auth_methods, prefix = "edge", "Operations", ["certificate"], "edge"
        device_count = 1 + int(entity_type == "user" and rng.random() < .35)
        devices = []
        for j in range(device_count):
            os_name = (["Windows 11", "macOS 15", "Ubuntu 24.04"][i % 3] if entity_type != "edge_device" else "EdgeOS")
            devices.append({
                "id": f"dev-{i:04d}-{j}", "os": os_name,
                "firmware": f"{1 + i % 4}.{j}.{3 + i % 7}",
                "browser": (["Chrome", "Edge", "Firefox"][j % 3] if entity_type == "user" else "headless"),
                "fingerprint": fingerprint(f"fp:{i}:{j}"), "mac_hash": fingerprint(f"mac:{i}:{j}"),
                "class": "edge_gateway" if entity_type == "edge_device" else "server" if entity_type == "service_account" else "workstation",
            })
        source_ips = [f"10.{20 + i % 180}.{10 + i % 200}.{20 + (i * 7) % 220}"]
        if entity_type == "user" and rng.random() < .35:
            source_ips.append(f"10.{20 + i % 180}.{30 + i % 180}.{30 + (i * 11) % 210}")
        api_routes = ([f"/api/v1/devices/{i:04d}/status", f"/api/v1/telemetry/{i:04d}"]
                      if entity_type == "edge_device" else
                      ["/api/v1/builds/status", "/api/v1/repositories", "/api/v1/metrics"]
                      if entity_type == "service_account" else
                      ["/api/v1/profile", "/api/v1/search"])
        entities.append(SyntheticEntity(
            f"{prefix}-{i:04d}", entity_type, role, department, office,
            bool(entity_type == "user" and rng.random() < .3), 8 if i % 12 else 18, devices, auth_methods,
            source_ips, api_routes, fingerprint(f"credential:{i}"),
            ["device:read", "telemetry:write"] if entity_type == "edge_device" else
            ["repository:read", "build:read"] if entity_type == "service_account" else ["profile:read"],
        ))
    return entities


def normal_event(entity: SyntheticEntity, timestamp: datetime, index: int, rng: np.random.Generator) -> AccessEvent:
    device = entity.devices[int(rng.integers(0, len(entity.devices)))]
    if entity.entity_type == "edge_device":
        allowed = [6, 7, 1]; event_type = rng.choice(["device_connection", "api_call", "resource_access"], p=[.45, .35, .2]).item()
    elif entity.entity_type == "service_account":
        allowed = [1, 2, 4, 6]; event_type = rng.choice(["api_call", "resource_access", "admin_action"], p=[.55, .38, .07]).item()
    else:
        allowed = list(range(6)); event_type = rng.choice(["login", "resource_access", "file_download", "admin_action"], p=[.28, .54, .15, .03]).item()
    resource = RESOURCES[allowed[int(rng.integers(0, len(allowed)))]]
    auth = "not_applicable"
    if event_type in {"login", "api_call", "device_connection"}:
        auth = "failure" if rng.random() < .025 else "success"
    method = entity.auth_methods[int(rng.integers(0, len(entity.auth_methods)))] if auth != "not_applicable" else "not_applicable"
    download = int(max(0, rng.lognormal(10.5, .75))) if event_type == "file_download" else int(rng.integers(0, 6000))
    commands = []
    if event_type == "admin_action": commands = list(rng.choice(["whoami", "list_services", "read_config", "restart_service"], size=2, replace=False))
    elif event_type == "api_call": commands = [rng.choice(["GET_STATUS", "LIST_ITEMS", "READ_METRIC"]).item()]
    privileged = entity.role == "administrator" and resource[2] > .8 and rng.random() < .25
    api_route = rng.choice(entity.api_routes).item() if event_type == "api_call" else None
    http_method = rng.choice(["GET", "POST"], p=[.82, .18]).item() if event_type == "api_call" else None
    http_status = (401 if auth == "failure" else int(rng.choice([200, 200, 200, 202]))) if event_type == "api_call" else None
    action = {"login": "authenticate", "resource_access": "read", "file_download": "read",
              "admin_action": "execute", "api_call": "invoke", "device_connection": "connect"}[event_type]
    allowed = auth != "failure"
    external = bool(event_type == "file_download" and rng.random() < .025)
    source_zone = "vpn" if entity.remote and rng.random() < .65 else "ot" if entity.entity_type == "edge_device" else "corporate"
    destination_zone = "external" if external else "ot" if resource[1] == "device_function" else "restricted" if resource[2] >= .8 else "internal"
    return AccessEvent(
        event_id=f"evt-normal-{index:08d}", timestamp=timestamp, entity_id=entity.entity_id,
        entity_type=entity.entity_type, user_id=entity.entity_id, user_role=entity.role, department=entity.department,
        device_id=device["id"], claimed_device_id=device["id"], operating_system=device["os"],
        firmware_version=device["firmware"], browser=device["browser"],
        user_agent=f"{device['browser']}/125 ({device['os']})", device_fingerprint=device["fingerprint"],
        device_mac_hash=device["mac_hash"], source_ip=rng.choice(entity.source_ips).item(),
        country=entity.office.country, city=entity.office.city,
        latitude=entity.office.latitude + rng.normal(0, .02), longitude=entity.office.longitude + rng.normal(0, .02),
        event_type=event_type, action=action, access_outcome="allowed" if allowed else "denied",
        authentication_result=auth, auth_method=method,
        mfa_result="success" if method == "biometric" and auth == "success" else "not_used" if auth != "not_applicable" else "not_applicable",
        api_route=api_route, http_method=http_method, http_status_code=http_status,
        api_latency_ms=float(max(2, rng.normal(85, 25))) if event_type == "api_call" else None,
        credential_id_hash=entity.credential_id_hash if event_type == "api_call" else None,
        token_scopes=entity.token_scopes if event_type == "api_call" else [],
        resource_id=resource[0], resource_type=resource[1], resource_sensitivity=resource[2],
        destination_host=f"{resource[0]}.external" if external else f"{resource[0]}.internal",
        source_network_zone=source_zone, destination_network_zone=destination_zone,
        is_external_destination=external, network_protocol=resource[3], destination_port=resource[4],
        command_sequence=commands, bytes_uploaded=int(rng.integers(0, 25000)), bytes_downloaded=download,
        session_id=f"ses-{entity.entity_id}-{index // 3}", session_duration_seconds=int(max(10, rng.normal(1400, 520))),
        device_connection_action="connect" if event_type == "device_connection" else "not_applicable",
        device_class=device["class"], is_vpn=source_zone == "vpn", is_privileged_action=privileged,
    )


def i_mod(value: int, divisor: int) -> int:
    return int(value % divisor)


def generate_normal(entities: list[SyntheticEntity], events_per_user: int, rng: np.random.Generator,
                    start: datetime | None = None) -> list[LabeledEvent]:
    """Generate habitual sequences plus benign look-alikes that prevent shortcut learning."""
    start = start or datetime.now(timezone.utc) - timedelta(days=max(90, events_per_user))
    records: list[LabeledEvent] = []
    index = 0
    for entity_index, entity in enumerate(entities):
        for position in range(events_per_user):
            day = int(position * max(90, events_per_user) / max(events_per_user, 1))
            hour = (entity.shift_hour + rng.normal(0, 1.4)) % 24
            stamp = start + timedelta(days=day, hours=float(hour), minutes=int(rng.integers(0, 60)), seconds=int(rng.integers(0, 60)))
            event = normal_event(entity, stamp, index, rng); updates = {}

            # Hard benign negatives: typos, approved exports, maintenance, device changes and legitimate travel.
            if position % 41 == 7 and entity.entity_type == "user":
                updates.update(event_type="login", action="authenticate", access_outcome="denied",
                               authentication_result="failure", auth_method="password", mfa_result="not_used",
                               api_route=None, http_method=None, http_status_code=None, api_latency_ms=None,
                               credential_id_hash=None, token_scopes=[], device_connection_action="not_applicable")
            elif position % 47 == 11 and entity.entity_type == "user":
                replacement = f"replacement-{entity_index}-{position}"
                updates.update(event_type="login", authentication_result="success", device_id=replacement,
                               claimed_device_id=replacement, device_fingerprint=fingerprint(replacement),
                               device_mac_hash=fingerprint(f"mac:{replacement}"), action="authenticate",
                               access_outcome="allowed", api_route=None, http_method=None, http_status_code=None,
                               api_latency_ms=None, credential_id_hash=None, token_scopes=[],
                               device_connection_action="not_applicable")
            elif position % 53 == 17 and entity.entity_type == "user":
                destination = OFFICES[(OFFICES.index(entity.office) + 1) % len(OFFICES)]
                updates.update(event_type="login", authentication_result="success", country=destination.country,
                               city=destination.city, latitude=destination.latitude, longitude=destination.longitude,
                               is_vpn=False, source_network_zone="corporate", action="authenticate",
                               access_outcome="allowed", api_route=None, http_method=None, http_status_code=None,
                               api_latency_ms=None, credential_id_hash=None, token_scopes=[],
                               device_connection_action="not_applicable", session_id=f"approved-travel-{entity_index}-{position}")
            elif position % 59 == 23:
                updates.update(event_type="file_download", resource_id="files", resource_type="storage",
                               resource_sensitivity=.4, destination_host="files.internal", network_protocol="smb",
                               destination_port=445, action="read", access_outcome="allowed",
                               authentication_result="not_applicable", auth_method="not_applicable", mfa_result="not_applicable",
                               api_route=None, http_method=None, http_status_code=None, api_latency_ms=None,
                               credential_id_hash=None, token_scopes=[], device_connection_action="not_applicable",
                               bytes_downloaded=int(rng.integers(800_000, 3_000_000)))
            elif position % 61 in {29, 30} and entity.entity_type != "user":
                updates.update(event_type="admin_action", authentication_result="not_applicable", auth_method="not_applicable",
                               action="execute", access_outcome="allowed", mfa_result="not_applicable",
                               api_route=None, http_method=None, http_status_code=None, api_latency_ms=None,
                               credential_id_hash=None, token_scopes=[], device_connection_action="not_applicable",
                               is_privileged_action=True, command_sequence=["maintenance_check", "restart_service"])

            event = event.model_copy(update=updates)
            records.append(LabeledEvent(event=event, label="normal", scenario_id=f"normal-{entity.entity_id}",
                                        sequence_id=event.session_id))
            index += 1
    return sorted(records, key=lambda row: row.event.timestamp)
