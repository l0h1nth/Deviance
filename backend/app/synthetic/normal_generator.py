from datetime import datetime, timedelta, timezone
from hashlib import sha256

import numpy as np

from app.schemas.events import AccessEvent
from app.synthetic.entities import OFFICES, SyntheticUser


DEPARTMENTS = ["Engineering", "Finance", "Sales", "HR", "Operations", "Security"]
ROLES = ["analyst", "engineer", "manager", "administrator", "support"]
RESOURCES = [
    ("wiki", "application", .2), ("crm", "application", .45), ("git", "repository", .5),
    ("payroll", "database", .85), ("prod-console", "infrastructure", .95), ("files", "storage", .4),
]


def fingerprint(seed: str) -> str: return sha256(seed.encode()).hexdigest()[:24]


def build_users(count: int, rng: np.random.Generator) -> list[SyntheticUser]:
    users = []
    for i in range(count):
        office = OFFICES[i % len(OFFICES)]
        role = ROLES[i % len(ROLES)]
        device_count = 1 + int(rng.random() < .3)
        devices = [
            {"id": f"dev-{i:03d}-{j}", "os": ["Windows 11", "macOS 15", "Ubuntu 24.04"][i % 3],
             "browser": ["Chrome", "Edge", "Firefox"][j % 3], "fingerprint": fingerprint(f"{i}:{j}")}
            for j in range(device_count)
        ]
        users.append(SyntheticUser(f"usr-{i:03d}", role, DEPARTMENTS[i % len(DEPARTMENTS)], office,
                                   bool(rng.random() < .25), 8 if i % 10 else 18, devices))
    return users


def normal_event(user: SyntheticUser, timestamp: datetime, index: int, rng: np.random.Generator) -> AccessEvent:
    device = user.devices[int(rng.integers(0, len(user.devices)))]
    resource = RESOURCES[int(rng.integers(0, 3 if user.role != "administrator" else len(RESOURCES)))]
    event_type = rng.choice(["login", "resource_access", "file_download"], p=[.28, .57, .15]).item()
    auth = "not_applicable"
    if event_type == "login": auth = "failure" if rng.random() < .025 else "success"
    download = int(max(0, rng.lognormal(10.4, .7))) if event_type == "file_download" else int(rng.integers(0, 5000))
    return AccessEvent(
        event_id=f"evt-normal-{index:07d}", timestamp=timestamp, user_id=user.user_id, user_role=user.role,
        department=user.department, device_id=device["id"], claimed_device_id=device["id"], operating_system=device["os"],
        browser=device["browser"], user_agent=f"{device['browser']}/125 ({device['os']})", device_fingerprint=device["fingerprint"],
        source_ip=f"10.{index % 250}.{(index // 3) % 250}.{(index * 7) % 250 + 1}", country=user.office.country,
        city=user.office.city, latitude=user.office.latitude + rng.normal(0, .02), longitude=user.office.longitude + rng.normal(0, .02),
        event_type=event_type, authentication_result=auth, resource_id=resource[0], resource_type=resource[1],
        resource_sensitivity=resource[2], destination_host=f"{resource[0]}.internal", bytes_uploaded=int(rng.integers(0, 20000)),
        bytes_downloaded=download, session_id=f"ses-{user.user_id}-{index // 3}",
        session_duration_seconds=int(max(10, rng.normal(1500, 500))), is_vpn=user.remote and rng.random() < .65,
        is_privileged_action=user.role == "administrator" and resource[2] > .8 and rng.random() < .25, ground_truth_label="normal",
    )


def generate_normal(users: list[SyntheticUser], events_per_user: int, rng: np.random.Generator,
                    start: datetime | None = None) -> list[AccessEvent]:
    start = start or datetime.now(timezone.utc) - timedelta(days=45)
    events: list[AccessEvent] = []
    index = 0
    for day in range(events_per_user):
        for user_index, user in enumerate(users):
            hour = (user.shift_hour + rng.normal(0, 1.3)) % 24
            stamp = start + timedelta(days=day, hours=float(hour), minutes=int(rng.integers(0, 60)))
            event = normal_event(user, stamp, index, rng)
            updates = {}
            # Realistic benign device changes prevent novelty from becoming a fixed attack rule.
            if day % 37 == 8 and user_index % 5 == 0:
                updates.update(event_type="login", authentication_result="success", browser=f"{event.browser} 126",
                               user_agent=f"{event.browser}/126 ({event.operating_system})")
            elif day % 37 == 13 and user_index % 7 == 0:
                updates.update(event_type="login", authentication_result="success",
                               operating_system=f"{event.operating_system} update", user_agent=f"{event.browser}/125 (updated OS)")
            elif day % 37 in {18, 19} and user_index % 9 == 0:
                replacement=f"replacement-{user_index}"
                updates.update(event_type="login", authentication_result="success", device_id=replacement,
                               claimed_device_id=replacement, device_fingerprint=fingerprint(replacement))
            elif day % 37 == 24 and user_index % 11 == 0:
                shared=f"shared-terminal-{user.department.lower()}"
                updates.update(event_type="login", authentication_result="success", device_id=shared,
                               claimed_device_id=shared, device_fingerprint=fingerprint(shared))
            elif day % 37 == 29 and user_index % 13 == 0:
                updates.update(event_type="login", authentication_result="success",
                               device_fingerprint=fingerprint(f"reset-{event.device_id}-{day}"))
            # Legitimate location transitions include proxy/VPN changes, nearby travel and day-separated flights.
            if day % 31 == 6 and user_index % 4 == 0:
                updates.update(source_ip=f"198.18.{user_index % 250}.{day + 1}", is_vpn=True)
            elif day % 31 == 11 and user_index % 6 == 0:
                updates.update(city=f"{user.office.city} Metro", latitude=user.office.latitude + .35,
                               longitude=user.office.longitude + .35)
            elif day % 31 == 17 and user_index % 10 == 0:
                destination=OFFICES[(OFFICES.index(user.office) + 1) % len(OFFICES)]
                updates.update(event_type="login", authentication_result="success", country=destination.country,
                               city=destination.city, latitude=destination.latitude, longitude=destination.longitude,
                               is_vpn=False, session_id=f"legitimate-flight-{user_index}-{day}")
            events.append(event.model_copy(update=updates)); index += 1
    return sorted(events, key=lambda e: e.timestamp)
