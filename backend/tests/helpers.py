from datetime import datetime, timedelta, timezone

from app.schemas.events import AccessEvent


def event(**changes) -> AccessEvent:
    data = dict(event_id="test-event", timestamp=datetime.now(timezone.utc)-timedelta(minutes=10), entity_id="u1",
        entity_type="user", user_id="u1",
        user_role="engineer", department="Engineering", device_id="d1", claimed_device_id="d1", operating_system="Ubuntu",
        firmware_version="1.0.0", browser="Chrome", user_agent="Chrome/125", device_fingerprint="abcdef123456",
        device_mac_hash="abcdef654321", source_ip="10.0.0.1",
        country="India", city="Bengaluru", latitude=12.9716, longitude=77.5946, event_type="login",
        authentication_result="success", auth_method="password", resource_id="wiki", resource_type="app", resource_sensitivity=.2,
        destination_host="wiki.internal", network_protocol="https", destination_port=443, command_sequence=[],
        bytes_uploaded=100, bytes_downloaded=1000, session_id="s1", session_duration_seconds=1200,
        is_vpn=False, is_privileged_action=False)
    data.update(changes); return AccessEvent(**data)
