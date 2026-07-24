from datetime import datetime, timedelta, timezone

from app.schemas.events import AccessEvent


def event(**changes) -> AccessEvent:
    data = dict(event_id="test-event", timestamp=datetime.now(timezone.utc)-timedelta(minutes=10), user_id="u1",
        user_role="engineer", department="Engineering", device_id="d1", claimed_device_id="d1", operating_system="Ubuntu",
        browser="Chrome", user_agent="Chrome/125", device_fingerprint="abcdef123456", source_ip="10.0.0.1",
        country="India", city="Bengaluru", latitude=12.9716, longitude=77.5946, event_type="login",
        authentication_result="success", resource_id="wiki", resource_type="app", resource_sensitivity=.2,
        destination_host="wiki.internal", bytes_uploaded=100, bytes_downloaded=1000, session_id="s1",
        session_duration_seconds=1200, is_vpn=False, is_privileged_action=False, ground_truth_label="normal")
    data.update(changes); return AccessEvent(**data)

