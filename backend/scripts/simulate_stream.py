#!/usr/bin/env python3
import argparse
import json
import sys
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx

BACKEND = Path(__file__).resolve().parents[1]; sys.path.insert(0, str(BACKEND))
from app.config import get_settings
from app.schemas.events import AccessEvent

SCENARIOS = ["mixed", "brute_force", "credential_misuse", "lateral_movement", "impossible_travel",
             "device_spoofing", "concept_drift", "cold_start"]


def load_stream(path: Path) -> list[AccessEvent]:
    with path.open() as handle: return [AccessEvent.model_validate_json(line) for line in handle if line.strip()]


def select_events(events: list[AccessEvent], scenario: str) -> list[AccessEvent]:
    if scenario == "mixed": return events
    if scenario in {"brute_force", "credential_misuse", "lateral_movement", "impossible_travel", "device_spoofing"}:
        matches = [e for e in events if e.ground_truth_label == scenario]
        return matches[:30]
    template = next(e for e in events if e.ground_truth_label == "normal")
    if scenario == "cold_start":
        return [template.model_copy(update={"user_id": "usr-cold-start", "device_id": "dev-new-user", "claimed_device_id": "dev-new-user",
                "device_fingerprint": "coldstart-safe-device-001", "ground_truth_label": None})]
    # Legitimate shift change: enough morning observations followed by evening observations for rolling drift.
    result = []
    for i in range(45):
        stamp = datetime.now(timezone.utc) - timedelta(days=45-i, hours=12 if i < 22 else 0)
        result.append(template.model_copy(update={"event_id": f"drift-{i}", "user_id": "usr-shift-demo", "timestamp": stamp,
                      "event_type": "login", "authentication_result": "success", "ground_truth_label": None}))
    return result


def simulate(scenario: str, interval: float, api_url: str, username: str = "admin", password: str = "admin") -> None:
    path = get_settings().data_dir / "processed" / "demo_stream.jsonl"
    if not path.exists(): raise SystemExit("Demo stream missing. Run generate_data.py first.")
    events = select_events(load_stream(path), scenario)
    login = httpx.post(f"{api_url.rstrip('/')}/api/auth/login", json={"username": username, "password": password}, timeout=30)
    login.raise_for_status(); headers = {"Authorization": f"Bearer {login.json()['access_token']}"}
    for index, event in enumerate(events):
        payload = event.model_dump(mode="json", exclude={"ground_truth_label"})
        payload["event_id"] = f"demo-{scenario}-{uuid.uuid4().hex[:12]}"
        try:
            response = httpx.post(f"{api_url.rstrip('/')}/api/events/ingest", json=payload, headers=headers, timeout=30)
            response.raise_for_status(); result = response.json()
            print(f"[{index+1:03d}/{len(events):03d}] {result['event_id']} risk={result['risk_score']:5.1f} "
                  f"class={result['predicted_attack']} alert={result.get('alert_id')}")
        except httpx.HTTPError as exc: print(f"stream failed: {exc}", file=sys.stderr); raise SystemExit(1) from exc
        if index + 1 < len(events): time.sleep(interval)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(); parser.add_argument("--scenario", choices=SCENARIOS, default="mixed")
    parser.add_argument("--interval", type=float, default=1); parser.add_argument("--api-url", default="http://127.0.0.1:8000")
    parser.add_argument("--username", default="admin"); parser.add_argument("--password", default="admin")
    args = parser.parse_args(); simulate(args.scenario, args.interval, args.api_url, args.username, args.password)
