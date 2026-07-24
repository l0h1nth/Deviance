#!/usr/bin/env python3
import argparse
import sys
import time
from pathlib import Path

import httpx

BACKEND = Path(__file__).resolve().parents[1]; sys.path.insert(0, str(BACKEND))
from app.config import get_settings
from app.synthetic.simulation import SCENARIOS, build_simulation_events


def simulate(scenario: str, interval: float, api_url: str, username: str = "admin", password: str = "admin") -> None:
    path = get_settings().data_dir / "processed" / "demo_stream.jsonl"
    if not path.exists(): raise SystemExit("Demo stream missing. Run generate_data.py first.")
    event_count = 45 if scenario == "concept_drift" else 30
    events = build_simulation_events(path, scenario, event_count, max(1, int(interval * 1000)))
    login = httpx.post(f"{api_url.rstrip('/')}/api/auth/login", json={"username": username, "password": password}, timeout=30)
    login.raise_for_status(); headers = {"Authorization": f"Bearer {login.json()['access_token']}"}
    for index, event in enumerate(events):
        payload = event.model_dump(mode="json", exclude={"ground_truth_label"})
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
