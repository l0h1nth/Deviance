# Deviance

Deviance is an AI-powered behavioral anomaly detection system for users, service accounts, and edge devices. It learns normal access behavior, evaluates event sequences in near real time, classifies known attack patterns, abstains on unfamiliar anomalies, explains every risk score, groups related events into incidents, and presents a ranked SOC analyst queue.

It implements the full hackathon brief: synthetic behavioral data, extreme class imbalance, sequential detection, brute force, credential misuse, credential stuffing, lateral movement, impossible travel, device spoofing, low-and-slow exfiltration, cold start, concept/insider drift, explainability, scalability evidence, and an analyst dashboard.

## Architecture at a glance

- Production telemetry has no label. Ground truth exists only in offline `*_labels.jsonl` sidecars.
- The scaler, Isolation Forest, bundled cold-start profile priors, and GRU sequence detector learn only normal events.
- A class-balanced Random Forest learns normal plus seven labeled attack types; validation-only sigmoid calibration adjusts its probabilities.
- Twenty-four behavioral features cover short windows, 30-day history, identity/device novelty, IP fan-out, travel, commands, privilege expansion, protocols, upload/download behavior, and off-hours activity.
- Risk combines 35% Isolation Forest, 25% GRU sequence novelty, 25% classifier evidence, 10% profile deviation, and 5% resource criticality.
- High anomaly with weak known-class evidence produces `unknown_anomaly` instead of a forced attack label.
- Related alerts are grouped into 15-minute entity/attack incidents and ranked by maximum risk.
- Trusted analyst outcomes update profiles; attack-like events do not poison normal baselines.

See [ARCHITECTURE.md](ARCHITECTURE.md), [MODEL_EVALUATION.md](MODEL_EVALUATION.md), and [SUBMISSION_REPORT.md](SUBMISSION_REPORT.md).

## Repository layout

```text
Deviance/
├── backend/app/
│   ├── api/          # authenticated FastAPI routes
│   ├── database/     # event, prediction, incident, feedback, drift tables
│   ├── ml/           # 24 features, IF, GRU, RF, calibration, evaluation
│   ├── services/     # inference, profiles, risk, explanations, SSE, drift
│   └── synthetic/    # entities, normal behavior, injected scenarios
├── backend/scripts/  # generate, train, evaluate, benchmark, simulate
├── backend/tests/
├── frontend/src/     # React analyst workspace
├── data/             # generated corpus, artifacts, and local SQLite DB
├── docs/PRESENTATION.md
└── Deviance_Learning_Guide/ (sibling folder)
```

## Install and build from a clean clone

Run these commands from the `Deviance` project root, not from `frontend`:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r backend/requirements.txt

python backend/scripts/generate_data.py
python backend/scripts/train_models.py --contamination 0.025
```

The default corpus contains 240 entities and roughly 29,500 events. Train/validation/test are entity-disjoint, chronological, and approximately 2.5% attacks.

## Run the application

Terminal 1, from the project root:

```bash
source .venv/bin/activate
uvicorn app.main:app --reload --app-dir backend
```

Terminal 2:

```bash
cd frontend
npm install
npm run dev
```

Open `http://localhost:5173`.

The demo login is deliberately shown on the login page for judging:

```text
Username: admin
Password: admin
```

Change `ADMIN_USERNAME`, `ADMIN_PASSWORD`, and `AUTH_SECRET` before any non-demo deployment.

## Best judging demonstration

1. Sign in and open **Run simulation**.
2. Select `mixed` to show multiple attack classes, or select a focused scenario.
3. Watch validated events arrive in **Live activity** through authenticated SSE.
4. Select an event in **Model insights** to compare Isolation Forest, GRU, classifier probabilities, the 24 features, and the final weighted risk.
5. Open **Detections**, which is risk-ranked and incident-grouped.
6. Open an incident to inspect the correlated timeline, raw telemetry, entity/device/network evidence, and recommended response.
7. Mark it investigating, confirmed threat, false positive, or closed; the disposition is persisted in its audit history.
8. Run `concept_drift`, `insider_drift`, or `cold_start` to demonstrate the non-attack edge cases required by the brief.

Available scenarios are `mixed`, `brute_force`, `credential_misuse`, `credential_stuffing`, `lateral_movement`, `impossible_travel`, `device_spoofing`, `low_slow_exfiltration`, `cold_start`, `concept_drift`, and `insider_drift`.

## Example production-shaped event

`timestamp` must contain a timezone and may not be over five minutes in the future. There is intentionally no label.

```json
{
  "event_id": "live-001",
  "timestamp": "2026-07-25T08:00:00Z",
  "entity_id": "usr-0042",
  "entity_type": "user",
  "user_id": "usr-0042",
  "user_role": "engineer",
  "department": "Engineering",
  "device_id": "dev-0042-0",
  "claimed_device_id": "dev-0042-0",
  "operating_system": "Ubuntu 24.04",
  "firmware_version": "2.0.4",
  "browser": "Chrome",
  "user_agent": "Chrome/125 (Ubuntu 24.04)",
  "device_fingerprint": "41cc80eece5b29ab128d8370",
  "device_mac_hash": "15f6e9c72d31d40a822fea90",
  "source_ip": "10.2.3.4",
  "country": "India",
  "city": "Bengaluru",
  "latitude": 12.9716,
  "longitude": 77.5946,
  "event_type": "login",
  "authentication_result": "success",
  "auth_method": "password",
  "resource_id": "git",
  "resource_type": "repository",
  "resource_sensitivity": 0.5,
  "destination_host": "git.internal",
  "network_protocol": "https",
  "destination_port": 443,
  "command_sequence": [],
  "bytes_uploaded": 1200,
  "bytes_downloaded": 2400,
  "session_id": "session-live-001",
  "session_duration_seconds": 900,
  "is_vpn": false,
  "is_privileged_action": false
}
```

Authenticate and ingest with:

```bash
TOKEN=$(curl -s -X POST http://127.0.0.1:8000/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"admin"}' | \
  python -c 'import json,sys; print(json.load(sys.stdin)["access_token"])')

curl -X POST http://127.0.0.1:8000/api/events/ingest \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $TOKEN" \
  --data @event.json
```

## Generate, train, evaluate, benchmark

```bash
source .venv/bin/activate
python backend/scripts/generate_data.py --seed 42 --users 240 --events-per-user 120 --attack-rate 0.025
python backend/scripts/train_models.py --contamination 0.025
python backend/scripts/evaluate_models.py
python backend/scripts/benchmark_inference.py --events 1000 --warmup 100
```

The active artifact validates feature schema `2.0.0` and exact feature order before inference. Never load an untrusted joblib file.

## Verify

```bash
source .venv/bin/activate
pytest backend/tests -q

cd frontend
npm test
npm run build
```

## Current honest evaluation

The fresh seed-42 test split contains 4,432 events from 36 unseen entities with 2.53% attacks. Current holdout results are 81.4% macro F1, 57.3% Isolation Forest PR-AUC, 6.9% sequence PR-AUC, and 64.4% precision within the top 1% risk budget. The operational validation threshold alerts on 1.17% of test events, detects 31.3% of test attacks, and falsely alerts on 0.39% of normal test events.

Impossible travel is intentionally the weakest rare class (60.0% F1 on six events), showing that the synthetic experiment is not presented as production-grade certainty. See [MODEL_EVALUATION.md](MODEL_EVALUATION.md) for every class, assumptions, and limitations.

## Production boundaries

This is a hackathon reference implementation, not a finished SIEM. SQLite, in-process SSE, synthetic data, and a single demo administrator are not production controls. A production build should use Kafka or another durable stream, Redis-backed rolling state, PostgreSQL, signed model storage, horizontally scaled inference, SSO/RBAC, TLS, rate limits, immutable audit storage, telemetry retention policy, and monitoring for feature/schema/model drift.
