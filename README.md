# Deviance

Deviance is an AI-powered behavioral anomaly detection system for users, service accounts, and edge devices. It learns normal access behavior, evaluates event sequences in near real time, classifies findings into the required attack taxonomy, explains every risk score, groups related events into incidents, and presents a ranked SOC analyst queue.

It implements the full hackathon brief: synthetic behavioral data, extreme class imbalance, sequential detection, brute force, credential stuffing, lateral movement, impossible travel, device spoofing, low-and-slow exfiltration, cold start, concept/insider drift, explainability, scalability evidence, and an analyst dashboard.

## Architecture at a glance

- Production telemetry has no label. Ground truth exists only in offline `*_labels.jsonl` sidecars.
- The scaler, one global Isolation Forest, four signal-domain Isolation Forests, bundled cold-start profile priors, and GRU sequence detector learn only normal events.
- Random Forest and XGBoost candidates learn normal plus the six required labeled attack types. A dedicated validation partition selects the stronger candidate, and separate validation data calibrates its probabilities.
- Thirty-two behavioral features cover API/authentication windows, 30-day history, identity/device novelty, IP fan-out, travel, actions, ordered commands, entropy, privilege expansion, protocols, and cumulative transfers.
- Risk combines 30% domain/global anomaly evidence, 5% GRU sequence novelty, 25% classifier evidence, 35% profile deviation, and 5% resource criticality.
- Behavioral anomalies are assigned to the closest required attack class while retaining honest classifier confidence; no extra classifier class is introduced.
- A recall-oriented finding threshold is constrained by validation false positives; a second frozen threshold reserves the highest-risk one percent for priority triage.
- Related alerts are grouped into 15-minute entity/attack incidents and ranked by maximum risk.
- Trusted analyst outcomes update profiles; attack-like events do not poison normal baselines.

See [ARCHITECTURE.md](ARCHITECTURE.md), [MODEL_EVALUATION.md](MODEL_EVALUATION.md), and [SUBMISSION_REPORT.md](SUBMISSION_REPORT.md).

## Repository layout

```text
Deviance/
├── backend/app/
│   ├── api/          # authenticated FastAPI routes
│   ├── database/     # event, prediction, incident, feedback, drift tables
│   ├── ml/           # 32 features, domain IFs, GRU, RF/XGBoost selection
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
python backend/scripts/train_models.py --contamination 0.03
```

The default seed-42 corpus contains 400 entities and 73,591 train/validation/test events: 72,000 normal events plus 1,591 attack events from scenarios injected at approximately 1% of normal sessions. The splits are entity-disjoint and chronological. `data/processed/manifest.json` records both scenario and event prevalence plus integrity checks.

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
4. Select an event in **Model insights** to compare Isolation Forest, GRU, classifier probabilities, the 32 features, and the final weighted risk.
5. Open **Detections**, which is risk-ranked and incident-grouped.
6. Open an incident to inspect the correlated timeline, raw telemetry, entity/device/network evidence, and recommended response.
7. Mark it investigating, confirmed threat, false positive, or closed; the disposition is persisted in its audit history.
8. Run `concept_drift`, `insider_drift`, or `cold_start` to demonstrate the non-attack edge cases required by the brief.

Available scenarios are `mixed`, `brute_force`, `credential_stuffing`, `lateral_movement`, `impossible_travel`, `device_spoofing`, `low_slow_exfiltration`, `cold_start_benign`, `cold_start_attack`, `concept_drift`, and `insider_drift`. The API retains `cold_start` as a backward-compatible alias for the benign scenario.

## Test live counters and drift monitoring

1. Restart the backend and frontend, sign in, and confirm the fresh dashboard begins at zero events and detections.
2. Run `brute_force` with 8 or more events at 500 ms. **Detections by attack class** counts detected events, so Brute Force should advance once per alert-worthy event even when they correlate into one incident.
3. Run `concept_drift` with exactly 40 events at 500 ms. The first 20 trusted events establish the reference access-hour window; the next 20 shift from approximately 09:00 to 19:00.
4. Open **Drift monitor**. During the run it shows reference/current window progress; at completion it should show an `access hour` drift record with the previous and current distributions.
5. Use `insider_drift` separately as the legitimate edge-case/false-positive demonstration. It is not an attack classifier output and is not the deterministic concept-drift trigger.

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
  "action": "authenticate",
  "access_outcome": "allowed",
  "authentication_result": "success",
  "auth_method": "password",
  "mfa_result": "not_used",
  "resource_id": "git",
  "resource_type": "repository",
  "resource_sensitivity": 0.5,
  "destination_host": "git.internal",
  "source_network_zone": "corporate",
  "destination_network_zone": "internal",
  "is_external_destination": false,
  "network_protocol": "https",
  "destination_port": 443,
  "command_sequence": [],
  "bytes_uploaded": 1200,
  "bytes_downloaded": 2400,
  "session_id": "session-live-001",
  "session_duration_seconds": 900,
  "device_connection_action": "not_applicable",
  "device_class": "workstation",
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
python backend/scripts/generate_data.py --seed 42 --users 400 --events-per-user 180 --attack-rate 0.01
python backend/scripts/train_models.py --contamination 0.03
python backend/scripts/evaluate_models.py
python backend/scripts/benchmark_inference.py --events 1000 --warmup 100
```

The active artifact validates feature schema `3.0.0` and exact feature order before inference. Never load an untrusted joblib file.

## Verify

```bash
source .venv/bin/activate
pytest backend/tests -q

cd frontend
npm test
npm run build
```

## Current honest evaluation

The seed-42 test split contains 11,036 events from 60 unseen entities with 2.14% attack events from scenarios injected at roughly 1% of sessions. Classifier accuracy is 99.72%, but the more informative Macro F1 is 93.46% because an always-normal prediction already achieves 97.86% accuracy. The operational layer reaches 93.98% precision and 86.02% recall at a 0.12% normal-event false-positive rate. Normal-only behavioral evidence reaches 80.67% PR-AUC and 73.73% recall. Insider-drift FPR is 0%, and all 38 attack scenarios have at least one surfaced event.

Validation selected Random Forest over XGBoost. All scores remain generator-dependent rather than production guarantees. See [MODEL_EVALUATION.md](MODEL_EVALUATION.md) for definitions, confusion matrices, class support, candidate selection, and limitations.

## Production boundaries

This is a hackathon reference implementation, not a finished SIEM. SQLite, in-process SSE, synthetic data, and a single demo administrator are not production controls. A production build should use Kafka or another durable stream, Redis-backed rolling state, PostgreSQL, signed model storage, horizontally scaled inference, SSO/RBAC, TLS, rate limits, immutable audit storage, telemetry retention policy, and monitoring for feature/schema/model drift.
