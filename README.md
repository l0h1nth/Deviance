# Deviance

Deviance is an AI-powered behavioral anomaly detection system for users, service accounts, and edge devices. It learns normal access behavior, evaluates event sequences in near real time, classifies findings into the required attack taxonomy, explains every risk score, groups related events into incidents, and presents a ranked SOC analyst queue.

It implements the full hackathon brief: synthetic behavioral data, extreme class imbalance, sequential detection, brute force, credential stuffing, lateral movement, impossible travel, device spoofing, low-and-slow exfiltration, cold start, concept/insider drift, explainability, scalability evidence, and an analyst dashboard.

## Architecture at a glance

- Production telemetry has no label. Ground truth exists only in offline `*_labels.jsonl` sidecars.
- The scaler, one global Isolation Forest, four signal-domain Isolation Forests, bundled cold-start profile priors, and both GRU sequence detectors learn only normal events.
- Random Forest and XGBoost candidates learn normal plus the six required labeled attack types. A dedicated validation partition selects the stronger candidate, and separate validation data calibrates its probabilities.
- Thirty-two behavioral features cover API/authentication windows, 30-day history, identity/device novelty, IP fan-out, travel, actions, ordered commands, entropy, privilege expansion, protocols, and cumulative transfers. The real-time anomaly path remains on this proven 32-value contract.
- The event GRU uses a sliding 12-event window over the 32 engineered values. A separate `EntityBehaviorGRU` receives those 32 plus four Isolation Forest domain scores and six calibrated classifier probabilities, aggregates its 42 inputs by entity/day, uses a sliding 30-day window, and ranks identities by maximum drift, persistent drift days, top-three drift, and recency.
- Risk combines 30% domain/global anomaly evidence, 5% GRU sequence novelty, 25% classifier evidence, 35% profile deviation, and 5% resource criticality.
- Behavioral anomalies are assigned to the closest required attack class while retaining honest classifier confidence; no extra classifier class is introduced.
- A recall-oriented finding threshold is constrained by validation false positives; a second frozen threshold reserves the highest-risk one percent for priority triage.
- Related alerts are grouped into 15-minute entity/attack incidents and ranked by maximum risk.
- Trusted analyst outcomes update profiles; attack-like events do not poison normal baselines.
- Runtime sequence history, profiles, and concept-drift windows are durable database state. Every response exposes an `entity_id` partition key and stable local partition number; no entity behavior depends on which API worker receives the event.

See [ARCHITECTURE.md](ARCHITECTURE.md), [MODEL_EVALUATION.md](MODEL_EVALUATION.md), and [SUBMISSION_REPORT.md](SUBMISSION_REPORT.md).

## Complete project pipeline

```text
OFFLINE
Synthetic entity habits + injected scenarios
                 │
       unlabeled events + label sidecars
                 │
     entity-disjoint chronological split
                 │
 normal-only scaler / IF / GRUs  +  labeled RF/XGBoost comparison
                 │
        calibrated, versioned model bundle

LIVE
Login / API / device telemetry
                 │
      authenticated HTTP + schema validation + event-id idempotency
                 │
     entity_id partition key ── preserves per-identity order
                 │
 durable profile + sequence history ── entity/device/peer/global cold-start fallback
                 │
              32 features
       ┌─────────┼───────────┐
       ▼         ▼           ▼
  Domain IF   Event GRU   Random Forest
       └─────────┼───────────┘
                 ▼
 weighted risk + attack class + explanation
                 │
   one transaction: event + features + prediction + correlated alert
                 │
       authenticated SSE → React SOC dashboard
                 │
       analyst disposition → trusted profile update

LONG-TERM
Trusted events → durable 20/20 concept-drift windows → analyst-approved adaptation
32 features + 4 IF scores + 6 RF probabilities → daily 42-vector
→ 30-day EntityBehaviorGRU → ranked identity-risk list
```

## Repository layout

```text
Deviance/
├── backend/app/
│   ├── api/          # authenticated FastAPI routes
│   ├── database/     # event, prediction, incident, feedback, drift tables
│   ├── ml/           # 32-input event GRU, 42-input daily GRU, domain IFs, classifier selection
│   ├── services/     # inference, durable state, partitioning, profiles, risk, SSE, drift
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

Simulation playback time is deliberately separate from security-event time. Choosing 500 ms makes results appear every half second, but brute-force, travel, drift, and exfiltration timestamps retain their original behavioral gaps for feature extraction. A focused 30-event low-and-slow replay uses one five-to-ten-event exfiltration sequence plus benign warm-up and interleaved context across the original multi-day window. Ground-truth labels remain in the simulator sidecar and never cross the production inference boundary; they are used only to report detected attacks, misses, correct attack types, misclassifications, false positives, and newly grouped incidents in the simulation modal.

## Test live counters and drift monitoring

1. Restart the backend and frontend, sign in, and confirm the fresh dashboard begins at zero events and detections.
2. Run `brute_force` with 8 or more events at 500 ms. **Detections by attack class** counts detected events, so Brute Force should advance once per alert-worthy event even when they correlate into one incident.
3. Run `concept_drift` with exactly 40 events at 500 ms. The first 20 trusted events establish the reference access-hour window; the next 20 shift from approximately 09:00 to 19:00.
4. Open **Drift monitor**. During the run it shows persistent reference/current window progress; at completion it should freeze `access hour` for review with effect-size and KS evidence.
5. Mark the finding **Investigating**, then either **Approve baseline** after verifying the legitimate shift or **Reject change** to retain the prior trusted reference. Neither path retrains the model automatically.
6. Restart the backend and return to **Drift monitor** to verify that window progress and dispositions survive process restarts.
7. Use `insider_drift` separately as the legitimate edge-case/false-positive demonstration. It is not an attack classifier output and is not the deterministic concept-drift trigger.

Run the deterministic Phase 2 benchmark with:

```bash
.venv/bin/python backend/scripts/evaluate_drift.py --stable-entities 100 --drift-entities 100
```

The benchmark reports entity-level drift precision/recall, stable-entity false-positive rate, detection delay, and the enforced adaptation safety contract. See [Phase 2 concept drift](docs/PHASE2_CONCEPT_DRIFT.md) for the complete lifecycle.

The experimental daily behavioral-risk path and its held-out comparison are documented in [Behavioral drift experiment](docs/BEHAVIORAL_DRIFT_EXPERIMENT.md).

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
python backend/scripts/benchmark_system.py --events 60 --concurrency 1,4,8
```

The Phase 3 benchmark starts a real Uvicorn server against a fresh temporary SQLite-WAL database. It measures authenticated TCP HTTP, validation, feature extraction, IF/GRU/RF inference, transaction persistence, response serialization, concurrent entity-partition queues, and expected failure handling.

| Concurrent queues | HTTP P50 | P95 | P99 | Throughput | Successful |
|---:|---:|---:|---:|---:|---:|
| 1 | 194 ms | 229 ms | 242 ms | 5.10 events/s | 60/60 |
| 4 | 913 ms | 1,153 ms | 1,232 ms | 4.30 events/s | 60/60 |
| 8 | 1,484 ms | 2,705 ms | 4,511 ms | 4.26 events/s | 60/60 |

All runs had zero HTTP 500 errors. Duplicate, invalid-schema, and unauthenticated probes were correctly rejected with 409, 422, and 401. Thread concurrency does not improve this intentionally small SQLite/single-process deployment; production throughput comes from entity-keyed stream partitions processed by independent workers. See [Scalability report](SCALABILITY_REPORT.md).

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

The seed-42 test split contains 11,036 events from 60 unseen entities with 2.14% attack events from scenarios injected at roughly 1% of sessions. Classifier accuracy is 99.68%, but the more informative Macro F1 is 92.80% because an always-normal prediction already achieves 97.86% accuracy. With the 32-feature event GRU restored, the operational layer reaches 94.04% precision and 86.86% recall at a 0.12% normal-event false-positive rate. Normal-only behavioral evidence reaches 80.67% PR-AUC and 73.73% recall. The retained daily behavior path reaches 76.50% PR-AUC and 79.03% recall at a 0.97% normal-day FPR.

The rejected enriched event GRU reaches only 43.96% PR-AUC versus 73.98% for the selected 32-feature event path, even though ROC-AUC rises from 97.43% to 98.24%. The result is retained as comparison evidence, but the 42-input candidate is not used during real-time inference.

Validation selected Random Forest over XGBoost. All scores remain generator-dependent rather than production guarantees. See [MODEL_EVALUATION.md](MODEL_EVALUATION.md) for definitions, confusion matrices, class support, candidate selection, and limitations.

## Production boundaries

This is a hackathon reference implementation, not a finished SIEM. SQLite, in-process SSE, synthetic data, and a single demo administrator are not production controls. The scale-out contract replaces direct HTTP fan-out with Kafka/Redpanda keyed by `entity_id`, hot sequence/profile windows with Redis Cluster, durable transactions with partitioned PostgreSQL, analytics with ClickHouse/object storage, and process-local notifications with durable pub/sub. Signed model storage, horizontally scaled consumers, SSO/RBAC, TLS, rate limits, immutable audit storage, retention policy, tracing, backpressure and dead-letter replay remain production responsibilities.
