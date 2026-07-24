# Deviance

Deviance is an ML-first behavioral threat detection system built for a solo hackathon. It learns normal identity and device access patterns, scores live telemetry with an Isolation Forest, classifies likely attacks with a class-balanced Random Forest, explains feature-level evidence, and streams alerts to a React analyst workspace.

It detects five synthetic multi-event scenarios: brute force, credential misuse, lateral movement, impossible travel, and device spoofing. Unlike signature-based tools, it uses no IP blocklist, hash, CVE, domain blacklist, or exploit-payload signature.

## What makes it different

- Exactly 12 versioned behavioral features shared by training and inference through one extensible registry.
- User → role/department peer → organization baseline hierarchy with confidence-aware cold start.
- Unsupervised anomaly evidence plus supervised multi-class classification; rules never select an attack class.
- Bounded, configurable, model-led 0–100 risk with concrete feature deviations and response actions.
- Chronological datasets, trusted-only profile updates, class weighting, threshold tuning, per-class metrics, and candidate model gates.
- SQLite persistence, live SSE, analyst disposition history, drift records, and production-ready seams for streams/PostgreSQL/model serving.

Read [ARCHITECTURE.md](ARCHITECTURE.md) for the detailed design, ER diagram, security model, and scale-out path. The standalone Mermaid flow is [architecture.mmd](architecture.mmd).

## Stack

Python 3.11+, FastAPI, Pydantic, SQLAlchemy, SQLite, NumPy, Pandas, scikit-learn, joblib, React, TypeScript, Vite, Recharts, Pytest, and Server-Sent Events.

## Repository layout

```text
Deviance/
├── backend/
│   ├── app/
│   │   ├── api/              # route modules
│   │   ├── database/         # SQLAlchemy models, sessions, repositories
│   │   ├── ml/               # registry, models, training, evaluation
│   │   ├── schemas/          # validated API contracts
│   │   ├── services/         # profiles, inference, risk, drift, SSE
│   │   ├── synthetic/        # entities and multi-event scenarios
│   │   ├── utils/            # geospatial/time helpers
│   │   ├── config.py
│   │   └── main.py
│   ├── scripts/              # generate, train, evaluate, simulate
│   ├── tests/
│   └── requirements.txt
├── frontend/
│   ├── src/                  # pages, components, hooks, API/types
│   └── package.json
├── data/
│   ├── raw/                  # generated and gitignored
│   ├── processed/            # chronological splits and demo stream
│   └── models/               # trained bundle and metrics
├── docs/
├── .env.example
├── ARCHITECTURE.md
├── architecture.mmd
└── README.md
```

## Install

Run from the `Deviance` directory:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r backend/requirements.txt
```

Python 3.11–3.14 are suitable with the currently constrained dependencies. Copy `.env.example` to `.env` only if defaults need changing. Generated data, model artifacts, the local database, virtual environment, dependencies, and secrets are gitignored.

## Generate data, train, and evaluate

```bash
source .venv/bin/activate
python backend/scripts/generate_data.py
python backend/scripts/train_models.py
python backend/scripts/evaluate_models.py
```

Default generation creates 120 users, 5,160 events, chronological train/validation/test files, and a 300-event mixed demonstration stream. Generation options include `--seed`, `--users`, `--events-per-user`, and `--scenarios-per-type`.

The active model is saved to `data/models/current.joblib`. Do not load joblib artifacts received from untrusted sources. The runtime restricts loading to the configured model directory and validates type, schema version, and feature order.

## Run the backend

```bash
source .venv/bin/activate
uvicorn app.main:app --reload --app-dir backend
```

The API is at `http://127.0.0.1:8000`, OpenAPI at `http://127.0.0.1:8000/docs`, and health at `http://127.0.0.1:8000/api/health`. Ingestion returns a clear 503 until models are trained.

## Run the frontend

In a second terminal:

```bash
cd frontend
npm install
npm run dev
```

Open `http://localhost:5173`. Vite proxies `/api` to the backend. For a separate deployment, set `VITE_API_URL` to the public API prefix before building.

## Run a live attack demonstration

Keep backend and frontend running, then use a third terminal from the project root:

```bash
source .venv/bin/activate
python backend/scripts/simulate_stream.py --scenario mixed --interval 1
```

Select a focused scenario with one of:

```bash
python backend/scripts/simulate_stream.py --scenario impossible_travel --interval 1
python backend/scripts/simulate_stream.py --scenario brute_force --interval 0.5
python backend/scripts/simulate_stream.py --scenario concept_drift --interval 0.1
python backend/scripts/simulate_stream.py --scenario cold_start --interval 0
```

Other choices are `credential_misuse`, `lateral_movement`, and `device_spoofing`. Events always pass through HTTP validation and inference; the script never calls a model directly.

## API surface

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/health` | Service/model readiness |
| POST | `/api/events/ingest` | Validate, feature-engineer, score, persist, publish |
| POST | `/api/events/batch` | Score up to 500 events |
| GET | `/api/events` | Filter recent events |
| GET | `/api/events/stream` | Live SSE stream |
| GET | `/api/alerts` | Filter alert queue |
| GET/PATCH | `/api/alerts/{id}` | Investigate or disposition an alert |
| GET | `/api/users/{id}/profile` | Hierarchical baseline summary |
| GET | `/api/users/{id}/timeline` | Activity and risk history |
| GET | `/api/metrics/overview` | Dashboard KPIs |
| GET | `/api/metrics/model` | Evaluation and artifact metadata |
| GET | `/api/drift` | Detected behavior changes |
| POST/GET | `/api/models/train`, `/api/models/status` | Candidate training and activation status |

Example ingestion (timestamps must include a timezone and may not be more than five minutes ahead):

```bash
curl -X POST http://127.0.0.1:8000/api/events/ingest \
  -H 'Content-Type: application/json' \
  -d '{
    "event_id":"live-001","timestamp":"2026-07-24T10:00:00Z",
    "user_id":"usr-042","user_role":"engineer","department":"Engineering",
    "device_id":"dev-042-0","claimed_device_id":"dev-042-0",
    "operating_system":"Ubuntu 24.04","browser":"Chrome","user_agent":"Chrome/125 (Ubuntu)",
    "device_fingerprint":"41cc80eece5b29ab128d8370","source_ip":"10.2.3.4",
    "country":"India","city":"Bengaluru","latitude":12.9716,"longitude":77.5946,
    "event_type":"login","authentication_result":"success",
    "resource_id":"git","resource_type":"repository","resource_sensitivity":0.5,
    "destination_host":"git.internal","bytes_uploaded":1200,"bytes_downloaded":2400,
    "session_id":"session-live-001","session_duration_seconds":900,
    "is_vpn":false,"is_privileged_action":false
  }'
```

Example response shape:

```json
{
  "event_id": "live-001",
  "anomaly_score": 0.18,
  "predicted_attack": "normal",
  "class_probabilities": {"normal": 0.91, "brute_force": 0.02},
  "classifier_confidence": 0.91,
  "model_confidence": 0.78,
  "baseline_confidence": 0.65,
  "risk_score": 19.4,
  "severity": "low",
  "top_contributing_features": [
    {"feature": "login_hour_deviation", "value": 1.3, "expected": 0, "deviation": 0.6, "description": "Circular-hour distance from normal login time"}
  ],
  "explanation": "Risk increased because login hour deviation was 1.30 relative to the user behavioral baseline.",
  "recommended_actions": ["Monitor for corroborating activity"],
  "baseline_type": "user",
  "historical_events": 38,
  "cold_start": false,
  "model_version": "v20260724-111928",
  "feature_schema_version": "1.0.0",
  "alert_id": null
}
```

Class probability responses contain all six model classes; the compact example is abbreviated.

## Tests and build verification

```bash
source .venv/bin/activate
pytest backend/tests -v

cd frontend
npm run build
```

Tests cover event validation, deterministic feature order/schema, Haversine and impossible travel, device novelty/fingerprint distance, rolling windows, cold start, model save/load, risk bounds, all attack generators, drift, HTTP ingestion, alert creation, and analyst feedback.

## Screenshots

- `docs/overview.png` — placeholder for the live command center screenshot.
- `docs/investigation.png` — placeholder for the feature explanation and analyst controls.
- `docs/model-performance.png` — placeholder for chronological holdout metrics.

Capture these after running the demo; binary screenshots are intentionally not committed in the initial source build.

## Current evaluation

With seed 42 on the generated chronological test split, the final verified run produced approximately 0.841 macro F1, 0.987 weighted F1, 0.46% false-positive rate, 12.31% false-negative rate, 0.952 anomaly ROC-AUC, and 0.674 anomaly PR-AUC. Exact model versions and complete class reports are stored in `data/models/metrics.json` after each run. Synthetic metrics demonstrate the workflow and must not be treated as production efficacy.

## Limitations and production path

Rare classes remain harder than high-volume attack sequences; more scenario diversity and calibrated probabilities are needed. The rolling drift detector is deliberately lightweight, SSE fan-out is process-local, the dashboard has no authentication or map provider, and SQLite is single-node. Real telemetry also carries sensitive identity/location data and needs strict retention and access controls.

For production, replace direct ingestion with Kafka/Redis Streams, SQLite with PostgreSQL, rolling history with Redis, artifacts with signed object storage and a model registry, and local inference with horizontally scaled model-serving workers. Add SSO/RBAC, TLS, audit trails, rate limits, OpenTelemetry, dead-letter/replay flows, partitioning by identity, and blue/green candidate approval. See [ARCHITECTURE.md](ARCHITECTURE.md#scalability-path).
