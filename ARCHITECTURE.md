# Deviance architecture

## Design objective

Deviance models normal access and connection behavior for users, service accounts, and edge devices. It detects both point anomalies and event-sequence anomalies, estimates which known attack a finding resembles, and preserves uncertainty when the event is unfamiliar.

The core trust boundary is strict: an `AccessEvent` accepted by the live API has no ground-truth field. Offline evaluation joins events to separate `TrainingLabel` sidecars by `event_id`.

## Data and leakage controls

The generator creates habitual per-entity behavior with varied shifts, offices, devices, authentication methods, resources, OS/firmware, network protocols, commands, uploads, downloads, and benign look-alikes. It then injects randomized multi-event attack scenarios at 0.5–3% prevalence.

The default corpus uses an entity-safe 70/15/15 train/validation/test split. No entity appears in more than one split. Within each split events are chronological. The scaler, profiles, Isolation Forest, and GRU detector fit only normal training rows. The classifier alone uses attack labels. Validation data calibrates class probabilities and fixes the analyst-budget threshold; the test split is evaluation only.

## Event contract

The v2 schema includes entity ID/type, compatibility user ID, role/department, timestamp, source IP and geography, resource and destination, authentication method/result, session duration, command sequence, device fingerprint/MAC hash, OS/firmware/browser, protocol/port, transfer volumes, VPN state, and privileged-action state.

Entity types are `user`, `service_account`, and `edge_device`. Attack sidecar classes are brute force, credential misuse, credential stuffing, lateral movement, impossible travel, device spoofing, and low-and-slow exfiltration.

## Twenty-four behavioral features

Short-window features:

1. Failed logins in one minute
2. Login attempts in five minutes
3. Login-hour deviation
4. New-device score
5. Device-fingerprint distance
6. Location novelty
7. Required travel speed
8. Unique destination hosts in five minutes
9. Sensitive-resource access ratio
10. Download-volume z-score
11. Session-duration z-score
12. Successful login after failures
13. Unique entities per source IP in five minutes
14. Source-IP failure ratio in five minutes
15. Authentication-method novelty
16. Log time since the previous entity event
17. Concurrent sessions in five minutes
18. Command-sequence novelty
19. Resource novelty
20. Privilege expansion
21. Protocol/port novelty
22. Upload-volume z-score
23. Sensitive downloads in 30 days
24. Off-hours activity

The same registry and order are used for training and live inference; schema mismatch returns an explicit conflict rather than silently scoring incorrect vectors.

## Baselines and cold start

The baseline hierarchy is entity → device (for edge devices) → entity-type/department/role peer group → organization. Normal-only training priors for peer/global profiles travel inside the signed model bundle, so an empty deployment has behavioral context without importing historical logs. Confidence grows as trusted runtime history replaces the prior. The GRU sequence component contributes zero until three prior events exist. Cold start is reported in the result and explanation rather than hidden.

Only normal training rows and trusted runtime outcomes update habitual profiles. Confirmed attack-like behavior cannot become “normal” merely by repetition.

## Models

One global Isolation Forest and four domain forests are fitted on scaled normal rows only. The domains isolate authentication, identity/device/geography, resource/network, and volume/timing signals. Their maximum and mean scores are blended with the global score so a sparse attack is not diluted by unrelated normal features.

The sequence detector implements GRU reset/update recurrence in a deterministic NumPy recurrent reservoir. A ridge decoder learns to predict the next normal feature vector from up to twelve prior entity events. The five strongest reconstruction residuals form the error, which is normalized from normal-only training errors. This provides genuine gated recurrence without adding a heavyweight deep-learning runtime to the hackathon bundle.

A balanced 320-tree Random Forest and a regularized XGBoost candidate are trained on normal plus all known attacks. A dedicated validation partition selects the candidate with the strongest Macro F1, using malicious PR-AUC as a tie-break. A different validation partition fits per-class one-vs-rest sigmoid calibrators. If normal-only behavioral evidence is high but no malicious class reaches defensible confidence, the result is `unknown_anomaly`.

## Risk and explainability

Final risk is bounded to 0–100:

```text
100 × (0.30 × domain/global Isolation Forest
     + 0.05 × GRU sequence anomaly
     + 0.25 × strongest malicious class probability
     + 0.35 × profile deviation
     + 0.05 × resource criticality)
```

Validation fixes two risk cutoffs. The broad finding threshold maximizes validation attack recall subject to a 0.10% normal-event false-positive constraint. The independent priority threshold is fixed at the highest-risk one percent of its validation partition. Evaluation reports event, scenario, and attacked-entity recall; finding and priority precision/recall/FPR; known-class and open-set results; and anomaly, sequence, classifier, and behavioral PR-AUC.

Each result includes the observed feature, expected baseline, normalized deviation, model components, plain-language rationale, recommended response, model/schema versions, and baseline/cold-start context.

## Runtime request flow

1. A signed administrator token authenticates ingestion.
2. Pydantic rejects unknown fields, invalid ranges, naive timestamps, and excessively future timestamps.
3. The service checks event-id idempotency and loads recent entity/IP history.
4. It selects an entity/device/peer/global baseline and extracts 24 features.
5. The active bundle applies the scaler, five normal-only Isolation Forests, GRU, and the validation-selected calibrated classifier.
6. The risk service composes score, severity, evidence, rationale, and response actions.
7. Event and prediction records are persisted.
8. Findings crossing the threshold are correlated by entity, predicted class, and 15-minute bucket. The incident keeps its event count and maximum-risk anchor.
9. Trusted values feed the drift monitor; scored events and status changes are broadcast through authenticated SSE.

## Persistence

SQLite tables store entities, devices, events, predictions, incident alerts, analyst feedback, behavior profiles, drift events, and model-run history. Raw validated events are retained as JSON alongside queryable correlation columns. A fresh hackathon run starts with an empty v2 database.

## Drift

Trusted-only rolling reference/current windows monitor login time, location, device novelty, download volume, resource novelty, privilege expansion, sequence anomaly, and point anomaly. Detected changes are reviewable; they do not trigger automatic blind retraining. The simulator provides both legitimate concept drift and ambiguous insider drift.

## Scalability path

The current system deliberately uses SQLite and in-process state for a reproducible solo demo. Scale-out boundaries are already explicit:

- Put Kafka/Redpanda or a durable managed stream before ingestion.
- Partition by entity ID so sequence order is stable.
- Keep window/profile state in Redis or a feature store.
- Replace SQLite with partitioned PostgreSQL/ClickHouse and explicit retention.
- Serve signed artifacts from a registry and horizontally scale stateless inference workers.
- Use a durable notification bus/WebSocket tier rather than process-local SSE.
- Add SSO/RBAC, TLS, rate limits, immutable audit storage, OpenTelemetry, dead-letter/replay, and blue/green model approval.

See [SCALABILITY_REPORT.md](SCALABILITY_REPORT.md) for the measured single-process baseline.

## Security limitations

The displayed `admin/admin` credentials are a hackathon requirement, not a production pattern. Joblib is safe only for trusted artifacts. Synthetic metrics do not prove real-world efficacy. Location and identity telemetry require data minimization, encryption, retention limits, and controlled analyst access.
