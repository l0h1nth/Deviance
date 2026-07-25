# Deviance architecture

## Design objective

Deviance models normal access and connection behavior for users, service accounts, and edge devices. It detects both point anomalies and event-sequence anomalies and assigns findings to the attack types required by the supplied problem taxonomy while retaining classifier confidence.

The core trust boundary is strict: an `AccessEvent` accepted by the live API has no ground-truth field. Offline evaluation joins events to separate `TrainingLabel` sidecars by `event_id`.

## Data and leakage controls

The generator creates habitual per-entity behavior with varied shifts, offices, stable IP pools, devices, API routes/tokens/scopes, authentication methods, resources, OS/firmware, network protocols, commands, transfers, and benign look-alikes. It then injects randomized multi-event attack scenarios at 0.5–3% of normal sessions (1% by default) and records event prevalence separately.

The default corpus uses an entity-safe 70/15/15 train/validation/test split. No entity appears in more than one split. Within each split events are chronological. The scaler, training profiles, Isolation Forest, and GRU detector fit only normal training rows. The classifier alone uses attack labels. Validation and test each begin from training-only profile priors and then update online without consulting labels, so malicious events can contaminate the holdout profile just as unlabeled traffic can in practice. Validation fixes probabilities and thresholds; test changes nothing.

## Event contract

The v3 schema includes the v2 identity, device, location, resource, network, command, transfer, and session fields plus action/outcome, MFA result, API route/method/status/latency, hashed credential/scopes, source/destination zones, external-destination state, parent authentication correlation, connection action, and device class.

Entity types are `user`, `service_account`, and `edge_device`. Attack sidecar classes are brute force, credential stuffing, lateral movement, impossible travel, device spoofing, and low-and-slow exfiltration. Insider drift is a legitimate normal-labeled hard negative, not an attack class.

## Thirty-two behavioral features

1. Failed authentications in one minute
2. Authentication attempts in five minutes
3. Successful authentication after failures
4. Unique entities per source IP in five minutes
5. Source-IP failure ratio in five minutes
6. Authentication-method novelty
7. API call-rate deviation in one minute
8. API error ratio in five minutes
9. API endpoint/method novelty
10. Source-IP novelty
11. New-device score
12. Device-fingerprint distance
13. Claimed/observed device mismatch
14. Device-posture novelty
15. Location novelty
16. VPN-aware travel anomaly
17. Access-hour deviation
18. Unique destination hosts in five minutes
19. Resource novelty
20. Event/action novelty
21. Resource-access entropy over 24 hours
22. Resource-sensitivity deviation
23. Privilege expansion
24. Protocol/port novelty
25. Ordered command-transition novelty
26. Download-volume z-score
27. Upload-volume z-score
28. Cumulative external-transfer deviation over 24 hours
29. Session-duration z-score
30. Inter-event-time z-score
31. Active overlapping-session count
32. Sensitive-access-rate deviation over 30 days

The same registry and order are used for training and live inference; schema mismatch returns an explicit conflict rather than silently scoring incorrect vectors.

## Baselines and cold start

The baseline hierarchy is entity → device (for edge devices) → entity-type/department/role peer group → organization. Normal-only training priors for peer/global profiles travel inside the signed model bundle, so an empty deployment has behavioral context without importing historical logs. Confidence grows as trusted runtime history replaces the prior. The GRU sequence component contributes zero until three prior events exist. Cold start is reported in the result and explanation rather than hidden.

Only normal training rows and trusted runtime outcomes update habitual profiles. Confirmed attack-like behavior cannot become “normal” merely by repetition.

## Models

One global Isolation Forest and four domain forests are fitted on scaled normal rows only. The domains isolate authentication, identity/device/geography, resource/network, and volume/timing signals. Their maximum and mean scores are blended with the global score so a sparse attack is not diluted by unrelated normal features.

The sequence detector implements GRU reset/update recurrence in a deterministic NumPy recurrent reservoir. It receives a curated 16-signal temporal subset rather than every tabular feature. A ridge decoder learns to predict the next normal temporal vector from up to twelve prior entity events. The five strongest reconstruction residuals form the error, normalized from normal-only training errors.

A balanced 320-tree Random Forest and a regularized XGBoost candidate are trained on normal plus the six required attacks. A dedicated validation partition selects the candidate with the strongest Macro F1, using malicious PR-AUC as a tie-break. A different validation partition fits class-balanced one-vs-rest sigmoid calibrators so rare attack probabilities are not erased by normal-class prevalence. When the behavioral layer flags an event that the classifier calls normal, the live pipeline selects the closest required attack class and preserves its potentially low confidence.

## Risk and explainability

Final risk is bounded to 0–100:

```text
100 × (0.30 × domain/global Isolation Forest
     + 0.05 × GRU sequence anomaly
     + 0.25 × strongest malicious class probability
     + 0.35 × profile deviation
     + 0.05 × resource criticality)
```

Validation fixes two risk cutoffs. The broad finding threshold maximizes validation attack recall subject to a 0.10% normal-event false-positive constraint. The independent priority threshold is fixed at the highest-risk one percent of its validation partition. Evaluation reports accuracy, Macro F1, per-class results, event/scenario recall, insider-drift FPR, finding and priority precision/recall/FPR, and anomaly, sequence, classifier, and behavioral PR-AUC.

Each result includes the observed feature, expected baseline, normalized deviation, model components, plain-language rationale, recommended response, model/schema versions, and baseline/cold-start context.

## Runtime request flow

1. A signed administrator token authenticates ingestion.
2. Pydantic rejects unknown fields, invalid ranges, naive timestamps, and excessively future timestamps.
3. The service checks event-id idempotency and loads recent entity/IP history.
4. It selects an entity/device/peer/global baseline and extracts 32 schema-3 features.
5. The active bundle applies the scaler, five normal-only Isolation Forests, GRU, and the validation-selected calibrated classifier.
6. The risk service composes score, severity, evidence, rationale, and response actions.
7. Event and prediction records are persisted.
8. Findings crossing the threshold are correlated by entity, predicted class, and 15-minute bucket. The incident keeps its event count and maximum-risk anchor.
9. Trusted values feed the drift monitor; scored events and status changes are broadcast through authenticated SSE.

## Persistence

SQLite tables store entities, devices, events, predictions, incident alerts, analyst feedback, behavior profiles, drift events, and model-run history. Raw validated events are retained as JSON alongside queryable correlation columns. A fresh hackathon run starts with an empty schema-3-compatible database.

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
