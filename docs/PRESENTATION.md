# Deviance presentation script

## Slide 1 — The idea

Deviance: AI-powered behavioral anomaly detection for users, service accounts, and edge devices. It recognizes deviations from normal behavior, not signatures.

## Slide 2 — Why behavior

Every login, API call, resource access, command, and device connection creates a behavioral trail. Novel and low-and-slow attacks can avoid fixed indicators, but they still alter timing, location, devices, resources, and sequences.

## Slide 3 — Synthetic environment

400 entities; 73,591 train/validation/test events; users, service accounts, and edge devices; varied offices, shifts, stable IPs, devices, API routes/tokens, auth methods, protocols, commands, resources, transfers, and benign look-alikes. The six required multi-event attack patterns are injected at about 1% of sessions. Labels are offline sidecars only; insider drift is a normal-labeled edge case.

## Slide 4 — Real-time and long-term models

A global Isolation Forest plus four signal-domain forests detect unusual 32-feature snapshots. A twelve-event GRU recurrence over 16 temporal signals detects unexpected sequence behavior. Random Forest and XGBoost candidates compete on validation before probability calibration. Separately, a 42-input, 30-day EntityBehaviorGRU ranks identities by daily behavioral drift.

## Slide 5 — No anomaly-label leakage

The scaler, training profiles, Isolation Forest, and GRU fit normal training events only. Only the attack classifier sees attack labels. Train, validation, and test have no shared entities. Holdout profiles begin from training-only priors and update chronologically without label access. Validation calibrates probabilities and thresholds; test changes nothing.

## Slide 6 — Explainable risk

Risk combines 30% point/domain anomaly, 5% sequence anomaly, 25% malicious class evidence, 35% baseline deviation, and 5% resource criticality. A recall-oriented finding threshold and a separate top-one-percent priority threshold control analyst load. Analysts see observed versus expected features, component weights, confidence, incident timeline, raw telemetry, and response actions.

## Slide 7 — Operational SOC workflow

Events are validated, feature-engineered, scored, persisted, correlated into 15-minute incidents, ranked by risk, and streamed live. Analysts investigate and disposition alerts. Trusted outcomes update normal profiles; malicious behavior does not poison them.

## Slide 8 — Cold start and drift

New entities use peer/global baselines with explicit low confidence, and sequence scoring waits for three prior events. Trusted rolling windows detect legitimate concept drift and ambiguous insider drift for review instead of blind retraining.

## Slide 9 — Honest results

Entity-disjoint test: 11,036 events with 2.14% attack rows. Accuracy is 99.68%, but Macro F1 is 92.80% and is more meaningful under imbalance. Operational precision is 94.04%, recall 86.86%, and normal-event FPR 0.12%. Behavioral-only PR-AUC is 80.67% with 73.73% attack recall. The daily identity model reaches 76.50% PR-AUC and 90.91% top-10 entity recall. Synthetic results are not production guarantees.

## Slide 10 — Live demo

Login with displayed admin credentials. Run mixed simulation. Show live event scoring and 32-feature evidence. Open the risk-ranked correlated incident. Record a disposition. Run cold-start or drift. Finish on model governance and leakage-control evidence.

## Slide 11 — Scalability

The complete authenticated TCP HTTP path—including feature extraction, inference, SQLite-WAL persistence and response—measures 194/229/242 ms P50/P95/P99 and 5.10 events/s sequentially. All 1/4/8-queue runs ingest 60/60 events with zero server errors and ordering violations, and correctly reject duplicate, invalid and unauthenticated requests. Concurrency exposes the single-process/SQLite ceiling; production partitions Kafka by entity and uses Redis, PostgreSQL, horizontally scaled consumers and durable notifications.

## Slide 12 — Close

Deviance is not just a high accuracy screenshot. It is a complete, reproducible behavioral detection workflow with honest imbalance-aware evaluation, uncertainty, explanations, analyst actions, drift, and a credible scale-out path.
