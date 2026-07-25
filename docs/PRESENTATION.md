# Deviance presentation script

## Slide 1 — The idea

Deviance: AI-powered behavioral anomaly detection for users, service accounts, and edge devices. It recognizes deviations from normal behavior, not signatures.

## Slide 2 — Why behavior

Every login, API call, resource access, command, and device connection creates a behavioral trail. Novel and low-and-slow attacks can avoid fixed indicators, but they still alter timing, location, devices, resources, and sequences.

## Slide 3 — Synthetic environment

400 entities; 73,807 train/validation/test events; users, service accounts, and edge devices; varied offices, shifts, devices, auth methods, protocols, commands, resources, transfers, and benign look-alikes. Seven multi-event attack patterns are injected at about 2.5% prevalence. Labels are offline sidecars only.

## Slide 4 — The three-model ensemble

A global Isolation Forest plus four signal-domain forests detect unusual 24-feature snapshots. A twelve-event GRU recurrence detects unexpected sequence behavior. Random Forest and XGBoost candidates compete on validation performance before probability calibration. High normal-only novelty with weak class evidence becomes unknown anomaly.

## Slide 5 — No anomaly-label leakage

The scaler, profiles, Isolation Forest, and GRU fit normal events only. Only the attack classifier sees attack labels. Train, validation, and test have no shared entities. Validation calibrates probabilities and the alert threshold; test data is untouched until evaluation.

## Slide 6 — Explainable risk

Risk combines 30% point/domain anomaly, 5% sequence anomaly, 25% malicious class evidence, 35% baseline deviation, and 5% resource criticality. A recall-oriented finding threshold and a separate top-one-percent priority threshold control analyst load. Analysts see observed versus expected features, component weights, confidence, incident timeline, raw telemetry, and response actions.

## Slide 7 — Operational SOC workflow

Events are validated, feature-engineered, scored, persisted, correlated into 15-minute incidents, ranked by risk, and streamed live. Analysts investigate and disposition alerts. Trusted outcomes update normal profiles; malicious behavior does not poison them.

## Slide 8 — Cold start and drift

New entities use peer/global baselines with explicit low confidence, and sequence scoring waits for three prior events. Trusted rolling windows detect legitimate concept drift and ambiguous insider drift for review instead of blind retraining.

## Slide 9 — Honest results

Entity-disjoint test: 11,070 events, 2.44% attacks. Operational precision 90.8%, recall 91.1%, and normal-event FPR 0.23%. Normal-only behavioral PR-AUC is 83.6% with 80.7% attack recall. Scenario and attacked-entity recall are 100%. Known-class Macro F1 is a more honest 64.3%; credential misuse and impossible travel remain weak exact labels. Synthetic results are not production guarantees.

## Slide 10 — Live demo

Login with displayed admin credentials. Run mixed simulation. Show live event scoring and 24-feature evidence. Open the risk-ranked correlated incident. Record a disposition. Run cold-start or drift. Finish on model governance and leakage-control evidence.

## Slide 11 — Scalability

Local sequential model inference with five anomaly forests: 107 ms median, 116 ms P95, 9.4 events/sec. Production design partitions by entity across durable-stream consumers with Redis/feature-store state, horizontally scaled model serving, analytical storage, and durable notifications.

## Slide 12 — Close

Deviance is not just a high accuracy screenshot. It is a complete, reproducible behavioral detection workflow with honest imbalance-aware evaluation, uncertainty, explanations, analyst actions, drift, and a credible scale-out path.
