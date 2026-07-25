# Model evaluation

## Experiment

- Seed: 42
- Feature schema: 3.0.0 (32 behavioral features)
- Train: 51,379 events, 280 entities, 979 attack events in 177 scenarios
- Validation: 11,010 events, 60 entities, 210 attack events in 38 scenarios
- Test: 11,010 events, 60 unseen entities, 210 attack events in 38 scenarios
- Attack injection: approximately 1% of normal sessions; 1.91% of event rows are attacks
- Entity overlap between splits: zero
- Isolation Forest contamination: 0.03
- Active classifier: XGBoost, selected over Random Forest on a dedicated validation partition

Telemetry and labels are stored separately. The robust scaler, profiles, global/domain Isolation Forests, and GRU detector fit normal rows only. Only classifier candidates see labeled attacks. Validation is split into probability-calibration, classifier-selection, and threshold-selection partitions; the test split changes no model, weight, or threshold.

## Untouched holdout summary

| Measure | Test result |
|---|---:|
| Known-class Macro F1 | 99.83% |
| Open-set Macro F1 | 88.70% |
| Classifier PR-AUC | 100.00% |
| Domain Isolation Forest PR-AUC | 83.51% |
| GRU sequence PR-AUC | 73.65% |
| Behavioral-only PR-AUC | 91.21% |
| Behavioral-only event recall | 88.10% |
| Behavioral-only normal-event FPR | 0.75% |
| Operational finding precision | 99.04% |
| Operational finding recall | 98.57% |
| Operational normal-event FPR | 0.02% |
| Attack-scenario recall | 100.00% |
| Attacked-entity recall | 100.00% |
| Frozen priority precision | 100.00% |
| Frozen priority recall | 57.62% |
| Top-one-percent precision | 100.00% |
| Top-one-percent recall | 52.86% |

The operational result contains 207 true positives, 2 false positives, 3 false negatives, and 10,798 true negatives. Precision is `207 / (207 + 2) = 99.04%`; recall is `207 / (207 + 3) = 98.57%`; normal-event FPR is `2 / 10,800 = 0.0185%`.

PR-AUC is emphasized because attacks are 1.91% of the holdout. The behavioral-only measurements exclude classifier evidence and show that normal-only learning detects 88.10% of injected attack events. Scenario recall is also reported because one timely event can surface a multi-event incident.

The finding threshold was fixed on validation by maximizing attack recall subject to at most 0.10% normal-event FPR. It achieved 97.26% validation recall with zero validation false positives, then transferred to unseen test entities with two false positives. A separate validation-derived priority threshold produced 121 test alerts, all attacks.

## Known-class classification

| Class | Precision | Recall | F1 | Support |
|---|---:|---:|---:|---:|
| Brute force | 100.0% | 100.0% | 100.0% | 48 |
| Credential misuse | 100.0% | 100.0% | 100.0% | 12 |
| Credential stuffing | 100.0% | 100.0% | 100.0% | 56 |
| Device spoofing | 100.0% | 100.0% | 100.0% | 12 |
| Impossible travel | 100.0% | 100.0% | 100.0% | 10 |
| Lateral movement | 100.0% | 100.0% | 100.0% | 35 |
| Low-and-slow exfiltration | 97.4% | 100.0% | 98.7% | 37 |
| Normal | 100.0% | 99.99% | 100.0% | 10,800 |

These near-perfect known-pattern results reflect a controlled synthetic taxonomy, stable schema, and class-balanced calibration; they are not evidence of equivalent real-world accuracy. The normal-only behavioral and open-set metrics are the more defensible measures of novel-deviation capability. Future evaluation should vary generator templates and use privacy-safe external logs.

## RF versus XGBoost

| Validation-selection candidate | Macro F1 | Malicious PR-AUC |
|---|---:|---:|
| Random Forest | 97.91% | 100.00% |
| XGBoost | 100.00% | 100.00% |

XGBoost won the untouched validation-selection partition. Per-class sigmoid calibration uses balanced one-vs-rest fitting on a separate validation partition so rare attack probabilities are not collapsed into the normal class.

SMOTE is not used. Interpolating independent event rows can create impossible device, geography, API, and sequence combinations. Imbalance is handled using complete scenarios, balanced tree learning, bounded XGBoost sample weights, and entity-disjoint evaluation.

## Schema 3.0 corrections

- Replaced 24 partially overlapping signals with 32 named behavioral features.
- Added first-class API route/method/status/token/scope telemetry and API attack variants.
- Added source-IP, claimed-device mismatch, device-posture, action, entropy, external-transfer, inter-event, true concurrency, and 30-day rate evidence.
- Bounded VPN-aware impossible-travel evidence and separated resource criticality from behavioral deviation.
- Injected attacks at a scenario/session rate rather than targeting attack event rows.
- Routed 7–9 relevant signals to each domain Isolation Forest and only 16 temporal signals to the GRU.
- Balanced rare-class probability calibration without exposing labels to anomaly or sequence training.

## Known limitations

All efficacy measurements are synthetic and single-seed. Several exact-class supports are small, and generator-specific patterns remain easier than unconstrained real adversaries. The GRU is a deterministic recurrent reservoir rather than an end-to-end trained deep network. There is no external-log validation or multi-seed confidence interval yet. Behavioral FPR moved from 0.25% validation to 0.75% test, demonstrating normal-only threshold shift across unseen entities even while the full operational ensemble remained conservative.
