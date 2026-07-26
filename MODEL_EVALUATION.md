# Model evaluation

## Experiment

- Seed: 42
- Feature schema: 3.0.0 (32 behavioral features)
- Required classifier taxonomy: normal, brute force, credential stuffing, lateral movement, impossible travel, device spoofing, and low-and-slow exfiltration
- Train: 51,505 events, 280 entities, 1,105 attack events in 177 scenarios
- Validation: 11,050 events, 60 entities, 250 attack events in 38 scenarios
- Test: 11,036 events, 60 unseen entities, 236 attack events in 38 scenarios
- Audit: 11,033 later events, 60 new entities, 233 attack events in 38 scenarios, generated with seed 10049
- Demo: a separate 500-event stream generated with seed 20053; never used for reported evaluation
- Attack injection: approximately 1% of normal sessions; 2.11% of audit event rows are attacks
- Entity overlap between splits: zero
- Temporal overlap between train, validation, test, and audit: zero
- Isolation Forest contamination: 0.03
- Active classifier: Random Forest, selected over XGBoost on a dedicated validation partition

Telemetry and labels are stored separately. The robust scaler, profiles, global/domain Isolation Forests, and GRU detector fit normal training rows only. Only the classifier sees labeled attacks. Validation is scenario-grouped into non-overlapping calibration, architecture-selection, and threshold-selection purposes. EntityBehaviorGRU training receives entity-disjoint out-of-fold, uncalibrated classifier probabilities, so validation labels cannot flow backward into its training inputs. Validation, test, and audit each start from training-only profile priors and update chronologically without consulting labels.

`insider_drift` is not an attack class. It is a gradual, legitimate privilege/resource expansion generated with a `normal` label and measured as a dedicated false-positive challenge.

## Untouched audit summary

| Measure | Audit result |
|---|---:|
| Classifier accuracy | 99.70% |
| Classifier Macro F1 | 94.37% |
| Classifier PR-AUC | 97.43% |
| Domain Isolation Forest PR-AUC | 46.95% |
| GRU sequence PR-AUC | 72.06% |
| Behavioral-only PR-AUC | 76.02% |
| Behavioral-only event recall | 52.36% |
| Behavioral-only normal-event FPR | 0.13% |
| Operational finding precision | 95.07% |
| Operational finding recall | 82.83% |
| Operational normal-event FPR | 0.093% |
| Insider-drift finding FPR | 0.00% |
| Attack-scenario recall | 100.00% |
| Frozen priority precision | 99.16% |
| Frozen priority recall | 50.64% |
| Top-one-percent precision | 99.10% |
| Top-one-percent recall | 47.21% |

The operational result contains 193 true positives, 10 false positives, 40 false negatives, and 10,790 true negatives. Precision is `193 / (193 + 10) = 95.07%`; recall is `193 / (193 + 40) = 82.83%`; normal-event FPR is `10 / 10,800 = 0.0926%`.

Accuracy is reported because the evaluation criteria request it, but it is not sufficient by itself. An always-normal classifier would already obtain `10,800 / 11,033 = 97.89%` accuracy on this audit. Macro F1, per-class recall, PR-AUC, and false-positive rate reveal performance that raw accuracy hides.

The finding threshold was fixed on its dedicated validation partition by maximizing attack recall subject to at most 0.10% validation normal-event FPR. A separate validation-derived threshold creates the narrow priority queue. Neither test nor audit changes a model, calibrator, weight, or threshold.

## Required-class classification

| Class | Precision | Recall | F1 | Support |
|---|---:|---:|---:|---:|
| Brute force | 100.0% | 100.0% | 100.0% | 63 |
| Credential stuffing | 96.4% | 98.1% | 97.2% | 54 |
| Device spoofing | 89.5% | 100.0% | 94.4% | 17 |
| Impossible travel | 92.3% | 100.0% | 96.0% | 12 |
| Lateral movement | 100.0% | 100.0% | 100.0% | 36 |
| Low-and-slow exfiltration | 71.7% | 74.5% | 73.1% | 51 |
| Normal | 99.9% | 99.8% | 99.9% | 10,800 |

Low-and-slow exfiltration is intentionally difficult at event level because individual transfers resemble legitimate activity; scenario recall is higher because evidence accumulates across the complete sequence. These measurements remain generator-dependent and are not evidence of equivalent production accuracy.

## Random Forest versus XGBoost

| Validation-selection candidate | Accuracy | Macro F1 | Malicious PR-AUC |
|---|---:|---:|---:|
| Random Forest | 99.84% | 97.51% | 94.23% |
| XGBoost | 99.59% | 82.65% | 93.39% |

Random Forest won the scenario-grouped validation-selection partition. Per-class sigmoid calibration uses a separate scenario-grouped validation partition. SMOTE is not used because interpolating independent event rows can create impossible device, geography, API, and sequence combinations.

## Decision contract

The classifier can output only the six required attack types or `normal`. If normal-only behavioral evidence crosses its anomaly threshold while the classifier prefers normal, the live pipeline routes the event to the closest required attack class and exposes the classifier's honest, potentially low confidence.

## Known limitations

All efficacy measurements are synthetic and single-seed. The audit uses new entities, later time boundaries, unique event IDs, and an independent RNG seed, but it still shares the generator family and behavioral assumptions with training. Several class supports are small and accuracy is dominated by normal events. A stronger future evaluation should use multiple seeds, a separately authored generator-shift corpus, lower attack prevalence, confidence intervals, and privacy-safe external telemetry.
