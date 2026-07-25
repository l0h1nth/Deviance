# Model evaluation

## Experiment

- Seed: 42
- Feature schema: 3.0.0 (32 behavioral features)
- Required classifier taxonomy: normal, brute force, credential stuffing, lateral movement, impossible travel, device spoofing, and low-and-slow exfiltration
- Train: 51,505 events, 280 entities, 1,105 attack events in 177 scenarios
- Validation: 11,050 events, 60 entities, 250 attack events in 38 scenarios
- Test: 11,036 events, 60 unseen entities, 236 attack events in 38 scenarios
- Attack injection: approximately 1% of normal sessions; 2.14% of test event rows are attacks
- Entity overlap between splits: zero
- Isolation Forest contamination: 0.03
- Active classifier: Random Forest, selected over XGBoost on a dedicated validation partition

Telemetry and labels are stored separately. The robust scaler, profiles, global/domain Isolation Forests, and GRU detector fit normal training rows only. Only the classifier sees labeled attacks. Validation and test each start from training-only profile priors and then update chronologically without consulting their labels. This permits realistic online adaptation and also permits attacks to contaminate holdout profiles.

`insider_drift` is not an attack class. It is a gradual, legitimate privilege/resource expansion generated with a `normal` label and measured as a dedicated false-positive challenge.

## Untouched holdout summary

| Measure | Test result |
|---|---:|
| Classifier accuracy | 99.72% |
| Classifier Macro F1 | 93.46% |
| Classifier PR-AUC | 97.88% |
| Domain Isolation Forest PR-AUC | 60.84% |
| GRU sequence PR-AUC | 73.98% |
| Behavioral-only PR-AUC | 80.67% |
| Behavioral-only event recall | 73.73% |
| Behavioral-only normal-event FPR | 0.74% |
| Operational finding precision | 93.98% |
| Operational finding recall | 86.02% |
| Operational normal-event FPR | 0.12% |
| Insider-drift finding FPR | 0.00% |
| Attack-scenario recall | 100.00% |
| Frozen priority precision | 100.00% |
| Frozen priority recall | 56.78% |
| Top-one-percent precision | 100.00% |
| Top-one-percent recall | 47.03% |

The operational result contains 203 true positives, 13 false positives, 33 false negatives, and 10,787 true negatives. Precision is `203 / (203 + 13) = 93.98%`; recall is `203 / (203 + 33) = 86.02%`; normal-event FPR is `13 / 10,800 = 0.1204%`.

Accuracy is reported because the evaluation criteria request detection accuracy, but it is not sufficient by itself. An always-normal classifier would already obtain `10,800 / 11,036 = 97.86%` accuracy on this holdout. Macro F1, per-class recall, PR-AUC, and false-positive rate reveal performance that raw accuracy hides.

The finding threshold was fixed on validation by maximizing attack recall subject to at most 0.10% validation normal-event FPR. A separate validation-derived threshold creates the narrow priority queue. The test split changes no model, weight, or threshold.

## Required-class classification

| Class | Precision | Recall | F1 | Support |
|---|---:|---:|---:|---:|
| Brute force | 100.0% | 100.0% | 100.0% | 60 |
| Credential stuffing | 100.0% | 100.0% | 100.0% | 62 |
| Device spoofing | 100.0% | 100.0% | 100.0% | 17 |
| Impossible travel | 92.3% | 100.0% | 96.0% | 12 |
| Lateral movement | 100.0% | 100.0% | 100.0% | 38 |
| Low-and-slow exfiltration | 84.0% | 44.7% | 58.3% | 47 |
| Normal | 99.8% | 100.0% | 99.9% | 10,800 |

Low-and-slow exfiltration is intentionally difficult at event level because individual transfers resemble legitimate activity; scenario recall is higher because evidence accumulates across the complete sequence. These measurements remain generator-dependent and are not evidence of equivalent production accuracy.

## Random Forest versus XGBoost

| Validation-selection candidate | Accuracy | Macro F1 | Malicious PR-AUC |
|---|---:|---:|---:|
| Random Forest | 99.62% | 90.96% | 98.12% |
| XGBoost | 99.48% | 76.22% | 85.60% |

Random Forest won the untouched validation-selection partition. Per-class sigmoid calibration uses a separate validation partition. SMOTE is not used because interpolating independent event rows can create impossible device, geography, API, and sequence combinations.

## Decision contract

The classifier can output only the six required attack types or `normal`. If normal-only behavioral evidence crosses its anomaly threshold while the classifier prefers normal, the live pipeline routes the event to the closest required attack class and exposes the classifier's honest, potentially low confidence.

## Known limitations

All efficacy measurements are synthetic and single-seed. Several class supports are small, and train/test attacks still share generator families. Accuracy is dominated by normal events. A stronger future evaluation should use multiple seeds, generator-shift tests, lower attack prevalence, confidence intervals, and privacy-safe external telemetry.
