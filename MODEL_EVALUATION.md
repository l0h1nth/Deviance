# Model evaluation

## Experiment

- Seed: 42
- Feature schema: 2.0.0 (24 behavioral features)
- Train: 51,661 events, 280 entities, 2.44% attacks
- Validation: 11,076 events, 60 entities, 2.49% attacks
- Test: 11,070 events, 60 unseen entities, 2.44% attacks
- Entity overlap between splits: zero
- Unique event identifiers across the combined corpus: yes
- Isolation Forest contamination: 0.03
- Active classifier: Random Forest, selected over XGBoost on a dedicated validation partition

Telemetry and labels are stored separately. The robust scaler, global and domain Isolation Forests, GRU detector, and behavioral profiles fit normal rows only. Only classifier candidates see labeled training attacks. Validation is split again into probability-calibration, classifier-selection, and threshold-selection partitions; the last fixes both behavioral and risk thresholds. The test set changes no model, weight, or threshold.

## Untouched holdout summary

| Measure | Test result |
|---|---:|
| Known-class Macro F1 | 64.25% |
| Weighted F1 | 99.19% |
| Classifier PR-AUC | 97.10% |
| Domain Isolation Forest ROC-AUC | 97.61% |
| Domain Isolation Forest PR-AUC | 78.48% |
| GRU sequence ROC-AUC | 74.79% |
| GRU sequence PR-AUC | 7.89% |
| Behavioral-only PR-AUC | 83.65% |
| Behavioral-only event recall | 80.74% |
| Behavioral-only normal-event FPR | 0.80% |
| Operational finding precision | 90.77% |
| Operational finding recall | 91.11% |
| Operational normal-event FPR | 0.23% |
| Operational finding rate | 2.45% |
| Attack-scenario recall | 100.00% |
| Attacked-entity recall | 100.00% |
| Frozen priority precision | 100.00% |
| Frozen priority recall | 19.26% |
| Frozen priority queue rate | 0.47% |

The event-level operational result contains 246 true positives, 25 false positives, and 24 false negatives. These counts produce precision `246 / (246 + 25) = 90.77%` and recall `246 / (246 + 24) = 91.11%`.

PR-AUC is emphasized because attacks are only 2.44% of the holdout. The behavioral-only metrics exclude classifier evidence and directly test whether normal-only learning can find attack deviations. Their 80.74% recall shows that known-attack supervision is not doing all the work. Scenario recall is also reported because a multi-event brute-force or lateral-movement incident only needs one timely event to reach an analyst.

The broad finding threshold was frozen on validation by maximizing attack recall subject to at most 0.10% normal-event FPR. It produced 0.23% FPR on unseen test entities. A separate top-one-percent validation threshold forms the higher priority queue. It remained conservative on test (0.47% of events, no false positives) because score distributions shifted slightly across entities.

## Known-class classification

| Class | Precision | Recall | F1 | Support |
|---|---:|---:|---:|---:|
| Brute force | 100.0% | 96.7% | 98.3% | 61 |
| Credential misuse | 0.0% | 0.0% | 0.0% | 14 |
| Credential stuffing | 100.0% | 90.2% | 94.9% | 82 |
| Device spoofing | 100.0% | 30.0% | 46.2% | 20 |
| Impossible travel | 0.0% | 0.0% | 0.0% | 12 |
| Lateral movement | 100.0% | 100.0% | 100.0% | 32 |
| Low-and-slow exfiltration | 96.8% | 61.2% | 75.0% | 49 |
| Normal | 99.4% | 100.0% | 99.7% | 10,800 |

The known-class table is intentionally not polished into implausible perfection. Credential misuse and impossible travel are weak as exact labels, while normal-only behavioral recall for those same classes is 92.9% and 50.0%, respectively. In other words, the system often knows that the behavior is abnormal without always naming it correctly. That is why detection, classification, abstention, and analyst priority are separate outputs.

## RF versus XGBoost

| Validation-selection candidate | Macro F1 | Malicious PR-AUC |
|---|---:|---:|
| Random Forest | 63.64% | 97.48% |
| XGBoost | 60.23% | 96.14% |

XGBoost is implemented and evaluated, but it is not forced into production. Random Forest won the held-out selection and is the active classifier for this seed. A future generator seed can legitimately select a different winner.

SMOTE is not used on individual feature rows. Interpolating unrelated security events can create impossible device, geography, and sequence combinations and leaks no realistic incident chronology. Imbalance is handled with whole injected scenarios, class-balanced Random Forest sampling, and bounded class weights for XGBoost.

## Major v3 corrections

- Increased the corpus from roughly 29,500 to 73,807 train/validation/test events and from 240 to 400 entities.
- Added globally unique split-namespaced event, session, sequence, and scenario identifiers plus a generated integrity manifest.
- Replaced a single point detector with a global plus four-domain normal-only Isolation Forest ensemble.
- Increased the GRU context to 12 events and focused reconstruction loss on the five strongest feature residuals.
- Added leakage-safe RF/XGBoost candidate selection and separate probability calibration data.
- Added a shared train/serve risk policy so offline and runtime scoring cannot silently disagree.
- Added distinct behavioral, finding, and priority thresholds.
- Added event, scenario, entity, known-class, open-set, behavioral-only, and frozen-priority evaluation views.

## Known limitations

All efficacy measurements are synthetic and single-seed. Attack generators can still leave artifacts that are easier to learn than real adversary behavior. The lightweight GRU reservoir is not an end-to-end trained deep network. There is no external privacy-safe log validation, confidence interval, or multi-seed aggregate yet. Behavioral FPR shifts from 0.25% validation to 0.80% test, demonstrating that threshold transfer across unseen entities is imperfect. Production work should add multi-seed confidence intervals, changed-template tests, public-data validation, and cost-aware monitoring before deployment.
