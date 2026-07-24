# Model evaluation

## Experiment

- Seed: 42
- Feature schema: 2.0.0 (24 features)
- Train: 20,664 events, 168 entities, 2.44% attacks
- Validation: 4,430 events, 36 entities, 2.48% attacks
- Test: 4,432 events, 36 entities, 2.53% attacks
- Entity overlap between splits: zero
- Isolation Forest contamination: 0.025
- Threshold selection: highest-risk 1% of the reserved validation-threshold subset

Events and labels are stored separately. The robust scaler, Isolation Forest, GRU detector, and behavioral profiles fit normal rows only. The Random Forest fits all labeled training classes. Probability calibrators use validation data. No test value selects a threshold or changes a model.

## Holdout summary

| Measure | Test result |
|---|---:|
| Macro F1 | 81.35% |
| Weighted F1 | 98.60% |
| Isolation Forest ROC-AUC | 96.10% |
| Isolation Forest PR-AUC | 57.34% |
| GRU sequence ROC-AUC | 77.88% |
| GRU sequence PR-AUC | 6.92% |
| Test attack prevalence | 2.53% |
| Top-1% precision | 64.44% |
| Top-1% recall | 25.89% |
| Operational alert rate | 1.17% |
| Operational alert precision | 67.31% |
| Operational alert recall | 31.25% |
| Normal-event operational alert rate | 0.39% |
| Alerts per 10,000 events | 117.33 |

PR-AUC is emphasized because attacks are rare; ROC-AUC alone would overstate operational usefulness. “Classifier false-positive rate” also counts high-novelty abstentions as non-normal predictions and is not the SOC alert rate. The operational row is the relevant analyst-load measure.

## Per-class classification

| Class | Precision | Recall | F1 | Support |
|---|---:|---:|---:|---:|
| Brute force | 95.7% | 95.7% | 95.7% | 23 |
| Credential misuse | 85.7% | 100.0% | 92.3% | 6 |
| Credential stuffing | 90.0% | 96.4% | 93.1% | 28 |
| Device spoofing | 100.0% | 100.0% | 100.0% | 11 |
| Impossible travel | 75.0% | 50.0% | 60.0% | 6 |
| Lateral movement | 100.0% | 100.0% | 100.0% | 19 |
| Low-and-slow exfiltration | 90.0% | 94.7% | 92.3% | 19 |
| Normal | 99.9% | 97.6% | 98.7% | 4,320 |

The perfect small-class values are synthetic results, not claims of production performance. Impossible travel remains the weakest rare class, and the GRU PR-AUC shows that sequence-only evidence is useful but insufficient by itself. This is preferable to hiding weakness behind weighted accuracy.

## What changed from v1

- Increased from 12 to 24 features and from 5 to 7 attack classes.
- Added service accounts and edge devices.
- Moved labels out of production events.
- Made all anomaly preprocessing explicitly normal-only.
- Added a normal-only GRU sequence detector and cold-start suppression.
- Added probability calibration and unknown-anomaly abstention.
- Replaced unconstrained threshold optimization with a fixed analyst budget.
- Added entity-disjoint splits, hard benign negatives, incident grouping, and risk-ranked triage.
- Replaced suspicious 96–100% headline performance with an honest entity-holdout report.

## Known limitations

The corpus is synthetic, several test classes have under 20 events, and scenario artifacts can still be easier to learn than real attacker behavior. The lightweight GRU reservoir is not a trained deep neural network. There is no external real-log validation, confidence interval, or multi-seed aggregate yet. Drift evaluation is scenario-based rather than a months-long production backtest.

Next experiments should add more entities and independent generator seeds, report bootstrap confidence intervals, validate on a privacy-safe public authentication dataset, tune sequence architecture only on validation data, and measure performance under changed attack templates.
