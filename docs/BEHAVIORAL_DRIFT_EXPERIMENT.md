# Behavioral drift experiment

This branch adds a second, non-alerting behavioral path while retaining the event-level security pipeline. It is intentionally evaluated against the previous architecture instead of assuming that more inputs must produce a better model.

## Implemented architecture

Each telemetry event is validated and converted into the existing 32 engineered behavioral features. Four normal-only Isolation Forest domain scores and six calibrated Random Forest attack probabilities are appended to form a fixed 42-value vector. The classifier never consumes GRU output, so there is no prediction feedback loop.

Two independent GRUs consume this contract:

1. The event sequence GRU slides over the previous 12 events for an entity and predicts the next 42-value event vector. Its reconstruction residual becomes sequence novelty evidence in the real-time risk pipeline.
2. `EntityBehaviorGRU` first aggregates each entity's event vectors into one daily vector using per-feature p95. It slides a 30-day window forward one day at a time, predicts the next daily vector, and converts the forecast residual into a drift score. It is trained only on normal entity-days and starts scoring after seven history days.

Daily drift does not directly produce a security alert. The Identity Risk page ranks entities using the most recent 30 daily scores:

```text
rank = 100 × (
  0.60 × maximum drift
  + 0.25 × min(drift days / 7, 1)
  + 0.10 × mean of top three drift scores
  + 0.05 × recency
)
```

Maximum drift is deliberately the dominant factor, while persistence prevents one isolated spike from controlling the entire list.

## Leakage controls

- Train, validation, and test entities are disjoint and time ordered.
- Isolation Forests, GRU scalers, and both GRUs fit normal data only.
- Event-GRU training uses out-of-fold classifier probabilities: a row's RF features come from a classifier that did not train on that entity.
- Validation chooses and freezes thresholds. The untouched test partition only reports results.
- Production telemetry contains no attack label; labels are evaluation-only sidecars.

## Held-out comparison

The seed-42 untouched test split contains 11,036 events from 60 unseen entities. Results from model version `v20260726-070010` are:

| Measurement | Previous architecture | Behavioral-drift branch |
|---|---:|---:|
| Event GRU PR-AUC | 73.98% (legacy 16-input replay) | 43.96% (42 inputs) |
| Event GRU ROC-AUC | 97.43% | 98.24% |
| Full behavioral ensemble PR-AUC | 80.67% | 81.24% |
| Full behavioral recall | 73.73% | 77.97% |
| Operational finding precision | 93.98% | 93.21% |
| Operational finding recall | 86.02% | 87.29% |
| Operational normal-event FPR | 0.12% | 0.14% |

The 42-input event GRU is **not an isolated improvement**: ROC-AUC rises slightly, but PR-AUC falls substantially. The full ensemble gains behavioral PR-AUC and recall because other evidence compensates, with a small precision/FPR cost. This branch therefore keeps the new event GRU as an experiment, not as proof that feature expansion is automatically beneficial.

The separate daily path operates on 10,664 test entity-days with 1.16% anomalous-day prevalence:

| Daily EntityBehaviorGRU metric | Result |
|---|---:|
| PR-AUC | 76.50% |
| ROC-AUC | 98.66% |
| Recall | 79.03% |
| Precision | 49.00% |
| Normal-day FPR | 0.97% |
| Top 1% ranked-entity precision | 100.00% |

The daily threshold is selected on validation under a 1% normal-day FPR constraint and then frozen. These are synthetic-corpus results, not production guarantees.

## Run and verify

Train the complete branch architecture:

```bash
source .venv/bin/activate
python backend/scripts/train_models.py --contamination 0.03
```

Re-evaluate and optionally save only the behavioral-drift threshold/metrics for the active artifact:

```bash
python backend/scripts/evaluate_behavioral_drift.py
python backend/scripts/evaluate_behavioral_drift.py --save
```

Start the application and open **Identity risk** to see the ranked list. Multi-day persisted telemetry is required before a runtime entity receives a meaningful daily score.

## Current limitations

- Daily vectors are recomputed from persisted predictions on request; production should materialize them in a feature store.
- Missing calendar days are not yet represented by an explicit mask.
- P95 aggregation preserves strong daily deviations but can discard ordering within the day.
- The enriched event GRU needs architecture or feature-ablation work before it should replace the legacy GRU on PR-AUC grounds.
- Ranking quality is measured on generated behavior and must be validated on representative production telemetry.
