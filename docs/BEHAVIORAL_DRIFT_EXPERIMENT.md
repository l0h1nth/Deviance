# Behavioral drift experiment

This branch adds a second, non-alerting behavioral path while retaining the event-level security pipeline. It is intentionally evaluated against the previous architecture instead of assuming that more inputs must produce a better model.

## Implemented architecture

Each telemetry event is validated and converted into the existing 32 engineered behavioral features. The real-time event GRU stays on that original contract. For the separate daily path, four normal-only Isolation Forest domain scores and six raw Random Forest attack probabilities are appended to form a fixed 42-value vector. Training probabilities are entity-disjoint out-of-fold predictions; validation calibration is deliberately excluded from the EntityBehaviorGRU input contract. The classifier never consumes GRU output, so there is no prediction feedback loop.

The two independent GRUs intentionally use different contracts:

1. The active event sequence GRU accepts each 32-value event, reconstructs the sequence-sensitive feature subset, and slides over the previous 12 events. Its reconstruction residual becomes sequence novelty evidence in the real-time risk pipeline.
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

- Train, validation, test, and audit entities are disjoint with strict chronological boundaries.
- Isolation Forests, GRU scalers, and both GRUs fit normal data only.
- Daily-GRU training uses out-of-fold classifier probabilities: a row's RF features come from a classifier that did not train on that entity.
- Validation chooses and freezes thresholds. Test and audit only report results; the independent demo corpus is never evaluation evidence.
- Production telemetry contains no attack label; labels are evaluation-only sidecars.

## Validation architecture comparison and audit result

The event-GRU architecture choice is made on a scenario-grouped validation selection partition, not on test or audit:

| Measurement | Selected 32-feature event path | Rejected 42-input candidate |
|---|---:|---:|
| Event GRU PR-AUC | 80.66% | 62.94% |
| Event GRU ROC-AUC | 98.84% | 98.79% |

The enriched event GRU lowers PR-AUC, so the original 32-feature event path remains active and the 42-input design is retained only in the daily EntityBehaviorGRU.

On the independent audit, the daily path operates on 9,967 entity-days with 1.29% anomalous-day prevalence:

| Daily EntityBehaviorGRU metric | Result |
|---|---:|
| PR-AUC | 75.12% |
| ROC-AUC | 96.52% |
| Recall | 76.74% |
| Precision | 51.83% |
| Normal-day FPR | 0.94% |
| Top 1% ranked-entity precision | 100.00% |
| Top-10 ranked-entity precision | 50.00% |
| Top-10 ranked-entity recall | 83.33% |

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
- The rejected enriched event GRU would need architecture or feature-ablation work before reconsideration.
- Ranking quality is measured on generated behavior and must be validated on representative production telemetry.
