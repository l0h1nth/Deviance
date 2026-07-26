# Deviance submission report

## Problem and solution

Traditional signatures recognize known bad artifacts. Deviance instead learns habitual entity behavior and flags deviations in access, location, device, resource, command, protocol, and time sequences. A three-model ensemble detects unusual behavior, classifies it into the required taxonomy, and gives an analyst inspectable evidence rather than a bare score.

## Deliverable coverage

| Required deliverable | Deviance implementation |
|---|---|
| Synthetic generator | 400 mixed entity types, 32 derived dimensions, API-aware benign hard negatives, six required randomized attacks at ~1% of sessions |
| Normal baseline | Entity/device/peer/global profiles; normal-only robust scaler and global plus four domain Isolation Forests |
| Sequence detection | Normal-only twelve-event event GRU plus 30-day EntityBehaviorGRU identity ranking |
| Attack classification | Validation selection between balanced Random Forest and regularized XGBoost, followed by sigmoid calibration over only the required classes |
| Explainability | Feature value, expected baseline, deviation, risk components, rationale, and action guidance |
| Analyst dashboard | Ranked incident queue, live SSE, investigation, entity timeline, model governance, drift, dispositions |
| Cold start | Peer/global baseline confidence plus sequence warm-up policy |
| Concept drift | Trusted rolling windows, review records, concept and insider simulations |
| Scalability | Durable sequence/drift state, entity-keyed partition contract, concurrent full-HTTP benchmark and production substitutions |
| Report/presentation | This report, model evaluation, architecture, scalability report, and presentation script |

## Evaluation against judging criteria

Detection accuracy is reported on a chronological, entity-disjoint test set rather than a random row split. Accuracy is 99.68%, while imbalance-aware Macro F1 is 92.80%. The operational layer reaches 94.04% precision, 86.86% recall and 0.12% normal-event FPR.

Attack scenarios are injected at 1% of normal sessions, producing 2.14% test attack rows. The normal-only behavioral layer reaches 80.67% PR-AUC and 73.73% recall. Insider drift remains normal ground truth and has 0% finding FPR. A recall-oriented finding threshold is constrained by validation false positives, while a separate top-one-percent threshold creates the priority queue.

Classification covers exactly brute force, credential stuffing, lateral movement, impossible travel, device spoofing, low-and-slow exfiltration, and normal, including API-channel variants. Random Forest beat XGBoost on a dedicated validation selection split. Balanced probability calibration prevents rare classes from being collapsed into normal.

Explainability connects raw event fields to 32 engineered signals, two anomaly scores, class probabilities, final risk components, and analyst guidance. It avoids claiming causal SHAP explanations; these are transparent feature deviations and weighted evidence.

Cold start and drift are observable states rather than hidden special cases. Holdout profiles evolve without label access, and production profiles use low-risk trust gating to limit poisoning.

System design is runnable on a laptop and has clear production seams. Sequence history, profiles and drift windows persist outside worker memory. A real Uvicorn/TCP benchmark measures authentication, validation, feature extraction, inference, SQLite-WAL transactions and responses under 1/4/8 entity-partition queues. The sequential result is 194/229/242 ms P50/P95/P99 at 5.10 events/s; all concurrent runs have zero server errors, zero ordering violations and expected 409/422/401 failure handling. Kafka/Redpanda, Redis, PostgreSQL, ClickHouse/object storage and durable notification substitutions are specified rather than presented as already deployed.

## Demo narrative

Start with the empty dashboard to establish a clean SOC shift. Run a mixed simulation and open Live Activity. Select an event to show the Isolation Forest, GRU sequence score, classifier distribution, and 32 evidence rows. Open the risk-ranked incident, walk through its correlated timeline and raw telemetry, then record an analyst disposition. Finally run a concept-drift or cold-start scenario and open Model Performance to show the holdout metrics and leakage controls.

## Assumptions and limitations

All efficacy measurements are synthetic. The GRU is a lightweight recurrent reservoir rather than a trained deep network. Several attack supports are small. SQLite, one demo administrator, local artifact storage, and process-local SSE are demo choices. No metric here should be interpreted as a production security guarantee.

## Reproducibility

```bash
python backend/scripts/generate_data.py --seed 42 --users 400 --events-per-user 180 --attack-rate 0.01
python backend/scripts/train_models.py --contamination 0.03
python backend/scripts/evaluate_models.py
python backend/scripts/benchmark_inference.py --events 1000 --warmup 100
python backend/scripts/benchmark_system.py --events 60 --concurrency 1,4,8
pytest backend/tests -q
```
