# Deviance submission report

## Problem and solution

Traditional signatures recognize known bad artifacts. Deviance instead learns habitual entity behavior and flags deviations in access, location, device, resource, command, protocol, and time sequences. A three-model ensemble detects unusual behavior, classifies known attack resemblance, preserves unknowns, and gives an analyst inspectable evidence rather than a bare score.

## Deliverable coverage

| Required deliverable | Deviance implementation |
|---|---|
| Synthetic generator | 240 mixed entity types, 24 raw/derived dimensions, benign hard negatives, seven randomized attacks at ~2.5% |
| Normal baseline | Entity/device/peer/global profiles; normal-only robust scaler and Isolation Forest |
| Sequence detection | Normal-only ten-event GRU recurrent reconstruction detector |
| Attack classification | Balanced 240-tree Random Forest with validation sigmoid calibration and unknown abstention |
| Explainability | Feature value, expected baseline, deviation, risk components, rationale, and action guidance |
| Analyst dashboard | Ranked incident queue, live SSE, investigation, entity timeline, model governance, drift, dispositions |
| Cold start | Peer/global baseline confidence plus sequence warm-up policy |
| Concept drift | Trusted rolling windows, review records, concept and insider simulations |
| Scalability | Entity partitioning design and repeatable latency/throughput benchmark |
| Report/presentation | This report, model evaluation, architecture, scalability report, and presentation script |

## Evaluation against judging criteria

Detection accuracy is reported on a chronological, entity-disjoint test set rather than a random row split. Macro F1 is 81.4%; the lower value is an honest consequence of rare classes and unknown abstention.

Class imbalance is realistic at 2.53% test attacks. The primary anomaly metric is PR-AUC, and the operational threshold is fixed by a validation top-1% analyst budget. The test normal-event alert rate is 0.39%.

Classification covers all requested patterns plus credential stuffing and low-and-slow exfiltration. Per-class metrics are visible in the UI; impossible travel is currently weakest at 60% F1.

Explainability connects raw event fields to 24 engineered signals, two anomaly scores, class probabilities, final risk components, and analyst guidance. It avoids claiming causal SHAP explanations; these are transparent feature deviations and weighted evidence.

Cold start and drift are observable states rather than hidden special cases. Trusted-only adaptation prevents detected attacks from immediately poisoning the baseline.

System design is runnable on a laptop and has clear production seams. The repeatable local benchmark measures 58.2 ms median model inference and 79.4 ms P95 for sequential per-event scoring.

## Demo narrative

Start with the empty dashboard to establish a clean SOC shift. Run a mixed simulation and open Live Activity. Select an event to show the Isolation Forest, GRU sequence score, classifier distribution, and 24 evidence rows. Open the risk-ranked incident, walk through its correlated timeline and raw telemetry, then record an analyst disposition. Finally run a concept-drift or cold-start scenario and open Model Performance to show the honest holdout metrics and leakage controls.

## Assumptions and limitations

All efficacy measurements are synthetic. The GRU is a lightweight recurrent reservoir rather than a trained deep network. Several attack supports are small. SQLite, one demo administrator, local artifact storage, and process-local SSE are demo choices. No metric here should be interpreted as a production security guarantee.

## Reproducibility

```bash
python backend/scripts/generate_data.py --seed 42 --users 240 --events-per-user 120 --attack-rate 0.025
python backend/scripts/train_models.py --contamination 0.025
python backend/scripts/evaluate_models.py
python backend/scripts/benchmark_inference.py --events 1000 --warmup 100
pytest backend/tests -q
```
