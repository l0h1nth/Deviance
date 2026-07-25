# Deviance submission report

## Problem and solution

Traditional signatures recognize known bad artifacts. Deviance instead learns habitual entity behavior and flags deviations in access, location, device, resource, command, protocol, and time sequences. A three-model ensemble detects unusual behavior, classifies known attack resemblance, preserves unknowns, and gives an analyst inspectable evidence rather than a bare score.

## Deliverable coverage

| Required deliverable | Deviance implementation |
|---|---|
| Synthetic generator | 400 mixed entity types, 24 derived dimensions, benign hard negatives, seven randomized attacks at ~2.5% |
| Normal baseline | Entity/device/peer/global profiles; normal-only robust scaler and global plus four domain Isolation Forests |
| Sequence detection | Normal-only twelve-event GRU reconstruction detector using sparse residuals |
| Attack classification | Validation selection between balanced Random Forest and regularized XGBoost, followed by sigmoid calibration and unknown abstention |
| Explainability | Feature value, expected baseline, deviation, risk components, rationale, and action guidance |
| Analyst dashboard | Ranked incident queue, live SSE, investigation, entity timeline, model governance, drift, dispositions |
| Cold start | Peer/global baseline confidence plus sequence warm-up policy |
| Concept drift | Trusted rolling windows, review records, concept and insider simulations |
| Scalability | Entity partitioning design and repeatable latency/throughput benchmark |
| Report/presentation | This report, model evaluation, architecture, scalability report, and presentation script |

## Evaluation against judging criteria

Detection accuracy is reported on a chronological, entity-disjoint test set rather than a random row split. The operational layer reaches 90.8% precision, 91.1% recall, 0.23% normal-event FPR, and 100% attack-scenario recall. Known-class Macro F1 is 64.3%, exposing weak exact labels rather than hiding them behind weighted accuracy.

Class imbalance is realistic at 2.44% test attacks. The normal-only behavioral layer reaches 83.6% PR-AUC and 80.7% recall. A recall-oriented finding threshold is constrained by validation false positives, while a separate top-one-percent validation threshold creates the priority queue.

Classification covers all requested patterns plus credential stuffing and low-and-slow exfiltration. Random Forest beat XGBoost on a dedicated validation selection split. Credential misuse and impossible travel remain weak exact labels, even though their behavioral-only recall is 92.9% and 50.0%.

Explainability connects raw event fields to 24 engineered signals, two anomaly scores, class probabilities, final risk components, and analyst guidance. It avoids claiming causal SHAP explanations; these are transparent feature deviations and weighted evidence.

Cold start and drift are observable states rather than hidden special cases. Trusted-only adaptation prevents detected attacks from immediately poisoning the baseline.

System design is runnable on a laptop and has clear production seams. The repeatable 1,000-event local benchmark measures 106.9 ms median model inference and 116.4 ms P95 for sequential per-event scoring through all five anomaly forests.

## Demo narrative

Start with the empty dashboard to establish a clean SOC shift. Run a mixed simulation and open Live Activity. Select an event to show the Isolation Forest, GRU sequence score, classifier distribution, and 24 evidence rows. Open the risk-ranked incident, walk through its correlated timeline and raw telemetry, then record an analyst disposition. Finally run a concept-drift or cold-start scenario and open Model Performance to show the honest holdout metrics and leakage controls.

## Assumptions and limitations

All efficacy measurements are synthetic. The GRU is a lightweight recurrent reservoir rather than a trained deep network. Several attack supports are small. SQLite, one demo administrator, local artifact storage, and process-local SSE are demo choices. No metric here should be interpreted as a production security guarantee.

## Reproducibility

```bash
python backend/scripts/generate_data.py --seed 42 --users 400 --events-per-user 180 --attack-rate 0.025
python backend/scripts/train_models.py --contamination 0.03
python backend/scripts/evaluate_models.py
python backend/scripts/benchmark_inference.py --events 1000 --warmup 100
pytest backend/tests -q
```
