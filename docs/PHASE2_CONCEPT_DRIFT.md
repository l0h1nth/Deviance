# Phase 2 — Governed Concept Drift

Phase 2 handles legitimate behavioral change without teaching the system that suspicious activity is normal. It is separate from attack classification: a drift finding means a trusted distribution changed, not that an intrusion occurred.

## Runtime lifecycle

1. Every event is validated, engineered into 32 behavioral features, and scored by the existing ensemble.
2. Only an event predicted as normal and below the low-risk profile-update boundary can enter drift monitoring. The concept-drift simulator uses an explicit pre-reviewed override solely to make the demo deterministic.
3. Eight signals are collected per identity in a durable 20-event trusted reference window and 20-event current window.
4. The detector requires all three conditions: a feature-specific meaningful absolute shift, standardized effect size of at least 2.5, and empirical two-sample KS distance of at least 0.55.
5. A significant signal is frozen as `pending_review`. More telemetry cannot overwrite either distribution while it is pending.
6. An analyst can investigate, approve adaptation, reject the change, or dismiss it. Approval promotes the reviewed current window to drift reference version `n+1`; rejection discards the challenged window and preserves version `n`.
7. Approval changes the drift reference only. It does not automatically retrain or activate an Isolation Forest, GRU, or classifier artifact.

```text
Validated telemetry
        │
        ▼
Normal + low risk? ── no ──► excluded from drift learning
        │ yes
        ▼
20-event reference ──► 20-event current ──► shift tests
                                                │
                              stable ────────────┴──► roll trusted window
                                                │ significant
                                                ▼
                                         frozen review gate
                                         /                \
                              approve adaptation      reject change
                              promote current         preserve reference
```

## Monitored signals

| Signal | Domain | Minimum meaningful shift |
|---|---|---:|
| Access time | Identity | 1.5 hours |
| Location novelty | Identity | 0.15 |
| Device novelty | Device | 0.15 |
| Download-volume z-score | Access | 0.75 |
| Resource novelty | Access | 0.15 |
| Privilege expansion | Access | 0.15 |
| GRU sequence anomaly | Sequence | 0.12 |
| Isolation/domain anomaly | Model | 0.12 |

Access time uses circular means and distances, so 23:59 and 00:01 are treated as adjacent rather than almost 24 hours apart.

## Statistics

Mean-shift effect size is:

```text
effect = |current_mean - reference_mean| / pooled_window_scale
```

The scale is floored per feature to prevent constant or nearly constant reference data from turning tiny numeric noise into an enormous effect. For access time, the numerator and scale use circular-hour distance.

The empirical KS distance is the largest difference between the two empirical cumulative distributions:

```text
KS = max_x |F_reference(x) - F_current(x)|
```

Both effect size and KS distance are shown in the analyst dashboard. Confidence is an evidence-strength indicator derived from those two tests; it is not an attack probability.

## Persistence and safety

- `drift_windows` persists reference values, current values, status, trusted-observation count, baseline version, and adaptation time.
- `drift_events` persists distribution snapshots, detector evidence, review state, comments, analyst identity, and immutable review-history entries.
- Pending signals accept no more observations until disposition.
- Final dispositions cannot be overwritten through the API.
- Suspicious/high-risk traffic never enters the windows in normal production flow.
- No drift decision activates a newly trained model.

## API

```http
GET /api/drift
```

Returns the governed summary, persistent entity-window progress, and drift findings.

```http
PATCH /api/drift/{id}
Content-Type: application/json

{
  "action": "approve_adaptation",
  "comment": "HR shift-change ticket SEC-142 verified"
}
```

Valid actions are `investigate`, `approve_adaptation`, `reject_change`, and `dismiss`. The analyst identity is taken from the authenticated token rather than trusted from the request body.

## Reproduce and test

Run the backend contract tests:

```bash
.venv/bin/python -m pytest backend/tests/test_drift.py backend/tests/test_workflows.py -q
```

Run the synthetic stable-versus-shifted benchmark:

```bash
.venv/bin/python backend/scripts/evaluate_drift.py --stable-entities 100 --drift-entities 100
```

For the live demo, start a `concept_drift` simulation with exactly 40 events. The first half is centered around 09:00 and the second around 19:00. Open **Drift monitor**, inspect the evidence, record a note, and explicitly approve or reject adaptation.

## Known boundary

This phase demonstrates entity-level numeric drift on synthetic telemetry. A production deployment would add cohort-level feature/schema drift, multiple-testing control, seasonal reference windows, durable streaming state such as Redis or a feature store, RBAC-separated approval, and shadow-model evaluation before any retrained artifact could be promoted.
