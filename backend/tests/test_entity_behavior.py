from datetime import datetime, timedelta, timezone

import numpy as np

from app.ml.entity_behavior import DailyBehaviorBatch, aggregate_daily, daily_evaluation, identity_rankings


def test_daily_aggregation_is_entity_and_calendar_day_safe():
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    vectors = np.asarray([[0.0] * 42, [1.0] * 42, [2.0] * 42, [3.0] * 42])
    batch = aggregate_daily(vectors, np.asarray(["normal", "brute_force", "normal", "normal"]),
        np.asarray(["u1", "u1", "u2", "u1"]),
        np.asarray([start, start + timedelta(hours=1), start, start + timedelta(days=1)], dtype=object))
    assert len(batch.vectors) == 3
    u1_day1 = np.flatnonzero((batch.entities == "u1") & (batch.days == "2026-01-01"))[0]
    assert batch.labels[u1_day1] == "brute_force" and batch.event_counts[u1_day1] == 2
    np.testing.assert_allclose(batch.vectors[u1_day1], np.full(42, .95))


def test_rankings_prioritize_maximum_and_persistent_drift():
    entities = np.asarray(["high", "high", "steady", "steady", "steady"])
    days = np.asarray(["2026-01-01", "2026-01-02", "2026-01-01", "2026-01-02", "2026-01-03"])
    scores = np.asarray([.2, 1.0, .7, .7, .7])
    rankings = identity_rankings(scores, np.asarray(["normal"] * 5), entities, days, .6)
    assert rankings[0]["entity_id"] == "high"
    assert rankings[0]["maximum_drift_30d"] == 1.0
    assert next(item for item in rankings if item["entity_id"] == "steady")["drift_days_30d"] == 3


def test_daily_ranking_metrics_use_same_latest_30_day_horizon():
    days = np.asarray([f"2026-01-{day:02d}" for day in range(1, 32)] + ["2026-01-31"])
    entities = np.asarray(["old-attack"] * 31 + ["recent-attack"])
    labels = np.asarray(["brute_force", *(["normal"] * 30), "brute_force"])
    scores = np.asarray([.99, *([.01] * 30), .98])
    batch = DailyBehaviorBatch(np.zeros((32, 1)), labels, entities, days, np.ones(32, dtype=int))
    metrics = daily_evaluation(scores, batch, .9)
    assert metrics["attacked_entity_count"] == 1
    assert metrics["top_10_precision"] == .5
    assert metrics["top_10_recall"] == 1.0
