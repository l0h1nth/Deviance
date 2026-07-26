from __future__ import annotations

import numpy as np
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database.models import EventRecord, PredictionRecord
from app.ml.enriched_features import enrich_scaled
from app.ml.entity_behavior import aggregate_daily, identity_rankings
from app.ml.model_bundle import ModelBundle


class BehaviorRankingService:
    """Replays persisted event evidence through the frozen daily forecasting path."""

    def __init__(self, db: Session, bundle: ModelBundle):
        self.db, self.bundle = db, bundle

    def _daily_scores(self):
        detector = getattr(self.bundle, "entity_behavior_detector", None)
        daily_scaler = getattr(self.bundle, "entity_behavior_scaler", None)
        if detector is None or daily_scaler is None:
            return None, None
        rows = list(self.db.scalars(select(PredictionRecord).join(PredictionRecord.event)
                    .order_by(EventRecord.timestamp, EventRecord.id)))
        if not rows:
            return None, None
        base = np.asarray([[row.features.get(name, 0.0) for name in self.bundle.feature_names] for row in rows])
        scaled = self.bundle.scaler.transform(base)
        enriched = enrich_scaled(scaled, self.bundle.anomaly_detector, self.bundle.attack_classifier, calibrated=False)
        labels = np.asarray(["normal"] * len(rows))
        entities = np.asarray([row.event.entity_id for row in rows])
        timestamps = np.asarray([row.event.timestamp for row in rows], dtype=object)
        daily = aggregate_daily(enriched, labels, entities, timestamps)
        scores = detector.score_stream(daily_scaler.transform(daily.vectors), daily.entities)
        return daily, scores

    def rankings(self) -> dict:
        daily, scores = self._daily_scores()
        threshold = float(getattr(self.bundle, "entity_behavior_threshold", .85))
        if daily is None:
            detector = getattr(self.bundle, "entity_behavior_detector", None)
            return {"model_ready": detector is not None, "model_version": self.bundle.version,
                    "threshold": threshold, "window_days": getattr(detector, "window_size", 30),
                    "minimum_history_days": getattr(detector, "minimum_history", None),
                    "daily_observations": 0, "rankings": []}
        rankings = identity_rankings(scores, daily.labels, daily.entities, daily.days, threshold)
        return {"model_ready": True, "model_version": self.bundle.version, "threshold": threshold,
                "window_days": self.bundle.entity_behavior_detector.window_size,
                "minimum_history_days": self.bundle.entity_behavior_detector.minimum_history,
                "daily_observations": len(scores), "rankings": rankings}

    def entity_history(self, entity_id: str) -> dict:
        daily, scores = self._daily_scores()
        if daily is None:
            return {"entity_id": entity_id, "days": []}
        mask = daily.entities == entity_id
        days = [{"date": str(day), "drift_score": float(score),
                 "is_drift_day": bool(score >= self.bundle.entity_behavior_threshold),
                 "event_count": int(count)}
                for day, score, count in zip(daily.days[mask], scores[mask], daily.event_counts[mask])]
        ranking = next((item for item in self.rankings()["rankings"] if item["entity_id"] == entity_id), None)
        return {"entity_id": entity_id, "ranking": ranking, "days": days}
