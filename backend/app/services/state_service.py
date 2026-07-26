"""Persistent runtime state boundaries used by sequence inference."""

import numpy as np
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database.models import EventRecord, PredictionRecord


class SequenceStateStore:
    """Read an entity's ordered sequence from durable prediction records.

    SQLite is the demo backend. The interface maps directly to a Redis list or a
    feature-store lookup in production; no sequence correctness depends on the
    Python worker that receives the next event.
    """

    def __init__(self, db: Session):
        self.db = db

    def previous_vectors(self, entity_id: str, before, feature_names: list[str], limit: int) -> np.ndarray:
        rows = list(self.db.scalars(
            select(PredictionRecord).join(PredictionRecord.event)
            .where(EventRecord.entity_id == entity_id, EventRecord.timestamp < before)
            .order_by(EventRecord.timestamp.desc(), EventRecord.id.desc()).limit(limit)
        ))
        rows.reverse()
        return np.asarray(
            [[row.features.get(name, 0.0) for name in feature_names] for row in rows], dtype=float
        ).reshape((-1, len(feature_names)))
