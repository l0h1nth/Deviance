from sqlalchemy import desc, select
from sqlalchemy.orm import Session, joinedload

from app.database.models import AlertRecord, EventRecord, PredictionRecord, ProfileRecord


class EventRepository:
    def __init__(self, db: Session): self.db = db

    def add(self, record: EventRecord) -> EventRecord:
        self.db.add(record); self.db.flush(); return record

    def recent(self, limit: int = 100, user_id: str | None = None) -> list[EventRecord]:
        query = select(EventRecord).options(joinedload(EventRecord.prediction)).order_by(desc(EventRecord.timestamp)).limit(limit)
        if user_id: query = query.where(EventRecord.user_id == user_id)
        return list(self.db.scalars(query).unique())


class AlertRepository:
    def __init__(self, db: Session): self.db = db

    def get(self, alert_id: int) -> AlertRecord | None:
        query = select(AlertRecord).options(
            joinedload(AlertRecord.prediction).joinedload(PredictionRecord.event), joinedload(AlertRecord.feedback)
        ).where(AlertRecord.id == alert_id)
        return self.db.scalars(query).unique().first()


class ProfileRepository:
    def __init__(self, db: Session): self.db = db

    def get(self, key: str) -> ProfileRecord | None:
        return self.db.scalar(select(ProfileRecord).where(ProfileRecord.profile_key == key))
