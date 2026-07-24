from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import desc, select
from sqlalchemy.orm import Session, joinedload

from app.database.models import EventRecord, PredictionRecord
from app.database.session import get_db
from app.schemas.events import AccessEvent
from app.services.profile_service import ProfileService

router = APIRouter(prefix="/users", tags=["profiles"])


def latest_event(user_id: str, db: Session) -> AccessEvent | None:
    record = db.scalar(select(EventRecord).where(EventRecord.user_id == user_id).order_by(desc(EventRecord.timestamp)).limit(1))
    return AccessEvent.model_validate(record.raw_event) if record else None


@router.get("/{user_id}/profile")
def profile(user_id: str, db: Session = Depends(get_db)):
    event = latest_event(user_id, db)
    if not event: raise HTTPException(404, "user profile not found")
    service = ProfileService(db); return {"user_id": user_id, **service.summary(service.baseline_for(event))}


@router.get("/{user_id}/timeline")
def timeline(user_id: str, limit: int = Query(100, ge=1, le=500), db: Session = Depends(get_db)):
    query = select(EventRecord).outerjoin(EventRecord.prediction).options(joinedload(EventRecord.prediction)).where(
        EventRecord.user_id == user_id).order_by(desc(EventRecord.timestamp)).limit(limit)
    return [{"event": row.raw_event, "risk_score": row.prediction.risk_score if row.prediction else None,
             "predicted_attack": row.prediction.predicted_attack if row.prediction else None} for row in db.scalars(query).unique()]

