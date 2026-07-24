from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import desc, select
from sqlalchemy.orm import Session, joinedload

from app.database.models import EventRecord, PredictionRecord, UserRecord
from app.database.session import get_db
from app.schemas.events import AccessEvent
from app.services.profile_service import ProfileService

router = APIRouter(prefix="/users", tags=["profiles"])


def display_name(user_id: str) -> str:
    return user_id.replace("-", " ").title()


@router.get("")
def users(search: str = "", limit: int = Query(20, ge=1, le=100), db: Session = Depends(get_db)):
    query = select(UserRecord).order_by(desc(UserRecord.last_seen)).limit(limit)
    if search:
        pattern = f"%{search}%"
        query = query.where(UserRecord.user_id.ilike(pattern) | UserRecord.role.ilike(pattern) |
                            UserRecord.department.ilike(pattern))
    return [{"user_id": row.user_id, "entity_id": row.user_id, "entity_type": row.entity_type,
             "display_name": display_name(row.user_id), "role": row.role,
             "department": row.department, "last_seen": row.last_seen} for row in db.scalars(query)]


def latest_event(user_id: str, db: Session) -> AccessEvent | None:
    record = db.scalar(select(EventRecord).where(EventRecord.entity_id == user_id).order_by(desc(EventRecord.timestamp)).limit(1))
    return AccessEvent.model_validate(record.raw_event) if record else None


@router.get("/{user_id}/profile")
def profile(user_id: str, db: Session = Depends(get_db)):
    event = latest_event(user_id, db)
    if not event: raise HTTPException(404, "user profile not found")
    service = ProfileService(db); summary = service.summary(service.baseline_for(event))
    return {"user_id": user_id, "entity_id": user_id, "entity_type": event.entity_type,
            "display_name": display_name(user_id), "role": event.user_role,
            "department": event.department, "profile_maturity": "mature" if not summary["cold_start"] else "building",
            "trusted_event_count": summary["event_count"],
            "cold_start_explanation": ("This entity has insufficient trusted history. Peer or global behavior is being used as the baseline."
                                       if summary["cold_start"] else None), **summary}


@router.get("/{user_id}/timeline")
def timeline(user_id: str, limit: int = Query(100, ge=1, le=500), db: Session = Depends(get_db)):
    query = select(EventRecord).outerjoin(EventRecord.prediction).options(joinedload(EventRecord.prediction)).where(
        EventRecord.entity_id == user_id).order_by(desc(EventRecord.timestamp)).limit(limit)
    return [{"event": row.raw_event, "risk_score": row.prediction.risk_score if row.prediction else None,
             "predicted_attack": row.prediction.predicted_attack if row.prediction else None} for row in db.scalars(query).unique()]
