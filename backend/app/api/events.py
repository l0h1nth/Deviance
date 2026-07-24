from fastapi import APIRouter, Depends, Query
from sqlalchemy import desc, select
from sqlalchemy.orm import Session, joinedload

from app.database.models import EventRecord
from app.database.session import get_db

router = APIRouter(tags=["events"])


@router.get("/events")
def events(user_id: str | None = None, event_type: str | None = None,
           limit: int = Query(100, ge=1, le=500), db: Session = Depends(get_db)):
    query = select(EventRecord).options(joinedload(EventRecord.prediction)).order_by(desc(EventRecord.timestamp)).limit(limit)
    if user_id: query = query.where(EventRecord.user_id == user_id)
    if event_type: query = query.where(EventRecord.event_type == event_type)
    rows = db.scalars(query).unique()
    return [{"event": row.raw_event, "trusted": row.trusted,
             "prediction": ({"risk_score": row.prediction.risk_score, "severity": row.prediction.severity,
                             "predicted_attack": row.prediction.predicted_attack} if row.prediction else None)} for row in rows]

