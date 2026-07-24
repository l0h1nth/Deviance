from fastapi import APIRouter, Depends, Query
from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from app.database.models import DriftEventRecord
from app.database.session import get_db

router = APIRouter(tags=["drift"])


@router.get("/drift")
def drift(limit: int = Query(100, ge=1, le=500), db: Session = Depends(get_db)):
    rows = db.scalars(select(DriftEventRecord).order_by(desc(DriftEventRecord.detected_at)).limit(limit))
    return [{"id": row.id, "subject_id": row.subject_id, "feature": row.feature, "magnitude": row.magnitude,
             "recommendation": row.recommendation, "detected_at": row.detected_at, "metadata": row.metadata_json} for row in rows]

