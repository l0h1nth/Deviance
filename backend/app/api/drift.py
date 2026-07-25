from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from app.database.models import DriftEventRecord
from app.database.session import get_db
from app.schemas.drift import DriftReview
from app.services.drift_service import DriftService

router = APIRouter(tags=["drift"])


def drift_dict(row: DriftEventRecord) -> dict:
    metadata = row.metadata_json or {}
    return {
        "id": row.id, "subject_id": row.subject_id, "feature": row.feature, "magnitude": row.magnitude,
        "recommendation": row.recommendation, "detected_at": row.detected_at, "status": "drift_detected",
        "review_status": metadata.get("review_status", "pending"),
        "previous_distribution": metadata.get("previous_distribution", {}),
        "current_distribution": metadata.get("current_distribution", {}),
        "drift_confidence": metadata.get("drift_confidence", 0),
        "severity": metadata.get("severity", "medium"), "domain": metadata.get("domain", "behavior"),
        "ks_distance": metadata.get("ks_distance", 0), "absolute_shift": metadata.get("absolute_shift", 0),
        "baseline_version": metadata.get("baseline_version", 1),
        "review_history": metadata.get("review_history", []), "metadata": metadata,
    }


@router.get("/drift")
def drift(limit: int = Query(100, ge=1, le=500), db: Session = Depends(get_db)):
    service = DriftService(db)
    rows = db.scalars(select(DriftEventRecord).order_by(desc(DriftEventRecord.detected_at)).limit(limit))
    return {"events": [drift_dict(row) for row in rows], "windows": service.window_status(),
            "summary": service.summary()}


@router.patch("/drift/{drift_id}")
def review_drift(drift_id: int, review: DriftReview, request: Request, db: Session = Depends(get_db)):
    row = db.get(DriftEventRecord, drift_id)
    if row is None:
        raise HTTPException(404, "drift finding not found")
    try:
        DriftService(db).review(row, review.action, request.state.user["sub"], review.comment)
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc
    db.commit(); db.refresh(row)
    return drift_dict(row)
