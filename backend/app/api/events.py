from fastapi import APIRouter, Depends, Query
from sqlalchemy import desc, select
from sqlalchemy.orm import Session, joinedload

from app.database.models import EventRecord
from app.database.session import get_db
from app.services.profile_service import is_cold_start_baseline

router = APIRouter(tags=["events"])


def event_dict(row: EventRecord) -> dict:
    raw, prediction = row.raw_event, row.prediction
    result = {"event_id": row.event_id, "timestamp": row.timestamp, "entity_id": row.entity_id,
              "entity_type": row.entity_type, "user_id": row.user_id,
              "device_id": row.device_id, "event_type": row.event_type,
              "location": {"city": raw.get("city"), "country": raw.get("country"),
                           "latitude": raw.get("latitude"), "longitude": raw.get("longitude")},
              "authentication_result": raw.get("authentication_result"), "trusted": row.trusted, "event": raw}
    if prediction:
        result.update({"predicted_attack": prediction.predicted_attack,
                       "display_attack": (f"Possible {prediction.predicted_attack.replace('_', ' ').title()}"
                                          if prediction.classifier_confidence < .6 and prediction.predicted_attack != "normal"
                                          else prediction.predicted_attack.replace('_', ' ').title()),
                       "anomaly_score": prediction.anomaly_score,
                       "sequence_anomaly_score": prediction.sequence_anomaly_score,
                       "classifier_confidence": prediction.classifier_confidence,
                       "class_probabilities": prediction.class_probabilities, "risk_score": prediction.risk_score,
                       "severity": prediction.severity, "latency_ms": prediction.latency_ms,
                       "features": prediction.features, "baseline_type": prediction.baseline_type,
                       "baseline_confidence": prediction.baseline_confidence, "model_version": prediction.model_version,
                       "feature_schema_version": prediction.feature_schema_version,
                       "feature_evidence": prediction.explanation.get("feature_evidence", []),
                       "top_contributing_features": prediction.explanation.get("top_contributing_features", []),
                       "risk_composition": prediction.explanation.get("risk_composition", {}),
                       "explanation": prediction.explanation.get("text", ""),
                       "cold_start": prediction.explanation.get("cold_start", is_cold_start_baseline(prediction.baseline_type))})
    return result


@router.get("/events")
def events(user_id: str | None = None, event_type: str | None = None,
           limit: int = Query(100, ge=1, le=500), db: Session = Depends(get_db)):
    query = select(EventRecord).options(joinedload(EventRecord.prediction)).order_by(desc(EventRecord.timestamp)).limit(limit)
    if user_id: query = query.where(EventRecord.user_id == user_id)
    if event_type: query = query.where(EventRecord.event_type == event_type)
    return [event_dict(row) for row in db.scalars(query).unique()]


@router.get("/events/latest")
def latest_event(db: Session = Depends(get_db)):
    row = db.scalar(select(EventRecord).options(joinedload(EventRecord.prediction)).order_by(desc(EventRecord.timestamp)).limit(1))
    return event_dict(row) if row else None
