from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import desc, select
from sqlalchemy.orm import Session, joinedload

from app.database.models import AlertRecord, AnalystFeedback, EventRecord, PredictionRecord
from app.database.session import get_db
from app.schemas.alerts import AlertUpdate

router = APIRouter(tags=["alerts"])


def alert_dict(alert: AlertRecord, detail: bool = False) -> dict:
    prediction, event = alert.prediction, alert.prediction.event
    result = {"id": alert.id, "timestamp": event.timestamp, "user_id": event.user_id, "device_id": event.device_id,
              "predicted_attack": prediction.predicted_attack, "risk_score": prediction.risk_score,
              "severity": prediction.severity, "confidence": prediction.classifier_confidence, "status": alert.status,
              "explanation": prediction.explanation.get("text", "")}
    if detail:
        result.update(event=event.raw_event, features=prediction.features, anomaly_score=prediction.anomaly_score,
                      class_probabilities=prediction.class_probabilities, baseline_type=prediction.baseline_type,
                      baseline_confidence=prediction.baseline_confidence, model_version=prediction.model_version,
                      feature_schema_version=prediction.feature_schema_version, explanation_detail=prediction.explanation,
                      feedback=[{"status": f.status, "analyst": f.analyst, "comment": f.comment, "created_at": f.created_at} for f in alert.feedback])
    return result


def query_alert(alert_id: int, db: Session) -> AlertRecord | None:
    return db.scalars(select(AlertRecord).options(joinedload(AlertRecord.feedback),
        joinedload(AlertRecord.prediction).joinedload(PredictionRecord.event)).where(AlertRecord.id == alert_id)).unique().first()


@router.get("/alerts")
def list_alerts(severity: str | None = None, attack_type: str | None = None, user_id: str | None = None,
                status: str | None = None, limit: int = Query(100, ge=1, le=500), db: Session = Depends(get_db)):
    query = select(AlertRecord).join(AlertRecord.prediction).join(PredictionRecord.event).options(
        joinedload(AlertRecord.prediction).joinedload(PredictionRecord.event)).order_by(desc(AlertRecord.created_at)).limit(limit)
    if severity: query = query.where(PredictionRecord.severity == severity)
    if attack_type: query = query.where(PredictionRecord.predicted_attack == attack_type)
    if user_id: query = query.where(EventRecord.user_id == user_id)
    if status: query = query.where(AlertRecord.status == status)
    return [alert_dict(alert) for alert in db.scalars(query).unique()]


@router.get("/alerts/{alert_id}")
def get_alert(alert_id: int, db: Session = Depends(get_db)):
    alert = query_alert(alert_id, db)
    if not alert: raise HTTPException(404, "alert not found")
    event = alert.prediction.event
    timeline_query = select(EventRecord).where(EventRecord.user_id == event.user_id).order_by(desc(EventRecord.timestamp)).limit(20)
    result = alert_dict(alert, True); result["timeline"] = [row.raw_event for row in db.scalars(timeline_query)]; return result


@router.patch("/alerts/{alert_id}")
def update_alert(alert_id: int, update: AlertUpdate, db: Session = Depends(get_db)):
    alert = query_alert(alert_id, db)
    if not alert: raise HTTPException(404, "alert not found")
    alert.status = update.status; feedback = AnalystFeedback(alert_id=alert.id, status=update.status,
                                                              analyst=update.analyst, comment=update.comment)
    db.add(feedback)
    if update.status == "false_positive": alert.prediction.event.trusted = True
    db.commit(); db.refresh(feedback)
    return {"id": alert.id, "status": alert.status, "feedback_id": feedback.id}

