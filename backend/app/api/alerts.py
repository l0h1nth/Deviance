from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import desc, select
from sqlalchemy.orm import Session, joinedload

from app.database.models import AlertRecord, AnalystFeedback, EventRecord, PredictionRecord
from app.database.session import get_db
from app.schemas.alerts import AlertUpdate
from app.schemas.events import AccessEvent
from app.services.profile_service import ProfileService

router = APIRouter(tags=["alerts"])


def alert_dict(alert: AlertRecord, detail: bool = False) -> dict:
    prediction, event = alert.prediction, alert.prediction.event
    result = {"id": alert.id, "timestamp": event.timestamp, "entity_id": event.entity_id,
              "entity_type": event.entity_type, "user_id": event.user_id, "device_id": event.device_id,
              "predicted_attack": prediction.predicted_attack, "risk_score": prediction.risk_score,
              "display_attack": (f"Possible {prediction.predicted_attack.replace('_', ' ').title()}"
                                 if prediction.classifier_confidence < .6 and prediction.predicted_attack != "normal"
                                 else prediction.predicted_attack.replace('_', ' ').title()),
              "severity": prediction.severity, "anomaly_score": prediction.anomaly_score,
              "sequence_anomaly_score": prediction.sequence_anomaly_score,
              "classifier_confidence": prediction.classifier_confidence, "confidence": prediction.classifier_confidence,
              "incident_event_count": alert.event_count, "incident_key": alert.incident_key,
              "status": alert.status, "location": f"{event.raw_event.get('city')}, {event.raw_event.get('country')}",
              "baseline_type": prediction.baseline_type, "model_version": prediction.model_version,
              "explanation": prediction.explanation.get("text", "")}
    if detail:
        result.update(event=event.raw_event, features=prediction.features, anomaly_score=prediction.anomaly_score,
                      class_probabilities=prediction.class_probabilities, baseline_type=prediction.baseline_type,
                      baseline_confidence=prediction.baseline_confidence, model_version=prediction.model_version,
                      feature_schema_version=prediction.feature_schema_version, explanation_detail=prediction.explanation,
                      feature_evidence=prediction.explanation.get("feature_evidence", []),
                      risk_composition=prediction.explanation.get("risk_composition", {}),
                      cold_start=prediction.explanation.get("cold_start", prediction.baseline_type != "entity"),
                      recommended_actions=prediction.explanation.get("recommended_actions", []),
                      feedback=[{"status": f.status, "analyst": f.analyst, "comment": f.comment, "created_at": f.created_at} for f in alert.feedback])
    return result


def query_alert(alert_id: int, db: Session) -> AlertRecord | None:
    return db.scalars(select(AlertRecord).options(joinedload(AlertRecord.feedback),
        joinedload(AlertRecord.prediction).joinedload(PredictionRecord.event)).where(AlertRecord.id == alert_id)).unique().first()


@router.get("/alerts")
def list_alerts(severity: str | None = None, attack_type: str | None = None, user_id: str | None = None,
                status: str | None = None, limit: int = Query(100, ge=1, le=500), db: Session = Depends(get_db)):
    query = select(AlertRecord).join(AlertRecord.prediction).join(PredictionRecord.event).options(
        joinedload(AlertRecord.prediction).joinedload(PredictionRecord.event)).order_by(desc(PredictionRecord.risk_score)).limit(limit)
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
    timeline_query = select(EventRecord).options(joinedload(EventRecord.prediction)).where(
        EventRecord.entity_id == event.entity_id).order_by(desc(EventRecord.timestamp)).limit(20)
    result = alert_dict(alert, True)
    result["timeline"] = [{"event": row.raw_event,
        "prediction": ({"anomaly_score": row.prediction.anomaly_score, "sequence_anomaly_score": row.prediction.sequence_anomaly_score,
                        "classifier_confidence": row.prediction.classifier_confidence,
                        "predicted_attack": row.prediction.predicted_attack, "risk_score": row.prediction.risk_score,
                        "severity": row.prediction.severity} if row.prediction else None)}
        for row in db.scalars(timeline_query).unique()]
    return result


@router.patch("/alerts/{alert_id}")
def update_alert(alert_id: int, update: AlertUpdate, db: Session = Depends(get_db)):
    alert = query_alert(alert_id, db)
    if not alert: raise HTTPException(404, "alert not found")
    alert.status = update.status; feedback = AnalystFeedback(alert_id=alert.id, status=update.status,
                                                              analyst=update.analyst, comment=update.comment)
    db.add(feedback)
    if update.status == "false_positive" and not alert.prediction.event.trusted:
        alert.prediction.event.trusted = True
        ProfileService(db).update_trusted(AccessEvent.model_validate(alert.prediction.event.raw_event))
    db.commit(); db.refresh(feedback)
    return {"id": alert.id, "status": alert.status, "feedback_id": feedback.id}
