from fastapi import APIRouter, Depends
from sqlalchemy import desc, select
from sqlalchemy.orm import Session, joinedload

from app.api.models import training_state
from app.database.models import AlertRecord, DriftEventRecord, PredictionRecord
from app.database.session import get_db
from app.services.simulation_service import simulation_manager

router = APIRouter(tags=["notifications"])


@router.get("/notifications")
def notifications(db: Session = Depends(get_db)):
    items = []
    alerts = db.scalars(select(AlertRecord).join(AlertRecord.prediction).options(
        joinedload(AlertRecord.prediction).joinedload(PredictionRecord.event)).where(
        PredictionRecord.severity == "critical").order_by(desc(AlertRecord.created_at)).limit(5)).unique()
    for alert in alerts:
        items.append({"id": f"alert-{alert.id}", "type": "critical_alert", "title": "Critical behavior alert",
                      "message": f"{alert.prediction.predicted_attack.replace('_', ' ')} · {alert.prediction.event.user_id}",
                      "created_at": alert.created_at, "page": "investigation", "alert_id": alert.id})
    recent_drifts = db.scalars(select(DriftEventRecord).order_by(desc(DriftEventRecord.detected_at)).limit(20))
    drifts = [row for row in recent_drifts if row.metadata_json.get("review_status", "pending") in {"pending", "investigating"}][:3]
    for drift in drifts:
        items.append({"id": f"drift-{drift.id}", "type": "drift_warning", "title": "Concept drift warning",
                      "message": f"{drift.subject_id} · {drift.feature.replace('_', ' ')}",
                      "created_at": drift.detected_at, "page": "drift"})
    if training_state.get("status") != "idle":
        items.append({"id": f"model-{training_state.get('status')}", "type": "model_training",
                      "title": "Model training", "message": training_state.get("status", "idle").replace("_", " "),
                      "created_at": None, "page": "model"})
    simulation = simulation_manager.status()
    if simulation["status"] != "idle":
        items.append({"id": f"simulation-{simulation['started_at']}", "type": "simulation_status",
                      "title": "Synthetic simulation", "message": f"{simulation['scenario']} · {simulation['status']}",
                      "created_at": simulation["started_at"], "page": "overview"})
    return {"notifications": items}
