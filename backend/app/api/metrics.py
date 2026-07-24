from fastapi import APIRouter, Depends, Query
from sqlalchemy import case, desc, func, select
from sqlalchemy.orm import Session, joinedload

from app.config import get_settings
from app.database.models import AlertRecord, EventRecord, PredictionRecord
from app.database.session import get_db
from app.ml.model_bundle import ModelBundle

router = APIRouter(prefix="/metrics", tags=["metrics"])


@router.get("/overview")
def overview(db: Session = Depends(get_db)):
    total_events = db.scalar(select(func.count(EventRecord.id))) or 0
    total_alerts = db.scalar(select(func.count(AlertRecord.id))) or 0
    critical = db.scalar(select(func.count(PredictionRecord.id)).where(PredictionRecord.severity == "critical")) or 0
    investigations = db.scalar(select(func.count(AlertRecord.id)).where(AlertRecord.status.in_(["open", "investigating"]))) or 0
    false_positive = db.scalar(select(func.count(AlertRecord.id)).where(AlertRecord.status == "false_positive")) or 0
    avg_latency = db.scalar(select(func.avg(PredictionRecord.latency_ms))) or 0
    attacks = dict(db.execute(select(PredictionRecord.predicted_attack, func.count()).group_by(PredictionRecord.predicted_attack)).all())
    trend_rows = list(db.scalars(select(PredictionRecord).order_by(desc(PredictionRecord.id)).limit(50)))
    return {"total_events": total_events, "total_alerts": total_alerts, "critical_alerts": critical,
            "open_investigations": investigations, "false_positive_rate": false_positive / max(total_alerts, 1),
            "average_detection_latency_ms": round(float(avg_latency), 2), "attacks_by_type": attacks,
            "risk_trend": [{"id": row.id, "risk": row.risk_score} for row in reversed(trend_rows)]}


@router.get("/model")
def model_metrics():
    settings = get_settings(); bundle = ModelBundle.load(settings.model_dir / "current.joblib", settings.model_dir)
    return {"model_version": bundle.version, "feature_schema_version": bundle.feature_schema_version,
            "feature_names": bundle.feature_names, "alert_threshold": bundle.alert_threshold,
            "anomaly_model": bundle.anomaly_detector.model_metadata(), "metrics": bundle.metrics}

