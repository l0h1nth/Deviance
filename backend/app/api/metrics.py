from fastapi import APIRouter, Depends, Query
from datetime import datetime, timedelta, timezone

from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session, joinedload

from app.config import get_settings
from app.database.models import AlertRecord, EventRecord, PredictionRecord
from app.database.session import get_db
from app.ml.model_bundle import ModelBundle

router = APIRouter(prefix="/metrics", tags=["metrics"])


@router.get("/overview")
def overview(db: Session = Depends(get_db)):
    events_analyzed = db.scalar(select(func.count(EventRecord.id))) or 0
    total_alerts = db.scalar(select(func.count(AlertRecord.id))) or 0
    open_alerts = db.scalar(select(func.count(AlertRecord.id)).where(AlertRecord.status == "open")) or 0
    investigating_alerts = db.scalar(select(func.count(AlertRecord.id)).where(AlertRecord.status == "investigating")) or 0
    confirmed_alerts = db.scalar(select(func.count(AlertRecord.id)).where(AlertRecord.status == "confirmed_threat")) or 0
    reviewed_alerts = db.scalar(select(func.count(AlertRecord.id)).where(
        AlertRecord.status.in_(["confirmed_threat", "false_positive", "closed"]))) or 0
    unresolved_alerts = open_alerts + investigating_alerts + confirmed_alerts
    critical_alerts = db.scalar(select(func.count(AlertRecord.id)).join(AlertRecord.prediction).where(
        PredictionRecord.severity == "critical")) or 0
    since = datetime.now(timezone.utc) - timedelta(hours=24)
    reviewed_24h = db.scalar(select(func.count(AlertRecord.id)).where(
        AlertRecord.updated_at >= since, AlertRecord.status.in_(["confirmed_threat", "false_positive", "closed"]))) or 0
    false_positive_24h = db.scalar(select(func.count(AlertRecord.id)).where(
        AlertRecord.updated_at >= since, AlertRecord.status == "false_positive")) or 0
    avg_latency = db.scalar(select(func.avg(PredictionRecord.latency_ms))) or 0
    attacks = dict(db.execute(select(PredictionRecord.predicted_attack, func.count(AlertRecord.id)).join(
        AlertRecord, AlertRecord.prediction_id == PredictionRecord.id).group_by(PredictionRecord.predicted_attack)).all())
    trend_rows = list(db.scalars(select(PredictionRecord).order_by(desc(PredictionRecord.id)).limit(50)))
    settings = get_settings(); bundle = ModelBundle.load(settings.model_dir / "current.joblib", settings.model_dir)
    holdout_fpr = float(bundle.metrics.get("test", {}).get("false_positive_rate", 0))
    holdout = bundle.metrics.get("test", {}); budget = holdout.get("top_1_percent", {})
    return {"events_analyzed": events_analyzed, "total_alerts": total_alerts,
            "unresolved_alerts": unresolved_alerts, "open_alerts": open_alerts,
            "investigating_alerts": investigating_alerts, "reviewed_alerts": reviewed_alerts,
            "critical_alerts": critical_alerts,
            "analyst_false_positive_rate_24h": false_positive_24h / max(reviewed_24h, 1),
            "holdout_false_positive_rate": holdout_fpr,
            "holdout_alert_rate": float(holdout.get("alert_rate", 0)),
            "top_1_percent_precision": float(budget.get("precision", 0)),
            "top_1_percent_recall": float(budget.get("recall", 0)),
            "alerts_per_10000": float(holdout.get("alerts_per_10000", 0)),
            "average_inference_latency_ms": round(float(avg_latency), 2), "attacks_by_type": attacks,
            "risk_trend": [{"id": row.id, "risk": row.risk_score} for row in reversed(trend_rows)]}


@router.get("/model")
def model_metrics():
    settings = get_settings(); bundle = ModelBundle.load(settings.model_dir / "current.joblib", settings.model_dir)
    return {"model_version": bundle.version, "feature_schema_version": bundle.feature_schema_version,
            "feature_names": bundle.feature_names, "alert_threshold": bundle.alert_threshold,
            "anomaly_model": bundle.anomaly_detector.model_metadata(),
            "sequence_model": bundle.sequence_detector.model_metadata(), "metrics": bundle.metrics}
