import json

from fastapi import APIRouter, BackgroundTasks, Depends
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.database.models import PredictionRecord
from app.database.session import get_db
from app.ml.model_bundle import ModelBundle
from app.ml.training import train
from app.services.prediction_service import PredictionService
from app.services.drift_service import DriftService

router = APIRouter(prefix="/models", tags=["models"])
training_state = {"status": "idle", "error": None}


def train_task():
    settings = get_settings(); training_state.update(status="training", error=None)
    try:
        current_path = settings.model_dir / "current.joblib"
        old = ModelBundle.load(current_path, settings.model_dir) if current_path.exists() else None
        candidate = train(settings.data_dir, settings.model_dir, seed=settings.random_seed, artifact_name="candidate.joblib")
        old_test = old.metrics.get("test", {}) if old else {}
        new_test = candidate.metrics.get("test", {})
        improves_f1 = not old or new_test.get("macro_f1", 0) >= old_test.get("macro_f1", 0) * .98
        controls_fpr = not old or new_test.get("alert_false_positive_rate", 1) <= old_test.get("alert_false_positive_rate", 0) + .001
        preserves_budget_precision = not old or new_test.get("top_1_percent", {}).get("precision", 0) >= old_test.get("top_1_percent", {}).get("precision", 0) * .95
        comparison = {"old_version": old.version if old else None, "candidate_version": candidate.version,
                      "old_macro_f1": old_test.get("macro_f1"), "candidate_macro_f1": new_test.get("macro_f1"),
                      "old_alert_fpr": old_test.get("alert_false_positive_rate"), "candidate_alert_fpr": new_test.get("alert_false_positive_rate"),
                      "old_top_1_precision": old_test.get("top_1_percent", {}).get("precision"),
                      "candidate_top_1_precision": new_test.get("top_1_percent", {}).get("precision")}
        if improves_f1 and controls_fpr and preserves_budget_precision:
            candidate.save(current_path)
            (settings.model_dir / "metrics.json").write_text(json.dumps(candidate.metrics, indent=2))
            PredictionService.reload(); training_state.update(status="ready", comparison=comparison, activated=True)
        else:
            training_state.update(status="candidate_rejected", comparison=comparison, activated=False)
    except Exception as exc:
        training_state.update(status="failed", error=str(exc))


@router.post("/train", status_code=202)
def trigger_training(tasks: BackgroundTasks):
    if training_state["status"] == "training": return training_state
    tasks.add_task(train_task); return {"status": "training"}


@router.get("/status")
def status(db: Session = Depends(get_db)):
    settings = get_settings(); path = settings.model_dir / "current.joblib"
    result = {**training_state, "model_ready": path.is_file()}
    if path.is_file():
        bundle = ModelBundle.load(path, settings.model_dir)
        result.update(model_version=bundle.version, feature_schema_version=bundle.feature_schema_version,
                      alert_threshold=bundle.alert_threshold, behavioral_threshold=bundle.behavioral_threshold,
                      priority_threshold=bundle.priority_threshold,
                      classifier=bundle.attack_classifier.model_metadata(),
                      last_trained_at=bundle.metrics.get("trained_at"), artifact_status="loaded",
                      average_inference_latency_ms=round(float(db.scalar(select(func.avg(PredictionRecord.latency_ms))) or 0), 2),
                      drift_state=DriftService(db).summary()["state"])
    else:
        result.update(artifact_status="missing", drift_state="unknown", average_inference_latency_ms=0)
    return result
