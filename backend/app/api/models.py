from fastapi import APIRouter, BackgroundTasks

from app.config import get_settings
from app.ml.model_bundle import ModelBundle
from app.ml.training import train
from app.services.prediction_service import PredictionService

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
        controls_fpr = not old or new_test.get("false_positive_rate", 1) <= old_test.get("false_positive_rate", 0) + .01
        comparison = {"old_version": old.version if old else None, "candidate_version": candidate.version,
                      "old_macro_f1": old_test.get("macro_f1"), "candidate_macro_f1": new_test.get("macro_f1"),
                      "old_fpr": old_test.get("false_positive_rate"), "candidate_fpr": new_test.get("false_positive_rate")}
        if improves_f1 and controls_fpr:
            candidate.save(current_path); PredictionService.reload(); training_state.update(status="ready", comparison=comparison, activated=True)
        else:
            training_state.update(status="candidate_rejected", comparison=comparison, activated=False)
    except Exception as exc:
        training_state.update(status="failed", error=str(exc))


@router.post("/train", status_code=202)
def trigger_training(tasks: BackgroundTasks):
    if training_state["status"] == "training": return training_state
    tasks.add_task(train_task); return {"status": "training"}


@router.get("/status")
def status():
    settings = get_settings(); path = settings.model_dir / "current.joblib"
    result = {**training_state, "model_ready": path.is_file()}
    if path.is_file():
        bundle = ModelBundle.load(path, settings.model_dir)
        result.update(model_version=bundle.version, feature_schema_version=bundle.feature_schema_version,
                      alert_threshold=bundle.alert_threshold)
    return result
