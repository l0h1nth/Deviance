from pathlib import Path

from app.ml.model_bundle import ModelBundle


def load_metrics(model_dir: Path) -> dict:
    bundle = ModelBundle.load(model_dir / "current.joblib", model_dir)
    return bundle.metrics

