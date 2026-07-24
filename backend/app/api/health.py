from fastapi import APIRouter

from app.config import get_settings

router = APIRouter(tags=["health"])


@router.get("/health")
def health():
    settings = get_settings(); model = settings.model_dir / "current.joblib"
    return {"status": "ok", "service": settings.app_name, "model_ready": model.is_file(), "environment": settings.environment}

