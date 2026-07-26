from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.config import get_settings
from app.database.session import get_db
from app.ml.model_bundle import ModelBundle
from app.services.behavior_ranking_service import BehaviorRankingService

router = APIRouter(prefix="/behavior", tags=["entity behavior"])


def service(db: Session) -> BehaviorRankingService:
    settings = get_settings()
    try:
        bundle = ModelBundle.load(settings.model_dir / "current.joblib", settings.model_dir)
    except FileNotFoundError as exc:
        raise HTTPException(503, "model artifact is not available") from exc
    return BehaviorRankingService(db, bundle)


@router.get("/rankings")
def rankings(db: Session = Depends(get_db)):
    return service(db).rankings()


@router.get("/entities/{entity_id}")
def entity_behavior(entity_id: str, db: Session = Depends(get_db)):
    return service(db).entity_history(entity_id)
