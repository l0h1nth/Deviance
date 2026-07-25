from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database.models import DriftEventRecord
from app.database.session import Base
from app.services.drift_service import DriftService


def values(hour: float) -> dict[str, float]:
    return {"access_hour": hour, "location_novelty_score": 0, "new_device_score": 0,
            "download_volume_zscore": 0, "session_duration_zscore": 0, "anomaly_score": 0}


def test_concept_drift_detection(tmp_path):
    engine=create_engine(f"sqlite:///{tmp_path/'drift.db'}");Base.metadata.create_all(engine);db=sessionmaker(bind=engine)()
    service=DriftService(db);service._windows.clear();found=[]
    for i in range(40): found.extend(service.observe("shift-user",values(0 if i<20 else 8)))
    db.commit();assert any(row.feature=="access_hour" for row in found)
