import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from app.database.models import DriftEventRecord, DriftWindowRecord
from app.database.session import Base
from app.services.drift_service import DriftService


def values(hour: float, **overrides: float) -> dict[str, float]:
    result = {
        "access_hour": hour, "location_novelty_score": 0, "new_device_score": 0,
        "download_volume_zscore": 0, "resource_novelty_score": 0,
        "privilege_expansion_score": 0, "sequence_anomaly_score": 0, "anomaly_score": 0,
    }
    result.update(overrides)
    return result


def database(tmp_path, name="drift.db"):
    engine = create_engine(f"sqlite:///{tmp_path/name}")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)


def test_concept_drift_detection_and_evidence(tmp_path):
    factory = database(tmp_path)
    with factory() as db:
        service = DriftService(db); found = []
        for index in range(40):
            found.extend(service.observe("shift-user", values(9 if index < 20 else 19)))
        db.commit()
        access = next(row for row in found if row.feature == "access_hour")
        assert access.magnitude >= 2.5
        assert access.metadata_json["ks_distance"] == 1
        assert access.metadata_json["review_status"] == "pending"
        assert access.metadata_json["trusted_events_only"] is True


def test_stable_trusted_traffic_rolls_without_false_drift(tmp_path):
    factory = database(tmp_path, "stable.db")
    with factory() as db:
        service = DriftService(db); found = []
        for index in range(80):
            found.extend(service.observe("steady-user", values(9 + (index % 4) * .1)))
        db.commit()
        assert found == []
        access = db.scalar(select(DriftWindowRecord).where(DriftWindowRecord.feature == "access_hour"))
        assert access and access.baseline_version >= 3 and access.status == "collecting_current"


def test_access_hour_is_circular_across_midnight(tmp_path):
    factory = database(tmp_path, "midnight.db")
    with factory() as db:
        service = DriftService(db); found = []
        for hour in [23.8, 23.9, 0.0, 0.1] * 5: found.extend(service.observe("night-user", values(hour)))
        for hour in [23.9, 0.0, 0.1, 0.2] * 5: found.extend(service.observe("night-user", values(hour)))
        assert not any(row.feature == "access_hour" for row in found)


def test_windows_persist_across_service_instances(tmp_path):
    factory = database(tmp_path, "persistent.db")
    with factory() as first:
        for _ in range(20): DriftService(first).observe("persistent-user", values(8))
        first.commit()
    with factory() as second:
        found = []
        service = DriftService(second)
        for _ in range(20): found.extend(service.observe("persistent-user", values(18)))
        second.commit()
        assert any(row.feature == "access_hour" for row in found)
        status = service.window_status()[0]
        assert status["status"] == "review_required"
        assert "access_hour" in status["flagged_features"]


def test_approved_adaptation_promotes_reviewed_window(tmp_path):
    factory = database(tmp_path, "approve.db")
    with factory() as db:
        service = DriftService(db); found = []
        for index in range(40): found.extend(service.observe("approved-user", values(9 if index < 20 else 19)))
        event = next(row for row in found if row.feature == "access_hour")
        service.review(event, "approve_adaptation", "admin", "Shift change verified")
        db.commit()
        window = db.scalar(select(DriftWindowRecord).where(DriftWindowRecord.feature == "access_hour"))
        assert window and window.reference_values == [19.0] * 20 and window.current_values == []
        assert window.baseline_version == 2 and window.adapted_at is not None
        assert event.metadata_json["review_status"] == "approved_adaptation"
        assert event.metadata_json["review_history"][0]["analyst"] == "admin"


def test_rejected_change_preserves_known_good_reference(tmp_path):
    factory = database(tmp_path, "reject.db")
    with factory() as db:
        service = DriftService(db); found = []
        for index in range(40): found.extend(service.observe("rejected-user", values(9 if index < 20 else 19)))
        event = next(row for row in found if row.feature == "access_hour")
        service.review(event, "reject_change", "admin", "Unapproved behavior")
        db.commit()
        window = db.scalar(select(DriftWindowRecord).where(DriftWindowRecord.feature == "access_hour"))
        assert window and window.reference_values == [9.0] * 20 and window.current_values == []
        assert window.baseline_version == 1 and window.status == "collecting_current"
        assert event.metadata_json["review_status"] == "rejected_change"
        with pytest.raises(ValueError):
            service.review(event, "approve_adaptation", "admin")


def test_summary_reports_governed_lifecycle(tmp_path):
    factory = database(tmp_path, "summary.db")
    with factory() as db:
        service = DriftService(db)
        for _ in range(8): service.observe("summary-user", values(9))
        summary = service.summary()
        assert summary["state"] == "learning"
        assert summary["monitored_entities"] == 1 and summary["trusted_events"] == 8
        assert summary["signals_monitored"] == 8
        assert summary["automatic_retraining"] is False
