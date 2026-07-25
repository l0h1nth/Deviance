from datetime import timedelta

import numpy as np
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database.models import ProfileRecord
from app.database.session import Base
from app.ml.sequence_model import GRUSequenceDetector
from app.services.profile_service import (
    ProfileService,
    empty_profile_data,
    is_cold_start_baseline,
)
from helpers import event


def profile_service(tmp_path, bootstrap=None):
    engine = create_engine(f"sqlite:///{tmp_path/'profiles.db'}")
    Base.metadata.create_all(engine)
    db = sessionmaker(bind=engine)()
    return db, ProfileService(db, bootstrap or {})


def test_benign_entity_moves_from_global_prior_to_mature_profile_after_twelve_trusted_events(tmp_path):
    bootstrap = {"global:organization": {"count": 500, "data": empty_profile_data()}}
    db, service = profile_service(tmp_path, bootstrap)
    sample = event(entity_id="cold-user", user_id="cold-user", device_id="cold-device",
                   claimed_device_id="cold-device")

    initial = service.baseline_for(sample)
    assert initial.baseline_type == "global_prior"
    assert is_cold_start_baseline(initial.baseline_type)

    for index in range(11):
        service.update_trusted(sample.model_copy(update={
            "event_id": f"cold-normal-{index}", "timestamp": sample.timestamp + timedelta(minutes=index),
        }))
    db.flush()
    assert service.baseline_for(sample).baseline_type == "global_prior"

    service.update_trusted(sample.model_copy(update={
        "event_id": "cold-normal-11", "timestamp": sample.timestamp + timedelta(minutes=11),
    }))
    db.flush()
    mature = service.baseline_for(sample)
    assert mature.baseline_type == "entity" and mature.event_count == 12
    assert not is_cold_start_baseline(mature.baseline_type)


def test_mature_device_fallback_for_a_new_user_is_not_reported_as_cold_start(tmp_path):
    db, service = profile_service(tmp_path)
    db.add(ProfileRecord(profile_key="device:shared-edge", profile_type="device", subject_id="shared-edge",
                         event_count=12, profile_data=empty_profile_data(), version=12))
    db.flush()
    baseline = service.baseline_for(event(
        entity_id="new-user", user_id="new-user", entity_type="user",
        user_role="engineer", department="Engineering", device_id="shared-edge",
        claimed_device_id="shared-edge", device_class="workstation",
    ))
    assert baseline.baseline_type == "device"
    assert not is_cold_start_baseline(baseline.baseline_type)


def test_gru_waits_for_three_previous_events_during_cold_start():
    detector = GRUSequenceDetector(32, feature_indices=np.arange(16))
    current = np.zeros(32)
    for history_length in range(3):
        assert detector.score_one(np.zeros((history_length, 32)), current) == 0.0
