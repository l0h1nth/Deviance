from datetime import timedelta

import pytest
from pydantic import ValidationError

from app.ml.feature_pipeline import FeaturePipeline, fingerprint_distance
from app.ml.feature_registry import FEATURE_SCHEMA_VERSION, registry
from app.ml.training import MemoryProfiles
from app.services.profile_service import Baseline, EMPTY_PROFILE
from app.utils.geo import haversine_km
from helpers import event


def baseline(**updates):
    data={key:list(value) for key,value in EMPTY_PROFILE.items()};data.update(updates)
    return Baseline("entity",20,.8,1,"now",data)


def test_raw_event_validation():
    with pytest.raises(ValidationError): event(latitude=100)
    with pytest.raises(ValidationError): event(timestamp=event().timestamp.replace(tzinfo=None))


def test_exact_feature_order_and_schema():
    assert len(registry.names)==24
    assert FeaturePipeline.names==["failed_login_count_1m","login_attempt_count_5m","login_hour_deviation","new_device_score",
        "device_fingerprint_distance","location_novelty_score","required_travel_speed_kmph","unique_destination_hosts_5m",
        "sensitive_resource_access_ratio","download_volume_zscore","session_duration_zscore","successful_login_after_failures_score",
        "source_ip_unique_entities_5m","source_ip_failure_ratio_5m","auth_method_novelty_score",
        "time_since_previous_event_log_seconds","concurrent_session_count_5m","command_sequence_novelty_score",
        "resource_novelty_score","privilege_expansion_score","protocol_port_novelty_score","upload_volume_zscore",
        "sensitive_download_count_30d","off_hours_activity_score"]
    assert FEATURE_SCHEMA_VERSION=="2.0.0"


def test_haversine_and_impossible_travel():
    assert 5500<haversine_km(51.5074,-.1278,40.7128,-74.006)<5700
    first=event(timestamp=event().timestamp-timedelta(minutes=30),latitude=51.5074,longitude=-.1278)
    current=event(event_id="second",latitude=40.7128,longitude=-74.006)
    vector,_=FeaturePipeline().transform_one(current,[first],baseline())
    assert vector[6]>10_000


def test_device_features_and_rolling_windows():
    now=event(); history=[event(event_id=f"f{i}",timestamp=now.timestamp-timedelta(seconds=10+i),authentication_result="failure") for i in range(4)]
    vector,_=FeaturePipeline().transform_one(now,history,baseline(devices=["trusted"],fingerprints=["zzzzzz123456"]))
    assert vector[0]==4 and vector[1]==4 and vector[3]==1 and vector[4]>0
    assert fingerprint_distance("abc",["abc"])==0


def test_cold_start_fallback():
    profiles=MemoryProfiles(entity_min=2,peer_min=2); e=event()
    assert profiles.baseline(e).baseline_type=="global_default"
    profiles.update(e,"normal"); assert profiles.baseline(e).baseline_type=="global"
