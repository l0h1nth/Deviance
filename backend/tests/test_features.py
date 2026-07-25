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
    with pytest.raises(ValidationError): event(event_type="api_call")
    with pytest.raises(ValidationError): event(event_type="device_connection")
    api = event(event_type="api_call", action="invoke", access_outcome="allowed",
                api_route="/api/v1/profile", http_method="GET", http_status_code=200,
                api_latency_ms=42, credential_id_hash="credential-hash", token_scopes=["profile:read"])
    assert api.api_route == "/api/v1/profile"


def test_exact_feature_order_and_schema():
    assert len(registry.names)==32
    assert FeaturePipeline.names==["failed_auth_count_1m","auth_attempt_count_5m","successful_auth_after_failures_score",
        "source_ip_unique_entities_5m","source_ip_failure_ratio_5m","auth_method_novelty_score","api_call_rate_1m_zscore",
        "api_error_ratio_5m","api_endpoint_method_novelty_score","source_ip_novelty_score","new_device_score",
        "device_fingerprint_distance","claimed_observed_device_mismatch_score","device_posture_novelty_score",
        "location_novelty_score","vpn_aware_travel_anomaly_score","access_hour_deviation_score",
        "unique_destination_hosts_5m","resource_novelty_score","event_action_novelty_score",
        "resource_access_entropy_24h","resource_sensitivity_deviation_score","privilege_expansion_score",
        "protocol_port_novelty_score","command_transition_novelty_score","download_volume_zscore","upload_volume_zscore",
        "cumulative_external_transfer_24h_zscore","session_duration_zscore","inter_event_time_zscore",
        "active_concurrent_session_count","sensitive_access_rate_30d_zscore"]
    assert FEATURE_SCHEMA_VERSION=="3.0.0"
    assert len(FeaturePipeline.sequence_feature_indices)==16


def test_haversine_and_impossible_travel():
    assert 5500<haversine_km(51.5074,-.1278,40.7128,-74.006)<5700
    first=event(timestamp=event().timestamp-timedelta(minutes=30),latitude=51.5074,longitude=-.1278)
    current=event(event_id="second",latitude=40.7128,longitude=-74.006)
    vector,_=FeaturePipeline().transform_one(current,[first],baseline())
    assert vector[FeaturePipeline.names.index("vpn_aware_travel_anomaly_score")]>.9


def test_device_features_and_rolling_windows():
    now=event(); history=[event(event_id=f"f{i}",timestamp=now.timestamp-timedelta(seconds=10+i),authentication_result="failure") for i in range(4)]
    vector,_=FeaturePipeline().transform_one(now,history,baseline(devices=["trusted"],fingerprints=["zzzzzz123456"]))
    assert vector[0]==4 and vector[1]==5
    assert vector[FeaturePipeline.names.index("new_device_score")]==1
    assert vector[FeaturePipeline.names.index("device_fingerprint_distance")]>0
    assert fingerprint_distance("abc",["abc"])==0


def test_claimed_device_mismatch_is_explicit_evidence():
    current = event(device_id="observed-device", claimed_device_id="claimed-device")
    vector,_ = FeaturePipeline().transform_one(current, [], baseline(devices=["observed-device"]))
    assert vector[FeaturePipeline.names.index("claimed_observed_device_mismatch_score")] == 1


def test_cold_start_fallback():
    profiles=MemoryProfiles(entity_min=2,peer_min=2); e=event()
    assert profiles.baseline(e).baseline_type=="global_default"
    profiles.update(e,"normal"); assert profiles.baseline(e).baseline_type=="global"
