from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database.models import EventRecord, PredictionRecord
from app.database.session import Base
from app.main import app
from app.services.partitioning import partition_for_entity, partition_key
from app.services.state_service import SequenceStateStore
from helpers import event


def authenticate(client: TestClient) -> dict[str, str]:
    token = client.post("/api/auth/login", json={"username": "admin", "password": "admin"}).json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def test_entity_partition_is_stable_and_valid():
    assert partition_key("usr-0042") == "usr-0042"
    assert partition_for_entity("usr-0042", 32) == partition_for_entity("usr-0042", 32)
    partitions = {partition_for_entity(f"usr-{index:04d}", 32) for index in range(200)}
    assert len(partitions) >= 28


def test_sequence_state_survives_service_and_session_restart(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path/'sequence.db'}")
    Base.metadata.create_all(engine); sessions = sessionmaker(bind=engine, expire_on_commit=False)
    timestamp = datetime.now(timezone.utc) - timedelta(minutes=1)
    with sessions() as db:
        stored = EventRecord(event_id="persisted-sequence", timestamp=timestamp, entity_id="usr-state",
            entity_type="user", user_id="usr-state", device_id="dev-state", department="Engineering",
            event_type="login", raw_event={}, trusted=False)
        db.add(stored); db.flush()
        db.add(PredictionRecord(event_db_id=stored.id, features={"one": 1.0, "two": 2.0},
            anomaly_score=0, sequence_anomaly_score=0, predicted_attack="normal", classifier_confidence=1,
            class_probabilities={"normal": 1}, risk_score=0, severity="low", explanation={},
            baseline_type="global", baseline_confidence=.5, model_version="test",
            feature_schema_version="test", latency_ms=1)); db.commit()
    with sessions() as restarted_db:
        values = SequenceStateStore(restarted_db).previous_vectors(
            "usr-state", timestamp + timedelta(seconds=1), ["one", "two"], 12)
        assert values.tolist() == [[1.0, 2.0]]


def test_concurrent_http_ingestion_returns_partition_metadata():
    with TestClient(app) as client:
        headers = authenticate(client)
        payloads = [event(event_id=f"concurrent-{uuid4().hex}", entity_id=f"usr-concurrent-{index}",
                          user_id=f"usr-concurrent-{index}", device_id=f"dev-concurrent-{index}",
                          claimed_device_id=f"dev-concurrent-{index}",
                          device_fingerprint=f"fingerprint-concurrent-{index}",
                          device_mac_hash=f"mac-hash-concurrent-{index}").model_dump(mode="json")
                    for index in range(4)]
        with ThreadPoolExecutor(max_workers=4) as workers:
            responses = list(workers.map(lambda payload: client.post(
                "/api/events/ingest", json=payload, headers=headers), payloads))
        assert all(response.status_code == 200 for response in responses)
        for payload, response in zip(payloads, responses):
            body = response.json()
            assert body["stream_partition_key"] == payload["entity_id"]
            assert body["stream_partition"] == partition_for_entity(payload["entity_id"], 32)


def test_system_design_endpoint_documents_production_substitutions():
    with TestClient(app) as client:
        body = client.get("/api/system/design", headers=authenticate(client)).json()
        assert body["partitioning"]["key"] == "entity_id"
        assert body["runtime_state"]["concept_drift"].startswith("durable")
        assert "Kafka" in body["production_substitutions"]["stream"]
