import asyncio
import uuid

from fastapi.testclient import TestClient

from app.main import app
from app.services.drift_service import DriftService
from app.services.event_service import EventBus
from helpers import event


def auth(client: TestClient) -> dict[str, str]:
    token = client.post("/api/auth/login", json={"username": "admin", "password": "admin"}).json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def test_simulation_start_stop_model_status_and_notifications():
    with TestClient(app) as client:
        headers = auth(client)
        started = client.post("/api/simulations/start", headers=headers,
            json={"scenario": "brute_force", "interval_ms": 500, "event_count": 8})
        assert started.status_code == 202 and started.json()["status"] == "running"
        stopped = client.post("/api/simulations/stop", headers=headers)
        assert stopped.status_code == 200 and stopped.json()["status"] in {"stopped", "completed"}
        status = client.get("/api/models/status", headers=headers).json()
        assert status["model_ready"] and status["artifact_status"] == "loaded"
        assert status["feature_schema_version"] == "1.0.0" and "average_inference_latency_ms" in status
        notifications = client.get("/api/notifications", headers=headers).json()["notifications"]
        assert any(item["type"] == "simulation_status" for item in notifications)


def test_live_event_bus_delivery():
    async def exercise():
        bus = EventBus()
        stream = bus.subscribe()
        pending = asyncio.create_task(anext(stream))
        await asyncio.sleep(0)
        await bus.publish({"type": "scored_event", "data": {"event_id": "live-test"}})
        message = await asyncio.wait_for(pending, 1)
        await stream.aclose()
        return message
    assert asyncio.run(exercise())["data"]["event_id"] == "live-test"


def test_metrics_consistency_enriched_alert_and_feedback():
    with TestClient(app) as client:
        headers = auth(client)
        latest = None
        for index in range(7):
            payload = event(event_id=f"workflow-{uuid.uuid4().hex}",
                authentication_result="failure" if index < 6 else "success",
                device_id="workflow-unknown-device", device_fingerprint="workflow-malicious-fingerprint",
                source_ip="198.51.100.221").model_dump(mode="json", exclude={"ground_truth_label"})
            response = client.post("/api/events/ingest", json=payload, headers=headers)
            assert response.status_code == 200
            latest = response.json()
        assert latest and latest["alert_id"]
        alerts = client.get("/api/alerts?limit=500", headers=headers).json()
        metrics = client.get("/api/metrics/overview", headers=headers).json()
        assert metrics["total_alerts"] == len(alerts)
        assert metrics["unresolved_alerts"] == sum(row["status"] in {"open", "investigating", "confirmed_threat"} for row in alerts)
        assert sum(metrics["attacks_by_type"].values()) == metrics["total_alerts"]
        detail = client.get(f"/api/alerts/{latest['alert_id']}", headers=headers).json()
        assert len(detail["feature_evidence"]) == 12 and detail["risk_composition"]
        assert detail["risk_score"] != detail["classifier_confidence"] and "anomaly_score" in detail
        update = client.patch(f"/api/alerts/{latest['alert_id']}", headers=headers,
            json={"status": "investigating", "analyst": "workflow-test", "comment": "triage started"})
        assert update.status_code == 200
        history = client.get(f"/api/alerts/{latest['alert_id']}", headers=headers).json()["feedback"]
        assert any(item["status"] == "investigating" and item["analyst"] == "workflow-test" for item in history)


def test_drift_window_progress_is_trusted_only(tmp_path):
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from app.database.session import Base
    engine = create_engine(f"sqlite:///{tmp_path/'progress.db'}"); Base.metadata.create_all(engine)
    db = sessionmaker(bind=engine)(); DriftService._windows.clear(); service = DriftService(db)
    values = {"login_hour_deviation": 0, "location_novelty_score": 0, "new_device_score": 0,
              "download_volume_zscore": 0, "session_duration_zscore": 0, "anomaly_score": 0}
    for _ in range(12): service.observe("trusted-user", values)
    status = DriftService.window_status()[0]
    assert status["reference_window"]["count"] == 12 and status["current_window"]["count"] == 0
    assert status["trusted_events_only"] is True
