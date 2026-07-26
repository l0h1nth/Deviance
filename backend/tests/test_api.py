import uuid

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import app
from helpers import event


def payload(**changes):
    data=event(event_id=f"api-{uuid.uuid4().hex}",**changes).model_dump(mode="json")
    return data


def auth_headers(client: TestClient) -> dict[str, str]:
    response=client.post("/api/auth/login",json={"username":"admin","password":"admin"})
    assert response.status_code==200
    return {"Authorization":f"Bearer {response.json()['access_token']}"}


def test_production_rejects_demo_secrets():
    with pytest.raises(RuntimeError, match="ADMIN_PASSWORD, AUTH_SECRET"):
        Settings(environment="production").validate_security()
    Settings(environment="production", admin_password="not-demo", auth_secret="a-long-random-secret").validate_security()


def test_health_and_malformed_event():
    with TestClient(app) as client:
        assert client.get("/api/health").status_code==200
        assert client.get("/api/alerts").status_code==401
        assert client.post("/api/auth/login",json={"username":"admin","password":"wrong"}).status_code==401
        headers=auth_headers(client)
        assert client.get("/api/auth/me").json()["role"]=="administrator"
        assert client.get("/api/auth/me",headers=headers).json()["role"]=="administrator"
        bad=payload();bad["latitude"]=999
        assert client.post("/api/events/ingest",json=bad,headers=headers).status_code==422


def test_auth_uses_cookie_and_rejects_url_tokens():
    with TestClient(app) as client:
        login = client.post("/api/auth/login", json={"username":"admin","password":"admin"})
        assert login.status_code == 200
        assert "httponly" in login.headers["set-cookie"].lower()
        token = login.json()["access_token"]
        client.cookies.clear()
        assert client.get(f"/api/alerts?token={token}").status_code == 401
        assert client.post("/api/auth/logout").status_code == 401

        auth_headers(client)
        assert client.post("/api/auth/logout").status_code == 204
        assert client.get("/api/auth/me").status_code == 401


def test_model_api_exposes_cold_start_safety_metrics():
    with TestClient(app) as client:
        response = client.get("/api/metrics/model", headers=auth_headers(client))
        assert response.status_code == 200
        cold = response.json()["metrics"]["audit"]["cold_start_evaluation"]
        assert cold["overall"]["normal_count"] > 0
        assert cold["attack_challenge"]["event_count"] > 0
        assert set(cold["attack_challenge"]["by_attack_class"]) == {
            "brute_force", "credential_stuffing", "device_spoofing",
            "impossible_travel", "lateral_movement", "low_slow_exfiltration",
        }


def test_behavioral_drift_api_exposes_frozen_daily_model():
    with TestClient(app) as client:
        response = client.get("/api/behavior/rankings", headers=auth_headers(client))
        assert response.status_code == 200
        body = response.json()
        assert body["model_ready"] is True
        assert body["window_days"] == 30
        assert body["minimum_history_days"] == 7
        assert 0 < body["threshold"] <= 1
        assert isinstance(body["rankings"], list)


def test_ingestion_alert_and_analyst_feedback():
    with TestClient(app) as client:
        headers=auth_headers(client)
        result=None
        for i in range(7):
            item=payload(authentication_result="failure" if i<6 else "success",device_id="unknown-attack-device",
                         claimed_device_id="d1", device_fingerprint="malicious-fingerprint-999",
                         device_mac_hash="malicious-mac-999", source_ip="198.51.100.200",
                         country="Germany", city="Berlin", latitude=52.52, longitude=13.405,
                         event_type="login" if i<6 else "admin_action",
                         auth_method="password" if i<6 else "not_applicable",
                         resource_id="prod-console", resource_type="infrastructure", resource_sensitivity=1.0,
                         destination_host="prod-console.internal", network_protocol="ssh", destination_port=22,
                         command_sequence=["remote_exec", "dump_config"], bytes_uploaded=8_000_000,
                         bytes_downloaded=25_000_000, is_privileged_action=True)
            response=client.post("/api/events/ingest",json=item,headers=headers);assert response.status_code==200,response.text;result=response.json()
        assert 0<=result["risk_score"]<=100 and result["predicted_attack"]
        alerts=client.get("/api/alerts",headers=headers).json();assert alerts
        alert_id=alerts[0]["id"]
        update=client.patch(f"/api/alerts/{alert_id}",headers=headers,json={"status":"false_positive","analyst":"pytest","comment":"validated"})
        assert update.status_code==200 and update.json()["status"]=="false_positive"
        detail=client.get(f"/api/alerts/{alert_id}",headers=headers).json();assert detail["feedback"]
