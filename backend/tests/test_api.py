import uuid

from fastapi.testclient import TestClient

from app.main import app
from helpers import event


def payload(**changes):
    data=event(event_id=f"api-{uuid.uuid4().hex}",**changes).model_dump(mode="json",exclude={"ground_truth_label"})
    return data


def test_health_and_malformed_event():
    with TestClient(app) as client:
        assert client.get("/api/health").status_code==200
        bad=payload();bad["latitude"]=999
        assert client.post("/api/events/ingest",json=bad).status_code==422


def test_ingestion_alert_and_analyst_feedback():
    with TestClient(app) as client:
        result=None
        for i in range(7):
            item=payload(authentication_result="failure" if i<6 else "success",device_id="unknown-attack-device",
                         device_fingerprint="malicious-fingerprint-999",source_ip="198.51.100.200")
            response=client.post("/api/events/ingest",json=item);assert response.status_code==200,response.text;result=response.json()
        assert 0<=result["risk_score"]<=100 and result["predicted_attack"]
        alerts=client.get("/api/alerts").json();assert alerts
        alert_id=alerts[0]["id"]
        update=client.patch(f"/api/alerts/{alert_id}",json={"status":"false_positive","analyst":"pytest","comment":"validated"})
        assert update.status_code==200 and update.json()["status"]=="false_positive"
        detail=client.get(f"/api/alerts/{alert_id}").json();assert detail["feedback"]

