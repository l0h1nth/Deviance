from time import perf_counter

import numpy as np
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.database.models import AlertRecord, DeviceRecord, EventRecord, FeatureVectorRecord, PredictionRecord, UserRecord
from app.ml.explainability import explain_features, human_explanation
from app.ml.feature_pipeline import FeaturePipeline
from app.ml.feature_registry import registry
from app.ml.model_bundle import ModelBundle
from app.schemas.events import AccessEvent
from app.services.drift_service import DriftService
from app.services.profile_service import ProfileService
from app.services.risk_service import RiskService


class PredictionService:
    _bundle: ModelBundle | None = None

    def __init__(self, db: Session):
        self.db = db; self.settings = get_settings(); self.pipeline = FeaturePipeline(); self.profiles = ProfileService(db)
        if self.__class__._bundle is None:
            self.__class__._bundle = ModelBundle.load(self.settings.model_dir / "current.joblib", self.settings.model_dir)
            self.__class__._bundle.validate(self.pipeline.names)
        self.bundle = self.__class__._bundle

    @classmethod
    def reload(cls): cls._bundle = None

    def _history(self, event: AccessEvent, limit: int = 1000) -> list[AccessEvent]:
        records = list(self.db.scalars(select(EventRecord).where(EventRecord.timestamp < event.timestamp)
                                      .order_by(EventRecord.timestamp.desc()).limit(limit)))
        history = []
        for record in reversed(records):
            try: history.append(AccessEvent.model_validate(record.raw_event))
            except ValueError: continue
        return history

    def process(self, event: AccessEvent, trusted_override: bool = False) -> dict:
        started = perf_counter()
        if self.db.scalar(select(EventRecord).where(EventRecord.event_id == event.event_id)):
            raise ValueError(f"event_id {event.event_id} already exists")
        baseline = self.profiles.baseline_for(event); history = self._history(event)
        user = self.db.scalar(select(UserRecord).where(UserRecord.user_id == event.user_id))
        if not user:
            user = UserRecord(user_id=event.user_id, role=event.user_role, department=event.department); self.db.add(user)
        else:
            user.role, user.department, user.last_seen = event.user_role, event.department, event.timestamp
        device = self.db.scalar(select(DeviceRecord).where(DeviceRecord.device_id == event.device_id))
        if not device:
            device = DeviceRecord(device_id=event.device_id, user_id=event.user_id, fingerprint=event.device_fingerprint,
                                  operating_system=event.operating_system, browser=event.browser); self.db.add(device)
        else:
            device.last_seen = event.timestamp
        vector, metadata = self.pipeline.transform_one(event, history, baseline)
        inference = self.bundle.infer(vector)
        risk_data = RiskService().score(inference, inference["scaled_vector"], event, baseline.confidence)
        contributions = explain_features(metadata["values"], inference["scaled_vector"], self.bundle.attack_classifier.feature_importances_)
        feature_evidence = [{
            "feature": definition.name,
            "value": float(metadata["values"][definition.name]),
            "baseline": 1.0 if definition.name == "unique_destination_hosts_5m" else 0.0,
            "deviation": float(abs(inference["scaled_vector"][index])),
            "description": definition.description,
        } for index, definition in enumerate(registry.definitions)]
        cold_start = baseline.baseline_type != "user"
        explanation = human_explanation(contributions, baseline.baseline_type, cold_start)
        predicted = inference["predicted_attack"]
        latency_ms = (perf_counter() - started) * 1000
        event_record = EventRecord(event_id=event.event_id, timestamp=event.timestamp, user_id=event.user_id,
            device_id=event.device_id, department=event.department, event_type=event.event_type,
            raw_event=event.model_dump(mode="json"), trusted=False)
        self.db.add(event_record); self.db.flush()
        self.db.add(FeatureVectorRecord(event_db_id=event_record.id, values=metadata["values"],
                    feature_schema_version=self.bundle.feature_schema_version,
                    baseline_metadata={key: metadata[key] for key in ("baseline_type", "historical_events", "baseline_confidence",
                                                                      "profile_version", "last_updated")}))
        explanation_json = {"top_contributing_features": contributions, "feature_evidence": feature_evidence,
                            "risk_composition": risk_data["risk_composition"], "text": explanation,
                            "recommended_actions": RiskService.actions(predicted, risk_data["severity"]), "cold_start": cold_start}
        prediction = PredictionRecord(event_db_id=event_record.id, features=metadata["values"],
            anomaly_score=inference["anomaly_score"], predicted_attack=predicted,
            classifier_confidence=inference["classifier_confidence"], class_probabilities=inference["class_probabilities"],
            risk_score=risk_data["risk_score"], severity=risk_data["severity"], explanation=explanation_json,
            baseline_type=baseline.baseline_type, baseline_confidence=baseline.confidence, model_version=self.bundle.version,
            feature_schema_version=self.bundle.feature_schema_version, latency_ms=latency_ms)
        self.db.add(prediction); self.db.flush()
        alert = None
        if risk_data["risk_score"] >= self.bundle.alert_threshold:
            alert = AlertRecord(prediction_id=prediction.id, status="open"); self.db.add(alert); self.db.flush()
        automatically_trusted = risk_data["risk_score"] <= self.settings.profile_update_max_risk and predicted == "normal"
        if trusted_override or automatically_trusted:
            event_record.trusted = True; device.trusted_event_count += 1; self.profiles.update_trusted(event)
        drift_values = {**metadata["values"], "anomaly_score": inference["anomaly_score"]}
        drift = DriftService(self.db).observe(event.user_id, drift_values) if event_record.trusted else []
        self.db.commit()
        return {
            "event_id": event.event_id, "anomaly_score": inference["anomaly_score"], "predicted_attack": predicted,
            "display_attack": (f"Possible {predicted.replace('_', ' ').title()}"
                               if inference["classifier_confidence"] < .6 and predicted != "normal"
                               else predicted.replace('_', ' ').title()),
            "class_probabilities": inference["class_probabilities"], "classifier_confidence": inference["classifier_confidence"],
            "model_confidence": risk_data["model_confidence"], "baseline_confidence": baseline.confidence,
            "risk_score": risk_data["risk_score"], "severity": risk_data["severity"],
            "top_contributing_features": contributions, "explanation": explanation,
            "recommended_actions": explanation_json["recommended_actions"], "baseline_type": baseline.baseline_type,
            "historical_events": baseline.event_count, "cold_start": cold_start, "model_version": self.bundle.version,
            "feature_schema_version": self.bundle.feature_schema_version, "alert_id": alert.id if alert else None,
            "latency_ms": latency_ms, "drift_detected": bool(drift), "user_id": event.user_id, "device_id": event.device_id,
            "timestamp": event.timestamp.isoformat(), "event_type": event.event_type,
            "location": {"country": event.country, "city": event.city, "latitude": event.latitude, "longitude": event.longitude},
            "authentication_result": event.authentication_result, "features": metadata["values"],
            "feature_evidence": feature_evidence, "risk_composition": risk_data["risk_composition"],
            "event": event.model_dump(mode="json", exclude={"ground_truth_label"}),
            "trusted": event_record.trusted,
            "trust_source": "pre_reviewed_synthetic_drift" if trusted_override else "automatic_low_risk" if automatically_trusted else None,
        }
