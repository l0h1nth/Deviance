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
        self.db = db; self.settings = get_settings(); self.pipeline = FeaturePipeline()
        if self.__class__._bundle is None:
            self.__class__._bundle = ModelBundle.load(self.settings.model_dir / "current.joblib", self.settings.model_dir)
            self.__class__._bundle.validate(self.pipeline.names)
        self.bundle = self.__class__._bundle
        self.profiles = ProfileService(db, self.bundle.bootstrap_profiles)

    @classmethod
    def reload(cls): cls._bundle = None

    def _history(self, event: AccessEvent, limit: int = 3000) -> list[AccessEvent]:
        records = list(self.db.scalars(select(EventRecord).where(EventRecord.timestamp < event.timestamp)
                                      .order_by(EventRecord.timestamp.desc()).limit(limit)))
        history = []
        for record in reversed(records):
            try: history.append(AccessEvent.model_validate(record.raw_event))
            except ValueError: continue
        return history

    def _sequence_vectors(self, event: AccessEvent) -> np.ndarray:
        rows = list(self.db.scalars(select(PredictionRecord).join(PredictionRecord.event)
                    .where(EventRecord.entity_id == event.entity_id, EventRecord.timestamp < event.timestamp)
                    .order_by(EventRecord.timestamp.desc()).limit(self.bundle.sequence_detector.window_size)))
        rows.reverse()
        return np.asarray([[row.features.get(name, 0.0) for name in self.pipeline.names] for row in rows], dtype=float)

    def process(self, event: AccessEvent, trusted_override: bool = False) -> dict:
        started = perf_counter()
        if self.db.scalar(select(EventRecord).where(EventRecord.event_id == event.event_id)):
            raise ValueError(f"event_id {event.event_id} already exists")
        baseline = self.profiles.baseline_for(event); history = self._history(event)
        entity = self.db.scalar(select(UserRecord).where(UserRecord.user_id == event.entity_id))
        if not entity:
            entity = UserRecord(user_id=event.entity_id, entity_type=event.entity_type,
                                role=event.user_role, department=event.department); self.db.add(entity)
        else:
            entity.entity_type, entity.role, entity.department, entity.last_seen = event.entity_type, event.user_role, event.department, event.timestamp
        device = self.db.scalar(select(DeviceRecord).where(DeviceRecord.device_id == event.device_id))
        if not device:
            device = DeviceRecord(device_id=event.device_id, user_id=event.entity_id, fingerprint=event.device_fingerprint,
                                  operating_system=event.operating_system, firmware_version=event.firmware_version,
                                  mac_hash=event.device_mac_hash, browser=event.browser); self.db.add(device)
        else:
            device.last_seen, device.fingerprint = event.timestamp, event.device_fingerprint
        vector, metadata = self.pipeline.transform_one(event, history, baseline)
        inference = self.bundle.infer(vector, self._sequence_vectors(event))
        risk_data = RiskService(self.bundle.risk_weights, self.bundle.priority_threshold).score(
            inference, inference["scaled_vector"], event, baseline.confidence)
        contributions = explain_features(metadata["values"], inference["scaled_vector"], self.bundle.attack_classifier.feature_importances_)
        feature_evidence = [{
            "feature": definition.name, "value": float(metadata["values"][definition.name]),
            "baseline": 1.0 if definition.name in {"unique_destination_hosts_5m", "source_ip_unique_entities_5m", "concurrent_session_count_5m"} else 0.0,
            "deviation": float(abs(inference["scaled_vector"][index])), "description": definition.description,
        } for index, definition in enumerate(registry.definitions)]
        cold_start = baseline.baseline_type != "entity"; predicted = inference["predicted_attack"]
        explanation = human_explanation(contributions, baseline.baseline_type, cold_start)
        latency_ms = (perf_counter() - started) * 1000
        event_record = EventRecord(event_id=event.event_id, timestamp=event.timestamp, entity_id=event.entity_id,
            entity_type=event.entity_type, user_id=event.entity_id, device_id=event.device_id, department=event.department,
            event_type=event.event_type, raw_event=event.model_dump(mode="json"), trusted=False)
        self.db.add(event_record); self.db.flush()
        self.db.add(FeatureVectorRecord(event_db_id=event_record.id, values=metadata["values"],
                    feature_schema_version=self.bundle.feature_schema_version,
                    baseline_metadata={key: metadata[key] for key in ("baseline_type", "historical_events", "baseline_confidence", "profile_version", "last_updated")}))
        explanation_json = {"top_contributing_features": contributions, "feature_evidence": feature_evidence,
                            "risk_composition": risk_data["risk_composition"], "text": explanation,
                            "recommended_actions": RiskService.actions(predicted, risk_data["severity"]), "cold_start": cold_start,
                            "sequence_window": self.bundle.sequence_detector.window_size,
                            "behavioral_score": inference["behavioral_score"],
                            "domain_anomaly_scores": inference["domain_anomaly_scores"]}
        prediction = PredictionRecord(event_db_id=event_record.id, features=metadata["values"],
            anomaly_score=inference["anomaly_score"], sequence_anomaly_score=inference["sequence_anomaly_score"],
            predicted_attack=predicted, classifier_confidence=inference["classifier_confidence"],
            class_probabilities=inference["class_probabilities"], risk_score=risk_data["risk_score"],
            severity=risk_data["severity"], explanation=explanation_json, baseline_type=baseline.baseline_type,
            baseline_confidence=baseline.confidence, model_version=self.bundle.version,
            feature_schema_version=self.bundle.feature_schema_version, latency_ms=latency_ms)
        self.db.add(prediction); self.db.flush()
        alert = None
        if risk_data["risk_score"] >= self.bundle.alert_threshold:
            time_bucket = int(event.timestamp.timestamp() // 900)
            incident_key = f"{event.entity_id}:{predicted}:{time_bucket}"
            alert = self.db.scalar(select(AlertRecord).where(AlertRecord.incident_key == incident_key))
            if alert:
                alert.event_count += 1; alert.last_event_at = event.timestamp
                if risk_data["risk_score"] > alert.max_risk_score:
                    alert.prediction_id, alert.max_risk_score = prediction.id, risk_data["risk_score"]
            else:
                alert = AlertRecord(prediction_id=prediction.id, incident_key=incident_key, event_count=1,
                                    max_risk_score=risk_data["risk_score"], last_event_at=event.timestamp, status="open")
                self.db.add(alert)
            self.db.flush()
        automatically_trusted = risk_data["risk_score"] <= self.settings.profile_update_max_risk and predicted == "normal"
        if trusted_override or automatically_trusted:
            event_record.trusted = True; device.trusted_event_count += 1; self.profiles.update_trusted(event)
        drift_values = {**metadata["values"], "anomaly_score": inference["anomaly_score"],
                        "sequence_anomaly_score": inference["sequence_anomaly_score"]}
        drift = DriftService(self.db).observe(event.entity_id, drift_values) if event_record.trusted else []
        self.db.commit()
        display = "Unknown behavioral anomaly" if predicted == "unknown_anomaly" else (
            f"Possible {predicted.replace('_', ' ').title()}" if inference["classifier_confidence"] < .6 and predicted != "normal"
            else predicted.replace("_", " ").title())
        return {
            "event_id": event.event_id, "entity_id": event.entity_id, "entity_type": event.entity_type,
            "anomaly_score": inference["anomaly_score"], "sequence_anomaly_score": inference["sequence_anomaly_score"],
            "behavioral_score": inference["behavioral_score"],
            "domain_anomaly_scores": inference["domain_anomaly_scores"],
            "predicted_attack": predicted, "display_attack": display,
            "class_probabilities": inference["class_probabilities"], "classifier_confidence": inference["classifier_confidence"],
            "model_confidence": risk_data["model_confidence"], "baseline_confidence": baseline.confidence,
            "risk_score": risk_data["risk_score"], "severity": risk_data["severity"],
            "top_contributing_features": contributions, "explanation": explanation,
            "recommended_actions": explanation_json["recommended_actions"], "baseline_type": baseline.baseline_type,
            "historical_events": baseline.event_count, "cold_start": cold_start, "model_version": self.bundle.version,
            "feature_schema_version": self.bundle.feature_schema_version, "alert_id": alert.id if alert else None,
            "incident_event_count": alert.event_count if alert else 0, "latency_ms": latency_ms,
            "drift_detected": bool(drift), "user_id": event.entity_id, "device_id": event.device_id,
            "timestamp": event.timestamp.isoformat(), "event_type": event.event_type,
            "location": {"country": event.country, "city": event.city, "latitude": event.latitude, "longitude": event.longitude},
            "authentication_result": event.authentication_result, "features": metadata["values"],
            "feature_evidence": feature_evidence, "risk_composition": risk_data["risk_composition"],
            "event": event.model_dump(mode="json"), "trusted": event_record.trusted,
            "trust_source": "pre_reviewed_synthetic_drift" if trusted_override else "automatic_low_risk" if automatically_trusted else None,
        }
