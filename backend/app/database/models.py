from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.session import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class UserRecord(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[str] = mapped_column(String(100), unique=True, index=True)
    entity_type: Mapped[str] = mapped_column(String(30), default="user", index=True)
    role: Mapped[str] = mapped_column(String(80))
    department: Mapped[str] = mapped_column(String(80), index=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class DeviceRecord(Base):
    __tablename__ = "devices"
    id: Mapped[int] = mapped_column(primary_key=True)
    device_id: Mapped[str] = mapped_column(String(100), unique=True, index=True)
    user_id: Mapped[str] = mapped_column(String(100), index=True)
    fingerprint: Mapped[str] = mapped_column(String(256))
    operating_system: Mapped[str] = mapped_column(String(100))
    firmware_version: Mapped[str] = mapped_column(String(100), default="unknown")
    mac_hash: Mapped[str] = mapped_column(String(128), default="unknown")
    browser: Mapped[str] = mapped_column(String(100))
    trusted_event_count: Mapped[int] = mapped_column(Integer, default=0)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class EventRecord(Base):
    __tablename__ = "events"
    id: Mapped[int] = mapped_column(primary_key=True)
    event_id: Mapped[str] = mapped_column(String(100), unique=True, index=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    entity_id: Mapped[str] = mapped_column(String(100), index=True)
    entity_type: Mapped[str] = mapped_column(String(30), index=True)
    user_id: Mapped[str] = mapped_column(String(100), index=True)
    device_id: Mapped[str] = mapped_column(String(100), index=True)
    department: Mapped[str] = mapped_column(String(80), index=True)
    event_type: Mapped[str] = mapped_column(String(50))
    raw_event: Mapped[dict] = mapped_column(JSON)
    trusted: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    prediction: Mapped["PredictionRecord"] = relationship(back_populates="event", uselist=False, cascade="all, delete-orphan")


class FeatureVectorRecord(Base):
    __tablename__ = "feature_vectors"
    id: Mapped[int] = mapped_column(primary_key=True)
    event_db_id: Mapped[int] = mapped_column(ForeignKey("events.id"), unique=True, index=True)
    values: Mapped[dict] = mapped_column(JSON)
    feature_schema_version: Mapped[str] = mapped_column(String(30))
    baseline_metadata: Mapped[dict] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class PredictionRecord(Base):
    __tablename__ = "predictions"
    id: Mapped[int] = mapped_column(primary_key=True)
    event_db_id: Mapped[int] = mapped_column(ForeignKey("events.id"), unique=True)
    features: Mapped[dict] = mapped_column(JSON)
    anomaly_score: Mapped[float] = mapped_column(Float)
    sequence_anomaly_score: Mapped[float] = mapped_column(Float, default=0.0)
    predicted_attack: Mapped[str] = mapped_column(String(50), index=True)
    classifier_confidence: Mapped[float] = mapped_column(Float)
    class_probabilities: Mapped[dict] = mapped_column(JSON)
    risk_score: Mapped[float] = mapped_column(Float, index=True)
    severity: Mapped[str] = mapped_column(String(20), index=True)
    explanation: Mapped[dict] = mapped_column(JSON)
    baseline_type: Mapped[str] = mapped_column(String(30))
    baseline_confidence: Mapped[float] = mapped_column(Float)
    model_version: Mapped[str] = mapped_column(String(80))
    feature_schema_version: Mapped[str] = mapped_column(String(30))
    latency_ms: Mapped[float] = mapped_column(Float)
    event: Mapped[EventRecord] = relationship(back_populates="prediction")
    alert: Mapped["AlertRecord"] = relationship(back_populates="prediction", uselist=False)


class AlertRecord(Base):
    __tablename__ = "alerts"
    id: Mapped[int] = mapped_column(primary_key=True)
    prediction_id: Mapped[int] = mapped_column(ForeignKey("predictions.id"), unique=True)
    incident_key: Mapped[str] = mapped_column(String(220), unique=True, index=True)
    event_count: Mapped[int] = mapped_column(Integer, default=1)
    max_risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    last_event_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    status: Mapped[str] = mapped_column(String(30), default="open", index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)
    prediction: Mapped[PredictionRecord] = relationship(back_populates="alert")
    feedback: Mapped[list["AnalystFeedback"]] = relationship(back_populates="alert", cascade="all, delete-orphan")


class AnalystFeedback(Base):
    __tablename__ = "analyst_feedback"
    id: Mapped[int] = mapped_column(primary_key=True)
    alert_id: Mapped[int] = mapped_column(ForeignKey("alerts.id"), index=True)
    status: Mapped[str] = mapped_column(String(30))
    analyst: Mapped[str] = mapped_column(String(100))
    comment: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    alert: Mapped[AlertRecord] = relationship(back_populates="feedback")


class ProfileRecord(Base):
    __tablename__ = "profiles"
    id: Mapped[int] = mapped_column(primary_key=True)
    profile_key: Mapped[str] = mapped_column(String(220), unique=True, index=True)
    profile_type: Mapped[str] = mapped_column(String(30), index=True)
    subject_id: Mapped[str] = mapped_column(String(180), index=True)
    event_count: Mapped[int] = mapped_column(Integer, default=0)
    profile_data: Mapped[dict] = mapped_column(JSON)
    version: Mapped[int] = mapped_column(Integer, default=1)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class DriftEventRecord(Base):
    __tablename__ = "drift_events"
    id: Mapped[int] = mapped_column(primary_key=True)
    subject_id: Mapped[str] = mapped_column(String(180), index=True)
    feature: Mapped[str] = mapped_column(String(100))
    magnitude: Mapped[float] = mapped_column(Float)
    recommendation: Mapped[str] = mapped_column(Text)
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    metadata_json: Mapped[dict] = mapped_column(JSON, default=dict)


class ModelVersionRecord(Base):
    __tablename__ = "model_versions"
    id: Mapped[int] = mapped_column(primary_key=True)
    version: Mapped[str] = mapped_column(String(80), unique=True)
    feature_schema_version: Mapped[str] = mapped_column(String(30))
    active: Mapped[bool] = mapped_column(Boolean, default=False)
    metrics: Mapped[dict] = mapped_column(JSON, default=dict)
    artifact_path: Mapped[str] = mapped_column(String(500))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
