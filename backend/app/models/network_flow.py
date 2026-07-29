from sqlalchemy import Column, Integer, String, Float, Boolean, DateTime, ForeignKey, JSON, func
from sqlalchemy.orm import relationship
from app.db.postgres import Base

class NetworkFlow(Base):
    """
    SQLAlchemy model representing the 'network_flows' table in PostgreSQL.
    Stores raw network flow telemetry, extracted feature snapshots,
    and associated threat classification results.
    """
    __tablename__ = "network_flows"

    id = Column(Integer, primary_key=True, index=True)
    event_id = Column(String, unique=True, index=True, nullable=False)
    captured_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    flow_start = Column(DateTime(timezone=True), nullable=False)
    flow_end = Column(DateTime(timezone=True), nullable=False)

    dataset_profile = Column(String, index=True, nullable=False)  # 'cicids2017' or 'unsw_nb15'

    # Network 5-tuple
    source_ip = Column(String, index=True, nullable=True)
    destination_ip = Column(String, index=True, nullable=True)
    source_port = Column(Integer, nullable=True)
    destination_port = Column(Integer, nullable=True)
    protocol = Column(String, index=True, nullable=True)

    # Basic Flow Counters
    packet_count = Column(Integer, nullable=False, default=0)
    byte_count = Column(Integer, nullable=False, default=0)
    duration = Column(Float, nullable=False, default=0.0)

    # Feature Snapshot (dict of all extracted features)
    feature_snapshot = Column(JSON, nullable=True)

    # Anomaly Detection Outcomes
    anomaly_detected = Column(Boolean, nullable=False)
    anomaly_score = Column(Float, nullable=False)

    # Supervised Intrusion Detection Outcomes
    is_attack = Column(Boolean, nullable=False)
    attack_probability = Column(Float, nullable=False)
    normal_probability = Column(Float, nullable=False)

    # Multiclass Outcomes
    attack_type = Column(String, index=True, nullable=True)
    classification_confidence = Column(Float, nullable=True)

    # Risk Scoring Outcomes
    threat_score = Column(Float, nullable=False)
    risk_level = Column(String, index=True, nullable=False)
    severity = Column(String, nullable=False)
    impact_level = Column(String, nullable=False)
    priority = Column(String, index=True, nullable=False)

    # Ingestion Signal Status (normal, anomaly_only, intrusion_only, confirmed_attack)
    signal_status = Column(String, index=True, nullable=False)

    # Optional linkages to Alert and Incident
    alert_id = Column(Integer, ForeignKey("alerts.id", ondelete="SET NULL"), index=True, nullable=True)
    incident_id = Column(Integer, ForeignKey("incidents.id", ondelete="SET NULL"), index=True, nullable=True)

    # System Diagnostics
    processing_latency_ms = Column(Float, nullable=False, default=0.0)
    model_version = Column(String, nullable=False, default="1.0")
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    # Relationships
    alert = relationship("Alert", foreign_keys=[alert_id])
    incident = relationship("Incident", foreign_keys=[incident_id])
