from sqlalchemy import Column, Integer, String, Float, Boolean, DateTime, ForeignKey, JSON, func
from sqlalchemy.orm import relationship
from app.db.postgres import Base

class Alert(Base):
    """
    SQLAlchemy model representing the 'alerts' table in PostgreSQL.
    Tracks security alerts generated from Phase 5 threat assessments.
    """
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    event_id = Column(String, unique=True, index=True, nullable=False)  # For absolute event idempotency
    deduplication_key = Column(String, index=True, nullable=False)      # SHA256 of canonicalized fields
    dataset = Column(String, index=True, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)

    status = Column(String, index=True, nullable=False, default="NEW")  # NEW, ACKNOWLEDGED, INVESTIGATING, RESOLVED, FALSE_POSITIVE, CLOSED
    severity = Column(String, index=True, nullable=False)
    priority = Column(String, index=True, nullable=False)               # P1, P2, P3, P4
    signal_status = Column(String, index=True, nullable=False)          # normal, anomaly_only, intrusion_only, confirmed_attack

    # Detection snapshots (Immutable detection metrics)
    threat_score = Column(Float, nullable=False)
    risk_level = Column(String, index=True, nullable=False)
    anomaly_detected = Column(Boolean, nullable=False)
    anomaly_score = Column(Float, nullable=False)
    is_attack = Column(Boolean, nullable=False)
    attack_probability = Column(Float, nullable=False)
    attack_type = Column(String, index=True, nullable=True)            # E.g. DDoS, PortScan, or None/null
    classification_confidence = Column(Float, nullable=True)

    # Optional network details
    source_ip = Column(String, nullable=True)
    destination_ip = Column(String, nullable=True)
    source_port = Column(Integer, nullable=True)
    destination_port = Column(Integer, nullable=True)
    protocol = Column(String, nullable=True)

    # Alert descriptions and metadata
    title = Column(String, nullable=False)
    description = Column(String, nullable=True)
    reasons = Column(JSON, nullable=True)
    repeat_count = Column(Integer, nullable=False, default=1)
    source = Column(String, nullable=False, default="NETSHIELD_AI")
    alert_type = Column(String, nullable=False)                         # ANOMALY_DETECTED, INTRUSION_DETECTED, CONFIRMED_ATTACK
    pipeline_version = Column(String, nullable=False, default="1.0")

    # Correlation fields
    correlation_type = Column(String, nullable=False, default="NONE")   # NONE, SAME_SOURCE, SAME_SOURCE_ATTACK, MANUAL
    correlation_reason = Column(String, nullable=True)

    incident_id = Column(Integer, ForeignKey("incidents.id", ondelete="SET NULL"), index=True, nullable=True)
    assigned_to = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    acknowledged_by = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    resolved_by = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)

    acknowledged_at = Column(DateTime(timezone=True), nullable=True)
    resolved_at = Column(DateTime(timezone=True), nullable=True)

    # Relationships
    incident = relationship("Incident", back_populates="alerts")
    assigned_user = relationship("User", foreign_keys=[assigned_to])
    acknowledged_user = relationship("User", foreign_keys=[acknowledged_by])
    resolved_user = relationship("User", foreign_keys=[resolved_by])
    history = relationship("AlertHistory", back_populates="alert", cascade="all, delete-orphan")
