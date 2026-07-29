from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, JSON, func
from sqlalchemy.orm import relationship
from app.db.postgres import Base

class IncidentHistory(Base):
    """
    SQLAlchemy model representing the 'incident_history' table in PostgreSQL.
    Audit log of all actions performed on a specific incident.
    """
    __tablename__ = "incident_history"

    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(Integer, ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True)
    action = Column(String, nullable=False)                            # E.g. CREATED, ALERT_ATTACHED, STATUS_CHANGED
    old_status = Column(String, nullable=True)
    new_status = Column(String, nullable=True)
    performed_by = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    timestamp = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    action_metadata = Column(JSON, nullable=True)

    # Relationships
    incident = relationship("Incident", back_populates="history")
    performed_by_user = relationship("User")
