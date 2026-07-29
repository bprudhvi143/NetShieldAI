from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, JSON, func
from sqlalchemy.orm import relationship
from app.db.postgres import Base

class AlertHistory(Base):
    """
    SQLAlchemy model representing the 'alert_history' table in PostgreSQL.
    Audit log of all actions performed on a specific alert.
    """
    __tablename__ = "alert_history"

    id = Column(Integer, primary_key=True, index=True)
    alert_id = Column(Integer, ForeignKey("alerts.id", ondelete="CASCADE"), nullable=False, index=True)
    action = Column(String, nullable=False)                            # E.g. CREATED, STATUS_CHANGED, ASSIGNED
    old_status = Column(String, nullable=True)
    new_status = Column(String, nullable=True)
    performed_by = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    timestamp = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    action_metadata = Column(JSON, nullable=True)                              # Detailed changes, e.g. {"reason": "..."}

    # Relationships
    alert = relationship("Alert", back_populates="history")
    performed_by_user = relationship("User")
