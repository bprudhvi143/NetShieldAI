from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, func
from sqlalchemy.orm import relationship
from app.db.postgres import Base

class Incident(Base):
    """
    SQLAlchemy model representing the 'incidents' table in PostgreSQL.
    A security case comprising one or more related alerts.
    """
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, nullable=False)
    description = Column(String, nullable=True)
    status = Column(String, index=True, nullable=False, default="OPEN")   # OPEN, INVESTIGATING, CONTAINED, RESOLVED, CLOSED
    priority = Column(String, index=True, nullable=False, default="P4")    # P1, P2, P3, P4
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)

    assigned_to = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    resolved_by = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    resolved_at = Column(DateTime(timezone=True), nullable=True)

    # Relationships
    alerts = relationship("Alert", back_populates="incident")
    assigned_user = relationship("User", foreign_keys=[assigned_to])
    resolved_user = relationship("User", foreign_keys=[resolved_by])
    history = relationship("IncidentHistory", back_populates="incident", cascade="all, delete-orphan")
