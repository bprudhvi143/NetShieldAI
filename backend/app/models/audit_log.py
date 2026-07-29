from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, func
from sqlalchemy.orm import relationship
from app.db.postgres import Base

class AuditLog(Base):
    """
    SQLAlchemy model representing the 'audit_logs' table in PostgreSQL.
    Tracks security incidents, authentication actions, and system updates.
    """
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    action = Column(String, index=True, nullable=False)  # LOGIN_SUCCESS, USER_REGISTERED, etc.
    ip_address = Column(String, nullable=True)
    details = Column(String, nullable=True)
    timestamp = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    # Relationship to user
    user = relationship("User", back_populates="audit_logs")
