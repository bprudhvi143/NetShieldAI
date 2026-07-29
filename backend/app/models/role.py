from sqlalchemy import Column, Integer, String
from sqlalchemy.orm import relationship
from app.db.postgres import Base

class Role(Base):
    """
    SQLAlchemy model representing the 'roles' table in PostgreSQL.
    Maps system privileges and role definitions (e.g. Security Admin, Security Analyst).
    """
    __tablename__ = "roles"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True, nullable=False)
    description = Column(String, nullable=True)

    # Relationship to users
    users = relationship("User", back_populates="role")
