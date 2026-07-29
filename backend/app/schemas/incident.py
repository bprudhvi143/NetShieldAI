from datetime import datetime
from typing import Optional, Dict, Any
from pydantic import BaseModel, Field, ConfigDict

class IncidentBase(BaseModel):
    title: str
    description: Optional[str] = None
    priority: str = "P4"

class IncidentCreate(IncidentBase):
    pass

class IncidentRead(IncidentBase):
    id: int
    status: str
    created_at: datetime
    updated_at: datetime
    assigned_to: Optional[int] = None
    resolved_by: Optional[int] = None
    resolved_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)

class IncidentStatusUpdate(BaseModel):
    status: str = Field(..., description="Status value: OPEN, INVESTIGATING, CONTAINED, RESOLVED, CLOSED")
    reason: Optional[str] = Field(default=None, description="Optional explanation for status transition")

class IncidentAssign(BaseModel):
    assigned_to: Optional[int] = Field(..., description="User ID to assign the incident to, or null/None to unassign")

class IncidentHistoryRead(BaseModel):
    id: int
    incident_id: int
    action: str
    old_status: Optional[str] = None
    new_status: Optional[str] = None
    performed_by: Optional[int] = None
    timestamp: datetime
    action_metadata: Optional[Dict[str, Any]] = None

    model_config = ConfigDict(from_attributes=True)
