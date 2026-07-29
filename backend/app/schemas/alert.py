from datetime import datetime
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field, ConfigDict

class AlertBase(BaseModel):
    title: str
    description: Optional[str] = None
    status: str = "NEW"
    severity: str
    priority: str
    signal_status: str
    threat_score: float
    risk_level: str
    anomaly_detected: bool
    anomaly_score: float
    is_attack: bool
    attack_probability: float
    attack_type: Optional[str] = None
    classification_confidence: Optional[float] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    protocol: Optional[str] = None
    reasons: Optional[List[str]] = None
    source: str = "NETSHIELD_AI"
    alert_type: str
    pipeline_version: str = "1.0"
    correlation_type: str = "NONE"
    correlation_reason: Optional[str] = None

class AlertRead(AlertBase):
    id: int
    event_id: str
    deduplication_key: str
    repeat_count: int
    created_at: datetime
    updated_at: datetime
    incident_id: Optional[int] = None
    assigned_to: Optional[int] = None
    acknowledged_by: Optional[int] = None
    resolved_by: Optional[int] = None
    acknowledged_at: Optional[datetime] = None
    resolved_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)

class AlertStatusUpdate(BaseModel):
    status: str = Field(..., description="Status value: NEW, ACKNOWLEDGED, INVESTIGATING, RESOLVED, FALSE_POSITIVE, CLOSED")
    reason: Optional[str] = Field(default=None, description="Optional explanation for the status change")

class AlertAssign(BaseModel):
    assigned_to: Optional[int] = Field(..., description="User ID to assign the alert to, or null/None to unassign")

class AlertHistoryRead(BaseModel):
    id: int
    alert_id: int
    action: str
    old_status: Optional[str] = None
    new_status: Optional[str] = None
    performed_by: Optional[int] = None
    timestamp: datetime
    action_metadata: Optional[Dict[str, Any]] = None

    model_config = ConfigDict(from_attributes=True)
