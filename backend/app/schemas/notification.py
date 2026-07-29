from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel

class NotificationPayload(BaseModel):
    event_type: str                  # E.g. ALERT_CREATED, INCIDENT_UPDATED
    alert_id: Optional[int] = None
    incident_id: Optional[int] = None
    timestamp: datetime
    title: str
    severity: str
    priority: str
    risk_level: str
    threat_score: float
    signal_status: str
    attack_type: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    protocol: Optional[str] = None
    summary: str
    reasons: List[str]
