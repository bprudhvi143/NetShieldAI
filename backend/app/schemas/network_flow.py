from pydantic import BaseModel, Field, ConfigDict
from datetime import datetime
from typing import Optional, Dict, Any

class NetworkFlowBase(BaseModel):
    event_id: str
    flow_start: datetime
    flow_end: datetime
    dataset_profile: str
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    protocol: Optional[str] = None
    packet_count: int
    byte_count: int
    duration: float
    feature_snapshot: Optional[Dict[str, Any]] = None

    anomaly_detected: bool
    anomaly_score: float

    is_attack: bool
    attack_probability: float
    normal_probability: float

    attack_type: Optional[str] = None
    classification_confidence: Optional[float] = None

    threat_score: float
    risk_level: str
    severity: str
    impact_level: str
    priority: str
    signal_status: str

    alert_id: Optional[int] = None
    incident_id: Optional[int] = None

    processing_latency_ms: float
    model_version: str

class NetworkFlowRead(NetworkFlowBase):
    id: int
    captured_at: datetime
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)
