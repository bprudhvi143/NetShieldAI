from pydantic import BaseModel, Field
from typing import Dict, Any, List, Optional

class DetectionSignal(BaseModel):
    status: str  # "Normal", "Suspicious", "Attack"
    anomaly_detected: bool
    anomaly_score: float

class IntrusionPrediction(BaseModel):
    is_attack: bool
    attack_probability: float
    normal_probability: float
    confidence: float

class AttackClassification(BaseModel):
    classification_status: str  # "performed", "not_run"
    predicted_class: Optional[str] = None
    confidence: Optional[float] = None
    class_probabilities: Dict[str, float] = Field(default_factory=dict)

class RiskAssessment(BaseModel):
    threat_score: float
    risk_level: str
    severity: str
    impact_level: str
    priority: str
    score_breakdown: Dict[str, float] = Field(default_factory=dict)

class UnifiedThreatAssessment(BaseModel):
    dataset: str
    detection: DetectionSignal
    intrusion_prediction: IntrusionPrediction
    attack_classification: AttackClassification
    risk: RiskAssessment
    signal_status: str  # "normal", "anomaly_only", "intrusion_only", "confirmed_attack"
    reasons: List[str] = Field(default_factory=list)
