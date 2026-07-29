import os
import json
import numpy as np
from typing import Dict, Any, List, Union

from ml.risk_scoring.severity import get_attack_severity
from ml.risk_scoring.impact import assess_impact
from ml.risk_scoring.priority import calculate_priority

def load_config() -> Dict[str, Any]:
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    config_path = os.path.join(base_dir, "config", "risk_scoring_config.json")
    if not os.path.exists(config_path):
        config_path = "c:/NetShieldAI/ml/config/risk_scoring_config.json"
    with open(config_path, "r", encoding="utf-8") as f:
        return json.load(f)

def normalize_anomaly_score(
    raw_score: float,
    dataset_name: str,
    config: Dict[str, Any] = None
) -> float:
    """
    Deterministically converts raw decision function scores from Isolation Forest into [0, 1].
    Isolation Forest scores are negative for outliers and positive for normal traffic.
    """
    bounds = {
        "cicids2017": (-0.24902324868143366, 0.1859617088397998),
        "unsw_nb15": (-0.1548645098117427, 0.1544734405436735)
    }
    dataset_key = dataset_name.lower().replace("-", "_")
    if dataset_key in bounds:
        score_min, score_max = bounds[dataset_key]
    else:
        # Default fallback bounds
        score_min, score_max = -0.5, 0.5
        
    numerator = score_max - raw_score
    denominator = score_max - score_min
    if abs(denominator) < 1e-9:
        denominator = 1.0
        
    normalized = numerator / denominator
    return float(np.clip(normalized, 0.0, 1.0))

def calculate_risk_score(
    dataset: str,
    anomaly_detected: bool,
    anomaly_score: float,
    predicted_class: str,
    intrusion_probability: float,
    confidence: float,
    is_anomaly_score_normalized: bool = False,
    config: Dict[str, Any] = None
) -> Dict[str, Any]:
    """
    Main deterministic risk-scoring function.
    Validates inputs, combines signals, and calculates the explainable threat score.
    """
    # 1. Input Validation
    valid_datasets = {"cicids2017", "unsw_nb15"}
    dataset_clean = dataset.lower().replace("-", "_")
    if dataset_clean not in valid_datasets:
        raise ValueError(f"Unknown dataset '{dataset}'. Must be one of {valid_datasets}.")
        
    if not (0.0 <= intrusion_probability <= 1.0):
        raise ValueError(f"intrusion_probability must be in [0, 1], got {intrusion_probability}")
        
    if not (0.0 <= confidence <= 1.0):
        raise ValueError(f"confidence must be in [0, 1], got {confidence}")
        
    if is_anomaly_score_normalized:
        if not (0.0 <= anomaly_score <= 1.0):
            raise ValueError(f"Normalized anomaly_score must be in [0, 1], got {anomaly_score}")
        normalized_as = anomaly_score
        raw_as = None
    else:
        raw_as = anomaly_score
        normalized_as = normalize_anomaly_score(raw_as, dataset_clean, config)
        
    if config is None:
        config = load_config()
        
    weights = config.get("weights", {})
    thresholds = config.get("risk_thresholds", {})
    
    # 2. Determine target class mappings
    normal_labels = {"benign", "normal"}
    is_attack = predicted_class.lower() not in normal_labels
    
    # 3. Calculate components
    # 3a. Severity Component
    sev_level, sev_score, is_fallback_sev = get_attack_severity(predicted_class, dataset_clean, config)
    
    # 3b. Impact Component
    imp_level, imp_score, imp_reason = assess_impact(intrusion_probability, normalized_as, predicted_class, sev_level)
    
    # 3c. Supervised Detection Probability Contribution
    # IP is in [0, 1], we map it to 0-100 scale
    ip_score = intrusion_probability * 100.0
    
    # 3d. Unsupervised Anomaly Contribution
    as_score = normalized_as * 100.0
    
    # 4. Compute Weighted Threat Score
    # Threat Score = w_ip * IP + w_as * AS + w_sev * Severity + w_imp * Impact
    w_ip = weights.get("intrusion_probability_weight", 0.40)
    w_as = weights.get("anomaly_weight", 0.20)
    w_sev = weights.get("severity_weight", 0.20)
    w_imp = weights.get("impact_weight", 0.20)
    
    contr_ip = w_ip * ip_score
    contr_as = w_as * as_score
    contr_sev = w_sev * sev_score
    contr_imp = w_imp * imp_score
    
    threat_score = contr_ip + contr_as + contr_sev + contr_imp
    threat_score = max(0.0, min(100.0, float(threat_score)))
    
    # 5. Map Threat Score to Risk Level
    # Low: 0-29, Medium: 30-59, High: 60-84, Critical: 85-100 (exclusive upper bounds for splits)
    if threat_score < 30.0:
        risk_level = "Low"
    elif threat_score < 60.0:
        risk_level = "Medium"
    elif threat_score < 85.0:
        risk_level = "High"
    else:
        risk_level = "Critical"
        
    # 6. Map Priority
    priority, priority_reason = calculate_priority(risk_level, imp_level, config)
    
    # 7. Signal Conflicts & Status
    reasons = []
    if is_attack:
        reasons.append(f"Supervised classifier detected an attack of category: '{predicted_class}'")
        reasons.append(f"Attack classification confidence: {confidence * 100:.1f}%")
        reasons.append(f"Supervised intrusion probability: {intrusion_probability * 100:.1f}%")
        reasons.append(f"Project-defined attack severity level: {sev_level} (score: {sev_score:.1f})")
        if is_fallback_sev:
            reasons.append(f"Warning: Unknown attack category fallback applied for severity classification.")
    else:
        reasons.append("Supervised classifier predicts traffic is normal/benign.")
        
    if anomaly_detected:
        reasons.append(f"Unsupervised anomaly detector triggered (normalized score: {normalized_as * 100:.1f}%)")
        
    # Determine signal conflict status
    if anomaly_detected and not is_attack:
        signal_status = "Anomaly Only"
        reasons.append("Conflict: Anomaly detector indicates unusual behavior, while the supervised classifier currently predicts Normal.")
    elif not anomaly_detected and is_attack:
        signal_status = "Intrusion Only"
        reasons.append("Conflict: Supervised classifier predicts an intrusion, while the anomaly detector considers the behavior normal.")
    elif anomaly_detected and is_attack:
        signal_status = "Confirmed Threat"
    else:
        signal_status = "Normal"
        
    reasons.append(f"Assessed potential impact: {imp_level} (score: {imp_score:.1f})")
    reasons.append("Notice: Risk thresholds (Low 0-29, Med 30-59, High 60-84, Crit 85-100) are project-defined initial configurations.")
    
    return {
        "dataset": dataset,
        "threat_score": float(np.round(threat_score, 2)),
        "risk_level": risk_level,
        "priority": priority,
        "prediction": {
            "is_attack": is_attack,
            "attack_probability": float(intrusion_probability),
            "predicted_class": predicted_class,
            "confidence": float(confidence)
        },
        "severity": {
            "level": sev_level,
            "score": float(sev_score),
            "is_fallback": is_fallback_sev
        },
        "impact": {
            "level": imp_level,
            "score": float(imp_score),
            "reason": imp_reason
        },
        "signals": {
            "anomaly_detected": bool(anomaly_detected),
            "anomaly_score": float(normalized_as),
            "raw_anomaly_score": float(raw_as) if raw_as is not None else None
        },
        "signal_status": signal_status,
        "score_breakdown": {
            "intrusion": float(np.round(contr_ip, 2)),
            "anomaly": float(np.round(contr_as, 2)),
            "severity": float(np.round(contr_sev, 2)),
            "impact": float(np.round(contr_imp, 2)),
            "total": float(np.round(threat_score, 2))
        },
        "reasons": reasons
    }
