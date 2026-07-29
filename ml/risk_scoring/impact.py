from typing import Dict, Any, Tuple

from typing import Dict, Any, Tuple
from ml.risk_scoring.severity import get_attack_severity

def assess_impact(
    intrusion_probability: float,
    anomaly_score: float,
    predicted_class: str,
    severity_level: str = None
) -> Tuple[str, float, str]:
    """
    Assesses potential consequence as an independent, project-defined consequence rating
    using classification metadata (predicted attack category and severity level).
    This mapping does NOT recombine intrusion probability and anomaly score, preventing double-counting.
    
    IMPORTANT: This impact mapping is project-defined and represents potential consequence
    based on available classification information, not actual business/asset impact.
    
    Args:
        intrusion_probability (float): Unused in calculation to prevent double-counting.
        anomaly_score (float): Unused in calculation to prevent double-counting.
        predicted_class (str): Predicted class name.
        severity_level (str, optional): Pre-computed severity level ("Low", "Medium", "High", "Critical").
        
    Returns:
        impact_level (str): "Low", "Medium", "High", "Critical"
        impact_score (float): Score in [0, 100]
        impact_reason (str): Explainable human-readable reasoning
    """
    # 1. Handle normal/benign cases explicitly
    normal_labels = {"benign", "normal"}
    if str(predicted_class).lower() in normal_labels:
        return "Low", 0.0, "Traffic predicted as normal. Potential impact is low (0.0)."
        
    # 2. Get severity level if not provided
    if severity_level is None:
        severity_level, _, _ = get_attack_severity(predicted_class, "cicids2017") # default dataset lookup
        
    # 3. Map severity level to project-defined impact score and level
    # This represents potential blast-radius based on attack category severity.
    impact_mapping = {
        "Critical": ("Critical", 100.0),
        "High": ("High", 75.0),
        "Medium": ("Medium", 45.0),
        "Low": ("Low", 15.0),
        "Not Applicable": ("Low", 0.0)
    }
    
    level, score = impact_mapping.get(severity_level, ("Medium", 45.0))
    
    reason = (
        f"Potential {level.lower()} consequence (score: {score:.1f}) assessed using "
        f"project-defined mappings for attack category '{predicted_class}' with severity '{severity_level}'."
    )
    
    return level, score, reason
