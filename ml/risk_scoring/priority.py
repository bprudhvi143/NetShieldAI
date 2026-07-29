import os
import json
from typing import Dict, Any, Tuple

def load_config() -> Dict[str, Any]:
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    config_path = os.path.join(base_dir, "config", "risk_scoring_config.json")
    if not os.path.exists(config_path):
        config_path = "c:/NetShieldAI/ml/config/risk_scoring_config.json"
    with open(config_path, "r", encoding="utf-8") as f:
        return json.load(f)

def calculate_priority(
    risk_level: str,
    impact_level: str,
    config: Dict[str, Any] = None
) -> Tuple[str, str]:
    """
    Determines incident priority level using a risk-impact lookup matrix.
    
    Args:
        risk_level (str): "Low", "Medium", "High", "Critical"
        impact_level (str): "Low", "Medium", "High", "Critical"
        config (dict): Optional config dictionary
        
    Returns:
        priority (str): "P1", "P2", "P3", "P4"
        reason (str): Structured reasoning explaining the priority assignment
    """
    if config is None:
        config = load_config()
        
    rules = config.get("priority_rules", {})
    
    # Capitalize arguments for matching keys
    risk_key = risk_level.capitalize() if risk_level else "Low"
    impact_key = impact_level.capitalize() if impact_level else "Low"
    
    # Fallback to defaults if keys are missing from rules
    if risk_key not in rules:
        risk_key = "Low"
    row = rules.get(risk_key, {})
    if impact_key not in row:
        impact_key = "Low"
        
    priority = row.get(impact_key, "P4")
    
    # Detailed mapping description
    priority_labels = {
        "P1": "Critical",
        "P2": "High",
        "P3": "Medium",
        "P4": "Low"
    }
    label = priority_labels.get(priority, "Low")
    
    reason = (
        f"Priority {priority} ({label}) assigned based on "
        f"{risk_key} risk level and {impact_key} impact level."
    )
    
    return priority, reason
