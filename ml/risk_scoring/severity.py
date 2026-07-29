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

def get_attack_severity(
    predicted_class: str,
    dataset_name: str,
    config: Dict[str, Any] = None
) -> Tuple[str, float, bool]:
    """
    Map attack category to severity level and score.
    Returns:
        severity_level (str): "Low", "Medium", "High", "Critical", or "Not Applicable"
        severity_score (float): Numerical score associated with the level
        is_fallback (bool): True if fallback severity was applied
    """
    if config is None:
        config = load_config()
        
    sev_map = config.get("severity_mapping", {})
    sev_scores = config.get("severity_scores", {})
    fallback_level = sev_map.get("fallback", "Medium")
    
    # Standardize dataset name
    dataset_key = dataset_name.lower().replace("-", "_")
    if dataset_key not in sev_map:
        # Fallback to binary or use global mapping if dataset is unknown
        dataset_key = "binary"
        
    dataset_mapping = sev_map.get(dataset_key, {})
    
    # 1. Handle normal/benign cases explicitly
    normal_labels = {"benign", "normal"}
    if str(predicted_class).lower() in normal_labels:
        level = "Not Applicable"
        return level, float(sev_scores.get(level, 0.0)), False
        
    # 2. Check direct mapping
    # Handle class name variants (e.g. mapping might contain exact string matching)
    level = dataset_mapping.get(predicted_class)
    is_fallback = False
    
    if level is None:
        # Case insensitive secondary lookup
        matched = False
        for k, v in dataset_mapping.items():
            if k.lower() == str(predicted_class).lower():
                level = v
                matched = True
                break
        if not matched:
            # Deterministic fallback
            level = fallback_level
            is_fallback = True
            
    score = float(sev_scores.get(level, 50.0))
    return level, score, is_fallback
