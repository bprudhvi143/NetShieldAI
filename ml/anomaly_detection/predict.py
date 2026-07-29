import os
import joblib
import pandas as pd
import numpy as np
from typing import Dict, Any, Union
from ml.anomaly_detection.isolation_forest import AnomalyDetector

def load_detector(model_path: str) -> AnomalyDetector:
    """Load the trained AnomalyDetector object."""
    if not os.path.exists(model_path):
        raise FileNotFoundError(f"Trained model not found at {model_path}")
    detector = joblib.load(model_path)
    if not isinstance(detector, AnomalyDetector):
        raise TypeError(f"Loaded object from {model_path} is not an AnomalyDetector instance.")
    return detector

def predict_single_flow(
    detector: AnomalyDetector,
    flow_df: pd.DataFrame,
    dataset_name: str,
    pipeline_version: str
) -> Dict[str, Any]:
    """
    Predict anomaly status for a single network flow represented as a 1-row DataFrame.
    """
    # 1. Verify schema compatibility
    detector.verify_feature_compatibility(flow_df, dataset_name, pipeline_version)
    
    # 2. Get predictions and scores
    anomaly_label = int(detector.predict(flow_df)[0]) # 1 = Anomaly, 0 = Normal
    raw_score = float(detector.decision_function(flow_df)[0])
    normalized_score = float(detector.compute_normalized_score(raw_score))
    
    return {
        "is_anomaly": anomaly_label == 1,
        "anomaly_label": anomaly_label,
        "raw_anomaly_score": raw_score,
        "normalized_anomaly_score": normalized_score
    }

def predict_batch(
    detector: AnomalyDetector,
    flows_df: pd.DataFrame,
    dataset_name: str,
    pipeline_version: str
) -> pd.DataFrame:
    """
    Predict anomaly status for a batch of network flows.
    Returns a DataFrame containing:
    - is_anomaly (bool)
    - anomaly_label (0 = Normal, 1 = Anomaly)
    - raw_anomaly_score (float)
    - normalized_anomaly_score (float)
    """
    # 1. Verify schema compatibility
    detector.verify_feature_compatibility(flows_df, dataset_name, pipeline_version)
    
    # 2. Run batch prediction
    anomaly_labels = detector.predict(flows_df)
    raw_scores = detector.decision_function(flows_df)
    normalized_scores = detector.compute_normalized_score(raw_scores) if hasattr(detector, 'compute_normalized_score') else detector.compute_normalized_score(raw_scores)
    
    results = pd.DataFrame({
        "is_anomaly": anomaly_labels == 1,
        "anomaly_label": anomaly_labels,
        "raw_anomaly_score": raw_scores,
        "normalized_anomaly_score": normalized_scores
    }, index=flows_df.index)
    
    return results
