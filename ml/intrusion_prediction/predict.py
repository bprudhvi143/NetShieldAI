import os
import joblib
import pandas as pd
from typing import Dict, Any, List
from ml.intrusion_prediction.xgboost_classifier import XGBoostIntrusionClassifier

def load_classifier(model_path: str) -> XGBoostIntrusionClassifier:
    """Load the trained XGBoostIntrusionClassifier object."""
    if not os.path.exists(model_path):
        raise FileNotFoundError(f"Trained model not found at {model_path}")
    classifier = joblib.load(model_path)
    if not isinstance(classifier, XGBoostIntrusionClassifier):
        raise TypeError(f"Loaded object from {model_path} is not an XGBoostIntrusionClassifier instance.")
    return classifier

def predict_single_flow(
    classifier: XGBoostIntrusionClassifier,
    flow_df: pd.DataFrame,
    dataset_name: str,
    pipeline_version: str
) -> Dict[str, Any]:
    """
    Predict intrusion status or attack class for a single network flow represented as a 1-row DataFrame.
    """
    # 1. Verify schema compatibility
    classifier.verify_feature_compatibility(flow_df, dataset_name, pipeline_version)
    
    # 2. Get predictions report
    report = classifier.get_prediction_report(flow_df)
    return report[0]

def predict_batch(
    classifier: XGBoostIntrusionClassifier,
    flows_df: pd.DataFrame,
    dataset_name: str,
    pipeline_version: str
) -> List[Dict[str, Any]]:
    """
    Predict intrusion status or attack classes for a batch of network flows.
    """
    # 1. Verify schema compatibility
    classifier.verify_feature_compatibility(flows_df, dataset_name, pipeline_version)
    
    # 2. Run batch prediction
    report = classifier.get_prediction_report(flows_df)
    return report
