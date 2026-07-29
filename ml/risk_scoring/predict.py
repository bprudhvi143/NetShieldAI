import os
import pandas as pd
from typing import Dict, Any, List, Tuple

from ml.anomaly_detection.predict import load_detector, predict_single_flow as anomaly_predict_single, predict_batch as anomaly_predict_batch
from ml.anomaly_detection.isolation_forest import AnomalyDetector
from ml.intrusion_prediction.predict import load_classifier, predict_single_flow as intrusion_predict_single, predict_batch as intrusion_predict_batch
from ml.intrusion_prediction.xgboost_classifier import XGBoostIntrusionClassifier

from ml.risk_scoring.risk_scorer import calculate_risk_score

def load_risk_models(
    dataset_name: str,
    task_type: str = "multiclass",
    base_dir: str = "c:/NetShieldAI"
) -> Tuple[AnomalyDetector, XGBoostIntrusionClassifier]:
    """
    Helper to load both the anomaly detector and XGBoost classifier for a given dataset.
    """
    ds_clean = dataset_name.lower().replace("-", "_")
    
    # 1. Anomaly Detector Path
    anomaly_path = os.path.join(base_dir, f"ml/models/{ds_clean}/isolation_forest.joblib")
    detector = load_detector(anomaly_path)
    
    # 2. XGBoost Path
    task_clean = task_type.lower()
    supervised_path = os.path.join(
        base_dir, 
        f"ml/models/intrusion_prediction/{ds_clean}/{task_clean}/xgboost_{task_clean}.joblib"
    )
    classifier = load_classifier(supervised_path)
    
    return detector, classifier

def predict_single_flow_risk(
    anomaly_detector: AnomalyDetector,
    supervised_classifier: XGBoostIntrusionClassifier,
    flow_df_anomaly: pd.DataFrame,
    dataset_name: str,
    pipeline_version: str,
    flow_df_class: pd.DataFrame = None,
    config: Dict[str, Any] = None
) -> Dict[str, Any]:
    """
    Predict risk scoring for a single network flow represented as a 1-row DataFrame.
    """
    if len(flow_df_anomaly) != 1:
        raise ValueError("flow_df_anomaly must contain exactly 1 row for single-flow prediction.")
        
    if flow_df_class is None:
        flow_df_class = flow_df_anomaly
        
    ds_clean = dataset_name.lower().replace("-", "_")
    
    # 1. Run anomaly detection
    anomaly_res = anomaly_predict_single(anomaly_detector, flow_df_anomaly, ds_clean, pipeline_version)
    
    # 2. Run intrusion classification
    intrusion_res = intrusion_predict_single(supervised_classifier, flow_df_class, ds_clean, pipeline_version)
    
    # 3. Extract signals for risk scorer
    anomaly_detected = anomaly_res["is_anomaly"]
    anomaly_score = anomaly_res["normalized_anomaly_score"]
    
    predicted_class = intrusion_res["predicted_class"]
    confidence = intrusion_res["confidence"]
    
    # Calculate intrusion probability based on model type
    if supervised_classifier.task_type == "binary":
        intrusion_probability = intrusion_res["attack_probability"]
    else:
        # Multiclass: 1.0 - Normal probability
        normal_class = "BENIGN" if ds_clean == "cicids2017" else "Normal"
        class_probs = intrusion_res.get("class_probabilities", {})
        normal_prob = class_probs.get(normal_class, 0.0)
        intrusion_probability = 1.0 - normal_prob
        
    # 4. Compute risk scoring
    risk_result = calculate_risk_score(
        dataset=dataset_name,
        anomaly_detected=anomaly_detected,
        anomaly_score=anomaly_score,
        predicted_class=predicted_class,
        intrusion_probability=intrusion_probability,
        confidence=confidence,
        is_anomaly_score_normalized=True,
        config=config
    )
    
    # Set raw anomaly score in signals for completeness
    risk_result["signals"]["raw_anomaly_score"] = anomaly_res["raw_anomaly_score"]
    
    return risk_result

def predict_batch_risk(
    anomaly_detector: AnomalyDetector,
    supervised_classifier: XGBoostIntrusionClassifier,
    flows_df_anomaly: pd.DataFrame,
    dataset_name: str,
    pipeline_version: str,
    flows_df_class: pd.DataFrame = None,
    config: Dict[str, Any] = None
) -> List[Dict[str, Any]]:
    """
    Predict risk scoring for a batch of network flows.
    """
    if flows_df_class is None:
        flows_df_class = flows_df_anomaly
        
    ds_clean = dataset_name.lower().replace("-", "_")
    
    # 1. Run batch anomaly detection
    anomaly_df = anomaly_predict_batch(anomaly_detector, flows_df_anomaly, ds_clean, pipeline_version)
    
    # 2. Run batch intrusion classification
    intrusion_reports = intrusion_predict_batch(supervised_classifier, flows_df_class, ds_clean, pipeline_version)
    
    # 3. Combine results
    risk_results = []
    normal_class = "BENIGN" if ds_clean == "cicids2017" else "Normal"
    
    for idx in range(len(flows_df_anomaly)):
        # Extract anomaly results for row
        anomaly_row = anomaly_df.iloc[idx]
        anomaly_detected = bool(anomaly_row["is_anomaly"])
        anomaly_score = float(anomaly_row["normalized_anomaly_score"])
        raw_anomaly_score = float(anomaly_row["raw_anomaly_score"])
        
        # Extract intrusion results for row
        int_report = intrusion_reports[idx]
        predicted_class = int_report["predicted_class"]
        confidence = float(int_report["confidence"])
        
        # Determine intrusion probability
        if supervised_classifier.task_type == "binary":
            intrusion_probability = float(int_report["attack_probability"])
        else:
            class_probs = int_report.get("class_probabilities", {})
            normal_prob = float(class_probs.get(normal_class, 0.0))
            intrusion_probability = 1.0 - normal_prob
            
        # Compute risk scoring
        risk_res = calculate_risk_score(
            dataset=dataset_name,
            anomaly_detected=anomaly_detected,
            anomaly_score=anomaly_score,
            predicted_class=predicted_class,
            intrusion_probability=intrusion_probability,
            confidence=confidence,
            is_anomaly_score_normalized=True,
            config=config
        )
        
        risk_res["signals"]["raw_anomaly_score"] = raw_anomaly_score
        risk_results.append(risk_res)
        
    return risk_results
