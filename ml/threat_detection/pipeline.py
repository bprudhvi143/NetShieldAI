import os
import json
import logging
from typing import Dict, Any, List, Union, Tuple, Optional
import pandas as pd
import numpy as np

# Import existing models and functions
from ml.anomaly_detection.predict import load_detector
from ml.anomaly_detection.isolation_forest import AnomalyDetector
from ml.intrusion_prediction.predict import load_classifier
from ml.intrusion_prediction.xgboost_classifier import XGBoostIntrusionClassifier
from ml.risk_scoring.risk_scorer import calculate_risk_score

# Import schemas
from ml.threat_detection.schemas import (
    DetectionSignal,
    IntrusionPrediction,
    AttackClassification,
    RiskAssessment,
    UnifiedThreatAssessment
)

# Set up logging using existing project conventions
logger = logging.getLogger("ml.threat_detection")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

class ThreatDetectionPipeline:
    """
    Unified threat-detection orchestration layer.
    Combines Anomaly Detection, Binary Intrusion Prediction, Multiclass Classification,
    and Risk Scoring into a single unified threat assessment.
    """
    def __init__(self, dataset_name: str, base_dir: str = "c:/NetShieldAI"):
        self.dataset_name = dataset_name.lower().replace("-", "_")
        self.base_dir = base_dir
        
        valid_datasets = {"cicids2017", "unsw_nb15"}
        if self.dataset_name not in valid_datasets:
            raise ValueError(f"Unknown dataset '{dataset_name}'. Must be one of {valid_datasets}.")
            
        logger.info(f"Initializing ThreatDetectionPipeline for dataset: {dataset_name.upper()}")
        
        # 1. Load Phase 1 Preprocessing Metadata
        metadata_path = os.path.join(self.base_dir, "ml/artifacts/metadata", f"{self.dataset_name}_metadata.json")
        if not os.path.exists(metadata_path):
            raise FileNotFoundError(f"Metadata file not found at {metadata_path}")
            
        with open(metadata_path, "r", encoding="utf-8") as f:
            self.metadata = json.load(f)
            
        self.pipeline_version = self.metadata.get("pipeline_version", "1.0")
        self.classification_features = self.metadata.get("final_classification_features", [])
        self.anomaly_features = self.metadata.get("final_anomaly_features", [])
        
        # 2. Load Models Once
        logger.info("Loading anomaly and supervised models...")
        
        # Anomaly Detector Path
        anomaly_path = os.path.join(self.base_dir, f"ml/models/{self.dataset_name}/isolation_forest.joblib")
        self.anomaly_detector = load_detector(anomaly_path)
        
        # Binary Classifier Path
        binary_path = os.path.join(
            self.base_dir, 
            f"ml/models/intrusion_prediction/{self.dataset_name}/binary/xgboost_binary.joblib"
        )
        self.binary_classifier = load_classifier(binary_path)
        
        # Multiclass Classifier Path
        multiclass_path = os.path.join(
            self.base_dir, 
            f"ml/models/intrusion_prediction/{self.dataset_name}/multiclass/xgboost_multiclass.joblib"
        )
        self.multiclass_classifier = load_classifier(multiclass_path)
        
        logger.info("Models loaded successfully. Pipeline ready.")

    def _verify_compatibility(self, X: pd.DataFrame, is_anomaly: bool) -> None:
        """
        Verify the feature count, names, and ordering against metadata to prevent execution with bad features.
        """
        expected_features = self.anomaly_features if is_anomaly else self.classification_features
        if len(X.columns) != len(expected_features):
            raise ValueError(
                f"Feature count mismatch! Expected {len(expected_features)} features, but got {len(X.columns)} columns."
            )
            
        for idx, (expected, actual) in enumerate(zip(expected_features, X.columns)):
            if expected != actual:
                raise ValueError(
                    f"Feature mismatch at index {idx}! Expected '{expected}', but found '{actual}'."
                )

    def predict_single(
        self,
        flow_df_anomaly: pd.DataFrame,
        flow_df_class: Optional[pd.DataFrame] = None
    ) -> UnifiedThreatAssessment:
        """
        Run the complete unified pipeline on a single network flow.
        """
        if flow_df_class is None:
            flow_df_class = flow_df_anomaly
            
        if len(flow_df_anomaly) != 1 or len(flow_df_class) != 1:
            raise ValueError("DataFrames must contain exactly 1 row for single-flow prediction.")
            
        # 1. Validation
        self._verify_compatibility(flow_df_anomaly, is_anomaly=True)
        self._verify_compatibility(flow_df_class, is_anomaly=False)
        
        # 2. Run Anomaly Detection
        # Maps outlier (-1) -> Anomaly (1), inlier (1) -> Normal (0)
        anomaly_label = int(self.anomaly_detector.predict(flow_df_anomaly)[0])
        raw_score = float(self.anomaly_detector.decision_function(flow_df_anomaly)[0])
        normalized_score = float(self.anomaly_detector.compute_normalized_score(raw_score))
        anomaly_detected = (anomaly_label == 1)
        
        # 3. Run Binary Classifier
        binary_report = self.binary_classifier.get_prediction_report(flow_df_class)[0]
        is_attack = (binary_report["predicted_class"] == "Attack")
        attack_prob = float(binary_report["attack_probability"])
        normal_prob = float(binary_report["normal_probability"])
        binary_confidence = float(binary_report["confidence"])
        
        # 4. Conditionally Run Multiclass Classifier
        if is_attack:
            multiclass_report = self.multiclass_classifier.get_prediction_report(flow_df_class)[0]
            predicted_class = multiclass_report["predicted_class"]
            classification_status = "performed"
            confidence = float(multiclass_report["confidence"])
            class_probs = multiclass_report["class_probabilities"]
            
            # Intrusion Probability is 1.0 - Normal probability
            normal_class_lbl = "BENIGN" if self.dataset_name == "cicids2017" else "Normal"
            intrusion_probability = 1.0 - float(class_probs.get(normal_class_lbl, 0.0))
        else:
            predicted_class = "BENIGN" if self.dataset_name == "cicids2017" else "Normal"
            classification_status = "not_run"
            confidence = binary_confidence
            class_probs = {}
            intrusion_probability = attack_prob
            
        # 5. Risk Scoring
        risk_res = calculate_risk_score(
            dataset=self.dataset_name,
            anomaly_detected=anomaly_detected,
            anomaly_score=normalized_score,
            predicted_class=predicted_class,
            intrusion_probability=intrusion_probability,
            confidence=confidence,
            is_anomaly_score_normalized=True
        )
        
        # 6. Map Unified Status and Signal Status
        # Anomaly=False + Binary=Normal -> Normal / normal
        # Anomaly=True  + Binary=Normal -> Suspicious / anomaly_only
        # Anomaly=False + Binary=Attack -> Attack / intrusion_only
        # Anomaly=True  + Binary=Attack -> Attack / confirmed_attack
        if is_attack:
            status = "Attack"
            signal_status = "confirmed_attack" if anomaly_detected else "intrusion_only"
        else:
            status = "Suspicious" if anomaly_detected else "Normal"
            signal_status = "anomaly_only" if anomaly_detected else "normal"
            
        # 7. Construct Pydantic Schema
        assessment = UnifiedThreatAssessment(
            dataset=self.dataset_name.upper(),
            detection=DetectionSignal(
                status=status,
                anomaly_detected=anomaly_detected,
                anomaly_score=normalized_score
            ),
            intrusion_prediction=IntrusionPrediction(
                is_attack=is_attack,
                attack_probability=attack_prob,
                normal_probability=normal_prob,
                confidence=binary_confidence
            ),
            attack_classification=AttackClassification(
                classification_status=classification_status,
                predicted_class=predicted_class if is_attack else None,
                confidence=confidence if is_attack else None,
                class_probabilities=class_probs
            ),
            risk=RiskAssessment(
                threat_score=risk_res["threat_score"],
                risk_level=risk_res["risk_level"],
                severity=risk_res["severity"]["level"],
                impact_level=risk_res["impact"]["level"],
                priority=risk_res["priority"],
                score_breakdown=risk_res["score_breakdown"]
            ),
            signal_status=signal_status,
            reasons=risk_res["reasons"]
        )
        
        return assessment

    def predict_batch(
        self,
        flows_df_anomaly: pd.DataFrame,
        flows_df_class: Optional[pd.DataFrame] = None
    ) -> List[Union[UnifiedThreatAssessment, Dict[str, Any]]]:
        """
        Run the complete unified pipeline on a batch of network flows.
        Reuses models and optimizes multiclass execution in batch.
        """
        if flows_df_class is None:
            flows_df_class = flows_df_anomaly
            
        if len(flows_df_anomaly) != len(flows_df_class):
            raise ValueError("Anomaly and Classification DataFrames must have the same length.")
            
        # 1. Validation (Fails the entire pipeline if schema is wrong)
        self._verify_compatibility(flows_df_anomaly, is_anomaly=True)
        self._verify_compatibility(flows_df_class, is_anomaly=False)
        
        N = len(flows_df_anomaly)
        logger.info(f"Running batch unified detection on {N} flows...")
        
        # 2. Batch Anomaly Detection
        # Predict labels and scores for all rows
        anomaly_labels = self.anomaly_detector.predict(flows_df_anomaly)
        raw_scores = self.anomaly_detector.decision_function(flows_df_anomaly)
        normalized_scores = self.anomaly_detector.compute_normalized_score(raw_scores)
        assert isinstance(normalized_scores, np.ndarray)
        
        # 3. Batch Binary Intrusion Prediction
        binary_reports = self.binary_classifier.get_prediction_report(flows_df_class)
        
        # 4. Conditionally Run Multiclass Classification in Batch
        # Identify indices where binary classifier predicted Attack
        attack_indices = []
        for idx in range(N):
            if binary_reports[idx]["predicted_class"] == "Attack":
                attack_indices.append(idx)
                
        # Run multiclass only on the filtered subset of flows
        multiclass_lookup = {}
        if attack_indices:
            logger.info(f"Running multiclass classification on {len(attack_indices)} attack flows...")
            df_class_attacks = flows_df_class.iloc[attack_indices]
            multiclass_reports = self.multiclass_classifier.get_prediction_report(df_class_attacks)
            
            # Map back using original index
            for map_idx, orig_idx in enumerate(attack_indices):
                multiclass_lookup[orig_idx] = multiclass_reports[map_idx]
                
        # 5. Assemble results row by row, catching any row-level scoring/schema errors
        results = []
        normal_class_lbl = "BENIGN" if self.dataset_name == "cicids2017" else "Normal"
        
        for idx in range(N):
            try:
                # 5a. Retrieve Anomaly Signals
                anomaly_detected = (anomaly_labels[idx] == 1)
                norm_score = float(normalized_scores[idx])
                
                # 5b. Retrieve Binary Signals
                bin_rep = binary_reports[idx]
                is_attack = (bin_rep["predicted_class"] == "Attack")
                attack_prob = float(bin_rep["attack_probability"])
                normal_prob = float(bin_rep["normal_probability"])
                binary_confidence = float(bin_rep["confidence"])
                
                # 5c. Retrieve Multiclass Signals
                if is_attack:
                    mul_rep = multiclass_lookup[idx]
                    predicted_class = mul_rep["predicted_class"]
                    classification_status = "performed"
                    confidence = float(mul_rep["confidence"])
                    class_probs = mul_rep["class_probabilities"]
                    intrusion_probability = 1.0 - float(class_probs.get(normal_class_lbl, 0.0))
                else:
                    predicted_class = "BENIGN" if self.dataset_name == "cicids2017" else "Normal"
                    classification_status = "not_run"
                    confidence = binary_confidence
                    class_probs = {}
                    intrusion_probability = attack_prob
                    
                # 5d. Calculate Risk
                risk_res = calculate_risk_score(
                    dataset=self.dataset_name,
                    anomaly_detected=anomaly_detected,
                    anomaly_score=norm_score,
                    predicted_class=predicted_class,
                    intrusion_probability=intrusion_probability,
                    confidence=confidence,
                    is_anomaly_score_normalized=True
                )
                
                # 5e. Map Unified Status and Signal Status
                if is_attack:
                    status = "Attack"
                    signal_status = "confirmed_attack" if anomaly_detected else "intrusion_only"
                else:
                    status = "Suspicious" if anomaly_detected else "Normal"
                    signal_status = "anomaly_only" if anomaly_detected else "normal"
                    
                # 5f. Build Unified Schema
                assessment = UnifiedThreatAssessment(
                    dataset=self.dataset_name.upper(),
                    detection=DetectionSignal(
                        status=status,
                        anomaly_detected=anomaly_detected,
                        anomaly_score=norm_score
                    ),
                    intrusion_prediction=IntrusionPrediction(
                        is_attack=is_attack,
                        attack_probability=attack_prob,
                        normal_probability=normal_prob,
                        confidence=binary_confidence
                    ),
                    attack_classification=AttackClassification(
                        classification_status=classification_status,
                        predicted_class=predicted_class if is_attack else None,
                        confidence=confidence if is_attack else None,
                        class_probabilities=class_probs
                    ),
                    risk=RiskAssessment(
                        threat_score=risk_res["threat_score"],
                        risk_level=risk_res["risk_level"],
                        severity=risk_res["severity"]["level"],
                        impact_level=risk_res["impact"]["level"],
                        priority=risk_res["priority"],
                        score_breakdown=risk_res["score_breakdown"]
                    ),
                    signal_status=signal_status,
                    reasons=risk_res["reasons"]
                )
                results.append(assessment)
                
            except Exception as e:
                logger.error(f"Row {idx} prediction failed: {str(e)}")
                results.append({
                    "error": str(e),
                    "index": idx,
                    "status": "failed"
                })
                
        return results
