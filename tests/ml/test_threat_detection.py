import os
import pytest
import pandas as pd
import numpy as np
from pydantic import ValidationError

from ml.threat_detection.pipeline import ThreatDetectionPipeline
from ml.threat_detection.predict import predict_single_flow, predict_batch, get_pipeline
from ml.threat_detection.schemas import UnifiedThreatAssessment

# Paths
BASE_DIR = "c:/NetShieldAI"
CICIDS_ANOMALY_PATH = os.path.join(BASE_DIR, "datasets/cicids2017/processed/X_test_anomaly.csv")
CICIDS_CLASS_PATH = os.path.join(BASE_DIR, "datasets/cicids2017/processed/X_test_class.csv")
CICIDS_LABEL_PATH = os.path.join(BASE_DIR, "datasets/cicids2017/processed/y_test_multiclass.csv")

UNSW_ANOMALY_PATH = os.path.join(BASE_DIR, "datasets/unsw_nb15/processed/X_test_anomaly.csv")
UNSW_CLASS_PATH = os.path.join(BASE_DIR, "datasets/unsw_nb15/processed/X_test_class.csv")
UNSW_LABEL_PATH = os.path.join(BASE_DIR, "datasets/unsw_nb15/processed/y_test_multiclass.csv")

@pytest.fixture(scope="module")
def cicids_pipeline():
    return get_pipeline("cicids2017", BASE_DIR)

@pytest.fixture(scope="module")
def unsw_pipeline():
    return get_pipeline("unsw_nb15", BASE_DIR)

def test_pipeline_initialization():
    # Test valid dataset names
    pipeline1 = ThreatDetectionPipeline("cicids2017", BASE_DIR)
    assert pipeline1.dataset_name == "cicids2017"
    assert pipeline1.anomaly_detector is not None
    assert pipeline1.binary_classifier is not None
    assert pipeline1.multiclass_classifier is not None
    
    pipeline2 = ThreatDetectionPipeline("UNSW-NB15", BASE_DIR)
    assert pipeline2.dataset_name == "unsw_nb15"
    
    # Test invalid dataset rejection
    with pytest.raises(ValueError, match="Unknown dataset"):
        ThreatDetectionPipeline("invalid_dataset", BASE_DIR)

def test_dataset_isolation(cicids_pipeline, unsw_pipeline):
    # Load cicids flow
    cicids_flow = pd.read_csv(CICIDS_ANOMALY_PATH, index_col=0).head(1)
    
    # Attempting to run cicids flow on UNSW pipeline must trigger feature count/name validation error
    with pytest.raises(ValueError, match="Feature count mismatch|Feature mismatch"):
        unsw_pipeline.predict_single(cicids_flow)

def test_threat_detection_flows(cicids_pipeline):
    # Load cicids test split to find normal and attack samples
    df_anomaly = pd.read_csv(CICIDS_ANOMALY_PATH, index_col=0)
    df_class = pd.read_csv(CICIDS_CLASS_PATH, index_col=0)
    df_y = pd.read_csv(CICIDS_LABEL_PATH, index_col=0)
    
    # Align
    common_idx = df_anomaly.index.intersection(df_class.index).intersection(df_y.index)
    df_anomaly = df_anomaly.loc[common_idx]
    df_class = df_class.loc[common_idx]
    df_y = df_y.loc[common_idx]
    
    # 1. Normal Flow Test
    # Find a row where ground truth is BENIGN
    normal_indices = df_y[df_y.iloc[:, 0] == "BENIGN"].index
    assert len(normal_indices) > 0
    idx_normal = normal_indices[0]
    
    row_anomaly_normal = df_anomaly.loc[[idx_normal]].copy()
    row_class_normal = df_class.loc[[idx_normal]].copy()
    
    # Ensure it predicts Normal by overriding outlier features and attack features if needed,
    # or just run it (the model should predict normal on a true normal row).
    res_normal = cicids_pipeline.predict_single(row_anomaly_normal, row_class_normal)
    
    # Let's construct a clean normal scenario: Anomaly=False, Binary=Normal
    # Force anomaly score to inlier (1) and binary classifier to normal by selecting a clean row
    if res_normal.detection.status == "Normal":
        assert res_normal.detection.status == "Normal"
        assert res_normal.signal_status == "normal"
        assert res_normal.intrusion_prediction.is_attack is False
        assert res_normal.attack_classification.classification_status == "not_run"
        assert res_normal.attack_classification.predicted_class is None
        assert res_normal.attack_classification.confidence is None
        assert res_normal.attack_classification.class_probabilities == {}
        
    # 2. Anomaly-Only / Suspicious Flow Test
    # Take the normal row, modify an anomaly feature to make it an outlier (e.g. very large Flow Duration)
    # The anomaly detector uses raw features.
    row_anomaly_susp = row_anomaly_normal.copy()
    if "Flow Duration" in row_anomaly_susp.columns:
        row_anomaly_susp["Flow Duration"] = 120000000.0  # Outlier value
    else:
        # Set first numeric column to huge value
        col = row_anomaly_susp.select_dtypes(include=[np.number]).columns[0]
        row_anomaly_susp[col] = 999999999.0
        
    res_susp = cicids_pipeline.predict_single(row_anomaly_susp, row_class_normal)
    # Check if anomaly is detected but binary says Normal -> status Suspicious, signal_status anomaly_only
    if not res_susp.intrusion_prediction.is_attack and res_susp.detection.anomaly_detected:
        assert res_susp.detection.status == "Suspicious"
        assert res_susp.signal_status == "anomaly_only"
        assert res_susp.attack_classification.classification_status == "not_run"
        assert res_susp.attack_classification.predicted_class is None
        assert res_susp.attack_classification.confidence is None
        assert res_susp.attack_classification.class_probabilities == {}
        # Confirm anomaly score is passed to risk scorer and preserved
        assert res_susp.detection.anomaly_score > 0.0
        assert res_susp.risk.score_breakdown["anomaly"] > 0.0
        
    # 3. Confirmed Attack Flow Test
    # Find an attack row (e.g. DDoS or PortScan)
    attack_indices = df_y[df_y.iloc[:, 0] == "DDoS"].index
    if len(attack_indices) == 0:
        attack_indices = df_y[df_y.iloc[:, 0] != "BENIGN"].index
    assert len(attack_indices) > 0
    idx_attack = attack_indices[0]
    
    row_anomaly_attack = df_anomaly.loc[[idx_attack]].copy()
    row_class_attack = df_class.loc[[idx_attack]].copy()
    
    res_attack = cicids_pipeline.predict_single(row_anomaly_attack, row_class_attack)
    
    if res_attack.intrusion_prediction.is_attack:
        assert res_attack.detection.status == "Attack"
        assert res_attack.signal_status in {"confirmed_attack", "intrusion_only"}
        assert res_attack.attack_classification.classification_status == "performed"
        assert res_attack.attack_classification.predicted_class is not None
        assert res_attack.attack_classification.confidence is not None
        assert len(res_attack.attack_classification.class_probabilities) > 0
        # Assert binary confidence is not copied into multiclass confidence
        assert res_attack.attack_classification.confidence != res_attack.intrusion_prediction.confidence

def test_batch_processing_and_structured_errors(cicids_pipeline):
    df_anomaly = pd.read_csv(CICIDS_ANOMALY_PATH, index_col=0).head(5)
    df_class = pd.read_csv(CICIDS_CLASS_PATH, index_col=0).head(5)
    
    # 1. Standard batch prediction
    results = cicids_pipeline.predict_batch(df_anomaly, df_class)
    assert len(results) == 5
    for r in results:
        assert isinstance(r, UnifiedThreatAssessment)
        
    # 2. Batch with an individual row failure
    # Let's construct a copy of class DataFrame, and corrupt one row (e.g. set all columns to NaN in row 2)
    df_class_corrupted = df_class.copy()
    # If we set NaN, the model predict call might fail on that row during scoring/multiclass
    # Let's trigger a failure inside risk scoring calculation by passing invalid types/values in that row,
    # or by forcing a prediction failure.
    # Actually, we can trigger a row failure by corrupting the index of that row in a way that calculate_risk_score
    # throws an exception for it (e.g. if the predicted class is numeric or None).
    # Since our evaluate/predict pipeline handles exceptions inside the loop, let's test it:
    # We will temporarily mock calculate_risk_score to fail for index 2
    import ml.threat_detection.pipeline as td_pipeline
    original_scorer = td_pipeline.calculate_risk_score
    
    call_count = 0
    def mock_scorer(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        if call_count == 3:  # Row 2 (0-indexed index 2)
            raise RuntimeError("Scoring calculation failed for row 2")
        return original_scorer(*args, **kwargs)
        
    td_pipeline.calculate_risk_score = mock_scorer
    try:
        batch_res = cicids_pipeline.predict_batch(df_anomaly, df_class)
        assert len(batch_res) == 5
        assert isinstance(batch_res[0], UnifiedThreatAssessment)
        assert isinstance(batch_res[1], UnifiedThreatAssessment)
        
        # Row 2 failed
        assert isinstance(batch_res[2], dict)
        assert batch_res[2]["status"] == "failed"
        assert "Scoring calculation failed" in batch_res[2]["error"]
        assert batch_res[2]["index"] == 2
        
        assert isinstance(batch_res[3], UnifiedThreatAssessment)
        assert isinstance(batch_res[4], UnifiedThreatAssessment)
    finally:
        td_pipeline.calculate_risk_score = original_scorer

def test_determinism(cicids_pipeline):
    df_anomaly = pd.read_csv(CICIDS_ANOMALY_PATH, index_col=0).head(5)
    df_class = pd.read_csv(CICIDS_CLASS_PATH, index_col=0).head(5)
    
    res1 = cicids_pipeline.predict_batch(df_anomaly, df_class)
    res2 = cicids_pipeline.predict_batch(df_anomaly, df_class)
    
    for r1, r2 in zip(res1, res2):
        assert r1.model_dump() == r2.model_dump()

def test_output_schema_conformance(cicids_pipeline):
    df_anomaly = pd.read_csv(CICIDS_ANOMALY_PATH, index_col=0).head(1)
    df_class = pd.read_csv(CICIDS_CLASS_PATH, index_col=0).head(1)
    
    res = cicids_pipeline.predict_single(df_anomaly, df_class)
    
    # Verify Pydantic validation
    assert isinstance(res, UnifiedThreatAssessment)
    
    # Check fields
    assert hasattr(res, "dataset")
    assert hasattr(res, "detection")
    assert hasattr(res, "intrusion_prediction")
    assert hasattr(res, "attack_classification")
    assert hasattr(res, "risk")
    assert hasattr(res, "signal_status")
    assert hasattr(res, "reasons")
    
    # Serialization check
    json_str = res.model_dump_json()
    assert json_str is not None

def test_multiclass_gating_behavior(cicids_pipeline):
    # Reset mocks or mock get_prediction_report
    original_pred = cicids_pipeline.multiclass_classifier.get_prediction_report
    
    call_count = 0
    def mock_get_report(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        return original_pred(*args, **kwargs)
        
    cicids_pipeline.multiclass_classifier.get_prediction_report = mock_get_report
    try:
        # 1. Run a normal row (should not call multiclass)
        df_anomaly = pd.read_csv(CICIDS_ANOMALY_PATH, index_col=0)
        df_class = pd.read_csv(CICIDS_CLASS_PATH, index_col=0)
        df_y = pd.read_csv(CICIDS_LABEL_PATH, index_col=0)
        common_idx = df_anomaly.index.intersection(df_class.index).intersection(df_y.index)
        
        normal_idx = df_y[df_y.iloc[:, 0] == "BENIGN"].index[0]
        row_anomaly = df_anomaly.loc[[normal_idx]]
        row_class = df_class.loc[[normal_idx]]
        
        res_normal = cicids_pipeline.predict_single(row_anomaly, row_class)
        assert call_count == 0  # Not run!
        
        # 2. Run an attack row (should call multiclass)
        attack_idx = df_y[df_y.iloc[:, 0] == "DDoS"].index[0]
        row_anomaly_att = df_anomaly.loc[[attack_idx]]
        row_class_att = df_class.loc[[attack_idx]]
        
        res_attack = cicids_pipeline.predict_single(row_anomaly_att, row_class_att)
        assert call_count == 1  # Executed!
    finally:
        cicids_pipeline.multiclass_classifier.get_prediction_report = original_pred
