import os
import tempfile
import pytest
import numpy as np
import pandas as pd
import joblib
from ml.anomaly_detection.isolation_forest import AnomalyDetector
from ml.anomaly_detection.evaluate import calculate_metrics

def test_anomaly_detector_initialization():
    detector = AnomalyDetector(config={
        "n_estimators": 50,
        "contamination": 0.05,
        "max_samples": 0.8,
        "random_state": 42
    })
    assert detector.n_estimators == 50
    assert detector.contamination == 0.05
    assert detector.max_samples == 0.8
    assert detector.random_state == 42
    assert detector.model.n_estimators == 50

def test_feature_compatibility_validation():
    detector = AnomalyDetector()
    detector.feature_names = ["feat1", "feat2", "feat3"]
    detector.dataset_name = "CICIDS2017"
    detector.pipeline_version = "1.0"
    
    # 1. Correct dataframe
    df_correct = pd.DataFrame(columns=["feat1", "feat2", "feat3"])
    detector.verify_feature_compatibility(df_correct, "cicids2017", "1.0") # should pass silently
    
    # 2. Dataset mismatch
    with pytest.raises(ValueError) as exc:
        detector.verify_feature_compatibility(df_correct, "unsw_nb15", "1.0")
    assert "Dataset mismatch!" in str(exc.value)
    
    # 3. Pipeline version mismatch
    with pytest.raises(ValueError) as exc:
        detector.verify_feature_compatibility(df_correct, "cicids2017", "2.0")
    assert "Pipeline version mismatch!" in str(exc.value)
    
    # 4. Feature count mismatch
    df_wrong_count = pd.DataFrame(columns=["feat1", "feat2"])
    with pytest.raises(ValueError) as exc:
        detector.verify_feature_compatibility(df_wrong_count, "cicids2017", "1.0")
    assert "Feature count mismatch!" in str(exc.value)
    
    # 5. Feature order/name mismatch
    df_wrong_order = pd.DataFrame(columns=["feat2", "feat1", "feat3"])
    with pytest.raises(ValueError) as exc:
        detector.verify_feature_compatibility(df_wrong_order, "cicids2017", "1.0")
    assert "Feature mismatch at index 0!" in str(exc.value)

def test_prediction_semantic_mapping():
    # Construct a small fitted detector
    detector = AnomalyDetector(config={"random_state": 42})
    X_train = pd.DataFrame({
        "feat1": np.random.normal(0, 1, 100),
        "feat2": np.random.normal(0, 1, 100)
    })
    detector.fit(X_train, "CICIDS2017", "1.0")
    
    # Isolation Forest predict returns 1 (inlier) or -1 (outlier)
    # Our predict must map them: 1 -> 0 (Normal), -1 -> 1 (Anomaly)
    test_df = pd.DataFrame({
        "feat1": [0.0, 100.0],  # 0.0 is very normal, 100.0 is outlier
        "feat2": [0.0, 100.0]
    })
    
    preds = detector.predict(test_df)
    assert len(preds) == 2
    assert preds[0] == 0  # Normal
    assert preds[1] == 1  # Anomaly
    
    # Decision function (raw scores) - lower for anomalies
    raw_scores = detector.decision_function(test_df)
    assert raw_scores[0] > raw_scores[1]
    
    # Normalized scores
    norm_score_normal = detector.compute_normalized_score(raw_scores[0])
    norm_score_anomaly = detector.compute_normalized_score(raw_scores[1])
    
    assert 0.0 <= norm_score_normal <= 1.0
    assert 0.0 <= norm_score_anomaly <= 1.0
    assert norm_score_anomaly > norm_score_normal

def test_metric_calculations():
    # Ground truth: Normal = 0, Attack = 1
    # Prediction: Normal = 0, Anomaly = 1
    # TP = Attack predicted as Anomaly = 5
    # TN = Normal predicted as Normal = 10
    # FP = Normal predicted as Anomaly = 2
    # FN = Attack predicted as Normal = 3
    y_true = np.array([1]*8 + [0]*12) # 8 Attacks, 12 Normals
    # We want:
    # 5 TP -> 5 Attacks predicted as 1
    # 3 FN -> 3 Attacks predicted as 0
    # 10 TN -> 10 Normals predicted as 0
    # 2 FP -> 2 Normals predicted as 1
    y_pred = np.array([1]*5 + [0]*3 + [0]*10 + [1]*2)
    
    res = calculate_metrics(y_true, y_pred)
    cm = res["confusion_matrix"]
    metrics = res["metrics"]
    
    assert cm["TP"] == 5
    assert cm["TN"] == 10
    assert cm["FP"] == 2
    assert cm["FN"] == 3
    
    total = 5 + 10 + 2 + 3 # 20
    assert metrics["accuracy"] == (5 + 10) / 20 # 0.75
    assert metrics["precision"] == 5 / (5 + 2) # 5/7
    assert metrics["true_positive_rate"] == 5 / (5 + 3) # 5/8 (Recall/TPR)
    assert metrics["false_positive_rate"] == 2 / (2 + 10) # 2/12 = 1/6
    assert metrics["true_negative_rate_specificity"] == 10 / (10 + 2) # 10/12 = 5/6
    assert metrics["false_negative_rate"] == 3 / (3 + 5) # 3/8

def test_zero_denominator_metric_cases():
    # Test case: No predicted anomalies -> FP + TP = 0 (Precision denominator = 0)
    y_true = np.array([0, 0, 1])
    y_pred = np.array([0, 0, 0])
    
    res = calculate_metrics(y_true, y_pred)
    assert res["metrics"]["precision"] == 0.0
    assert res["warnings"]["precision_zero_denominator"] is True
    
    # Test case: No actual attacks -> FN + TP = 0 (Recall denominator = 0)
    y_true_no_attack = np.array([0, 0, 0])
    y_pred_no_attack = np.array([0, 1, 0])
    
    res_no_attack = calculate_metrics(y_true_no_attack, y_pred_no_attack)
    assert res_no_attack["metrics"]["recall_detection_rate"] == 0.0
    assert res_no_attack["warnings"]["recall_zero_denominator"] is True

def test_model_persistence():
    # Fit a detector
    detector = AnomalyDetector(config={"n_estimators": 10, "random_state": 42})
    X_train = pd.DataFrame({
        "feat1": np.random.normal(0, 1, 50),
        "feat2": np.random.normal(0, 1, 50)
    })
    detector.fit(X_train, "CICIDS2017", "1.0")
    
    test_df = pd.DataFrame({
        "feat1": [0.0, 5.0],
        "feat2": [0.0, 5.0]
    })
    original_preds = detector.predict(test_df)
    original_scores = detector.decision_function(test_df)
    
    # Save model to temp file
    temp_dir = tempfile.mkdtemp()
    model_path = os.path.join(temp_dir, "test_model.joblib")
    
    joblib.dump(detector, model_path)
    
    # Load back
    loaded_detector = joblib.load(model_path)
    loaded_preds = loaded_detector.predict(test_df)
    loaded_scores = loaded_detector.decision_function(test_df)
    
    # Check consistency
    np.testing.assert_array_equal(original_preds, loaded_preds)
    np.testing.assert_array_equal(original_scores, loaded_scores)
    assert loaded_detector.dataset_name == "CICIDS2017"
    assert loaded_detector.pipeline_version == "1.0"
    assert loaded_detector.feature_names == ["feat1", "feat2"]
    
    # Clean up temp
    os.remove(model_path)
    os.rmdir(temp_dir)
