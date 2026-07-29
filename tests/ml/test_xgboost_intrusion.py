import os
import tempfile
import pytest
import numpy as np
import pandas as pd
import joblib
from ml.intrusion_prediction.xgboost_classifier import XGBoostIntrusionClassifier
from ml.intrusion_prediction.evaluate import calculate_binary_metrics, calculate_multiclass_metrics

def test_xgboost_classifier_initialization():
    classifier = XGBoostIntrusionClassifier(task_type="binary", config={
        "n_estimators": 50,
        "max_depth": 4,
        "learning_rate": 0.1,
        "random_state": 42
    })
    assert classifier.task_type == "binary"
    assert classifier.n_estimators == 50
    assert classifier.max_depth == 4
    assert classifier.learning_rate == 0.1
    assert classifier.random_state == 42
    assert classifier.model.n_estimators == 50

def test_target_leakage_detection():
    classifier = XGBoostIntrusionClassifier()
    classifier.feature_names = ["feat1", "feat2", "feat3"]
    classifier.dataset_name = "CICIDS2017"
    classifier.pipeline_version = "1.0"
    
    # 1. Leakage columns in features
    for col in ["Label", "attack_cat", "Label_binary", "Label_multiclass"]:
        df_leakage = pd.DataFrame(columns=["feat1", "feat2", col])
        with pytest.raises(ValueError) as exc:
            classifier.verify_feature_compatibility(df_leakage, "cicids2017", "1.0")
        assert "CRITICAL TARGET LEAKAGE DETECTED!" in str(exc.value)

def test_feature_compatibility_validation():
    classifier = XGBoostIntrusionClassifier()
    classifier.feature_names = ["feat1", "feat2", "feat3"]
    classifier.dataset_name = "CICIDS2017"
    classifier.pipeline_version = "1.0"
    
    df_correct = pd.DataFrame(columns=["feat1", "feat2", "feat3"])
    classifier.verify_feature_compatibility(df_correct, "cicids2017", "1.0") # should pass silently
    
    # Dataset mismatch
    with pytest.raises(ValueError) as exc:
        classifier.verify_feature_compatibility(df_correct, "unsw_nb15", "1.0")
    assert "Dataset mismatch!" in str(exc.value)
    
    # Pipeline version mismatch
    with pytest.raises(ValueError) as exc:
        classifier.verify_feature_compatibility(df_correct, "cicids2017", "2.0")
    assert "Pipeline version mismatch!" in str(exc.value)
    
    # Feature count mismatch
    df_wrong_count = pd.DataFrame(columns=["feat1", "feat2"])
    with pytest.raises(ValueError) as exc:
        classifier.verify_feature_compatibility(df_wrong_count, "cicids2017", "1.0")
    assert "Feature count mismatch!" in str(exc.value)
    
    # Feature order mismatch
    df_wrong_order = pd.DataFrame(columns=["feat2", "feat1", "feat3"])
    with pytest.raises(ValueError) as exc:
        classifier.verify_feature_compatibility(df_wrong_order, "cicids2017", "1.0")
    assert "Feature mismatch at index 0!" in str(exc.value)

def test_binary_prediction_semantics():
    classifier = XGBoostIntrusionClassifier(task_type="binary")
    X_train = pd.DataFrame({
        "feat1": np.random.normal(0, 1, 100),
        "feat2": np.random.normal(0, 1, 100)
    })
    y_train = pd.Series(np.random.randint(0, 2, 100))
    
    classifier.fit(X_train, y_train, "CICIDS2017", "1.0")
    
    test_df = pd.DataFrame({
        "feat1": [0.0, 1.0],
        "feat2": [0.0, 1.0]
    })
    
    preds = classifier.predict(test_df)
    assert len(preds) == 2
    assert preds[0] in ["Normal", "Attack"]
    
    probs = classifier.predict_probabilities(test_df)
    assert probs.shape == (2, 2)
    assert np.all(probs >= 0.0) & np.all(probs <= 1.0)
    np.testing.assert_array_almost_equal(np.sum(probs, axis=1), [1.0, 1.0])
    
    report = classifier.get_prediction_report(test_df)
    assert len(report) == 2
    assert "predicted_class" in report[0]
    assert "normal_probability" in report[0]
    assert "attack_probability" in report[0]
    assert "confidence" in report[0]
    assert report[0]["confidence"] == max(report[0]["normal_probability"], report[0]["attack_probability"])

def test_multiclass_prediction_semantics():
    classifier = XGBoostIntrusionClassifier(task_type="multiclass")
    X_train = pd.DataFrame({
        "feat1": np.random.normal(0, 1, 100),
        "feat2": np.random.normal(0, 1, 100)
    })
    # Multiclass targets containing normal class and attack types
    y_train = pd.Series(np.random.choice(["Normal", "Generic", "Exploits"], 100))
    
    classifier.fit(X_train, y_train, "UNSW-NB15", "1.0")
    
    # 1. Normal/BENIGN must be mapped to index 0
    assert classifier.class_mapping["Normal"] == 0
    assert classifier.inverse_class_mapping[0] == "Normal"
    
    test_df = pd.DataFrame({
        "feat1": [0.0, 1.0],
        "feat2": [0.0, 1.0]
    })
    
    preds = classifier.predict(test_df)
    assert len(preds) == 2
    assert preds[0] in ["Normal", "Generic", "Exploits"]
    
    probs = classifier.predict_probabilities(test_df)
    assert probs.shape == (2, 3)
    np.testing.assert_array_almost_equal(np.sum(probs, axis=1), [1.0, 1.0])
    
    report = classifier.get_prediction_report(test_df)
    assert len(report) == 2
    assert "predicted_class" in report[0]
    assert "predicted_class_index" in report[0]
    assert "confidence" in report[0]
    assert "class_probabilities" in report[0]
    assert len(report[0]["class_probabilities"]) == 3
    assert report[0]["confidence"] == max(report[0]["class_probabilities"].values())

def test_metrics_calculation():
    # 1. Binary metrics
    y_true_bin = np.array([0, 0, 1, 1])
    y_pred_sem = np.array(["Normal", "Normal", "Normal", "Attack"]) # TN=2, FN=1, TP=1, FP=0
    res_bin = calculate_binary_metrics(y_true_bin, y_pred_sem)
    
    metrics = res_bin["metrics"]
    cm = res_bin["confusion_matrix"]
    
    assert cm["TP"] == 1
    assert cm["TN"] == 2
    assert cm["FP"] == 0
    assert cm["FN"] == 1
    assert metrics["accuracy"] == 0.75
    assert metrics["precision"] == 1.0
    assert metrics["recall_detection_rate"] == 0.5
    assert metrics["false_positive_rate"] == 0.0
    
    # 2. Multiclass metrics
    y_true_mul = np.array(["Normal", "Normal", "Generic", "Exploits"])
    y_pred_mul = np.array(["Normal", "Normal", "Exploits", "Exploits"])
    res_mul = calculate_multiclass_metrics(y_true_mul, y_pred_mul, "unsw_nb15")
    
    metrics_mul = res_mul["metrics"]
    assert metrics_mul["accuracy"] == 0.75
    # Attacks in y_true are Generic and Exploits. Generic was mispredicted as Exploits.
    # Exploits was predicted correctly.
    # Total actual attack samples = 2 (Generic, Exploits). Correct multiclass predictions on attacks = 1 (Exploits).
    # Attack classification accuracy = 1 / 2 = 0.5.
    assert metrics_mul["attack_classification_accuracy"] == 0.5
    
    # 3. Zero denominator cases
    y_true_zero = np.array([0, 0, 0])
    y_pred_zero = np.array(["Normal", "Normal", "Normal"])
    res_zero = calculate_binary_metrics(y_true_zero, y_pred_zero)
    assert res_zero["metrics"]["precision"] == 0.0
    assert res_zero["warnings"]["precision_zero_denominator"] is True

def test_model_persistence():
    classifier = XGBoostIntrusionClassifier(task_type="binary", config={"n_estimators": 5, "random_state": 42})
    X_train = pd.DataFrame({
        "feat1": np.random.normal(0, 1, 50),
        "feat2": np.random.normal(0, 1, 50)
    })
    y_train = pd.Series(np.random.randint(0, 2, 50))
    classifier.fit(X_train, y_train, "CICIDS2017", "1.0")
    
    test_df = pd.DataFrame({
        "feat1": [0.0, 1.0],
        "feat2": [0.0, 1.0]
    })
    
    original_preds = classifier.predict(test_df)
    original_probs = classifier.predict_probabilities(test_df)
    
    # Save model to temp file
    temp_dir = tempfile.mkdtemp()
    model_path = os.path.join(temp_dir, "xgb_test_model.joblib")
    joblib.dump(classifier, model_path)
    
    # Load back
    loaded_classifier = joblib.load(model_path)
    loaded_preds = loaded_classifier.predict(test_df)
    loaded_probs = loaded_classifier.predict_probabilities(test_df)
    
    # Check consistency
    np.testing.assert_array_equal(original_preds, loaded_preds)
    np.testing.assert_array_equal(original_probs, loaded_probs)
    assert loaded_classifier.dataset_name == "CICIDS2017"
    assert loaded_classifier.pipeline_version == "1.0"
    assert loaded_classifier.feature_names == ["feat1", "feat2"]
    
    # Clean up temp
    os.remove(model_path)
    os.rmdir(temp_dir)
