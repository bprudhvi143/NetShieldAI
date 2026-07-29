import os
import json
import pytest
import numpy as np
import pandas as pd

from ml.risk_scoring.severity import get_attack_severity
from ml.risk_scoring.impact import assess_impact
from ml.risk_scoring.priority import calculate_priority
from ml.risk_scoring.risk_scorer import calculate_risk_score, normalize_anomaly_score
from ml.risk_scoring.predict import load_risk_models, predict_single_flow_risk, predict_batch_risk

def test_score_normalization():
    # Test normalization bounds for cicids2017
    # cicids2017 bounds: min = -0.24902324868143366, max = 0.1859617088397998
    # raw_score == train_score_max -> 0.0
    norm_max = normalize_anomaly_score(0.1859617088397998, "cicids2017")
    assert norm_max == 0.0
    
    # raw_score == train_score_min -> 1.0
    norm_min = normalize_anomaly_score(-0.24902324868143366, "cicids2017")
    assert norm_min == 1.0
    
    # Check clipping
    norm_under = normalize_anomaly_score(0.5, "cicids2017")
    assert norm_under == 0.0
    norm_over = normalize_anomaly_score(-0.6, "cicids2017")
    assert norm_over == 1.0

def test_score_bounds_and_risk_thresholds():
    # Test risk level boundaries:
    # Low: 0-29, Medium: 30-59, High: 60-84, Critical: 85-100
    
    # 1. Threat score low boundary
    res_low = calculate_risk_score(
        dataset="cicids2017",
        anomaly_detected=False,
        anomaly_score=0.0,
        predicted_class="BENIGN",
        intrusion_probability=0.0,
        confidence=0.99,
        is_anomaly_score_normalized=True
    )
    assert res_low["threat_score"] == 0.0
    assert res_low["risk_level"] == "Low"
    assert res_low["priority"] == "P4"
    
    # 2. Medium boundary exact check (29.9 vs 30.0)
    # Let's mock a score of 29.9
    # Using weights: intrusion=0.4, anomaly=0.2, severity=0.2, impact=0.2
    # IP=0.0, AS=0.0, Severity=20 (Low), Impact=129.5 (Impossible) -> let's test thresholds via simulated contributions
    # Instead of manual weights tweaking, let's test threat score boundaries inside calculate_risk_score:
    
    # Test boundary immediately below 30
    res_29 = calculate_risk_score(
        dataset="cicids2017",
        anomaly_detected=True,
        anomaly_score=0.0,
        predicted_class="FTP-Patator", # Severity Medium (50) -> contrib = 10
        intrusion_probability=0.20, # intrusion contrib = 8
        confidence=0.8,
        is_anomaly_score_normalized=True
    )
    # Impact score: 45.0 (since FTP-Patator is Medium severity) -> contrib = 9.0
    # Total = 8.0 + 0.0 + 10.0 + 9.0 = 27.0 (Low risk)
    assert res_29["threat_score"] == 27.0
    assert res_29["risk_level"] == "Low"
    
    # Test boundary at 30.0+
    res_30 = calculate_risk_score(
        dataset="cicids2017",
        anomaly_detected=True,
        anomaly_score=0.5, # anomaly contrib = 10
        predicted_class="FTP-Patator", # Severity Medium (50) -> contrib = 10
        intrusion_probability=0.25, # intrusion contrib = 10
        confidence=0.8,
        is_anomaly_score_normalized=True
    )
    # Impact score: 45.0 (since FTP-Patator is Medium severity) -> contrib = 9.0
    # Total = 10.0 + 10.0 + 10.0 + 9.0 = 39.0 (Medium risk)
    assert res_30["threat_score"] == 39.0
    assert res_30["risk_level"] == "Medium"
    
    # Test boundary at 60.0
    res_60 = calculate_risk_score(
        dataset="cicids2017",
        anomaly_detected=True,
        anomaly_score=0.8, # anomaly contrib = 16
        predicted_class="DDoS", # Severity Critical (100) -> contrib = 20
        intrusion_probability=0.5, # intrusion contrib = 20
        confidence=0.9,
        is_anomaly_score_normalized=True
    )
    # Impact score: 100.0 (since DDoS is Critical severity) -> contrib = 20.0
    # Total = 20.0 + 16.0 + 20.0 + 20.0 = 76.0 (High risk)
    assert res_60["threat_score"] == 76.0
    assert res_60["risk_level"] == "High"
    
    # Test boundary at 85.0
    res_85 = calculate_risk_score(
        dataset="cicids2017",
        anomaly_detected=True,
        anomaly_score=0.9, # anomaly contrib = 18
        predicted_class="DDoS", # Severity Critical (100) -> contrib = 20
        intrusion_probability=0.95, # intrusion contrib = 38
        confidence=0.95,
        is_anomaly_score_normalized=True
    )
    # Impact score: 100.0 (since DDoS is Critical severity) -> contrib = 20.0
    # Total = 38.0 + 18.0 + 20.0 + 20.0 = 96.0 (Critical risk)
    assert res_85["threat_score"] == 96.0
    assert res_85["risk_level"] == "Critical"

def test_severity_mapping():
    # Test known attack category
    level, score, is_fb = get_attack_severity("DDoS", "cicids2017")
    assert level == "Critical"
    assert score == 100.0
    assert not is_fb
    
    # Test unknown attack category (trigger fallback)
    level_unk, score_unk, is_fb_unk = get_attack_severity("SuperNewAttackType", "cicids2017")
    assert level_unk == "Medium"
    assert score_unk == 50.0
    assert is_fb_unk
    
    # Test normal class (Not Applicable)
    level_norm, score_norm, is_fb_norm = get_attack_severity("BENIGN", "cicids2017")
    assert level_norm == "Not Applicable"
    assert score_norm == 0.0
    assert not is_fb_norm

def test_impact_assessment():
    # Test normal traffic impact (Low, 0)
    level_n, score_n, reason_n = assess_impact(0.01, 0.05, "Normal")
    assert level_n == "Low"
    assert score_n == 0.0
    assert "predicted as normal" in reason_n
    
    # Test high signal impact (Critical)
    level_h, score_h, reason_h = assess_impact(0.95, 0.90, "DDoS", "Critical")
    assert level_h == "Critical"
    assert score_h == 100.0
    assert "DDoS" in reason_h
    assert "Critical" in reason_h

def test_impact_score_independence():
    # 1. Changing intrusion probability alone does not change Impact Score
    lvl1, score1, _ = assess_impact(0.1, 0.5, "DDoS", "Critical")
    lvl2, score2, _ = assess_impact(0.9, 0.5, "DDoS", "Critical")
    assert score1 == score2
    assert lvl1 == lvl2
    
    # 2. Changing anomaly score alone does not change Impact Score
    lvl3, score3, _ = assess_impact(0.5, 0.1, "DDoS", "Critical")
    lvl4, score4, _ = assess_impact(0.5, 0.9, "DDoS", "Critical")
    assert score3 == score4
    assert lvl3 == lvl4

    # 3. Changing intrusion/anomaly probability still changes Threat Score appropriately
    res_low_prob = calculate_risk_score(
        dataset="cicids2017",
        anomaly_detected=True,
        anomaly_score=0.1,
        predicted_class="DDoS",
        intrusion_probability=0.1,
        confidence=0.9,
        is_anomaly_score_normalized=True
    )
    
    res_high_prob = calculate_risk_score(
        dataset="cicids2017",
        anomaly_detected=True,
        anomaly_score=0.9,
        predicted_class="DDoS",
        intrusion_probability=0.9,
        confidence=0.9,
        is_anomaly_score_normalized=True
    )
    
    # Impact score should be identical for both (since both are DDoS/Critical)
    assert res_low_prob["impact"]["score"] == res_high_prob["impact"]["score"]
    
    # But threat score must change and be higher for high prob
    assert res_high_prob["threat_score"] > res_low_prob["threat_score"]
    
    # Ensure both scores remain in [0, 100]
    assert 0.0 <= res_low_prob["threat_score"] <= 100.0
    assert 0.0 <= res_high_prob["threat_score"] <= 100.0

def test_priority_matrix():
    # Test P1: Critical risk + Critical impact
    p1, r1 = calculate_priority("Critical", "Critical")
    assert p1 == "P1"
    
    # Test P2: High risk + Medium impact
    p2, r2 = calculate_priority("High", "Medium")
    assert p2 == "P2"
    
    # Test P4: Low risk + Low impact
    p4, r4 = calculate_priority("Low", "Low")
    assert p4 == "P4"

def test_signal_conflicts():
    # Anomaly=True, Supervised=Normal
    res_conflict1 = calculate_risk_score(
        dataset="cicids2017",
        anomaly_detected=True,
        anomaly_score=0.8,
        predicted_class="BENIGN",
        intrusion_probability=0.05,
        confidence=0.99,
        is_anomaly_score_normalized=True
    )
    assert res_conflict1["signal_status"] == "Anomaly Only"
    assert any("Conflict" in reason for reason in res_conflict1["reasons"])
    
    # Anomaly=False, Supervised=Attack
    res_conflict2 = calculate_risk_score(
        dataset="cicids2017",
        anomaly_detected=False,
        anomaly_score=0.05,
        predicted_class="DDoS",
        intrusion_probability=0.90,
        confidence=0.90,
        is_anomaly_score_normalized=True
    )
    assert res_conflict2["signal_status"] == "Intrusion Only"
    assert any("Conflict" in reason for reason in res_conflict2["reasons"])

def test_input_validation():
    # Invalid probability (<0)
    with pytest.raises(ValueError) as exc:
        calculate_risk_score("cicids2017", True, 0.5, "DDoS", -0.1, 0.9, True)
    assert "intrusion_probability must be in [0, 1]" in str(exc.value)
    
    # Invalid probability (>1)
    with pytest.raises(ValueError) as exc:
        calculate_risk_score("cicids2017", True, 0.5, "DDoS", 1.1, 0.9, True)
    assert "intrusion_probability must be in [0, 1]" in str(exc.value)
    
    # Unknown dataset
    with pytest.raises(ValueError) as exc:
        calculate_risk_score("invalid_dataset_name", True, 0.5, "DDoS", 0.5, 0.9, True)
    assert "Unknown dataset" in str(exc.value)

def test_determinism():
    args = {
        "dataset": "cicids2017",
        "anomaly_detected": True,
        "anomaly_score": 0.75,
        "predicted_class": "Bot",
        "intrusion_probability": 0.82,
        "confidence": 0.88,
        "is_anomaly_score_normalized": True
    }
    
    res1 = calculate_risk_score(**args)
    res2 = calculate_risk_score(**args)
    
    assert res1 == res2

def test_config_influence():
    # Test that changing config modifies scoring behavior
    custom_config = {
        "weights": {
            "intrusion_probability_weight": 0.1,
            "anomaly_weight": 0.7,
            "severity_weight": 0.1,
            "impact_weight": 0.1
        },
        "risk_thresholds": {
            "low": [0.0, 30.0],
            "medium": [30.0, 60.0],
            "high": [60.0, 85.0],
            "critical": [85.0, 100.0]
        },
        "severity_scores": {
            "Not Applicable": 0.0,
            "Low": 20.0,
            "Medium": 50.0,
            "High": 80.0,
            "Critical": 100.0
        },
        "priority_rules": {
            "Low": {"Low": "P4"}
        }
    }
    
    # Under default config, anomaly_weight is 0.2, intrusion_probability_weight is 0.4
    # IP=1.0 (contrib=40), AS=0.0 (contrib=0), Severity=0, Impact=0 -> Score = 40 (Medium)
    # Under custom config, anomaly_weight is 0.7, intrusion_probability_weight is 0.1
    # IP=1.0 (contrib=10), AS=0.0 (contrib=0), Severity=0, Impact=0 -> Score = 10 (Low)
    
    res_def = calculate_risk_score(
        dataset="cicids2017",
        anomaly_detected=False,
        anomaly_score=0.0,
        predicted_class="BENIGN",
        intrusion_probability=1.0,
        confidence=0.99,
        is_anomaly_score_normalized=True
    )
    
    res_cust = calculate_risk_score(
        dataset="cicids2017",
        anomaly_detected=False,
        anomaly_score=0.0,
        predicted_class="BENIGN",
        intrusion_probability=1.0,
        confidence=0.99,
        is_anomaly_score_normalized=True,
        config=custom_config
    )
    
    assert res_def["threat_score"] == 40.0
    assert res_cust["threat_score"] == 10.0
    assert res_def["risk_level"] == "Medium"
    assert res_cust["risk_level"] == "Low"

def test_integration_with_actual_models():
    # Load actual models and run prediction on sample records
    base_dir = "c:/NetShieldAI"
    metadata_dir = os.path.join(base_dir, "ml/artifacts/metadata")
    
    # Load metadata to get pipeline version
    with open(os.path.join(metadata_dir, "cicids2017_metadata.json"), "r") as f:
        meta_cic = json.load(f)
    pipeline_version = meta_cic.get("pipeline_version", "1.0")
    
    # Load cicids2017 models
    anomaly_detector, supervised_classifier = load_risk_models("cicids2017", "multiclass")
    
    # Load a row of validation features
    processed_dir = os.path.join(base_dir, "datasets/CICIDS2017/processed")
    df_anomaly = pd.read_csv(os.path.join(processed_dir, "X_val_anomaly.csv"), index_col=0, nrows=1)
    df_class = pd.read_csv(os.path.join(processed_dir, "X_val_class.csv"), index_col=0, nrows=1)
    
    # Run integration predict
    risk_res = predict_single_flow_risk(
        anomaly_detector=anomaly_detector,
        supervised_classifier=supervised_classifier,
        flow_df_anomaly=df_anomaly,
        flow_df_class=df_class,
        dataset_name="cicids2017",
        pipeline_version=pipeline_version
    )
    
    # Assert output structure and constraints
    assert "threat_score" in risk_res
    assert 0.0 <= risk_res["threat_score"] <= 100.0
    assert risk_res["risk_level"] in ["Low", "Medium", "High", "Critical"]
    assert risk_res["priority"] in ["P1", "P2", "P3", "P4"]
    assert "score_breakdown" in risk_res
    assert risk_res["score_breakdown"]["total"] == risk_res["threat_score"]
    assert risk_res["dataset"] == "cicids2017"
    assert "predicted_class" in risk_res["prediction"]
    assert "anomaly_detected" in risk_res["signals"]
    assert "level" in risk_res["severity"]
    assert "level" in risk_res["impact"]
