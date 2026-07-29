import os
import json
import time
from datetime import datetime
from typing import Tuple
import logging
import pandas as pd
import numpy as np
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix

logger = logging.getLogger("ml.threat_detection.evaluate")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

from ml.threat_detection.pipeline import ThreatDetectionPipeline
from ml.threat_detection.predict import get_pipeline

def evaluate_pipeline_split(
    dataset: str,
    split: str,
    base_dir: str = "c:/NetShieldAI"
) -> Tuple[dict, str]:
    """
    Evaluates the complete threat detection pipeline on a specific dataset and split.
    Returns a metrics dict and a markdown formatted report string.
    """
    split_clean = split.lower()
    split_fn = "val" if split_clean == "validation" else "test"
    ds_clean = dataset.lower().replace("-", "_")
    
    # 1. Load Data Paths
    folder_name = "CICIDS2017" if ds_clean == "cicids2017" else "UNSW-NB15"
    anomaly_path = os.path.join(base_dir, f"datasets/{folder_name}/processed/X_{split_fn}_anomaly.csv")
    class_path = os.path.join(base_dir, f"datasets/{folder_name}/processed/X_{split_fn}_class.csv")
    y_path = os.path.join(base_dir, f"datasets/{folder_name}/processed/y_{split_fn}_multiclass.csv")
    
    if not (os.path.exists(anomaly_path) and os.path.exists(class_path) and os.path.exists(y_path)):
        raise FileNotFoundError(f"Missing evaluation files for {dataset} {split}.")
        
    X_anomaly = pd.read_csv(anomaly_path, index_col=0)
    X_class = pd.read_csv(class_path, index_col=0)
    y_df = pd.read_csv(y_path, index_col=0)
    
    # Align indices
    common_idx = X_anomaly.index.intersection(X_class.index).intersection(y_df.index)
    X_anomaly = X_anomaly.loc[common_idx]
    X_class = X_class.loc[common_idx]
    y_df = y_df.loc[common_idx]
    
    # 2. Get Ground Truth
    target_col = y_df.columns[0]
    y_true_multiclass = y_df[target_col].astype(str).values
    
    normal_label = "BENIGN" if ds_clean == "cicids2017" else "Normal"
    y_true_binary = np.where(y_true_multiclass == normal_label, 0, 1)
    
    # 3. Load Pipeline & Run Predictions (loaded once and reused)
    pipeline = get_pipeline(ds_clean, base_dir)
    
    start_time = time.perf_counter()
    results = pipeline.predict_batch(X_anomaly, X_class)
    elapsed = time.perf_counter() - start_time
    
    N = len(results)
    latency_ms = (elapsed / N) * 1000.0
    throughput = N / elapsed
    
    # Extract prediction values
    pred_status = []
    pred_anomaly_detected = []
    pred_is_attack = []
    pred_multiclass = []
    pred_classification_status = []
    pred_threat_score = []
    pred_risk_level = []
    pred_signal_status = []
    
    for r in results:
        if isinstance(r, dict):
            # If a row failed, put default fallback values to not break evaluations
            pred_status.append("Normal")
            pred_anomaly_detected.append(False)
            pred_is_attack.append(False)
            pred_multiclass.append(normal_label)
            pred_classification_status.append("not_run")
            pred_threat_score.append(0.0)
            pred_risk_level.append("Low")
            pred_signal_status.append("normal")
        else:
            pred_status.append(r.detection.status)
            pred_anomaly_detected.append(r.detection.anomaly_detected)
            pred_is_attack.append(r.intrusion_prediction.is_attack)
            pred_multiclass.append(r.attack_classification.predicted_class)
            pred_classification_status.append(r.attack_classification.classification_status)
            pred_threat_score.append(r.risk.threat_score)
            pred_risk_level.append(r.risk.risk_level)
            pred_signal_status.append(r.signal_status)
            
    pred_status = np.array(pred_status)
    pred_anomaly_detected = np.array(pred_anomaly_detected)
    pred_is_attack = np.array(pred_is_attack)
    pred_multiclass = np.array(pred_multiclass)
    pred_classification_status = np.array(pred_classification_status)
    pred_threat_score = np.array(pred_threat_score)
    pred_risk_level = np.array(pred_risk_level)
    pred_signal_status = np.array(pred_signal_status)
    
    # 4. Calculate Metrics
    
    # Total samples
    total_samples = N
    normal_samples = int(np.sum(y_true_binary == 0))
    attack_samples = int(np.sum(y_true_binary == 1))
    
    # Anomaly rate
    anomaly_rate = float(np.mean(pred_anomaly_detected))
    anomaly_normal = int(np.sum(pred_anomaly_detected[y_true_binary == 0]))
    anomaly_attack = int(np.sum(pred_anomaly_detected[y_true_binary == 1]))
    
    # Anomaly Rate calculations
    normal_false_anomaly_rate = anomaly_normal / normal_samples if normal_samples > 0 else 0.0
    attack_anomaly_detection_rate = anomaly_attack / attack_samples if attack_samples > 0 else 0.0
    
    # Intrusion (binary classifier) metrics
    acc = float(accuracy_score(y_true_binary, pred_is_attack))
    
    # Safe precision, recall, f1
    if np.sum(pred_is_attack) > 0:
        prec = float(precision_score(y_true_binary, pred_is_attack, zero_division=0))
    else:
        prec = 0.0
    rec = float(recall_score(y_true_binary, pred_is_attack, zero_division=0))
    f1 = float(f1_score(y_true_binary, pred_is_attack, zero_division=0))
    
    tn, fp, fn, tp = confusion_matrix(y_true_binary, pred_is_attack).ravel()
    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
    
    # Clean/map None values in pred_multiclass to normal_label for pipeline accuracy calculations
    pred_multiclass_clean = np.array([p if p is not None else normal_label for p in pred_multiclass])

    # Standalone multiclass model predictions (run model directly on the entire test set)
    logger.info("Computing standalone multiclass model predictions...")
    multiclass_all_reports = pipeline.multiclass_classifier.get_prediction_report(X_class)
    pred_multiclass_all = np.array([r["predicted_class"] for r in multiclass_all_reports])
    standalone_multiclass_acc = float(accuracy_score(y_true_multiclass, pred_multiclass_all))
    standalone_macro_f1 = float(f1_score(y_true_multiclass, pred_multiclass_all, average="macro", zero_division=0))
    
    # Pipeline Gated Multiclass metrics
    pipeline_gated_multi_acc = float(accuracy_score(y_true_multiclass, pred_multiclass_clean))
    pipeline_gated_macro_f1 = float(f1_score(y_true_multiclass, pred_multiclass_clean, average="macro", zero_division=0))
    
    # True-Attack Classification Accuracy (accuracy of the pipeline's multiclass output on true attacks)
    attack_mask = (y_true_binary == 1)
    if np.sum(attack_mask) > 0:
        true_attack_class_acc = float(accuracy_score(
            y_true_multiclass[attack_mask], 
            pred_multiclass_clean[attack_mask]
        ))
    else:
        true_attack_class_acc = 0.0
        
    # Classification status counts
    perf_count = int(np.sum(pred_classification_status == "performed"))
    not_run_count = int(np.sum(pred_classification_status == "not_run"))
    
    # Risk Metrics
    mean_score_all = float(np.mean(pred_threat_score))
    median_score_all = float(np.median(pred_threat_score))
    
    mean_score_norm = float(np.mean(pred_threat_score[y_true_binary == 0]))
    median_score_norm = float(np.median(pred_threat_score[y_true_binary == 0]))
    
    mean_score_att = float(np.mean(pred_threat_score[y_true_binary == 1]))
    median_score_att = float(np.median(pred_threat_score[y_true_binary == 1]))
    
    # Risk Level Distributions
    risk_dist_normal = {"Low": 0, "Medium": 0, "High": 0, "Critical": 0}
    risk_dist_attack = {"Low": 0, "Medium": 0, "High": 0, "Critical": 0}
    
    for level in risk_dist_normal.keys():
        risk_dist_normal[level] = int(np.sum((pred_risk_level == level) & (y_true_binary == 0)))
        risk_dist_attack[level] = int(np.sum((pred_risk_level == level) & (y_true_binary == 1)))
        
    # High/Critical coverage & false alarm rates
    high_crit_levels = {"High", "Critical"}
    att_hc = np.sum([risk_dist_attack[l] for l in high_crit_levels])
    norm_hc = np.sum([risk_dist_normal[l] for l in high_crit_levels])
    
    high_crit_coverage = float(att_hc / attack_samples) if attack_samples > 0 else 0.0
    high_crit_false_rate = float(norm_hc / normal_samples) if normal_samples > 0 else 0.0
    
    # Signal consistency status counts
    signal_status_counts = {
        "normal": int(np.sum(pred_signal_status == "normal")),
        "anomaly_only": int(np.sum(pred_signal_status == "anomaly_only")),
        "intrusion_only": int(np.sum(pred_signal_status == "intrusion_only")),
        "confirmed_attack": int(np.sum(pred_signal_status == "confirmed_attack"))
    }
    
    metrics = {
        "creation_timestamp": datetime.now().isoformat(),
        "overview": {
            "dataset": dataset.upper(),
            "split": split.upper(),
            "total_samples": total_samples,
            "normal_samples": normal_samples,
            "attack_samples": attack_samples,
            "pipeline_version": pipeline.pipeline_version
        },
        "performance": {
            "latency_ms_per_flow": latency_ms,
            "throughput_flows_per_sec": throughput
        },
        "detection_status_counts": {
            "Normal": int(np.sum(pred_status == "Normal")),
            "Suspicious": int(np.sum(pred_status == "Suspicious")),
            "Pipeline_Attack_Status_Count": int(np.sum(pred_status == "Attack"))
        },
        "anomaly_metrics": {
            "overall_anomaly_rate": anomaly_rate,
            "normal_false_anomaly_rate": normal_false_anomaly_rate,
            "attack_anomaly_detection_rate": attack_anomaly_detection_rate,
            "normal_anomaly_count": anomaly_normal,
            "attack_anomaly_count": anomaly_attack
        },
        "supervised_binary_metrics": {
            "accuracy": acc,
            "precision": prec,
            "recall": rec,
            "f1_score": f1,
            "false_positive_rate": fpr,
            "confusion_matrix": {
                "TP": int(tp),
                "TN": int(tn),
                "FP": int(fp),
                "FN": int(fn)
            }
        },
        "supervised_multiclass_metrics": {
            "standalone_multiclass_model_accuracy": standalone_multiclass_acc,
            "standalone_multiclass_model_macro_f1": standalone_macro_f1,
            "pipeline_gated_multiclass_accuracy": pipeline_gated_multi_acc,
            "pipeline_gated_multiclass_macro_f1": pipeline_gated_macro_f1,
            "true_attack_classification_accuracy": true_attack_class_acc,
            "pipeline_multiclass_invocations": perf_count,
            "classification_status": {
                "performed": perf_count,
                "not_run": not_run_count
            }
        },
        "risk_metrics": {
            "threat_score": {
                "all_mean": mean_score_all,
                "all_median": median_score_all,
                "normal_mean": mean_score_norm,
                "normal_median": median_score_norm,
                "attack_mean": mean_score_att,
                "attack_median": median_score_att
            },
            "risk_level_distribution": {
                "normal": risk_dist_normal,
                "attack": risk_dist_attack
            },
            "coverage_and_false_alarms": {
                "attack_high_critical_coverage_rate": high_crit_coverage,
                "normal_high_critical_false_rate": high_crit_false_rate
            }
        },
        "signal_consistency": signal_status_counts
    }
    
    # 5. Generate Markdown Report
    md = f"""# Unified Threat Detection Pipeline Evaluation Report

* **Dataset**: {dataset.upper()}
* **Split**: {split.upper()}
* **Generated At**: {metrics["creation_timestamp"]}
* **Pipeline Version**: {pipeline.pipeline_version}

---

## 1. Overview & Data Split
* **Total Evaluation Samples**: {total_samples}
* **Normal Traffic Samples**: {normal_samples}
* **Attack Traffic Samples**: {attack_samples}

## 2. Detection Performance (Orchestrated Pipeline Status)
The pipeline categorizes traffic into three statuses: `Normal`, `Suspicious` (anomaly only), or `Attack`.

| Status | Total Mapped | Percentage |
| --- | --- | --- |
| **Normal** | {metrics["detection_status_counts"]["Normal"]} | {metrics["detection_status_counts"]["Normal"] / total_samples * 100:.2f}% |
| **Suspicious** | {metrics["detection_status_counts"]["Suspicious"]} | {metrics["detection_status_counts"]["Suspicious"] / total_samples * 100:.2f}% |
| **Pipeline Attack Status Count** | {metrics["detection_status_counts"]["Pipeline_Attack_Status_Count"]} | {metrics["detection_status_counts"]["Pipeline_Attack_Status_Count"] / total_samples * 100:.2f}% |

*Note: The Pipeline Attack Status Count represents model predictions (including false positives), not ground-truth attack samples.*

### Signal Consistency Distribution
* **Normal (`normal`)**: {signal_status_counts["normal"]}
* **Suspicious/Anomaly-Only (`anomaly_only`)**: {signal_status_counts["anomaly_only"]}
* **Intrusion-Only (`intrusion_only`)**: {signal_status_counts["intrusion_only"]}
* **Confirmed Attack (`confirmed_attack`)**: {signal_status_counts["confirmed_attack"]}

## 3. Anomaly Detector Diagnostics
* **Overall Anomaly Rate**: {anomaly_rate * 100:.2f}%
* **Normal False Anomaly Rate**: {normal_false_anomaly_rate * 100:.2f}% (Normal flagged anomalous: {anomaly_normal} / {normal_samples})
* **Attack Anomaly Detection Rate**: {attack_anomaly_detection_rate * 100:.2f}% (Attack flagged anomalous: {anomaly_attack} / {attack_samples})

## 4. Supervised Intrusion Prediction (Binary Classifier)
Evaluation of the XGBoost Binary Classifier.

* **Accuracy**: {acc:.4f}
* **Precision**: {prec:.4f}
* **Recall (Detection Rate)**: {rec:.4f}
* **F1-Score**: {f1:.4f}
* **False Positive Rate**: {fpr:.4f}

### Confusion Matrix
* **True Positives (TP)**: {tp}
* **True Negatives (TN)**: {tn}
* **False Positives (FP)**: {fp}
* **False Negatives (FN)**: {fn}

## 5. Supervised Attack Classification (Multiclass Classifier)
Distinct metrics separating standalone classifier performance from pipeline-gated execution.

* **Standalone Multiclass Model Accuracy**: {standalone_multiclass_acc:.4f} (Evaluated on all samples)
* **Standalone Multiclass Model Macro F1**: {standalone_macro_f1:.4f}
* **Pipeline Gated Multiclass Accuracy**: {pipeline_gated_multi_acc:.4f} (Pipeline prediction vs ground truth)
* **True-Attack Classification Accuracy**: {true_attack_class_acc:.4f} (Accuracy of the pipeline's multiclass output on true attacks)
* **Pipeline Multiclass Invocations**: {perf_count} (Number of times multiclass was run because Binary = Attack)
* **Multiclass Actions**:
  * Multiclass Classifier Performed: {perf_count}
  * Multiclass Classifier Not Run (Skipped for Normal): {not_run_count}

## 6. Risk Scoring Diagnostics
Risk Score calibration and risk level distributions.

### Threat Score Statistics
* **All Traffic**: Mean `{mean_score_all:.2f}`, Median `{median_score_all:.2f}`
* **Normal Traffic**: Mean `{mean_score_norm:.2f}`, Median `{median_score_norm:.2f}`
* **Attack Traffic**: Mean `{mean_score_att:.2f}`, Median `{median_score_att:.2f}`

### Risk Level Distribution
* **Normal Traffic**:
  * Low: {risk_dist_normal["Low"]}
  * Medium: {risk_dist_normal["Medium"]}
  * High: {risk_dist_normal["High"]}
  * Critical: {risk_dist_normal["Critical"]}
* **Attack Traffic**:
  * Low: {risk_dist_attack["Low"]}
  * Medium: {risk_dist_attack["Medium"]}
  * High: {risk_dist_attack["High"]}
  * Critical: {risk_dist_attack["Critical"]}

### Safety Coverage & False Alarms
* **Attack High/Critical Coverage Rate**: {high_crit_coverage * 100:.2f}% (Percentage of true attacks rated High/Critical)
* **Normal High/Critical False Alarm Rate**: {high_crit_false_rate * 100:.2f}% (Percentage of true normal traffic rated High/Critical)

## 7. Performance Benchmarks
* **Single Inference Latency**: {latency_ms:.3f} ms / flow
* **Batch Throughput**: {throughput:.1f} flows / second

---
> [!NOTE]
> This unified threat-detection workflow is currently evaluated on static development-sample splits.
"""
    return metrics, md

def main():
    print("=== STARTING UNIFIED THREAT DETECTION WORKFLOW EVALUATION ===")
    
    datasets = ["cicids2017", "unsw_nb15"]
    splits = ["validation", "test"]
    base_dir = "c:/NetShieldAI"
    
    for ds in datasets:
        for split in splits:
            print(f"Evaluating {ds.upper()} on {split.upper()} split...")
            try:
                metrics, md = evaluate_pipeline_split(ds, split, base_dir)
                
                # Save Paths
                out_dir = os.path.join(base_dir, f"ml/reports/threat_detection/{ds}/{split}")
                os.makedirs(out_dir, exist_ok=True)
                
                json_path = os.path.join(out_dir, "evaluation.json")
                md_path = os.path.join(out_dir, "evaluation.md")
                
                with open(json_path, "w", encoding="utf-8") as f:
                    json.dump(metrics, f, indent=4)
                    
                with open(md_path, "w", encoding="utf-8") as f:
                    f.write(md)
                    
                print(f"Completed evaluation. Saved reports to {out_dir}")
                
            except Exception as e:
                print(f"Failed to evaluate {ds} on {split}: {str(e)}")
                
    print("\n=== UNIFIED THREAT DETECTION WORKFLOW EVALUATION COMPLETE ===")

if __name__ == "__main__":
    main()
