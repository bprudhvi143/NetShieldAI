import os
import json
import datetime
import pandas as pd
import numpy as np
from typing import Dict, Any, Tuple

# Set matplotlib backend to Agg to prevent GUI popups in headless scripts
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

from ml.anomaly_detection.predict import load_detector

def calculate_metrics(y_true: np.ndarray, y_pred: np.ndarray) -> Dict[str, Any]:
    """
    Computes classification and security metrics.
    Ground truth: Normal = 0, Attack = 1
    Predictions: Normal = 0, Anomaly = 1
    """
    tp = int(np.sum((y_true == 1) & (y_pred == 1)))
    tn = int(np.sum((y_true == 0) & (y_pred == 0)))
    fp = int(np.sum((y_true == 0) & (y_pred == 1)))
    fn = int(np.sum((y_true == 1) & (y_pred == 0)))
    
    total = tp + tn + fp + fn
    
    accuracy = (tp + tn) / total if total > 0 else 0.0
    
    # Precision: TP / (TP + FP)
    precision_denom = tp + fp
    precision = tp / precision_denom if precision_denom > 0 else 0.0
    precision_warning = precision_denom == 0
    
    # Recall / TPR / Detection Rate: TP / (TP + FN)
    recall_denom = tp + fn
    tpr = tp / recall_denom if recall_denom > 0 else 0.0
    recall_warning = recall_denom == 0
    
    # F1-score: 2 * Precision * Recall / (Precision + Recall)
    f1_denom = precision + tpr
    f1 = 2 * precision * tpr / f1_denom if f1_denom > 0 else 0.0
    
    # False Positive Rate (FPR): FP / (FP + TN)
    fpr_denom = fp + tn
    fpr = fp / fpr_denom if fpr_denom > 0 else 0.0
    fpr_warning = fpr_denom == 0
    
    # Specificity / True Negative Rate (TNR): TN / (TN + FP)
    tnr_denom = tn + fp
    tnr = tn / tnr_denom if tnr_denom > 0 else 0.0
    tnr_warning = tnr_denom == 0
    
    # False Negative Rate (FNR): FN / (FN + TP)
    fnr_denom = fn + tp
    fnr = fn / fnr_denom if fnr_denom > 0 else 0.0
    fnr_warning = fnr_denom == 0

    return {
        "confusion_matrix": {
            "TP": tp,
            "TN": tn,
            "FP": fp,
            "FN": fn
        },
        "metrics": {
            "accuracy": float(accuracy),
            "precision": float(precision),
            "recall_detection_rate": float(tpr),
            "f1_score": float(f1),
            "true_positive_rate": float(tpr),
            "false_positive_rate": float(fpr),
            "true_negative_rate_specificity": float(tnr),
            "false_negative_rate": float(fnr)
        },
        "warnings": {
            "precision_zero_denominator": precision_warning,
            "recall_zero_denominator": recall_warning,
            "fpr_zero_denominator": fpr_warning,
            "tnr_zero_denominator": tnr_warning,
            "fnr_zero_denominator": fnr_warning
        }
    }

def get_score_stats(scores: np.ndarray) -> Dict[str, float]:
    """Calculate basic numeric statistics of a 1D score array."""
    if len(scores) == 0:
        return {"count": 0, "min": 0.0, "max": 0.0, "mean": 0.0, "median": 0.0, "std": 0.0}
    return {
        "count": int(len(scores)),
        "min": float(np.min(scores)),
        "max": float(np.max(scores)),
        "mean": float(np.mean(scores)),
        "median": float(np.median(scores)),
        "std": float(np.std(scores))
    }

def generate_evaluation_visualizations(
    raw_scores: np.ndarray,
    y_true: np.ndarray,
    confusion_dict: dict,
    output_dir: str
):
    """
    Generate and save confusion matrix and score distribution plots.
    """
    os.makedirs(output_dir, exist_ok=True)
    
    # 1. Anomaly Score Distribution Plot (Histogram)
    normal_scores = raw_scores[y_true == 0]
    attack_scores = raw_scores[y_true == 1]
    
    plt.figure(figsize=(10, 5))
    if len(normal_scores) > 0:
        plt.hist(normal_scores, bins=30, alpha=0.6, label="Normal Traffic", color="blue", density=True)
    if len(attack_scores) > 0:
        plt.hist(attack_scores, bins=30, alpha=0.6, label="Attack Traffic", color="red", density=True)
        
    plt.title("Anomaly Score Distribution")
    plt.xlabel("Raw Anomaly Score (decision_function)")
    plt.ylabel("Density")
    plt.legend()
    plt.grid(True, linestyle="--", alpha=0.6)
    
    dist_plot_path = os.path.join(output_dir, "anomaly_score_distribution.png")
    plt.savefig(dist_plot_path, bbox_inches="tight")
    plt.close()
    
    # 2. Confusion Matrix Plot
    tp = confusion_dict["TP"]
    tn = confusion_dict["TN"]
    fp = confusion_dict["FP"]
    fn = confusion_dict["FN"]
    
    cm = np.array([[tn, fp], [fn, tp]])
    
    fig, ax = plt.subplots(figsize=(6, 5))
    im = ax.imshow(cm, interpolation='nearest', cmap=plt.cm.Blues)
    ax.figure.colorbar(im, ax=ax)
    
    ax.set(xticks=np.arange(cm.shape[1]),
           yticks=np.arange(cm.shape[0]),
           xticklabels=["Normal", "Anomaly"],
           yticklabels=["Normal", "Anomaly"],
           title="Confusion Matrix",
           ylabel="Actual Label",
           xlabel="Predicted Label")
    
    # Loop over data dimensions and create text annotations
    thresh = cm.max() / 2.
    for i in range(cm.shape[0]):
        for j in range(cm.shape[1]):
            ax.text(j, i, format(cm[i, j], 'd'),
                    ha="center", va="center",
                    color="white" if cm[i, j] > thresh else "black",
                    fontsize=14)
            
    fig.tight_layout()
    cm_plot_path = os.path.join(output_dir, "confusion_matrix.png")
    plt.savefig(cm_plot_path, bbox_inches="tight")
    plt.close()

def save_report_files(
    dataset_name: str,
    split_name: str,
    results_dict: dict,
    output_dir: str
):
    """
    Saves JSON and Markdown report files.
    """
    os.makedirs(output_dir, exist_ok=True)
    
    # Save JSON report
    json_path = os.path.join(output_dir, "evaluation.json")
    with open(json_path, 'w') as f:
        json.dump(results_dict, f, indent=4)
        
    # Generate Markdown Report
    overview = results_dict["overview"]
    cm = results_dict["confusion_matrix"]
    metrics = results_dict["metrics"]
    normal_stats = results_dict["normal_score_statistics"]
    attack_stats = results_dict["attack_score_statistics"]
    
    md_content = f"""# Anomaly Detection Evaluation - {dataset_name.upper()} ({split_name.upper()})

Generated on: {results_dict["creation_timestamp"]}
Preprocessing Pipeline Version: {overview["pipeline_version"]}

> [!WARNING]
> The current results are based on the Phase 1 development samples of approximately 5,000 rows and are not final full-dataset or production performance.

## 1. Split Overview
- **Dataset**: {dataset_name.upper()}
- **Evaluation Split**: {split_name.upper()}
- **Total Samples**: {overview["total_samples"]:,}
- **Normal Samples**: {overview["normal_samples"]:,}
- **Attack Samples**: {overview["attack_samples"]:,}
- **Features Used**: {overview["feature_count"]}

## 2. Security Performance Metrics
- **Accuracy**: {metrics["accuracy"]:.4f}
- **Precision**: {metrics["precision"]:.4f}
- **Recall (Detection Rate / TPR)**: {metrics["recall_detection_rate"]:.4f}
- **F1-Score**: {metrics["f1_score"]:.4f}
- **False Positive Rate (FPR)**: {metrics["false_positive_rate"]:.4f}
- **True Negative Rate (Specificity)**: {metrics["true_negative_rate_specificity"]:.4f}
- **False Negative Rate (FNR)**: {metrics["false_negative_rate"]:.4f}

### Confusion Matrix:

| | Predicted Normal | Predicted Anomaly |
| --- | --- | --- |
| **Actual Normal** | **TN**: {cm["TN"]:,} | **FP**: {cm["FP"]:,} |
| **Actual Attack** | **FN**: {cm["FN"]:,} | **TP**: {cm["TP"]:,} |

*Semantic Definitions*:
- **TP (True Positive)**: Attack flow correctly identified as Anomaly.
- **TN (True Negative)**: Normal flow correctly identified as Normal.
- **FP (False Positive)**: Normal flow incorrectly identified as Anomaly (triggers false alert).
- **FN (False Negative)**: Attack flow incorrectly identified as Normal (escapes detection).

## 3. Anomaly Score Numerical Statistics
Isolation Forest decision function values (raw scores) are smaller for anomalies and larger/positive for normal traffic.

| Statistic | Normal Traffic Scores | Attack Traffic Scores |
| --- | --- | --- |
| **Count** | {normal_stats["count"]:,} | {attack_stats["count"]:,} |
| **Minimum** | {normal_stats["min"]:.6f} | {attack_stats["min"]:.6f} |
| **Maximum** | {normal_stats["max"]:.6f} | {attack_stats["max"]:.6f} |
| **Mean** | {normal_stats["mean"]:.6f} | {attack_stats["mean"]:.6f} |
| **Median** | {normal_stats["median"]:.6f} | {attack_stats["median"]:.6f} |
| **Std Dev** | {normal_stats["std"]:.6f} | {attack_stats["std"]:.6f} |

## 4. Visualizations
- **Confusion Matrix**: [confusion_matrix.png](confusion_matrix.png)
- **Anomaly Score Distributions**: [anomaly_score_distribution.png](anomaly_score_distribution.png)
"""
    md_path = os.path.join(output_dir, "evaluation.md")
    with open(md_path, 'w') as f:
        f.write(md_content)

def evaluate_dataset_split(dataset_name: str, split_name: str) -> dict:
    print(f"Evaluating {dataset_name.upper()} on {split_name.upper()} split...")
    
    # Paths
    base_dir = "c:/NetShieldAI"
    model_path = os.path.join(base_dir, f"ml/models/{dataset_name.lower()}/isolation_forest.joblib")
    metadata_dir = os.path.join(base_dir, "ml/artifacts/metadata")
    processed_dir = os.path.join(base_dir, f"datasets/{dataset_name.upper() if dataset_name.lower() == 'cicids2017' else 'UNSW-NB15'}/processed")
    reports_dir = os.path.join(base_dir, f"ml/reports/anomaly_detection/{dataset_name.lower()}/{split_name.lower()}")
    
    # 1. Load model and verify compatibility
    detector = load_detector(model_path)
    
    # Load Phase 1 metadata
    metadata_path = os.path.join(metadata_dir, f"{dataset_name.lower()}_metadata.json")
    with open(metadata_path, 'r') as f:
        phase1_meta = json.load(f)
    pipeline_version = phase1_meta.get("pipeline_version", "1.0")
    
    # Load splits
    split_abbr = "val" if split_name.lower() == "validation" else split_name.lower()
    X_path = os.path.join(processed_dir, f"X_{split_abbr}_anomaly.csv")
    y_path = os.path.join(processed_dir, f"y_{split_abbr}_binary.csv")
    
    if not os.path.exists(X_path) or not os.path.exists(y_path):
        raise FileNotFoundError(f"Evaluation splits not found: {X_path} or {y_path}")
        
    X_eval = pd.read_csv(X_path, index_col=0)
    y_eval = pd.read_csv(y_path, index_col=0)
    
    # 2. Strict model/preprocessor compatibility checks
    detector.verify_feature_compatibility(X_eval, dataset_name, pipeline_version)
    
    # 3. Perform prediction and extract scores
    preds = detector.predict(X_eval) # Normal = 0, Anomaly = 1
    raw_scores = detector.decision_function(X_eval)
    
    # Labels
    label_col = y_eval.columns[0]
    y_true = y_eval[label_col].values
    
    # 4. Calculate metrics
    calc_results = calculate_metrics(y_true, preds)
    
    # 5. Extract score distributions stats
    normal_scores = raw_scores[y_true == 0]
    attack_scores = raw_scores[y_true == 1]
    
    normal_score_stats = get_score_stats(normal_scores)
    attack_score_stats = get_score_stats(attack_scores)
    
    # 6. Assemble complete results dict
    results = {
        "creation_timestamp": datetime.datetime.now().isoformat(),
        "overview": {
            "dataset": dataset_name.upper(),
            "split": split_name.upper(),
            "pipeline_version": pipeline_version,
            "total_samples": len(X_eval),
            "normal_samples": len(normal_scores),
            "attack_samples": len(attack_scores),
            "feature_count": X_eval.shape[1]
        },
        "confusion_matrix": calc_results["confusion_matrix"],
        "metrics": calc_results["metrics"],
        "metric_warnings": calc_results["warnings"],
        "normal_score_statistics": normal_score_stats,
        "attack_score_statistics": attack_score_stats
    }
    
    # 7. Generate plots
    generate_evaluation_visualizations(raw_scores, y_true, calc_results["confusion_matrix"], reports_dir)
    
    # 8. Save reports
    save_report_files(dataset_name, split_name, results, reports_dir)
    
    print(f"Saved reports for {dataset_name} ({split_name}) to {reports_dir}")
    return results

def evaluate_all():
    print("=== STARTING ML EVALUATION PIPELINE ===")
    
    # Evaluate CICIDS2017
    evaluate_dataset_split("cicids2017", "validation")
    evaluate_dataset_split("cicids2017", "test")
    
    # Evaluate UNSW-NB15
    evaluate_dataset_split("unsw_nb15", "validation")
    evaluate_dataset_split("unsw_nb15", "test")
    
    print("\n=== ANOMALY DETECTION MODEL EVALUATION COMPLETE ===")

if __name__ == "__main__":
    evaluate_all()
