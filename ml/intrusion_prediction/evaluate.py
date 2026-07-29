import os
import json
import datetime
import pandas as pd
import numpy as np
from typing import Dict, Any, Tuple, List

# Set matplotlib backend to Agg to prevent GUI popups in headless scripts
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

from sklearn.metrics import precision_recall_fscore_support
from ml.intrusion_prediction.predict import load_classifier

def calculate_binary_metrics(y_true: np.ndarray, y_pred_semantic: np.ndarray) -> Dict[str, Any]:
    """
    Computes binary classification and security metrics.
    Actual target values are expected to be 0 (Normal) or 1 (Attack).
    y_pred_semantic contains string predicted classes ("Normal" or "Attack").
    """
    # Map semantic predictions to binary integers
    pred_map = {"Normal": 0, "Attack": 1}
    y_pred = np.array([pred_map.get(p, 0) for p in y_pred_semantic])
    y_true = y_true.astype(int)
    
    tp = int(np.sum((y_true == 1) & (y_pred == 1)))
    tn = int(np.sum((y_true == 0) & (y_pred == 0)))
    fp = int(np.sum((y_true == 0) & (y_pred == 1)))
    fn = int(np.sum((y_true == 1) & (y_pred == 0)))
    
    total = tp + tn + fp + fn
    accuracy = (tp + tn) / total if total > 0 else 0.0
    
    # Precision
    precision_denom = tp + fp
    precision = tp / precision_denom if precision_denom > 0 else 0.0
    precision_warning = precision_denom == 0
    
    # Recall / TPR
    recall_denom = tp + fn
    tpr = tp / recall_denom if recall_denom > 0 else 0.0
    recall_warning = recall_denom == 0
    
    # F1-score
    f1_denom = precision + tpr
    f1 = 2 * precision * tpr / f1_denom if f1_denom > 0 else 0.0
    
    # FPR
    fpr_denom = fp + tn
    fpr = fp / fpr_denom if fpr_denom > 0 else 0.0
    fpr_warning = fpr_denom == 0
    
    # Specificity / TNR
    tnr_denom = tn + fp
    tnr = tn / tnr_denom if tnr_denom > 0 else 0.0
    tnr_warning = tnr_denom == 0
    
    # FNR
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

def calculate_multiclass_metrics(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    dataset_name: str
) -> Dict[str, Any]:
    """
    Computes multiclass classification metrics, per-class details, and attack classification accuracy.
    y_true and y_pred contain string class labels.
    """
    total = len(y_true)
    correct = int(np.sum(y_true == y_pred))
    accuracy = correct / total if total > 0 else 0.0
    
    # Get unique classes present in actual or predicted labels
    classes = sorted(list(set(y_true) | set(y_pred)))
    
    # Compute per-class precision, recall, f1, support
    precision_per_class, recall_per_class, f1_per_class, support_per_class = precision_recall_fscore_support(
        y_true, y_pred, labels=classes, zero_division=0
    )
    
    per_class_metrics = {}
    for idx, cls in enumerate(classes):
        per_class_metrics[cls] = {
            "precision": float(precision_per_class[idx]),
            "recall": float(recall_per_class[idx]),
            "f1_score": float(f1_per_class[idx]),
            "support": int(support_per_class[idx])
        }
        
    # Calculate Macro and Weighted Metrics
    macro_precision = np.mean(precision_per_class)
    macro_recall = np.mean(recall_per_class)
    macro_f1 = np.mean(f1_per_class)
    
    weights = support_per_class / total if total > 0 else np.zeros_like(support_per_class)
    weighted_precision = np.sum(precision_per_class * weights)
    weighted_recall = np.sum(recall_per_class * weights)
    weighted_f1 = np.sum(f1_per_class * weights)
    
    # Attack Classification Accuracy (excluding Normal/BENIGN)
    normal_class = "BENIGN" if dataset_name.lower() == "cicids2017" else "Normal"
    attack_indices = np.where(y_true != normal_class)[0]
    if len(attack_indices) > 0:
        correct_attack_preds = int(np.sum(y_true[attack_indices] == y_pred[attack_indices]))
        attack_classification_accuracy = correct_attack_preds / len(attack_indices)
    else:
        attack_classification_accuracy = 0.0
        
    return {
        "metrics": {
            "accuracy": float(accuracy),
            "macro_precision": float(macro_precision),
            "macro_recall": float(macro_recall),
            "macro_f1": float(macro_f1),
            "weighted_precision": float(weighted_precision),
            "weighted_recall": float(weighted_recall),
            "weighted_f1": float(weighted_f1),
            "attack_classification_accuracy": float(attack_classification_accuracy)
        },
        "per_class": per_class_metrics,
        "classes_evaluated": classes
    }

def generate_visualizations(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    classes: list,
    feature_importance_df: pd.DataFrame,
    output_dir: str
):
    """
    Generate and save confusion matrix and feature importance plots.
    """
    os.makedirs(output_dir, exist_ok=True)
    
    # 1. Feature Importance Plot
    top_n = min(15, len(feature_importance_df))
    top_feat = feature_importance_df.head(top_n).sort_values(by="importance", ascending=True)
    
    plt.figure(figsize=(10, 6))
    plt.barh(top_feat["feature"], top_feat["importance"], color="teal", alpha=0.8)
    plt.title(f"Top {top_n} XGBoost Feature Importance")
    plt.xlabel("Importance Score")
    plt.ylabel("Features")
    plt.grid(True, linestyle="--", alpha=0.5)
    
    # Caption notice in text block rather than plot itself to keep it clean
    plt.tight_layout()
    feat_plot_path = os.path.join(output_dir, "feature_importance.png")
    plt.savefig(feat_plot_path, bbox_inches="tight")
    plt.close()
    
    # 2. Confusion Matrix Plot
    # We construct the matrix manually or using sklearn mapping
    from sklearn.metrics import confusion_matrix
    cm = confusion_matrix(y_true, y_pred, labels=classes)
    
    fig, ax = plt.subplots(figsize=(8, 7))
    im = ax.imshow(cm, interpolation='nearest', cmap=plt.cm.Blues)
    ax.figure.colorbar(im, ax=ax)
    
    # Show labels
    ax.set(xticks=np.arange(cm.shape[1]),
           yticks=np.arange(cm.shape[0]),
           xticklabels=classes,
           yticklabels=classes,
           title="Confusion Matrix",
           ylabel="Actual Label",
           xlabel="Predicted Label")
    
    # Rotate tick labels if long
    if len(classes) > 4:
        plt.setp(ax.get_xticklabels(), rotation=45, ha="right", rotation_mode="anchor")
        
    # Text annotations
    thresh = cm.max() / 2.
    for i in range(cm.shape[0]):
        for j in range(cm.shape[1]):
            ax.text(j, i, format(cm[i, j], 'd'),
                    ha="center", va="center",
                    color="white" if cm[i, j] > thresh else "black")
            
    fig.tight_layout()
    cm_plot_path = os.path.join(output_dir, "confusion_matrix.png")
    plt.savefig(cm_plot_path, bbox_inches="tight")
    plt.close()

def save_report_files(
    dataset_name: str,
    task_type: str,
    split_name: str,
    results_dict: dict,
    feature_importance_df: pd.DataFrame,
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
    metrics = results_dict["metrics"]
    
    md_content = f"""# XGBoost Intrusion Prediction - {dataset_name.upper()} {task_type.upper()} ({split_name.upper()})

Generated on: {results_dict["creation_timestamp"]}
Preprocessing Pipeline Version: {overview["pipeline_version"]}

> [!WARNING]
> The current results are based on the Phase 1 development samples of approximately 5,000 rows and are not final full-dataset or production performance.

## 1. Split Overview
- **Dataset**: {dataset_name.upper()}
- **Task Type**: {task_type.upper()}
- **Evaluation Split**: {split_name.upper()}
- **Total Samples**: {overview["total_samples"]:,}
- **Features Count**: {overview["feature_count"]}

"""

    if task_type == "binary":
        cm = results_dict["confusion_matrix"]
        md_content += f"""## 2. Security Performance Metrics
- **Accuracy**: {metrics["accuracy"]:.4f}
- **Precision**: {metrics["precision"]:.4f}
- **Recall (Detection Rate / TPR)**: {metrics["recall_detection_rate"]:.4f}
- **F1-Score**: {metrics["f1_score"]:.4f}
- **False Positive Rate (FPR)**: {metrics["false_positive_rate"]:.4f}
- **True Negative Rate (Specificity)**: {metrics["true_negative_rate_specificity"]:.4f}
- **False Negative Rate (FNR)**: {metrics["false_negative_rate"]:.4f}

### Confusion Matrix:

| | Predicted Normal | Predicted Attack |
| --- | --- | --- |
| **Actual Normal** | **TN**: {cm["TN"]:,} | **FP**: {cm["FP"]:,} |
| **Actual Attack** | **FN**: {cm["FN"]:,} | **TP**: {cm["TP"]:,} |

*Semantic Definitions*:
- **TP (True Positive)**: Attack flow correctly identified as Attack.
- **TN (True Negative)**: Normal flow correctly identified as Normal.
- **FP (False Positive)**: Normal flow incorrectly identified as Attack (triggers false alert).
- **FN (False Negative)**: Attack flow incorrectly identified as Normal (escapes detection).
"""
    else:
        # Multiclass
        md_content += f"""## 2. Supervised Performance Metrics
- **Overall Accuracy**: {metrics["accuracy"]:.4f}
- **Attack Classification Accuracy (Outliers Only)**: {metrics["attack_classification_accuracy"]:.4f}
- **Macro Precision**: {metrics["macro_precision"]:.4f}
- **Macro Recall**: {metrics["macro_recall"]:.4f}
- **Macro F1-Score**: {metrics["macro_f1"]:.4f}
- **Weighted Precision**: {metrics["weighted_precision"]:.4f}
- **Weighted Recall**: {metrics["weighted_recall"]:.4f}
- **Weighted F1-Score**: {metrics["weighted_f1"]:.4f}

### Per-Class Performance Table:

| Class Name | Precision | Recall | F1-Score | Support |
| --- | --- | --- | --- | --- |
"""
        for cls_name, cls_metrics in results_dict["per_class"].items():
            md_content += f"| **{cls_name}** | {cls_metrics['precision']:.4f} | {cls_metrics['recall']:.4f} | {cls_metrics['f1_score']:.4f} | {cls_metrics['support']:,} |\n"
            
    # Feature Importance Section
    md_content += """
## 3. Feature Importance Analysis
Top 10 features sorted by XGBoost `feature_importances_` metric:

| Rank | Feature Name | Importance Score |
| --- | --- | --- |
"""
    for _, row in feature_importance_df.head(10).iterrows():
        md_content += f"| {row['rank']} | {row['feature']} | {row['importance']:.6f} |\n"
        
    md_content += """
> [!NOTE]
> **Causality Notice**: Feature importance represents the model's contribution/association with predictions and does NOT establish causal relationships or physical network-attack causation.

## 4. Visualizations
- **Confusion Matrix**: [confusion_matrix.png](confusion_matrix.png)
- **Feature Importance Plot**: [feature_importance.png](feature_importance.png)
"""
    md_path = os.path.join(output_dir, "evaluation.md")
    with open(md_path, 'w') as f:
        f.write(md_content)

def evaluate_model_split(dataset_name: str, task_type: str, split_name: str) -> dict:
    print(f"Evaluating {dataset_name.upper()} ({task_type.upper()}) on {split_name.upper()} split...")
    
    # Paths
    base_dir = "c:/NetShieldAI"
    model_path = os.path.join(base_dir, f"ml/models/intrusion_prediction/{dataset_name.lower()}/{task_type.lower()}/xgboost_{task_type.lower()}.joblib")
    metadata_dir = os.path.join(base_dir, "ml/artifacts/metadata")
    processed_dir = os.path.join(base_dir, f"datasets/{dataset_name.upper() if dataset_name.lower() == 'cicids2017' else 'UNSW-NB15'}/processed")
    reports_dir = os.path.join(base_dir, f"ml/reports/intrusion_prediction/{dataset_name.lower()}/{task_type.lower()}/{split_name.lower()}")
    
    # Load model
    classifier = load_classifier(model_path)
    
    # Load Phase 1 metadata
    metadata_path = os.path.join(metadata_dir, f"{dataset_name.lower()}_metadata.json")
    with open(metadata_path, 'r') as f:
        phase1_meta = json.load(f)
    pipeline_version = phase1_meta.get("pipeline_version", "1.0")
    
    # Load processed splits
    split_abbr = "val" if split_name.lower() == "validation" else split_name.lower()
    X_path = os.path.join(processed_dir, f"X_{split_abbr}_class.csv")
    
    target_suffix = "binary" if task_type == "binary" else "multiclass"
    y_path = os.path.join(processed_dir, f"y_{split_abbr}_{target_suffix}.csv")
    
    if not os.path.exists(X_path) or not os.path.exists(y_path):
        raise FileNotFoundError(f"Evaluation splits not found at {X_path} or {y_path}!")
        
    X_eval = pd.read_csv(X_path, index_col=0)
    y_eval = pd.read_csv(y_path, index_col=0)
    
    # 1. Verify schema compatibility
    classifier.verify_feature_compatibility(X_eval, dataset_name, pipeline_version)
    
    # 2. Get predictions (returns semantic string classes)
    preds = classifier.predict(X_eval)
    
    # Extract true values
    target_col = y_eval.columns[0]
    y_true_raw = y_eval[target_col].values
    
    # 3. Calculate metrics
    if task_type == "binary":
        calc_results = calculate_binary_metrics(y_true_raw, preds)
        results = {
            "creation_timestamp": datetime.datetime.now().isoformat(),
            "overview": {
                "dataset": dataset_name.upper(),
                "task_type": task_type,
                "split": split_name.upper(),
                "pipeline_version": pipeline_version,
                "total_samples": len(X_eval),
                "feature_count": X_eval.shape[1]
            },
            "confusion_matrix": calc_results["confusion_matrix"],
            "metrics": calc_results["metrics"],
            "metric_warnings": calc_results["warnings"]
        }
        classes_evaluated = ["Normal", "Attack"]
    else:
        # Multiclass
        # Convert true values to strings for consistent text matching
        y_true_str = y_true_raw.astype(str)
        calc_results = calculate_multiclass_metrics(y_true_str, preds, dataset_name)
        results = {
            "creation_timestamp": datetime.datetime.now().isoformat(),
            "overview": {
                "dataset": dataset_name.upper(),
                "task_type": task_type,
                "split": split_name.upper(),
                "pipeline_version": pipeline_version,
                "total_samples": len(X_eval),
                "feature_count": X_eval.shape[1]
            },
            "metrics": calc_results["metrics"],
            "per_class": calc_results["per_class"]
        }
        classes_evaluated = calc_results["classes_evaluated"]
        
    # 4. Extract feature importances
    feature_importance_df = classifier.get_feature_importances()
    
    # 5. Generate plots
    if task_type == "binary":
        y_true_str = np.where(y_true_raw == 1, "Attack", "Normal")
    else:
        y_true_str = y_true_raw.astype(str)
        
    generate_visualizations(y_true_str, preds, classes_evaluated, feature_importance_df, reports_dir)
    
    # 6. Save report files
    save_report_files(dataset_name, task_type, split_name, results, feature_importance_df, reports_dir)
    
    print(f"Saved reports for {dataset_name} ({task_type} {split_name}) to {reports_dir}")
    return results

def evaluate_all():
    print("=== STARTING ML EVALUATION PIPELINE ===")
    
    for dataset in ["cicids2017", "unsw_nb15"]:
        for task in ["binary", "multiclass"]:
            for split in ["validation", "test"]:
                evaluate_model_split(dataset, task, split)
                
    print("\n=== XGBOOST MODEL EVALUATION PIPELINE COMPLETE ===")

if __name__ == "__main__":
    evaluate_all()
