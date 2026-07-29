import os
import json
import datetime
import pandas as pd
import numpy as np

# Set matplotlib backend to Agg to prevent GUI popups
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

from ml.risk_scoring.predict import load_risk_models, predict_batch_risk

def get_stats_dict(scores: np.ndarray) -> dict:
    if len(scores) == 0:
        return {"min": 0.0, "max": 0.0, "mean": 0.0, "median": 0.0}
    return {
        "min": float(np.min(scores)),
        "max": float(np.max(scores)),
        "mean": float(np.mean(scores)),
        "median": float(np.median(scores))
    }

def generate_distribution_plot(
    normal_scores: np.ndarray,
    attack_scores: np.ndarray,
    output_dir: str
):
    """
    Generate a histogram showing threat score distributions for normal vs attack traffic.
    """
    os.makedirs(output_dir, exist_ok=True)
    
    plt.figure(figsize=(10, 5))
    if len(normal_scores) > 0:
        plt.hist(normal_scores, bins=20, range=(0, 100), alpha=0.6, label="Normal Traffic", color="blue")
    if len(attack_scores) > 0:
        plt.hist(attack_scores, bins=20, range=(0, 100), alpha=0.6, label="Attack Traffic", color="red")
        
    plt.title("Threat Score Calibration & Separation Analysis")
    plt.xlabel("Threat Score (0 - 100)")
    plt.ylabel("Frequency")
    plt.legend()
    plt.grid(True, linestyle="--", alpha=0.5)
    
    plot_path = os.path.join(output_dir, "threat_score_distribution.png")
    plt.savefig(plot_path, bbox_inches="tight")
    plt.close()

def save_evaluation_reports(
    dataset_name: str,
    task_type: str,
    split_name: str,
    pipeline_version: str,
    results_dict: dict,
    output_dir: str
):
    os.makedirs(output_dir, exist_ok=True)
    
    # 1. Save JSON Report
    json_path = os.path.join(output_dir, "evaluation.json")
    with open(json_path, 'w', encoding="utf-8") as f:
        json.dump(results_dict, f, indent=4)
        
    # 2. Save Markdown Report
    normal_stats = results_dict["score_statistics"]["normal"]
    attack_stats = results_dict["score_statistics"]["attack"]
    
    normal_dist = results_dict["risk_level_distribution"]["normal"]
    attack_dist = results_dict["risk_level_distribution"]["attack"]
    
    metrics = results_dict["calibration_metrics"]
    
    md_content = f"""# Risk Scoring Calibration Report - {dataset_name.upper()} {task_type.upper()} ({split_name.upper()})

Generated on: {results_dict["creation_timestamp"]}
Preprocessing Pipeline Version: {pipeline_version}

> [!WARNING]
> **Diagnostic & Calibration Notice**: 
> This evaluation is currently based on the Phase 1 development samples (approximately 5,000 rows) and represents a calibration/diagnostic analysis. 
> It should NOT be interpreted as final production risk-calibration performance, and the scoring thresholds are project-defined initial configurations.

## 1. Split & Model Overview
- **Dataset**: {dataset_name.upper()}
- **Supervised Task Type**: {task_type.upper()}
- **Evaluation Split**: {split_name.upper()}
- **Total Samples**: {results_dict["overview"]["total_samples"]:,}

## 2. Threat Score Calibration Statistics

| Statistic | Normal Traffic | Attack Traffic |
| --- | --- | --- |
| **Count** | {results_dict["overview"]["normal_samples"]:,} | {results_dict["overview"]["attack_samples"]:,} |
| **Minimum** | {normal_stats["min"]:.2f} | {attack_stats["min"]:.2f} |
| **Maximum** | {normal_stats["max"]:.2f} | {attack_stats["max"]:.2f} |
| **Mean** | {normal_stats["mean"]:.2f} | {attack_stats["mean"]:.2f} |
| **Median** | {normal_stats["median"]:.2f} | {attack_stats["median"]:.2f} |

### Separation Analysis:
- **Mean Score Separation**: {metrics["mean_score_separation"]:.2f}
- **Median Score Separation**: {metrics["median_score_separation"]:.2f}

---

## 3. Risk Level Distribution

Project-defined thresholds are:
* **Low**: `0 - 29`
* **Medium**: `30 - 59`
* **High**: `60 - 84`
* **Critical**: `85 - 100`

### Distribution Table:

| Risk Level | Normal Traffic Count (%) | Attack Traffic Count (%) |
| --- | --- | --- |
| **Low** | {normal_dist["Low"]:,} ({normal_dist["Low"] / max(1, results_dict["overview"]["normal_samples"]) * 100:.1f}%) | {attack_dist["Low"]:,} ({attack_dist["Low"] / max(1, results_dict["overview"]["attack_samples"]) * 100:.1f}%) |
| **Medium** | {normal_dist["Medium"]:,} ({normal_dist["Medium"] / max(1, results_dict["overview"]["normal_samples"]) * 100:.1f}%) | {attack_dist["Medium"]:,} ({attack_dist["Medium"] / max(1, results_dict["overview"]["attack_samples"]) * 100:.1f}%) |
| **High** | {normal_dist["High"]:,} ({normal_dist["High"] / max(1, results_dict["overview"]["normal_samples"]) * 100:.1f}%) | {attack_dist["High"]:,} ({attack_dist["High"] / max(1, results_dict["overview"]["attack_samples"]) * 100:.1f}%) |
| **Critical** | {normal_dist["Critical"]:,} ({normal_dist["Critical"] / max(1, results_dict["overview"]["normal_samples"]) * 100:.1f}%) | {attack_dist["Critical"]:,} ({attack_dist["Critical"] / max(1, results_dict["overview"]["attack_samples"]) * 100:.1f}%) |

### Security Coverage Metrics:
* **Attack High/Critical Coverage Rate**: {metrics["attack_high_critical_coverage_rate"] * 100:.2f}% (Percentage of true attacks classified as High/Critical Risk)
* **Normal High/Critical False Alarm Rate**: {metrics["normal_high_critical_false_rate"] * 100:.2f}% (Percentage of true normal traffic incorrectly classified as High/Critical Risk)

---

## 4. Visualizations
- **Threat Score Distribution Plot**: [threat_score_distribution.png](threat_score_distribution.png)
"""
    md_path = os.path.join(output_dir, "evaluation.md")
    with open(md_path, 'w', encoding="utf-8") as f:
        f.write(md_content)

def evaluate_risk_split(
    dataset_name: str,
    task_type: str,
    split_name: str,
    base_dir: str = "c:/NetShieldAI"
) -> dict:
    print(f"Evaluating risk scoring for {dataset_name.upper()} ({task_type.upper()}) on {split_name.upper()} split...")
    
    ds_clean = dataset_name.lower().replace("-", "_")
    task_clean = task_type.lower()
    split_clean = split_name.lower()
    
    # 1. Paths
    processed_dir = os.path.join(base_dir, f"datasets/{dataset_name.upper() if ds_clean == 'cicids2017' else 'UNSW-NB15'}/processed")
    metadata_dir = os.path.join(base_dir, "ml/artifacts/metadata")
    reports_dir = os.path.join(base_dir, f"ml/reports/risk_scoring/{ds_clean}/{task_clean}/{split_clean}")
    
    # Load Phase 1 metadata
    metadata_path = os.path.join(metadata_dir, f"{ds_clean}_metadata.json")
    with open(metadata_path, 'r', encoding="utf-8") as f:
        phase1_meta = json.load(f)
    pipeline_version = phase1_meta.get("pipeline_version", "1.0")
    
    # Load models
    detector, classifier = load_risk_models(dataset_name, task_type, base_dir)
    
    # Load data splits
    split_abbr = "val" if split_clean == "validation" else split_clean
    X_anomaly_path = os.path.join(processed_dir, f"X_{split_abbr}_anomaly.csv")
    X_class_path = os.path.join(processed_dir, f"X_{split_abbr}_class.csv")
    
    target_suffix = "binary" if task_clean == "binary" else "multiclass"
    y_path = os.path.join(processed_dir, f"y_{split_abbr}_{target_suffix}.csv")
    
    if not all(os.path.exists(p) for p in [X_anomaly_path, X_class_path, y_path]):
        raise FileNotFoundError(f"Missing evaluation splits for {dataset_name} {split_name}!")
        
    X_eval_anomaly = pd.read_csv(X_anomaly_path, index_col=0)
    X_eval_class = pd.read_csv(X_class_path, index_col=0)
    y_eval = pd.read_csv(y_path, index_col=0)
    
    # Align rows just in case
    common_idx = X_eval_anomaly.index.intersection(X_eval_class.index).intersection(y_eval.index)
    X_eval_anomaly = X_eval_anomaly.loc[common_idx]
    X_eval_class = X_eval_class.loc[common_idx]
    y_eval = y_eval.loc[common_idx]
    
    # Get ground truth labels
    target_col = y_eval.columns[0]
    y_true_raw = y_eval[target_col].values
    
    # Identify true normal vs attack
    normal_label = "BENIGN" if ds_clean == "cicids2017" else "Normal"
    if task_clean == "binary":
        is_attack_gt = (y_true_raw == 1)
    else:
        is_attack_gt = (y_true_raw.astype(str) != normal_label)
        
    # 2. Predict risk scores in batch
    risk_results = predict_batch_risk(
        anomaly_detector=detector,
        supervised_classifier=classifier,
        flows_df_anomaly=X_eval_anomaly,
        flows_df_class=X_eval_class,
        dataset_name=dataset_name,
        pipeline_version=pipeline_version
    )
    
    # Extract threat scores and risk levels
    scores = np.array([r["threat_score"] for r in risk_results])
    levels = np.array([r["risk_level"] for r in risk_results])
    
    normal_scores = scores[~is_attack_gt]
    attack_scores = scores[is_attack_gt]
    
    normal_levels = levels[~is_attack_gt]
    attack_levels = levels[is_attack_gt]
    
    # Compute counts per risk level
    level_types = ["Low", "Medium", "High", "Critical"]
    normal_counts = {l: int(np.sum(normal_levels == l)) for l in level_types}
    attack_counts = {l: int(np.sum(attack_levels == l)) for l in level_types}
    
    # Calculate coverage and false alarm rates
    attacks_high_crit = attack_counts["High"] + attack_counts["Critical"]
    normal_high_crit = normal_counts["High"] + normal_counts["Critical"]
    
    attack_coverage = attacks_high_crit / len(attack_scores) if len(attack_scores) > 0 else 0.0
    normal_false_rate = normal_high_crit / len(normal_scores) if len(normal_scores) > 0 else 0.0
    
    # Calculate separation
    mean_sep = float(np.mean(attack_scores) - np.mean(normal_scores)) if len(attack_scores) > 0 and len(normal_scores) > 0 else 0.0
    median_sep = float(np.median(attack_scores) - np.median(normal_scores)) if len(attack_scores) > 0 and len(normal_scores) > 0 else 0.0
    
    results = {
        "creation_timestamp": datetime.datetime.now().isoformat(),
        "overview": {
            "dataset": dataset_name.upper(),
            "task_type": task_type,
            "split": split_name.upper(),
            "total_samples": len(scores),
            "normal_samples": len(normal_scores),
            "attack_samples": len(attack_scores)
        },
        "score_statistics": {
            "all": get_stats_dict(scores),
            "normal": get_stats_dict(normal_scores),
            "attack": get_stats_dict(attack_scores)
        },
        "risk_level_distribution": {
            "normal": normal_counts,
            "attack": attack_counts
        },
        "calibration_metrics": {
            "attack_high_critical_coverage_rate": attack_coverage,
            "normal_high_critical_false_rate": normal_false_rate,
            "mean_score_separation": mean_sep,
            "median_score_separation": median_sep
        }
    }
    
    # Plot score separation
    generate_distribution_plot(normal_scores, attack_scores, reports_dir)
    
    # Save reports
    save_evaluation_reports(dataset_name, task_type, split_name, pipeline_version, results, reports_dir)
    
    print(f"Completed evaluation. Saved reports to {reports_dir}")
    return results

def evaluate_all():
    print("=== STARTING ML RISK SCORING CALIBRATION EVALUATION ===")
    
    datasets = ["cicids2017", "unsw_nb15"]
    task_types = ["binary", "multiclass"]
    splits = ["validation", "test"]
    
    for dataset in datasets:
        for task in task_types:
            for split in splits:
                evaluate_risk_split(dataset, task, split)
                
    print("\n=== ML RISK SCORING CALIBRATION EVALUATION COMPLETE ===")

if __name__ == "__main__":
    evaluate_all()
