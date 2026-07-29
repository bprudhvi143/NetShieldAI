import os
import json
import datetime
import joblib
import pandas as pd
import numpy as np
from ml.preprocessing.cicids2017 import CICIDS2017Pipeline
from ml.preprocessing.unsw_nb15 import UNSWNB15Pipeline
from ml.features.feature_schema import FEATURE_SCHEMA, get_features_by_usage

def generate_quality_report(dataset_name: str, pipeline_stats: dict, output_dir: str):
    """
    Generates human-readable Markdown and machine-readable JSON data-quality reports.
    """
    os.makedirs(output_dir, exist_ok=True)
    schema = FEATURE_SCHEMA.get(dataset_name.lower(), {})
    
    # Excluded fields summary
    excluded_fields = []
    for col, meta in schema.items():
        if meta["exclusion_status"]:
            excluded_fields.append({
                "field_name": col,
                "reason": meta["exclusion_reason"],
                "is_target_related": meta["role"] == "target",
                "is_metadata": meta["role"] == "metadata",
                "is_leakage": "leakage" in (meta["exclusion_reason"] or "").lower() or meta["role"] == "target"
            })
            
    report_data = {
        "dataset_name": dataset_name.upper(),
        "creation_timestamp": datetime.datetime.now().isoformat(),
        "overview": {
            "num_raw_files": pipeline_stats["raw_files"],
            "raw_total_rows": pipeline_stats["raw_total_rows"],
            "raw_total_columns": pipeline_stats["raw_total_columns"],
            "processed_row_count": pipeline_stats["processed_row_count"],
            "processed_feature_count": pipeline_stats.get("feature_count", 0)
        },
        "quality": {
            "missing_values_before_imputation": pipeline_stats.get("nans_before_imputation", {}),
            "infinite_values_converted": pipeline_stats.get("infs_before_imputation", {}),
            "duplicates_removed_count": pipeline_stats.get("duplicates_removed", 0),
            "constant_columns_found": [], # None in these datasets' selected schemas
            "invalid_values_found": pipeline_stats.get("attack_cat_mappings", {}).get("inconsistencies_count", 0)
        },
        "labels": {
            "label_column": "Label" if dataset_name.lower() == "cicids2017" else "Label / attack_cat",
            "normal_count": pipeline_stats["binary_distribution"].get(0, 0) if dataset_name.lower() == "unsw_nb15" else pipeline_stats["binary_distribution"].get(0, 0), # 0 is BENIGN or normal
            "attack_count": pipeline_stats["binary_distribution"].get(1, 0),
            "attack_percentage": pipeline_stats["attack_percentage"],
            "num_attack_classes": pipeline_stats["num_attack_classes"],
            "samples_per_class": pipeline_stats["multiclass_distribution"]
        },
        "exclusions": excluded_fields,
        "split": {
            "train_count": pipeline_stats["split_counts"]["train"],
            "validation_count": pipeline_stats["split_counts"]["validation"],
            "test_count": pipeline_stats["split_counts"]["test"]
        }
    }
    
    # Save JSON report
    json_path = os.path.join(output_dir, f"{dataset_name.lower()}_quality_report.json")
    with open(json_path, 'w') as f:
        json.dump(report_data, f, indent=4)
        
    # Generate Markdown report
    md_content = f"""# Data Quality & Preprocessing Report - {dataset_name.upper()}

Generated on: {report_data["creation_timestamp"]}

## 1. Dataset Overview
- **Number of Raw Files**: {report_data["overview"]["num_raw_files"]}
- **Total Raw Rows (Estimated)**: {report_data["overview"]["raw_total_rows"]:,}
- **Total Raw Columns**: {report_data["overview"]["raw_total_columns"]}
- **Processed Rows**: {report_data["overview"]["processed_row_count"]:,}
- **Processed Features (after encoding)**: {report_data["overview"]["processed_feature_count"]}

## 2. Data Quality Details
- **Duplicate Rows Removed**: {report_data["quality"]["duplicates_removed_count"]:,}
- **Inconsistencies Found**: {report_data["quality"]["invalid_values_found"]}
- **NaNs Imputed**: {json.dumps(report_data["quality"]["missing_values_before_imputation"])}

## 3. Label & Class Distributions
- **Target Column**: `{report_data["labels"]["label_column"]}`
- **Normal Records Count**: {report_data["labels"]["normal_count"]:,}
- **Attack Records Count**: {report_data["labels"]["attack_count"]:,}
- **Attack Percentage**: {report_data["labels"]["attack_percentage"]}%
- **Number of Attack Classes**: {report_data["labels"]["num_attack_classes"]}

### Samples Per Multi-Class Category:
"""
    for cls, count in sorted(report_data["labels"]["samples_per_class"].items(), key=lambda x: x[1], reverse=True):
        md_content += f"- **{cls}**: {count:,} samples\n"

    md_content += f"""
## 4. Feature Selection & Leakage Prevention
Below is the list of excluded fields along with the target leakage and temporal generalization reasons:

| Field Name | Role | Reason | Leakage Risk? |
| --- | --- | --- | --- |
"""
    for field in excluded_fields:
        role = "Target" if field["is_target_related"] else ("Metadata" if field["is_metadata"] else "Excluded Feature")
        leakage = "Yes" if field["is_leakage"] else "No"
        md_content += f"| `{field['field_name']}` | {role} | {field['reason']} | {leakage} |\n"

    md_content += f"""
## 5. Splits & Stratification
- **Train Set Count**: {report_data["split"]["train_count"]:,}
- **Validation Set Count**: {report_data["split"]["validation_count"]:,}
- **Test Set Count**: {report_data["split"]["test_count"]:,}
- **Split Ratio**: 70% Train / 15% Validation / 15% Test
- **Anomaly Detection Training Set Count (Benign Only)**: {pipeline_stats["anomaly_train_count"]:,}

> [!NOTE]
> This is a baseline stratified evaluation split. It establishes the initial model assessment criteria. Future work may incorporate group-aware or temporal splits to validate generalization to different network environments.
"""

    md_path = os.path.join(output_dir, f"{dataset_name.lower()}_quality_report.md")
    with open(md_path, 'w') as f:
        f.write(md_content)
        
    print(f"Saved quality reports for {dataset_name} to {output_dir}")

def run_all():
    print("=== STARTING ML PREPROCESSING PIPELINE ===")
    
    artifacts_dir = "c:/NetShieldAI/ml/artifacts"
    preprocessors_dir = os.path.join(artifacts_dir, "preprocessors")
    schemas_dir = os.path.join(artifacts_dir, "schemas")
    metadata_dir = os.path.join(artifacts_dir, "metadata")
    reports_dir = "c:/NetShieldAI/ml/reports"
    
    os.makedirs(preprocessors_dir, exist_ok=True)
    os.makedirs(schemas_dir, exist_ok=True)
    os.makedirs(metadata_dir, exist_ok=True)
    os.makedirs(reports_dir, exist_ok=True)

    # 1. CICIDS2017 Pipeline
    print("\nRunning CICIDS2017 Pipeline...")
    cicids_pipeline = CICIDS2017Pipeline()
    cicids_stats, cicids_class_trans, cicids_anomaly_trans = cicids_pipeline.run(sample_size=5000)
    
    # Save preprocessors
    joblib.dump(cicids_class_trans, os.path.join(preprocessors_dir, "cicids2017_class_preprocessor.joblib"))
    joblib.dump(cicids_anomaly_trans, os.path.join(preprocessors_dir, "cicids2017_anomaly_preprocessor.joblib"))
    
    # Add final metadata
    cicids_class_features = []
    cicids_anomaly_features = []
    X_train_class_path = "c:/NetShieldAI/datasets/CICIDS2017/processed/X_train_class.csv"
    X_train_anomaly_path = "c:/NetShieldAI/datasets/CICIDS2017/processed/X_train_anomaly.csv"
    if os.path.exists(X_train_class_path):
        df_cols = pd.read_csv(X_train_class_path, index_col=0, nrows=1)
        cicids_class_features = list(df_cols.columns)
    if os.path.exists(X_train_anomaly_path):
        df_cols_a = pd.read_csv(X_train_anomaly_path, index_col=0, nrows=1)
        cicids_anomaly_features = list(df_cols_a.columns)

    cicids_stats["feature_count"] = len(cicids_class_features)
    
    cicids_metadata = {
        "pipeline_version": "1.0",
        "dataset_name": "CICIDS2017",
        "random_state": 42,
        "classification_feature_count": len(cicids_class_features),
        "anomaly_feature_count": len(cicids_anomaly_features),
        "final_classification_features": cicids_class_features,
        "final_anomaly_features": cicids_anomaly_features,
        "label_mappings": {
            "binary": {"BENIGN": 0, "Attack": 1},
            "multiclass": list(cicids_stats["multiclass_distribution"].keys())
        },
        "creation_timestamp": datetime.datetime.now().isoformat()
    }
    
    with open(os.path.join(metadata_dir, "cicids2017_metadata.json"), 'w') as f:
        json.dump(cicids_metadata, f, indent=4)
        
    generate_quality_report("cicids2017", cicids_stats, reports_dir)

    # 2. UNSW-NB15 Pipeline
    print("\nRunning UNSW-NB15 Pipeline...")
    unsw_pipeline = UNSWNB15Pipeline()
    unsw_stats, unsw_class_trans, unsw_anomaly_trans = unsw_pipeline.run(sample_size=5000)
    
    # Save preprocessors
    joblib.dump(unsw_class_trans, os.path.join(preprocessors_dir, "unsw_nb15_class_preprocessor.joblib"))
    joblib.dump(unsw_anomaly_trans, os.path.join(preprocessors_dir, "unsw_nb15_anomaly_preprocessor.joblib"))
    
    # Add final metadata
    unsw_class_features = []
    unsw_anomaly_features = []
    X_train_class_path_unsw = "c:/NetShieldAI/datasets/UNSW-NB15/processed/X_train_class.csv"
    X_train_anomaly_path_unsw = "c:/NetShieldAI/datasets/UNSW-NB15/processed/X_train_anomaly.csv"
    if os.path.exists(X_train_class_path_unsw):
        df_cols = pd.read_csv(X_train_class_path_unsw, index_col=0, nrows=1)
        unsw_class_features = list(df_cols.columns)
    if os.path.exists(X_train_anomaly_path_unsw):
        df_cols_a = pd.read_csv(X_train_anomaly_path_unsw, index_col=0, nrows=1)
        unsw_anomaly_features = list(df_cols_a.columns)

    unsw_stats["feature_count"] = len(unsw_class_features)
        
    unsw_metadata = {
        "pipeline_version": "1.0",
        "dataset_name": "UNSW-NB15",
        "random_state": 42,
        "classification_feature_count": len(unsw_class_features),
        "anomaly_feature_count": len(unsw_anomaly_features),
        "final_classification_features": unsw_class_features,
        "final_anomaly_features": unsw_anomaly_features,
        "label_mappings": {
            "binary": {"Normal (0)": 0, "Attack (1)": 1},
            "multiclass": list(unsw_stats["multiclass_distribution"].keys())
        },
        "creation_timestamp": datetime.datetime.now().isoformat()
    }
    
    with open(os.path.join(metadata_dir, "unsw_nb15_metadata.json"), 'w') as f:
        json.dump(unsw_metadata, f, indent=4)
        
    generate_quality_report("unsw_nb15", unsw_stats, reports_dir)

    print("\n=== PIPELINE RUN COMPLETE ===")

if __name__ == "__main__":
    run_all()
