import os
import json
import datetime
import joblib
import pandas as pd
import numpy as np
from typing import Dict, Any
from ml.intrusion_prediction.xgboost_classifier import XGBoostIntrusionClassifier

DEFAULT_XGB_PARAMS = {
    "n_estimators": 100,
    "max_depth": 6,
    "learning_rate": 0.3,
    "subsample": 0.8,
    "colsample_bytree": 0.8,
    "random_state": 42,
    "n_jobs": -1
}

def train_and_save_model(
    dataset_name: str,
    task_type: str,
    config: Dict[str, Any]
) -> Dict[str, Any]:
    print(f"\n==========================================")
    print(f"TRAINING XGBOOST: {dataset_name.upper()} ({task_type.upper()})")
    print(f"==========================================")
    
    # 1. Path definitions
    base_dir = "c:/NetShieldAI"
    metadata_dir = os.path.join(base_dir, "ml/artifacts/metadata")
    processed_dir = os.path.join(base_dir, f"datasets/{dataset_name.upper() if dataset_name.lower() == 'cicids2017' else 'UNSW-NB15'}/processed")
    models_dir = os.path.join(base_dir, f"ml/models/intrusion_prediction/{dataset_name.lower()}/{task_type.lower()}")
    os.makedirs(models_dir, exist_ok=True)
    
    # 2. Load Phase 1 metadata
    phase1_meta_path = os.path.join(metadata_dir, f"{dataset_name.lower()}_metadata.json")
    if not os.path.exists(phase1_meta_path):
        raise FileNotFoundError(f"Phase 1 metadata not found at {phase1_meta_path}!")
        
    with open(phase1_meta_path, 'r') as f:
        phase1_meta = json.load(f)
        
    pipeline_version = phase1_meta.get("pipeline_version", "1.0")
    final_features = phase1_meta.get("final_classification_features", [])
    
    if not final_features:
        raise ValueError(f"final_classification_features list is empty or missing in {phase1_meta_path}!")
        
    # 3. Load processed splits
    X_train = pd.read_csv(os.path.join(processed_dir, "X_train_class.csv"), index_col=0)
    X_val = pd.read_csv(os.path.join(processed_dir, "X_val_class.csv"), index_col=0)
    X_test = pd.read_csv(os.path.join(processed_dir, "X_test_class.csv"), index_col=0)
    
    target_suffix = "binary" if task_type == "binary" else "multiclass"
    y_train = pd.read_csv(os.path.join(processed_dir, f"y_train_{target_suffix}.csv"), index_col=0)
    y_val = pd.read_csv(os.path.join(processed_dir, f"y_val_{target_suffix}.csv"), index_col=0)
    y_test = pd.read_csv(os.path.join(processed_dir, f"y_test_{target_suffix}.csv"), index_col=0)
    
    # y target column name
    target_col = y_train.columns[0]
    
    # 4. Target Leakage Checks
    # Explicitly check target columns are not in features
    leakage_cols = ["Label", "attack_cat", "Label_binary", "Label_multiclass"]
    for col in leakage_cols:
        if col in X_train.columns or col in X_val.columns or col in X_test.columns:
            raise ValueError(f"CRITICAL TARGET LEAKAGE DETECTED! Target column '{col}' is in input features.")
    print("Leakage verification PASSED: target information is not present in features.")
    
    # 5. Class Imbalance Measurement
    print("\nClass Imbalance Metrics (Train Set):")
    total_train = len(y_train)
    value_counts = y_train[target_col].value_counts().to_dict()
    for cls_val, count in value_counts.items():
        pct = (count / total_train) * 100
        print(f"  Class '{cls_val}': Count = {count:,} ({pct:.2f}%)")
        
    # 6. Initialize Wrapper
    classifier = XGBoostIntrusionClassifier(task_type=task_type, config={
        "n_estimators": config.get("n_estimators", 100),
        "max_depth": config.get("max_depth", 6),
        "learning_rate": config.get("learning_rate", 0.3),
        "subsample": config.get("subsample", 0.8),
        "colsample_bytree": config.get("colsample_bytree", 0.8),
        "random_state": config.get("random_state", 42),
        "n_jobs": config.get("n_jobs", -1)
    })
    
    # Fit model (validates feature columns internally)
    print("\nFitting XGBClassifier...")
    classifier.fit(
        X_train, y_train[target_col],
        dataset_name=dataset_name,
        pipeline_version=pipeline_version,
        validation_data=(X_val, y_val[target_col])
    )
    
    # 7. Model and metadata persistence
    model_path = os.path.join(models_dir, f"xgboost_{task_type.lower()}.joblib")
    joblib.dump(classifier, model_path)
    print(f"Model saved to {model_path}")
    
    metadata = classifier.get_metadata(artifact_path=model_path)
    metadata.update({
        "train_row_count": len(X_train),
        "validation_row_count": len(X_val),
        "test_row_count": len(X_test),
        "training_timestamp": datetime.datetime.now().isoformat()
    })
    
    metadata_path = os.path.join(models_dir, f"xgboost_{task_type.lower()}_metadata.json")
    with open(metadata_path, 'w') as f:
        json.dump(metadata, f, indent=4)
    print(f"Model metadata saved to {metadata_path}")
    
    return metadata

def train_all():
    print("=== STARTING SUPERVISED XGBOOST TRAINING ===")
    
    # Train CICIDS2017 models
    train_and_save_model("cicids2017", "binary", DEFAULT_XGB_PARAMS)
    train_and_save_model("cicids2017", "multiclass", DEFAULT_XGB_PARAMS)
    
    # Train UNSW-NB15 models
    train_and_save_model("unsw_nb15", "binary", DEFAULT_XGB_PARAMS)
    train_and_save_model("unsw_nb15", "multiclass", DEFAULT_XGB_PARAMS)
    
    print("\n=== XGBOOST MODEL TRAINING PIPELINE COMPLETE ===")

if __name__ == "__main__":
    train_all()
