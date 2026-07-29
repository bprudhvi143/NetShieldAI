import os
import json
import datetime
import joblib
import pandas as pd
import numpy as np
from typing import Dict, Any
from ml.anomaly_detection.isolation_forest import AnomalyDetector

def train_dataset_model(dataset_name: str, config: Dict[str, Any]) -> Dict[str, Any]:
    print(f"\n--- Training Isolation Forest for {dataset_name.upper()} ---")
    
    # Paths
    base_dir = "c:/NetShieldAI"
    metadata_dir = os.path.join(base_dir, "ml/artifacts/metadata")
    processed_dir = os.path.join(base_dir, f"datasets/{dataset_name.upper() if dataset_name.lower() == 'cicids2017' else 'UNSW-NB15'}/processed")
    models_dir = os.path.join(base_dir, f"ml/models/{dataset_name.lower()}")
    os.makedirs(models_dir, exist_ok=True)
    
    # 1. Load Phase 1 metadata
    metadata_filename = f"{dataset_name.lower()}_metadata.json"
    metadata_path = os.path.join(metadata_dir, metadata_filename)
    if not os.path.exists(metadata_path):
        raise FileNotFoundError(f"Phase 1 metadata not found at {metadata_path}. Please run Phase 1 pipeline first.")
        
    with open(metadata_path, 'r') as f:
        phase1_meta = json.load(f)
        
    pipeline_version = phase1_meta.get("pipeline_version", "1.0")
    final_features = phase1_meta.get("final_anomaly_features", [])
    
    if not final_features:
        raise ValueError(f"final_anomaly_features list is empty or missing in {metadata_path}!")
        
    # 2. Load processed datasets
    X_train_path = os.path.join(processed_dir, "X_train_anomaly.csv")
    y_train_path = os.path.join(processed_dir, "y_train_binary.csv")
    
    if not os.path.exists(X_train_path) or not os.path.exists(y_train_path):
        raise FileNotFoundError(f"Processed splits not found in {processed_dir}. Make sure pipeline has run successfully.")
        
    X_train = pd.read_csv(X_train_path, index_col=0)
    y_train = pd.read_csv(y_train_path, index_col=0)
    
    print(f"Loaded training features shape: {X_train.shape}")
    print(f"Loaded training labels shape: {y_train.shape}")
    
    # 3. Strict normal-only training data check
    # Match labels by index
    common_idx = X_train.index
    y_train_matched = y_train.loc[common_idx]
    
    # Find any non-normal records (binary label != 0)
    # y_train has label column (usually first column)
    label_col = y_train_matched.columns[0]
    attack_records = y_train_matched[y_train_matched[label_col] != 0]
    
    if len(attack_records) > 0:
        raise ValueError(
            f"CRITICAL ERROR: Training anomaly dataset contains {len(attack_records)} attack records! "
            f"Isolation Forest must be trained exclusively on normal traffic. Row indices: {list(attack_records.index[:10])} ..."
        )
    print("Verification PASSED: Training data contains 100% normal/benign traffic.")
    
    # 4. Strict feature schema compatibility check
    # Check that X_train has exactly the expected columns in the exact order
    input_cols = list(X_train.columns)
    if len(input_cols) != len(final_features):
        raise ValueError(
            f"Feature count mismatch! Preprocessing expected {len(final_features)} features, but X_train has {len(input_cols)}."
        )
        
    for idx, (expected, actual) in enumerate(zip(final_features, input_cols)):
        if expected != actual:
            raise ValueError(
                f"Feature mismatch at index {idx}! Expected '{expected}', but found '{actual}'. "
                "Feature columns must match Phase 1 metadata ordering exactly."
            )
    print("Verification PASSED: Feature columns match Phase 1 metadata exactly in order and count.")

    # 5. Initialize AnomalyDetector and Fit
    detector = AnomalyDetector(config={
        "n_estimators": config.get("n_estimators", 100),
        "contamination": config.get("contamination", "auto"),
        "max_samples": config.get("max_samples", "auto"),
        "random_state": config.get("random_state", 42),
        "n_jobs": config.get("n_jobs", -1)
    })
    
    print("Fitting Isolation Forest...")
    detector.fit(X_train, dataset_name=dataset_name, pipeline_version=pipeline_version)
    
    # 6. Save model joblib
    model_path = os.path.join(models_dir, "isolation_forest.joblib")
    joblib.dump(detector, model_path)
    print(f"Successfully saved trained model to {model_path}")
    
    # 7. Generate and save model metadata
    model_metadata = {
        "model_type": "IsolationForest",
        "dataset": dataset_name.upper(),
        "model_version": "1.0",
        "pipeline_version": pipeline_version,
        "random_state": detector.random_state,
        "n_estimators": detector.n_estimators,
        "contamination": str(detector.contamination),
        "max_samples": str(detector.max_samples),
        "training_rows": len(X_train),
        "feature_count": len(detector.feature_names),
        "feature_names": detector.feature_names,
        "train_score_min": detector.train_score_min,
        "train_score_max": detector.train_score_max,
        "training_class": "BENIGN" if dataset_name.lower() == "cicids2017" else "Normal",
        "artifact_path": model_path,
        "created_at": datetime.datetime.now().isoformat()
    }
    
    model_meta_path = os.path.join(metadata_dir, f"{dataset_name.lower()}_anomaly_model_metadata.json")
    with open(model_meta_path, 'w') as f:
        json.dump(model_metadata, f, indent=4)
    print(f"Successfully saved model metadata to {model_meta_path}")
    
    return model_metadata

def train_all():
    config = {
        "n_estimators": 100,
        "contamination": "auto",
        "max_samples": "auto",
        "random_state": 42,
        "n_jobs": -1
    }
    
    train_dataset_model("cicids2017", config)
    train_dataset_model("unsw_nb15", config)
    print("\n=== ANOMALY DETECTION MODEL TRAINING COMPLETE ===")

if __name__ == "__main__":
    train_all()
