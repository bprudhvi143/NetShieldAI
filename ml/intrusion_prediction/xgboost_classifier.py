import os
import numpy as np
import pandas as pd
import joblib
from typing import Dict, Any, List, Union
import xgboost as xgb

class XGBoostIntrusionClassifier:
    """
    Wrapper for XGBoost classifier supporting binary and multiclass tasks.
    Enforces strict feature compatibility verification, target leakage checks, 
    and handles deterministic target class mappings where Normal is always index 0.
    """
    def __init__(self, task_type: str = "binary", config: Dict[str, Any] = None):
        self.task_type = task_type.lower()
        if self.task_type not in ["binary", "multiclass"]:
            raise ValueError("task_type must be either 'binary' or 'multiclass'.")
            
        self.config = config if config is not None else {}
        self.n_estimators = self.config.get("n_estimators", 100)
        self.max_depth = self.config.get("max_depth", 6)
        self.learning_rate = self.config.get("learning_rate", 0.3)
        self.subsample = self.config.get("subsample", 0.8)
        self.colsample_bytree = self.config.get("colsample_bytree", 0.8)
        self.random_state = self.config.get("random_state", 42)
        self.n_jobs = self.config.get("n_jobs", -1)
        
        # XGBoost Classifier initialization
        if self.task_type == "binary":
            self.model = xgb.XGBClassifier(
                n_estimators=self.n_estimators,
                max_depth=self.max_depth,
                learning_rate=self.learning_rate,
                subsample=self.subsample,
                colsample_bytree=self.colsample_bytree,
                random_state=self.random_state,
                n_jobs=self.n_jobs,
                objective="binary:logistic",
                eval_metric="logloss"
            )
        else: # multiclass
            self.model = xgb.XGBClassifier(
                n_estimators=self.n_estimators,
                max_depth=self.max_depth,
                learning_rate=self.learning_rate,
                subsample=self.subsample,
                colsample_bytree=self.colsample_bytree,
                random_state=self.random_state,
                n_jobs=self.n_jobs,
                objective="multi:softprob",
                eval_metric="mlogloss"
            )
            
        # Compatibility & serialization metadata
        self.dataset_name: str = self.config.get("dataset_name", "")
        self.pipeline_version: str = self.config.get("pipeline_version", "")
        self.feature_names: List[str] = self.config.get("feature_names", [])
        self.feature_hash: str = self.config.get("feature_hash", "")
        self.target_column: str = self.config.get("target_column", "")
        
        # Class mappings for target labels (to enforce Normal is always index 0)
        self.class_mapping: Dict[str, int] = self.config.get("class_mapping", {})
        self.inverse_class_mapping: Dict[int, str] = {}
        if self.class_mapping:
            # Reconstruct inverse mapping
            self.inverse_class_mapping = {int(k) if isinstance(k, str) else k: v for k, v in self.class_mapping.items()}
            # Reconstruct string key mapping for ease of serialization
            self.class_mapping = {k: int(v) for k, v in self.class_mapping.items()}

    def verify_feature_compatibility(self, X: pd.DataFrame, dataset_name: str, pipeline_version: str) -> None:
        """
        Verify exact feature counts, ordering, names, dataset name, and pipeline versions.
        Fails loudly with ValueError if there is any mismatch or target leakage.
        """
        # 1. Target Leakage check
        leakage_cols = ["Label", "attack_cat", "Label_binary", "Label_multiclass"]
        for col in leakage_cols:
            if col in X.columns:
                raise ValueError(f"CRITICAL TARGET LEAKAGE DETECTED! Target column '{col}' is present in the feature matrix.")
                
        # 2. Dataset name check
        if self.dataset_name and dataset_name.lower().replace("-", "_") != self.dataset_name.lower().replace("-", "_"):
            raise ValueError(
                f"Dataset mismatch! Model trained on '{self.dataset_name}', but input dataset is '{dataset_name}'."
            )
            
        # 3. Pipeline version check
        if self.pipeline_version and pipeline_version != self.pipeline_version:
            raise ValueError(
                f"Pipeline version mismatch! Model expects version '{self.pipeline_version}', but input is '{pipeline_version}'."
            )
            
        # 4. Feature dimensions check
        input_cols = list(X.columns)
        if len(input_cols) != len(self.feature_names):
            raise ValueError(
                f"Feature count mismatch! Model expects {len(self.feature_names)} features, but input has {len(input_cols)} columns."
            )
            
        # 5. Exact feature naming and ordering check
        for idx, (expected, actual) in enumerate(zip(self.feature_names, input_cols)):
            if expected != actual:
                raise ValueError(
                    f"Feature mismatch at index {idx}! Expected '{expected}', but found '{actual}'. "
                    "Columns must match expected training feature order exactly."
                )

    def _build_class_mapping(self, unique_labels: np.ndarray, dataset_name: str) -> None:
        """Build a deterministic class mapping where the Normal category is mapped to index 0."""
        # Find which label is Normal/Benign
        normal_class = "BENIGN"
        if dataset_name.lower().replace("-", "_") == "unsw_nb15":
            normal_class = "Normal"
            
        unique_list = list(unique_labels)
        if normal_class not in unique_list:
            # Fallback if label is not exactly BENIGN/Normal (e.g. binary integer targets)
            # Binary targets are expected to be 0 or 1 already
            if 0 in unique_list or "0" in unique_list:
                normal_class = 0 if 0 in unique_list else "0"
            else:
                normal_class = unique_list[0]
                
        # Map normal class to 0, other classes to 1..C-1 (sorted alphabetically)
        self.class_mapping = {str(normal_class): 0}
        other_labels = sorted([str(l) for l in unique_list if str(l) != str(normal_class)])
        
        for idx, label in enumerate(other_labels):
            self.class_mapping[label] = idx + 1
            
        self.inverse_class_mapping = {v: k for k, v in self.class_mapping.items()}

    def fit(
        self,
        X: pd.DataFrame,
        y: pd.Series,
        dataset_name: str,
        pipeline_version: str,
        validation_data: tuple = None
    ) -> 'XGBoostIntrusionClassifier':
        """
        Validate schema, build target mappings, map y, fit the model (with early stopping if validation_data is provided).
        """
        # Set compatibility details
        self.feature_names = list(X.columns)
        self.dataset_name = dataset_name
        self.pipeline_version = pipeline_version
        
        # Calculate feature list hash (simple deterministic representation)
        import hashlib
        feat_str = ",".join(self.feature_names)
        self.feature_hash = hashlib.sha256(feat_str.encode()).hexdigest()
        
        # Target leakage validation
        self.verify_feature_compatibility(X, dataset_name, pipeline_version)
        
        # Target column name
        self.target_column = y.name if hasattr(y, 'name') else 'target'
        
        # Build target class mapping
        y_raw = y.values
        unique_labels = np.unique(y_raw)
        
        if self.task_type == "binary":
            # For binary classification, y is expected to be 0 and 1
            self.class_mapping = {"0": 0, "1": 1}
            self.inverse_class_mapping = {0: "Normal", 1: "Attack"}
            y_mapped = y_raw.astype(int)
        else:
            # Multiclass
            self._build_class_mapping(unique_labels, dataset_name)
            # Map labels to integers using class_mapping
            y_mapped = np.array([self.class_mapping[str(val)] for val in y_raw])
            
        # Parse validation data
        eval_set = None
        if validation_data is not None:
            X_val, y_val = validation_data
            self.verify_feature_compatibility(X_val, dataset_name, pipeline_version)
            
            if self.task_type == "binary":
                y_val_mapped = y_val.values.astype(int)
            else:
                y_val_mapped = np.array([self.class_mapping[str(val)] for val in y_val.values])
                
            eval_set = [(X, y_mapped), (X_val, y_val_mapped)]
            
        # Fit XGBClassifier
        if eval_set is not None:
            # Check XGBoost version to support early stopping compatibly
            # In XGBoost v1.6+, early_stopping_rounds can be passed to fit or __init__
            try:
                self.model.fit(
                    X, y_mapped,
                    eval_set=eval_set,
                    verbose=False
                )
            except TypeError:
                # Fallback for other API arguments
                self.model.fit(X, y_mapped, eval_set=eval_set, verbose=False)
        else:
            self.model.fit(X, y_mapped)
            
        return self

    def predict(self, X: pd.DataFrame) -> np.ndarray:
        """
        Runs inference and maps predicted integer class indexes back to their string semantic names.
        """
        preds = self.model.predict(X)
        if self.task_type == "binary":
            # Map 0 -> Normal, 1 -> Attack
            return np.array([self.inverse_class_mapping[p] for p in preds])
        else:
            # Map index back to class name
            return np.array([self.inverse_class_mapping[p] for p in preds])

    def predict_probabilities(self, X: pd.DataFrame) -> np.ndarray:
        """Return raw class probability array."""
        return self.model.predict_proba(X)

    def get_prediction_report(self, X: pd.DataFrame) -> List[Dict[str, Any]]:
        """
        Generate a detailed semantic prediction report for each input flow.
        """
        probs = self.predict_probabilities(X)
        preds = self.model.predict(X)
        
        report = []
        for idx in range(len(X)):
            pred_idx = int(preds[idx])
            flow_probs = probs[idx]
            
            if self.task_type == "binary":
                report.append({
                    "predicted_label": pred_idx,
                    "predicted_class": self.inverse_class_mapping[pred_idx],
                    "normal_probability": float(flow_probs[0]),
                    "attack_probability": float(flow_probs[1]),
                    "confidence": float(flow_probs[pred_idx])
                })
            else:
                class_probs = {self.inverse_class_mapping[i]: float(p) for i, p in enumerate(flow_probs)}
                report.append({
                    "predicted_class": self.inverse_class_mapping[pred_idx],
                    "predicted_class_index": pred_idx,
                    "confidence": float(flow_probs[pred_idx]),
                    "class_probabilities": class_probs
                })
        return report

    def get_feature_importances(self) -> pd.DataFrame:
        """Extracts and ranks features by model feature_importances_."""
        importances = self.model.feature_importances_
        df_imp = pd.DataFrame({
            "feature": self.feature_names,
            "importance": importances
        })
        df_imp = df_imp.sort_values(by="importance", ascending=False).reset_index(drop=True)
        df_imp["rank"] = df_imp.index + 1
        return df_imp[["rank", "feature", "importance"]]

    def get_metadata(self, artifact_path: str = "") -> Dict[str, Any]:
        """Generate a metadata dictionary representing this trained model configuration."""
        best_iteration = None
        if hasattr(self.model, "best_iteration"):
            best_iteration = self.model.best_iteration
            
        return {
            "model_type": "XGBClassifier",
            "dataset": self.dataset_name.upper(),
            "task_type": self.task_type,
            "xgboost_version": xgb.__version__,
            "preprocessing_version": self.pipeline_version,
            "feature_count": len(self.feature_names),
            "feature_names": self.feature_names,
            "feature_hash": self.feature_hash,
            "target_column": self.target_column,
            "class_mapping": {str(k): int(v) for k, v in self.class_mapping.items()},
            "random_state": self.random_state,
            "training_parameters": {
                "n_estimators": self.n_estimators,
                "max_depth": self.max_depth,
                "learning_rate": self.learning_rate,
                "subsample": self.subsample,
                "colsample_bytree": self.colsample_bytree
            },
            "best_iteration": best_iteration,
            "artifact_path": artifact_path
        }
