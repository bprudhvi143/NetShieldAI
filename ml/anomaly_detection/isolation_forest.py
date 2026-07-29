import os
import numpy as np
import pandas as pd
from typing import Dict, Any, List, Union
from sklearn.ensemble import IsolationForest

class AnomalyDetector:
    """
    Wrapper for Scikit-Learn's Isolation Forest anomaly detector.
    Provides semantic prediction mapping (0 = Normal, 1 = Anomaly),
    relative score normalization using training bounds, and strict feature/pipeline compatibility verification.
    """
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config if config is not None else {}
        self.n_estimators = self.config.get("n_estimators", 100)
        self.contamination = self.config.get("contamination", "auto")
        self.max_samples = self.config.get("max_samples", "auto")
        self.random_state = self.config.get("random_state", 42)
        self.n_jobs = self.config.get("n_jobs", -1)
        
        # Internal model
        self.model = IsolationForest(
            n_estimators=self.n_estimators,
            contamination=self.contamination,
            max_samples=self.max_samples,
            random_state=self.random_state,
            n_jobs=self.n_jobs
        )
        
        # Verification properties (to be set during fitting or loaded)
        self.dataset_name: str = self.config.get("dataset_name", "")
        self.pipeline_version: str = self.config.get("pipeline_version", "")
        self.feature_names: List[str] = self.config.get("feature_names", [])
        
        # Training anomaly score bounds for relative normalization
        self.train_score_min: float = self.config.get("train_score_min", -0.5)
        self.train_score_max: float = self.config.get("train_score_max", 0.0)

    def verify_feature_compatibility(self, X: pd.DataFrame, dataset_name: str, pipeline_version: str) -> None:
        """
        Statically verifies feature counts, ordering, names, dataset name,
        and pipeline versions. Fails loudly with ValueError if there is any mismatch.
        """
        # 1. Dataset identity check
        if self.dataset_name and dataset_name.lower() != self.dataset_name.lower():
            raise ValueError(
                f"Dataset mismatch! Model trained on '{self.dataset_name}', but input dataset is '{dataset_name}'."
            )
            
        # 2. Pipeline version check
        if self.pipeline_version and pipeline_version != self.pipeline_version:
            raise ValueError(
                f"Pipeline version mismatch! Model expects version '{self.pipeline_version}', but input is '{pipeline_version}'."
            )
            
        # 3. Column dimensions check
        input_cols = list(X.columns)
        if len(input_cols) != len(self.feature_names):
            raise ValueError(
                f"Feature count mismatch! Model expects {len(self.feature_names)} features, but input has {len(input_cols)} columns."
            )
            
        # 4. Exact feature naming and ordering check
        for idx, (expected, actual) in enumerate(zip(self.feature_names, input_cols)):
            if expected != actual:
                raise ValueError(
                    f"Feature mismatch at index {idx}! Expected '{expected}', but found '{actual}'. "
                    "Columns must match expected training feature order exactly."
                )

    def fit(self, X: pd.DataFrame, dataset_name: str, pipeline_version: str) -> 'AnomalyDetector':
        """
        Verify feature schema, fit the Isolation Forest model, and compute training score bounds.
        """
        self.feature_names = list(X.columns)
        self.dataset_name = dataset_name
        self.pipeline_version = pipeline_version
        
        # Run fit
        self.model.fit(X)
        
        # Compute bounds for relative normalization on training scores
        train_raw_scores = self.model.decision_function(X)
        self.train_score_min = float(np.min(train_raw_scores))
        self.train_score_max = float(np.max(train_raw_scores))
        
        # Ensure max is strictly greater than min to avoid division by zero
        if abs(self.train_score_max - self.train_score_min) < 1e-9:
            self.train_score_max = self.train_score_min + 1.0
            
        return self

    def predict(self, X: pd.DataFrame) -> np.ndarray:
        """
        Predict normal vs anomaly status.
        Maps native predictions:
        - Outlier (-1) -> Anomaly (1)
        - Inlier (1) -> Normal (0)
        """
        # Call Scikit-Learn predict
        preds = self.model.predict(X)
        
        # Map: -1 -> 1, 1 -> 0
        mapped_preds = np.where(preds == -1, 1, 0)
        return mapped_preds

    def decision_function(self, X: pd.DataFrame) -> np.ndarray:
        """
        Returns raw decision function scores.
        Scores are negative for outliers/anomalies and positive/higher for inliers/normal.
        """
        return self.model.decision_function(X)

    def compute_normalized_score(self, raw_scores: Union[np.ndarray, float]) -> Union[np.ndarray, float]:
        """
        Calculates a relative normalized anomaly score in [0, 1] using training-set score bounds.
        - Closer to 1.0 represents highly anomalous.
        - Closer to 0.0 represents normal traffic.
        
        IMPORTANT: This normalized score is not an attack probability and must not be described as such.
        It represents the relative outlier distance from the training distribution.
        """
        # Shift relative: lower raw score -> higher anomaly status (closer to 1.0)
        # raw_score == train_score_min -> 1.0
        # raw_score == train_score_max -> 0.0
        numerator = self.train_score_max - raw_scores
        denominator = self.train_score_max - self.train_score_min
        
        normalized = numerator / denominator
        # Clip to [0.0, 1.0] range
        if isinstance(normalized, np.ndarray):
            return np.clip(normalized, 0.0, 1.0)
        else:
            return float(np.clip(normalized, 0.0, 1.0))
            
    def get_metadata(self, artifact_path: str = "") -> Dict[str, Any]:
        """
        Generate a metadata dictionary representing this trained model configuration.
        """
        return {
            "model_type": "IsolationForest",
            "dataset": self.dataset_name,
            "pipeline_version": self.pipeline_version,
            "random_state": self.random_state,
            "n_estimators": self.n_estimators,
            "contamination": str(self.contamination),
            "max_samples": str(self.max_samples),
            "n_jobs": self.n_jobs,
            "training_rows": len(self.feature_names), # Stub or placeholder, train.py sets this properly
            "feature_count": len(self.feature_names),
            "feature_names": self.feature_names,
            "train_score_min": self.train_score_min,
            "train_score_max": self.train_score_max,
            "training_class": "BENIGN" if self.dataset_name.lower() == "cicids2017" else "Normal",
            "artifact_path": artifact_path
        }
