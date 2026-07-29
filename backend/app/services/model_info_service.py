import os
import json
import datetime
from typing import List, Dict, Any

class ModelInfoService:
    """
    Service for inspecting trained ML models, preprocessors, and evaluation metrics,
    returning structured metadata for display in the frontend.
    """
    def __init__(self):
        # Resolve project root path (c:\NetShieldAI)
        self.backend_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        self.project_root = os.path.dirname(self.backend_dir)
        self.models_dir = os.path.join(self.project_root, "ml", "models")
        self.reports_dir = os.path.join(self.project_root, "ml", "reports")
        self.artifacts_dir = os.path.join(self.project_root, "ml", "artifacts")

    def _format_size(self, size_bytes: int) -> str:
        if size_bytes < 1024:
            return f"{size_bytes} B"
        elif size_bytes < 1024 * 1024:
            return f"{size_bytes / 1024:.1f} KB"
        else:
            return f"{size_bytes / (1024 * 1024):.2f} MB"

    def _read_json(self, file_path: str) -> Dict[str, Any]:
        if os.path.exists(file_path):
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass
        return {}

    def get_all_models(self) -> List[Dict[str, Any]]:
        models_info = []

        model_definitions = [
            # 1. CICIDS2017 Isolation Forest
            {
                "id": "cicids2017_isolation_forest",
                "name": "CICIDS2017 Isolation Forest Anomaly Detector",
                "dataset": "CICIDS2017",
                "task_type": "Anomaly Detection",
                "model_type": "IsolationForest",
                "model_rel_path": os.path.join("ml", "models", "cicids2017", "isolation_forest.joblib"),
                "eval_rel_path": os.path.join("ml", "reports", "anomaly_detection", "cicids2017", "test", "evaluation.json"),
                "metadata_rel_path": None,
                "feature_count": 77,
            },
            # 2. UNSW-NB15 Isolation Forest
            {
                "id": "unsw_nb15_isolation_forest",
                "name": "UNSW-NB15 Isolation Forest Anomaly Detector",
                "dataset": "UNSW-NB15",
                "task_type": "Anomaly Detection",
                "model_type": "IsolationForest",
                "model_rel_path": os.path.join("ml", "models", "unsw_nb15", "isolation_forest.joblib"),
                "eval_rel_path": os.path.join("ml", "reports", "anomaly_detection", "unsw_nb15", "test", "evaluation.json"),
                "metadata_rel_path": None,
                "feature_count": 43,
            },
            # 3. CICIDS2017 XGBoost Binary
            {
                "id": "cicids2017_xgboost_binary",
                "name": "CICIDS2017 XGBoost Binary Intrusion Predictor",
                "dataset": "CICIDS2017",
                "task_type": "Binary Intrusion Classification",
                "model_type": "XGBClassifier (Binary)",
                "model_rel_path": os.path.join("ml", "models", "intrusion_prediction", "cicids2017", "binary", "xgboost_binary.joblib"),
                "eval_rel_path": os.path.join("ml", "reports", "intrusion_prediction", "cicids2017", "binary", "test", "evaluation.json"),
                "metadata_rel_path": os.path.join("ml", "models", "intrusion_prediction", "cicids2017", "binary", "xgboost_binary_metadata.json"),
                "feature_count": 77,
            },
            # 4. CICIDS2017 XGBoost Multiclass
            {
                "id": "cicids2017_xgboost_multiclass",
                "name": "CICIDS2017 XGBoost Multiclass Attack Classifier",
                "dataset": "CICIDS2017",
                "task_type": "Multiclass Attack Classification",
                "model_type": "XGBClassifier (Multiclass)",
                "model_rel_path": os.path.join("ml", "models", "intrusion_prediction", "cicids2017", "multiclass", "xgboost_multiclass.joblib"),
                "eval_rel_path": os.path.join("ml", "reports", "intrusion_prediction", "cicids2017", "multiclass", "test", "evaluation.json"),
                "metadata_rel_path": os.path.join("ml", "models", "intrusion_prediction", "cicids2017", "multiclass", "xgboost_multiclass_metadata.json"),
                "feature_count": 77,
            },
            # 5. UNSW-NB15 XGBoost Binary
            {
                "id": "unsw_nb15_xgboost_binary",
                "name": "UNSW-NB15 XGBoost Binary Intrusion Predictor",
                "dataset": "UNSW-NB15",
                "task_type": "Binary Intrusion Classification",
                "model_type": "XGBClassifier (Binary)",
                "model_rel_path": os.path.join("ml", "models", "intrusion_prediction", "unsw_nb15", "binary", "xgboost_binary.joblib"),
                "eval_rel_path": os.path.join("ml", "reports", "intrusion_prediction", "unsw_nb15", "binary", "test", "evaluation.json"),
                "metadata_rel_path": os.path.join("ml", "models", "intrusion_prediction", "unsw_nb15", "binary", "xgboost_binary_metadata.json"),
                "feature_count": 43,
            },
            # 6. UNSW-NB15 XGBoost Multiclass
            {
                "id": "unsw_nb15_xgboost_multiclass",
                "name": "UNSW-NB15 XGBoost Multiclass Attack Classifier",
                "dataset": "UNSW-NB15",
                "task_type": "Multiclass Attack Classification",
                "model_type": "XGBClassifier (Multiclass)",
                "model_rel_path": os.path.join("ml", "models", "intrusion_prediction", "unsw_nb15", "multiclass", "xgboost_multiclass.joblib"),
                "eval_rel_path": os.path.join("ml", "reports", "intrusion_prediction", "unsw_nb15", "multiclass", "test", "evaluation.json"),
                "metadata_rel_path": os.path.join("ml", "models", "intrusion_prediction", "unsw_nb15", "multiclass", "xgboost_multiclass_metadata.json"),
                "feature_count": 43,
            },
            # 7. Preprocessors
            {
                "id": "cicids2017_class_preprocessor",
                "name": "CICIDS2017 Classification Feature Preprocessor",
                "dataset": "CICIDS2017",
                "task_type": "Feature Preprocessing",
                "model_type": "ColumnTransformer / StandardScaler",
                "model_rel_path": os.path.join("ml", "artifacts", "preprocessors", "cicids2017_class_preprocessor.joblib"),
                "eval_rel_path": None,
                "metadata_rel_path": None,
                "feature_count": 77,
            },
            {
                "id": "unsw_nb15_class_preprocessor",
                "name": "UNSW-NB15 Classification Feature Preprocessor",
                "dataset": "UNSW-NB15",
                "task_type": "Feature Preprocessing",
                "model_type": "ColumnTransformer / OneHotEncoder / StandardScaler",
                "model_rel_path": os.path.join("ml", "artifacts", "preprocessors", "unsw_nb15_class_preprocessor.joblib"),
                "eval_rel_path": None,
                "metadata_rel_path": None,
                "feature_count": 43,
            },
        ]

        for defn in model_definitions:
            abs_model_path = os.path.join(self.project_root, defn["model_rel_path"])
            exists = os.path.exists(abs_model_path)
            
            file_size_bytes = os.path.getsize(abs_model_path) if exists else 0
            file_size_formatted = self._format_size(file_size_bytes) if exists else "N/A"
            
            last_modified = ""
            if exists:
                mtime = os.path.getmtime(abs_model_path)
                last_modified = datetime.datetime.fromtimestamp(mtime).isoformat()

            # Load evaluation JSON if available
            eval_data = {}
            if defn["eval_rel_path"]:
                abs_eval_path = os.path.join(self.project_root, defn["eval_rel_path"])
                eval_data = self._read_json(abs_eval_path)

            # Load metadata JSON if available
            meta_data = {}
            if defn["metadata_rel_path"]:
                abs_meta_path = os.path.join(self.project_root, defn["metadata_rel_path"])
                meta_data = self._read_json(abs_meta_path)

            metrics = eval_data.get("metrics", {})
            overview = eval_data.get("overview", {})
            training_params = meta_data.get("training_parameters", {})
            confusion_matrix = eval_data.get("confusion_matrix", {})

            model_info = {
                "id": defn["id"],
                "name": defn["name"],
                "dataset": defn["dataset"],
                "task_type": defn["task_type"],
                "model_type": defn["model_type"],
                "file_name": os.path.basename(defn["model_rel_path"]),
                "file_path": defn["model_rel_path"],
                "exists": exists,
                "file_size_bytes": file_size_bytes,
                "file_size_formatted": file_size_formatted,
                "last_modified": last_modified,
                "feature_count": defn["feature_count"],
                "metrics": {
                    "accuracy": metrics.get("accuracy"),
                    "precision": metrics.get("precision"),
                    "recall": metrics.get("recall_detection_rate") or metrics.get("recall"),
                    "f1_score": metrics.get("f1_score"),
                    "false_positive_rate": metrics.get("false_positive_rate"),
                    "true_negative_rate": metrics.get("true_negative_rate_specificity") or metrics.get("specificity"),
                },
                "overview": {
                    "total_samples": overview.get("total_samples"),
                    "normal_samples": overview.get("normal_samples"),
                    "attack_samples": overview.get("attack_samples"),
                    "pipeline_version": overview.get("pipeline_version", "1.0"),
                },
                "confusion_matrix": confusion_matrix,
                "training_parameters": training_params,
                "training_timestamp": meta_data.get("training_timestamp"),
            }

            models_info.append(model_info)

        return models_info

model_info_service = ModelInfoService()
