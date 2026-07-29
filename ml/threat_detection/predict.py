import pandas as pd
from typing import List, Union, Dict, Any
from ml.threat_detection.pipeline import ThreatDetectionPipeline
from ml.threat_detection.schemas import UnifiedThreatAssessment

# Global cache to reuse pipeline instances
_pipelines: Dict[str, ThreatDetectionPipeline] = {}

def get_pipeline(dataset_name: str, base_dir: str = "c:/NetShieldAI") -> ThreatDetectionPipeline:
    """
    Get or initialize a cached ThreatDetectionPipeline instance.
    """
    ds_clean = dataset_name.lower().replace("-", "_")
    if ds_clean not in _pipelines:
        _pipelines[ds_clean] = ThreatDetectionPipeline(dataset_name=ds_clean, base_dir=base_dir)
    return _pipelines[ds_clean]

def predict_single_flow(
    flow_df_anomaly: pd.DataFrame,
    flow_df_class: pd.DataFrame = None,
    dataset_name: str = "cicids2017",
    base_dir: str = "c:/NetShieldAI"
) -> UnifiedThreatAssessment:
    """
    Unified single-event prediction API.
    """
    pipeline = get_pipeline(dataset_name, base_dir)
    return pipeline.predict_single(flow_df_anomaly, flow_df_class)

def predict_batch(
    flows_df_anomaly: pd.DataFrame,
    flows_df_class: pd.DataFrame = None,
    dataset_name: str = "cicids2017",
    base_dir: str = "c:/NetShieldAI"
) -> List[Union[UnifiedThreatAssessment, Dict[str, Any]]]:
    """
    Unified batch prediction API.
    """
    pipeline = get_pipeline(dataset_name, base_dir)
    return pipeline.predict_batch(flows_df_anomaly, flows_df_class)
