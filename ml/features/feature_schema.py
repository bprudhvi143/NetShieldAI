import os
from typing import Dict, Any, List

# Feature schema definition for CICIDS2017 and UNSW-NB15.
# Categorizes every column, tracks its role, datatype, transformation, and task-specific usages.

FEATURE_SCHEMA: Dict[str, Dict[str, Dict[str, Any]]] = {
    "cicids2017": {
        'Destination Port': {
            "original_column": 'Destination Port',
            "role": "feature",
            "data_type": "numeric",
            "transformation": "standard_scale",
            "binary_classification_usage": True,
            "multiclass_classification_usage": True,
            "anomaly_detection_usage": True,
            "exclusion_status": False,
            "exclusion_reason": None
        },
        'Flow Duration': {
            "original_column": 'Flow Duration',
            "role": "feature",
            "data_type": "numeric",
            "transformation": "standard_scale",
            "binary_classification_usage": True,
            "multiclass_classification_usage": True,
            "anomaly_detection_usage": True,
            "exclusion_status": False,
            "exclusion_reason": None
        },
        'Total Fwd Packets': {
            "original_column": 'Total Fwd Packets',
            "role": "feature",
            "data_type": "numeric",
            "transformation": "standard_scale",
            "binary_classification_usage": True,
            "multiclass_classification_usage": True,
            "anomaly_detection_usage": True,
            "exclusion_status": False,
            "exclusion_reason": None
        },
        'Total Backward Packets': {
            "original_column": 'Total Backward Packets',
            "role": "feature",
            "data_type": "numeric",
            "transformation": "standard_scale",
            "binary_classification_usage": True,
            "multiclass_classification_usage": True,
            "anomaly_detection_usage": True,
            "exclusion_status": False,
            "exclusion_reason": None
        },
        'Total Length of Fwd Packets': {
            "original_column": 'Total Length of Fwd Packets',
            "role": "feature",
            "data_type": "numeric",
            "transformation": "standard_scale",
            "binary_classification_usage": True,
            "multiclass_classification_usage": True,
            "anomaly_detection_usage": True,
            "exclusion_status": False,
            "exclusion_reason": None
        },
        'Total Length of Bwd Packets': {
            "original_column": 'Total Length of Bwd Packets',
            "role": "feature",
            "data_type": "numeric",
            "transformation": "standard_scale",
            "binary_classification_usage": True,
            "multiclass_classification_usage": True,
            "anomaly_detection_usage": True,
            "exclusion_status": False,
            "exclusion_reason": None
        },
        'Fwd Packet Length Max': {
            "original_column": 'Fwd Packet Length Max',
            "role": "feature",
            "data_type": "numeric",
            "transformation": "standard_scale",
            "binary_classification_usage": True,
            "multiclass_classification_usage": True,
            "anomaly_detection_usage": True,
            "exclusion_status": False,
            "exclusion_reason": None
        },
        'Fwd Packet Length Min': {
            "original_column": 'Fwd Packet Length Min',
            "role": "feature",
            "data_type": "numeric",
            "transformation": "standard_scale",
            "binary_classification_usage": True,
            "multiclass_classification_usage": True,
            "anomaly_detection_usage": True,
            "exclusion_status": False,
            "exclusion_reason": None
        },
        'Fwd Packet Length Mean': {
            "original_column": 'Fwd Packet Length Mean',
            "role": "feature",
            "data_type": "numeric",
            "transformation": "standard_scale",
            "binary_classification_usage": True,
            "multiclass_classification_usage": True,
            "anomaly_detection_usage": True,
            "exclusion_status": False,
            "exclusion_reason": None
        },
        'Fwd Packet Length Std': {
            "original_column": 'Fwd Packet Length Std',
            "role": "feature",
            "data_type": "numeric",
            "transformation": "standard_scale",
            "binary_classification_usage": True,
            "multiclass_classification_usage": True,
            "anomaly_detection_usage": True,
            "exclusion_status": False,
            "exclusion_reason": None
        },
        'Bwd Packet Length Max': {
            "original_column": 'Bwd Packet Length Max',
            "role": "feature",
            "data_type": "numeric",
            "transformation": "standard_scale",
            "binary_classification_usage": True,
            "multiclass_classification_usage": True,
            "anomaly_detection_usage": True,
            "exclusion_status": False,
            "exclusion_reason": None
        },
        'Bwd Packet Length Min': {
            "original_column": 'Bwd Packet Length Min',
            "role": "feature",
            "data_type": "numeric",
            "transformation": "standard_scale",
            "binary_classification_usage": True,
            "multiclass_classification_usage": True,
            "anomaly_detection_usage": True,
            "exclusion_status": False,
            "exclusion_reason": None
        },
        'Bwd Packet Length Mean': {
            "original_column": 'Bwd Packet Length Mean',
            "role": "feature",
            "data_type": "numeric",
            "transformation": "standard_scale",
            "binary_classification_usage": True,
            "multiclass_classification_usage": True,
            "anomaly_detection_usage": True,
            "exclusion_status": False,
            "exclusion_reason": None
        },
        'Bwd Packet Length Std': {
            "original_column": 'Bwd Packet Length Std',
            "role": "feature",
            "data_type": "numeric",
            "transformation": "standard_scale",
            "binary_classification_usage": True,
            "multiclass_classification_usage": True,
            "anomaly_detection_usage": True,
            "exclusion_status": False,
            "exclusion_reason": None
        },
        'Flow Bytes/s': {
            "original_column": 'Flow Bytes/s',
            "role": "feature",
            "data_type": "numeric",
            "transformation": "standard_scale",
            "binary_classification_usage": True,
            "multiclass_classification_usage": True,
            "anomaly_detection_usage": True,
            "exclusion_status": False,
            "exclusion_reason": None
        },
        'Flow Packets/s': {
            "original_column": 'Flow Packets/s',
            "role": "feature",
            "data_type": "numeric",
            "transformation": "standard_scale",
            "binary_classification_usage": True,
            "multiclass_classification_usage": True,
            "anomaly_detection_usage": True,
            "exclusion_status": False,
            "exclusion_reason": None
        },
        'Flow IAT Mean': {
            "original_column": 'Flow IAT Mean',
            "role": "feature",
            "data_type": "numeric",
            "transformation": "standard_scale",
            "binary_classification_usage": True,
            "multiclass_classification_usage": True,
            "anomaly_detection_usage": True,
            "exclusion_status": False,
            "exclusion_reason": None
        },
        'Flow IAT Std': {
            "original_column": 'Flow IAT Std',
            "role": "feature",
            "data_type": "numeric",
            "transformation": "standard_scale",
            "binary_classification_usage": True,
            "multiclass_classification_usage": True,
            "anomaly_detection_usage": True,
            "exclusion_status": False,
            "exclusion_reason": None
        },
        'Flow IAT Max': {
            "original_column": 'Flow IAT Max',
            "role": "feature",
            "data_type": "numeric",
            "transformation": "standard_scale",
            "binary_classification_usage": True,
            "multiclass_classification_usage": True,
            "anomaly_detection_usage": True,
            "exclusion_status": False,
            "exclusion_reason": None
        },
        'Flow IAT Min': {
            "original_column": 'Flow IAT Min',
            "role": "feature",
            "data_type": "numeric",
            "transformation": "standard_scale",
            "binary_classification_usage": True,
            "multiclass_classification_usage": True,
            "anomaly_detection_usage": True,
            "exclusion_status": False,
            "exclusion_reason": None
        },
        'Fwd IAT Total': {
            "original_column": 'Fwd IAT Total',
            "role": "feature",
            "data_type": "numeric",
            "transformation": "standard_scale",
            "binary_classification_usage": True,
            "multiclass_classification_usage": True,
            "anomaly_detection_usage": True,
            "exclusion_status": False,
            "exclusion_reason": None
        },
        'Fwd IAT Mean': {
            "original_column": 'Fwd IAT Mean',
            "role": "feature",
            "data_type": "numeric",
            "transformation": "standard_scale",
            "binary_classification_usage": True,
            "multiclass_classification_usage": True,
            "anomaly_detection_usage": True,
            "exclusion_status": False,
            "exclusion_reason": None
        },
        'Fwd IAT Std': {
            "original_column": 'Fwd IAT Std',
            "role": "feature",
            "data_type": "numeric",
            "transformation": "standard_scale",
            "binary_classification_usage": True,
            "multiclass_classification_usage": True,
            "anomaly_detection_usage": True,
            "exclusion_status": False,
            "exclusion_reason": None
        },
        'Fwd IAT Max': {
            "original_column": 'Fwd IAT Max',
            "role": "feature",
            "data_type": "numeric",
            "transformation": "standard_scale",
            "binary_classification_usage": True,
            "multiclass_classification_usage": True,
            "anomaly_detection_usage": True,
            "exclusion_status": False,
            "exclusion_reason": None
        },
        'Fwd IAT Min': {
            "original_column": 'Fwd IAT Min',
            "role": "feature",
            "data_type": "numeric",
            "transformation": "standard_scale",
            "binary_classification_usage": True,
            "multiclass_classification_usage": True,
            "anomaly_detection_usage": True,
            "exclusion_status": False,
            "exclusion_reason": None
        },
        'Bwd IAT Total': {
            "original_column": 'Bwd IAT Total',
            "role": "feature",
            "data_type": "numeric",
            "transformation": "standard_scale",
            "binary_classification_usage": True,
            "multiclass_classification_usage": True,
            "anomaly_detection_usage": True,
            "exclusion_status": False,
            "exclusion_reason": None
        },
        'Bwd IAT Mean': {
            "original_column": 'Bwd IAT Mean',
            "role": "feature",
            "data_type": "numeric",
            "transformation": "standard_scale",
            "binary_classification_usage": True,
            "multiclass_classification_usage": True,
            "anomaly_detection_usage": True,
            "exclusion_status": False,
            "exclusion_reason": None
        },
        'Bwd IAT Std': {
            "original_column": 'Bwd IAT Std',
            "role": "feature",
            "data_type": "numeric",
            "transformation": "standard_scale",
            "binary_classification_usage": True,
            "multiclass_classification_usage": True,
            "anomaly_detection_usage": True,
            "exclusion_status": False,
            "exclusion_reason": None
        },
        'Bwd IAT Max': {
            "original_column": 'Bwd IAT Max',
            "role": "feature",
            "data_type": "numeric",
            "transformation": "standard_scale",
            "binary_classification_usage": True,
            "multiclass_classification_usage": True,
            "anomaly_detection_usage": True,
            "exclusion_status": False,
            "exclusion_reason": None
        },
        'Bwd IAT Min': {
            "original_column": 'Bwd IAT Min',
            "role": "feature",
            "data_type": "numeric",
            "transformation": "standard_scale",
            "binary_classification_usage": True,
            "multiclass_classification_usage": True,
            "anomaly_detection_usage": True,
            "exclusion_status": False,
            "exclusion_reason": None
        },
        'Fwd PSH Flags': {
            "original_column": 'Fwd PSH Flags',
            "role": "feature",
            "data_type": "numeric",
            "transformation": "standard_scale",
            "binary_classification_usage": True,
            "multiclass_classification_usage": True,
            "anomaly_detection_usage": True,
            "exclusion_status": False,
            "exclusion_reason": None
        },
        'Bwd PSH Flags': {
            "original_column": 'Bwd PSH Flags',
            "role": "feature",
            "data_type": "numeric",
            "transformation": "standard_scale",
            "binary_classification_usage": True,
            "multiclass_classification_usage": True,
            "anomaly_detection_usage": True,
            "exclusion_status": False,
            "exclusion_reason": None
        },
        'Fwd URG Flags': {
            "original_column": 'Fwd URG Flags',
            "role": "feature",
            "data_type": "numeric",
            "transformation": "standard_scale",
            "binary_classification_usage": True,
            "multiclass_classification_usage": True,
            "anomaly_detection_usage": True,
            "exclusion_status": False,
            "exclusion_reason": None
        },
        'Bwd URG Flags': {
            "original_column": 'Bwd URG Flags',
            "role": "feature",
            "data_type": "numeric",
            "transformation": "standard_scale",
            "binary_classification_usage": True,
            "multiclass_classification_usage": True,
            "anomaly_detection_usage": True,
            "exclusion_status": False,
            "exclusion_reason": None
        },
        'Fwd Header Length': {
            "original_column": 'Fwd Header Length',
            "role": "feature",
            "data_type": "numeric",
            "transformation": "standard_scale",
            "binary_classification_usage": True,
            "multiclass_classification_usage": True,
            "anomaly_detection_usage": True,
            "exclusion_status": False,
            "exclusion_reason": None
        },
        'Bwd Header Length': {
            "original_column": 'Bwd Header Length',
            "role": "feature",
            "data_type": "numeric",
            "transformation": "standard_scale",
            "binary_classification_usage": True,
            "multiclass_classification_usage": True,
            "anomaly_detection_usage": True,
            "exclusion_status": False,
            "exclusion_reason": None
        },
        'Fwd Packets/s': {
            "original_column": 'Fwd Packets/s',
            "role": "feature",
            "data_type": "numeric",
            "transformation": "standard_scale",
            "binary_classification_usage": True,
            "multiclass_classification_usage": True,
            "anomaly_detection_usage": True,
            "exclusion_status": False,
            "exclusion_reason": None
        },
        'Bwd Packets/s': {
            "original_column": 'Bwd Packets/s',
            "role": "feature",
            "data_type": "numeric",
            "transformation": "standard_scale",
            "binary_classification_usage": True,
            "multiclass_classification_usage": True,
            "anomaly_detection_usage": True,
            "exclusion_status": False,
            "exclusion_reason": None
        },
        'Min Packet Length': {
            "original_column": 'Min Packet Length',
            "role": "feature",
            "data_type": "numeric",
            "transformation": "standard_scale",
            "binary_classification_usage": True,
            "multiclass_classification_usage": True,
            "anomaly_detection_usage": True,
            "exclusion_status": False,
            "exclusion_reason": None
        },
        'Max Packet Length': {
            "original_column": 'Max Packet Length',
            "role": "feature",
            "data_type": "numeric",
            "transformation": "standard_scale",
            "binary_classification_usage": True,
            "multiclass_classification_usage": True,
            "anomaly_detection_usage": True,
            "exclusion_status": False,
            "exclusion_reason": None
        },
        'Packet Length Mean': {
            "original_column": 'Packet Length Mean',
            "role": "feature",
            "data_type": "numeric",
            "transformation": "standard_scale",
            "binary_classification_usage": True,
            "multiclass_classification_usage": True,
            "anomaly_detection_usage": True,
            "exclusion_status": False,
            "exclusion_reason": None
        },
        'Packet Length Std': {
            "original_column": 'Packet Length Std',
            "role": "feature",
            "data_type": "numeric",
            "transformation": "standard_scale",
            "binary_classification_usage": True,
            "multiclass_classification_usage": True,
            "anomaly_detection_usage": True,
            "exclusion_status": False,
            "exclusion_reason": None
        },
        'Packet Length Variance': {
            "original_column": 'Packet Length Variance',
            "role": "feature",
            "data_type": "numeric",
            "transformation": "standard_scale",
            "binary_classification_usage": True,
            "multiclass_classification_usage": True,
            "anomaly_detection_usage": True,
            "exclusion_status": False,
            "exclusion_reason": None
        },
        'FIN Flag Count': {
            "original_column": 'FIN Flag Count',
            "role": "feature",
            "data_type": "numeric",
            "transformation": "standard_scale",
            "binary_classification_usage": True,
            "multiclass_classification_usage": True,
            "anomaly_detection_usage": True,
            "exclusion_status": False,
            "exclusion_reason": None
        },
        'SYN Flag Count': {
            "original_column": 'SYN Flag Count',
            "role": "feature",
            "data_type": "numeric",
            "transformation": "standard_scale",
            "binary_classification_usage": True,
            "multiclass_classification_usage": True,
            "anomaly_detection_usage": True,
            "exclusion_status": False,
            "exclusion_reason": None
        },
        'RST Flag Count': {
            "original_column": 'RST Flag Count',
            "role": "feature",
            "data_type": "numeric",
            "transformation": "standard_scale",
            "binary_classification_usage": True,
            "multiclass_classification_usage": True,
            "anomaly_detection_usage": True,
            "exclusion_status": False,
            "exclusion_reason": None
        },
        'PSH Flag Count': {
            "original_column": 'PSH Flag Count',
            "role": "feature",
            "data_type": "numeric",
            "transformation": "standard_scale",
            "binary_classification_usage": True,
            "multiclass_classification_usage": True,
            "anomaly_detection_usage": True,
            "exclusion_status": False,
            "exclusion_reason": None
        },
        'ACK Flag Count': {
            "original_column": 'ACK Flag Count',
            "role": "feature",
            "data_type": "numeric",
            "transformation": "standard_scale",
            "binary_classification_usage": True,
            "multiclass_classification_usage": True,
            "anomaly_detection_usage": True,
            "exclusion_status": False,
            "exclusion_reason": None
        },
        'URG Flag Count': {
            "original_column": 'URG Flag Count',
            "role": "feature",
            "data_type": "numeric",
            "transformation": "standard_scale",
            "binary_classification_usage": True,
            "multiclass_classification_usage": True,
            "anomaly_detection_usage": True,
            "exclusion_status": False,
            "exclusion_reason": None
        },
        'CWE Flag Count': {
            "original_column": 'CWE Flag Count',
            "role": "feature",
            "data_type": "numeric",
            "transformation": "standard_scale",
            "binary_classification_usage": True,
            "multiclass_classification_usage": True,
            "anomaly_detection_usage": True,
            "exclusion_status": False,
            "exclusion_reason": None
        },
        'ECE Flag Count': {
            "original_column": 'ECE Flag Count',
            "role": "feature",
            "data_type": "numeric",
            "transformation": "standard_scale",
            "binary_classification_usage": True,
            "multiclass_classification_usage": True,
            "anomaly_detection_usage": True,
            "exclusion_status": False,
            "exclusion_reason": None
        },
        'Down/Up Ratio': {
            "original_column": 'Down/Up Ratio',
            "role": "feature",
            "data_type": "numeric",
            "transformation": "standard_scale",
            "binary_classification_usage": True,
            "multiclass_classification_usage": True,
            "anomaly_detection_usage": True,
            "exclusion_status": False,
            "exclusion_reason": None
        },
        'Average Packet Size': {
            "original_column": 'Average Packet Size',
            "role": "feature",
            "data_type": "numeric",
            "transformation": "standard_scale",
            "binary_classification_usage": True,
            "multiclass_classification_usage": True,
            "anomaly_detection_usage": True,
            "exclusion_status": False,
            "exclusion_reason": None
        },
        'Avg Fwd Segment Size': {
            "original_column": 'Avg Fwd Segment Size',
            "role": "feature",
            "data_type": "numeric",
            "transformation": "standard_scale",
            "binary_classification_usage": True,
            "multiclass_classification_usage": True,
            "anomaly_detection_usage": True,
            "exclusion_status": False,
            "exclusion_reason": None
        },
        'Avg Bwd Segment Size': {
            "original_column": 'Avg Bwd Segment Size',
            "role": "feature",
            "data_type": "numeric",
            "transformation": "standard_scale",
            "binary_classification_usage": True,
            "multiclass_classification_usage": True,
            "anomaly_detection_usage": True,
            "exclusion_status": False,
            "exclusion_reason": None
        },
        'Fwd Header Length.1': {
            "original_column": 'Fwd Header Length.1',
            "role": "excluded",
            "data_type": "numeric",
            "transformation": "none",
            "binary_classification_usage": False,
            "multiclass_classification_usage": False,
            "anomaly_detection_usage": False,
            "exclusion_status": True,
            "exclusion_reason": "Duplicate column of Fwd Header Length."
        },
        'Fwd Avg Bytes/Bulk': {
            "original_column": 'Fwd Avg Bytes/Bulk',
            "role": "feature",
            "data_type": "numeric",
            "transformation": "standard_scale",
            "binary_classification_usage": True,
            "multiclass_classification_usage": True,
            "anomaly_detection_usage": True,
            "exclusion_status": False,
            "exclusion_reason": None
        },
        'Fwd Avg Packets/Bulk': {
            "original_column": 'Fwd Avg Packets/Bulk',
            "role": "feature",
            "data_type": "numeric",
            "transformation": "standard_scale",
            "binary_classification_usage": True,
            "multiclass_classification_usage": True,
            "anomaly_detection_usage": True,
            "exclusion_status": False,
            "exclusion_reason": None
        },
        'Fwd Avg Bulk Rate': {
            "original_column": 'Fwd Avg Bulk Rate',
            "role": "feature",
            "data_type": "numeric",
            "transformation": "standard_scale",
            "binary_classification_usage": True,
            "multiclass_classification_usage": True,
            "anomaly_detection_usage": True,
            "exclusion_status": False,
            "exclusion_reason": None
        },
        'Bwd Avg Bytes/Bulk': {
            "original_column": 'Bwd Avg Bytes/Bulk',
            "role": "feature",
            "data_type": "numeric",
            "transformation": "standard_scale",
            "binary_classification_usage": True,
            "multiclass_classification_usage": True,
            "anomaly_detection_usage": True,
            "exclusion_status": False,
            "exclusion_reason": None
        },
        'Bwd Avg Packets/Bulk': {
            "original_column": 'Bwd Avg Packets/Bulk',
            "role": "feature",
            "data_type": "numeric",
            "transformation": "standard_scale",
            "binary_classification_usage": True,
            "multiclass_classification_usage": True,
            "anomaly_detection_usage": True,
            "exclusion_status": False,
            "exclusion_reason": None
        },
        'Bwd Avg Bulk Rate': {
            "original_column": 'Bwd Avg Bulk Rate',
            "role": "feature",
            "data_type": "numeric",
            "transformation": "standard_scale",
            "binary_classification_usage": True,
            "multiclass_classification_usage": True,
            "anomaly_detection_usage": True,
            "exclusion_status": False,
            "exclusion_reason": None
        },
        'Subflow Fwd Packets': {
            "original_column": 'Subflow Fwd Packets',
            "role": "feature",
            "data_type": "numeric",
            "transformation": "standard_scale",
            "binary_classification_usage": True,
            "multiclass_classification_usage": True,
            "anomaly_detection_usage": True,
            "exclusion_status": False,
            "exclusion_reason": None
        },
        'Subflow Fwd Bytes': {
            "original_column": 'Subflow Fwd Bytes',
            "role": "feature",
            "data_type": "numeric",
            "transformation": "standard_scale",
            "binary_classification_usage": True,
            "multiclass_classification_usage": True,
            "anomaly_detection_usage": True,
            "exclusion_status": False,
            "exclusion_reason": None
        },
        'Subflow Bwd Packets': {
            "original_column": 'Subflow Bwd Packets',
            "role": "feature",
            "data_type": "numeric",
            "transformation": "standard_scale",
            "binary_classification_usage": True,
            "multiclass_classification_usage": True,
            "anomaly_detection_usage": True,
            "exclusion_status": False,
            "exclusion_reason": None
        },
        'Subflow Bwd Bytes': {
            "original_column": 'Subflow Bwd Bytes',
            "role": "feature",
            "data_type": "numeric",
            "transformation": "standard_scale",
            "binary_classification_usage": True,
            "multiclass_classification_usage": True,
            "anomaly_detection_usage": True,
            "exclusion_status": False,
            "exclusion_reason": None
        },
        'Init_Win_bytes_forward': {
            "original_column": 'Init_Win_bytes_forward',
            "role": "feature",
            "data_type": "numeric",
            "transformation": "standard_scale",
            "binary_classification_usage": True,
            "multiclass_classification_usage": True,
            "anomaly_detection_usage": True,
            "exclusion_status": False,
            "exclusion_reason": None
        },
        'Init_Win_bytes_backward': {
            "original_column": 'Init_Win_bytes_backward',
            "role": "feature",
            "data_type": "numeric",
            "transformation": "standard_scale",
            "binary_classification_usage": True,
            "multiclass_classification_usage": True,
            "anomaly_detection_usage": True,
            "exclusion_status": False,
            "exclusion_reason": None
        },
        'act_data_pkt_fwd': {
            "original_column": 'act_data_pkt_fwd',
            "role": "feature",
            "data_type": "numeric",
            "transformation": "standard_scale",
            "binary_classification_usage": True,
            "multiclass_classification_usage": True,
            "anomaly_detection_usage": True,
            "exclusion_status": False,
            "exclusion_reason": None
        },
        'min_seg_size_forward': {
            "original_column": 'min_seg_size_forward',
            "role": "feature",
            "data_type": "numeric",
            "transformation": "standard_scale",
            "binary_classification_usage": True,
            "multiclass_classification_usage": True,
            "anomaly_detection_usage": True,
            "exclusion_status": False,
            "exclusion_reason": None
        },
        'Active Mean': {
            "original_column": 'Active Mean',
            "role": "feature",
            "data_type": "numeric",
            "transformation": "standard_scale",
            "binary_classification_usage": True,
            "multiclass_classification_usage": True,
            "anomaly_detection_usage": True,
            "exclusion_status": False,
            "exclusion_reason": None
        },
        'Active Std': {
            "original_column": 'Active Std',
            "role": "feature",
            "data_type": "numeric",
            "transformation": "standard_scale",
            "binary_classification_usage": True,
            "multiclass_classification_usage": True,
            "anomaly_detection_usage": True,
            "exclusion_status": False,
            "exclusion_reason": None
        },
        'Active Max': {
            "original_column": 'Active Max',
            "role": "feature",
            "data_type": "numeric",
            "transformation": "standard_scale",
            "binary_classification_usage": True,
            "multiclass_classification_usage": True,
            "anomaly_detection_usage": True,
            "exclusion_status": False,
            "exclusion_reason": None
        },
        'Active Min': {
            "original_column": 'Active Min',
            "role": "feature",
            "data_type": "numeric",
            "transformation": "standard_scale",
            "binary_classification_usage": True,
            "multiclass_classification_usage": True,
            "anomaly_detection_usage": True,
            "exclusion_status": False,
            "exclusion_reason": None
        },
        'Idle Mean': {
            "original_column": 'Idle Mean',
            "role": "feature",
            "data_type": "numeric",
            "transformation": "standard_scale",
            "binary_classification_usage": True,
            "multiclass_classification_usage": True,
            "anomaly_detection_usage": True,
            "exclusion_status": False,
            "exclusion_reason": None
        },
        'Idle Std': {
            "original_column": 'Idle Std',
            "role": "feature",
            "data_type": "numeric",
            "transformation": "standard_scale",
            "binary_classification_usage": True,
            "multiclass_classification_usage": True,
            "anomaly_detection_usage": True,
            "exclusion_status": False,
            "exclusion_reason": None
        },
        'Idle Max': {
            "original_column": 'Idle Max',
            "role": "feature",
            "data_type": "numeric",
            "transformation": "standard_scale",
            "binary_classification_usage": True,
            "multiclass_classification_usage": True,
            "anomaly_detection_usage": True,
            "exclusion_status": False,
            "exclusion_reason": None
        },
        'Idle Min': {
            "original_column": 'Idle Min',
            "role": "feature",
            "data_type": "numeric",
            "transformation": "standard_scale",
            "binary_classification_usage": True,
            "multiclass_classification_usage": True,
            "anomaly_detection_usage": True,
            "exclusion_status": False,
            "exclusion_reason": None
        },
        'Label': {
            "original_column": 'Label',
            "role": "target",
            "data_type": "numeric",
            "transformation": "label_encode",
            "binary_classification_usage": False,
            "multiclass_classification_usage": False,
            "anomaly_detection_usage": False,
            "exclusion_status": True,
            "exclusion_reason": "Target label column"
        },
    },
    "unsw_nb15": {
        'srcip': {
            "original_column": 'srcip',
            "role": "metadata",
            "data_type": "categorical",
            "transformation": "none",
            "binary_classification_usage": False,
            "multiclass_classification_usage": False,
            "anomaly_detection_usage": False,
            "exclusion_status": True,
            "exclusion_reason": "Excluded from baseline features due to potential dataset-specific target leakage, memorization risk, or poor generalization to unseen network environments."
        },
        'sport': {
            "original_column": 'sport',
            "role": "feature",
            "data_type": "numeric",
            "transformation": "standard_scale",
            "binary_classification_usage": True,
            "multiclass_classification_usage": True,
            "anomaly_detection_usage": True,
            "exclusion_status": False,
            "exclusion_reason": None
        },
        'dstip': {
            "original_column": 'dstip',
            "role": "metadata",
            "data_type": "categorical",
            "transformation": "none",
            "binary_classification_usage": False,
            "multiclass_classification_usage": False,
            "anomaly_detection_usage": False,
            "exclusion_status": True,
            "exclusion_reason": "Excluded from baseline features due to potential dataset-specific target leakage, memorization risk, or poor generalization to unseen network environments."
        },
        'dsport': {
            "original_column": 'dsport',
            "role": "feature",
            "data_type": "numeric",
            "transformation": "standard_scale",
            "binary_classification_usage": True,
            "multiclass_classification_usage": True,
            "anomaly_detection_usage": True,
            "exclusion_status": False,
            "exclusion_reason": None
        },
        'proto': {
            "original_column": 'proto',
            "role": "feature",
            "data_type": "categorical",
            "transformation": "one_hot_encode",
            "binary_classification_usage": True,
            "multiclass_classification_usage": True,
            "anomaly_detection_usage": True,
            "exclusion_status": False,
            "exclusion_reason": None
        },
        'state': {
            "original_column": 'state',
            "role": "feature",
            "data_type": "categorical",
            "transformation": "one_hot_encode",
            "binary_classification_usage": True,
            "multiclass_classification_usage": True,
            "anomaly_detection_usage": True,
            "exclusion_status": False,
            "exclusion_reason": None
        },
        'dur': {
            "original_column": 'dur',
            "role": "feature",
            "data_type": "numeric",
            "transformation": "standard_scale",
            "binary_classification_usage": True,
            "multiclass_classification_usage": True,
            "anomaly_detection_usage": True,
            "exclusion_status": False,
            "exclusion_reason": None
        },
        'sbytes': {
            "original_column": 'sbytes',
            "role": "feature",
            "data_type": "numeric",
            "transformation": "standard_scale",
            "binary_classification_usage": True,
            "multiclass_classification_usage": True,
            "anomaly_detection_usage": True,
            "exclusion_status": False,
            "exclusion_reason": None
        },
        'dbytes': {
            "original_column": 'dbytes',
            "role": "feature",
            "data_type": "numeric",
            "transformation": "standard_scale",
            "binary_classification_usage": True,
            "multiclass_classification_usage": True,
            "anomaly_detection_usage": True,
            "exclusion_status": False,
            "exclusion_reason": None
        },
        'sttl': {
            "original_column": 'sttl',
            "role": "feature",
            "data_type": "numeric",
            "transformation": "standard_scale",
            "binary_classification_usage": True,
            "multiclass_classification_usage": True,
            "anomaly_detection_usage": True,
            "exclusion_status": False,
            "exclusion_reason": None
        },
        'dttl': {
            "original_column": 'dttl',
            "role": "feature",
            "data_type": "numeric",
            "transformation": "standard_scale",
            "binary_classification_usage": True,
            "multiclass_classification_usage": True,
            "anomaly_detection_usage": True,
            "exclusion_status": False,
            "exclusion_reason": None
        },
        'sloss': {
            "original_column": 'sloss',
            "role": "feature",
            "data_type": "numeric",
            "transformation": "standard_scale",
            "binary_classification_usage": True,
            "multiclass_classification_usage": True,
            "anomaly_detection_usage": True,
            "exclusion_status": False,
            "exclusion_reason": None
        },
        'dloss': {
            "original_column": 'dloss',
            "role": "feature",
            "data_type": "numeric",
            "transformation": "standard_scale",
            "binary_classification_usage": True,
            "multiclass_classification_usage": True,
            "anomaly_detection_usage": True,
            "exclusion_status": False,
            "exclusion_reason": None
        },
        'service': {
            "original_column": 'service',
            "role": "feature",
            "data_type": "categorical",
            "transformation": "one_hot_encode",
            "binary_classification_usage": True,
            "multiclass_classification_usage": True,
            "anomaly_detection_usage": True,
            "exclusion_status": False,
            "exclusion_reason": None
        },
        'Sload': {
            "original_column": 'Sload',
            "role": "feature",
            "data_type": "numeric",
            "transformation": "standard_scale",
            "binary_classification_usage": True,
            "multiclass_classification_usage": True,
            "anomaly_detection_usage": True,
            "exclusion_status": False,
            "exclusion_reason": None
        },
        'Dload': {
            "original_column": 'Dload',
            "role": "feature",
            "data_type": "numeric",
            "transformation": "standard_scale",
            "binary_classification_usage": True,
            "multiclass_classification_usage": True,
            "anomaly_detection_usage": True,
            "exclusion_status": False,
            "exclusion_reason": None
        },
        'Spkts': {
            "original_column": 'Spkts',
            "role": "feature",
            "data_type": "numeric",
            "transformation": "standard_scale",
            "binary_classification_usage": True,
            "multiclass_classification_usage": True,
            "anomaly_detection_usage": True,
            "exclusion_status": False,
            "exclusion_reason": None
        },
        'Dpkts': {
            "original_column": 'Dpkts',
            "role": "feature",
            "data_type": "numeric",
            "transformation": "standard_scale",
            "binary_classification_usage": True,
            "multiclass_classification_usage": True,
            "anomaly_detection_usage": True,
            "exclusion_status": False,
            "exclusion_reason": None
        },
        'swin': {
            "original_column": 'swin',
            "role": "feature",
            "data_type": "numeric",
            "transformation": "standard_scale",
            "binary_classification_usage": True,
            "multiclass_classification_usage": True,
            "anomaly_detection_usage": True,
            "exclusion_status": False,
            "exclusion_reason": None
        },
        'dwin': {
            "original_column": 'dwin',
            "role": "feature",
            "data_type": "numeric",
            "transformation": "standard_scale",
            "binary_classification_usage": True,
            "multiclass_classification_usage": True,
            "anomaly_detection_usage": True,
            "exclusion_status": False,
            "exclusion_reason": None
        },
        'stcpb': {
            "original_column": 'stcpb',
            "role": "feature",
            "data_type": "numeric",
            "transformation": "standard_scale",
            "binary_classification_usage": True,
            "multiclass_classification_usage": True,
            "anomaly_detection_usage": True,
            "exclusion_status": False,
            "exclusion_reason": None
        },
        'dtcpb': {
            "original_column": 'dtcpb',
            "role": "feature",
            "data_type": "numeric",
            "transformation": "standard_scale",
            "binary_classification_usage": True,
            "multiclass_classification_usage": True,
            "anomaly_detection_usage": True,
            "exclusion_status": False,
            "exclusion_reason": None
        },
        'smeansz': {
            "original_column": 'smeansz',
            "role": "feature",
            "data_type": "numeric",
            "transformation": "standard_scale",
            "binary_classification_usage": True,
            "multiclass_classification_usage": True,
            "anomaly_detection_usage": True,
            "exclusion_status": False,
            "exclusion_reason": None
        },
        'dmeansz': {
            "original_column": 'dmeansz',
            "role": "feature",
            "data_type": "numeric",
            "transformation": "standard_scale",
            "binary_classification_usage": True,
            "multiclass_classification_usage": True,
            "anomaly_detection_usage": True,
            "exclusion_status": False,
            "exclusion_reason": None
        },
        'trans_depth': {
            "original_column": 'trans_depth',
            "role": "feature",
            "data_type": "numeric",
            "transformation": "standard_scale",
            "binary_classification_usage": True,
            "multiclass_classification_usage": True,
            "anomaly_detection_usage": True,
            "exclusion_status": False,
            "exclusion_reason": None
        },
        'res_bdy_len': {
            "original_column": 'res_bdy_len',
            "role": "feature",
            "data_type": "numeric",
            "transformation": "standard_scale",
            "binary_classification_usage": True,
            "multiclass_classification_usage": True,
            "anomaly_detection_usage": True,
            "exclusion_status": False,
            "exclusion_reason": None
        },
        'Sjit': {
            "original_column": 'Sjit',
            "role": "feature",
            "data_type": "numeric",
            "transformation": "standard_scale",
            "binary_classification_usage": True,
            "multiclass_classification_usage": True,
            "anomaly_detection_usage": True,
            "exclusion_status": False,
            "exclusion_reason": None
        },
        'Djit': {
            "original_column": 'Djit',
            "role": "feature",
            "data_type": "numeric",
            "transformation": "standard_scale",
            "binary_classification_usage": True,
            "multiclass_classification_usage": True,
            "anomaly_detection_usage": True,
            "exclusion_status": False,
            "exclusion_reason": None
        },
        'Stime': {
            "original_column": 'Stime',
            "role": "metadata",
            "data_type": "numeric",
            "transformation": "none",
            "binary_classification_usage": False,
            "multiclass_classification_usage": False,
            "anomaly_detection_usage": False,
            "exclusion_status": True,
            "exclusion_reason": "Excluded from baseline features due to potential dataset-specific target leakage, memorization risk, or poor generalization to unseen network environments."
        },
        'Ltime': {
            "original_column": 'Ltime',
            "role": "metadata",
            "data_type": "numeric",
            "transformation": "none",
            "binary_classification_usage": False,
            "multiclass_classification_usage": False,
            "anomaly_detection_usage": False,
            "exclusion_status": True,
            "exclusion_reason": "Excluded from baseline features due to potential dataset-specific target leakage, memorization risk, or poor generalization to unseen network environments."
        },
        'Sintpkt': {
            "original_column": 'Sintpkt',
            "role": "feature",
            "data_type": "numeric",
            "transformation": "standard_scale",
            "binary_classification_usage": True,
            "multiclass_classification_usage": True,
            "anomaly_detection_usage": True,
            "exclusion_status": False,
            "exclusion_reason": None
        },
        'Dintpkt': {
            "original_column": 'Dintpkt',
            "role": "feature",
            "data_type": "numeric",
            "transformation": "standard_scale",
            "binary_classification_usage": True,
            "multiclass_classification_usage": True,
            "anomaly_detection_usage": True,
            "exclusion_status": False,
            "exclusion_reason": None
        },
        'tcprtt': {
            "original_column": 'tcprtt',
            "role": "feature",
            "data_type": "numeric",
            "transformation": "standard_scale",
            "binary_classification_usage": True,
            "multiclass_classification_usage": True,
            "anomaly_detection_usage": True,
            "exclusion_status": False,
            "exclusion_reason": None
        },
        'synack': {
            "original_column": 'synack',
            "role": "feature",
            "data_type": "numeric",
            "transformation": "standard_scale",
            "binary_classification_usage": True,
            "multiclass_classification_usage": True,
            "anomaly_detection_usage": True,
            "exclusion_status": False,
            "exclusion_reason": None
        },
        'ackdat': {
            "original_column": 'ackdat',
            "role": "feature",
            "data_type": "numeric",
            "transformation": "standard_scale",
            "binary_classification_usage": True,
            "multiclass_classification_usage": True,
            "anomaly_detection_usage": True,
            "exclusion_status": False,
            "exclusion_reason": None
        },
        'is_sm_ips_ports': {
            "original_column": 'is_sm_ips_ports',
            "role": "feature",
            "data_type": "numeric",
            "transformation": "standard_scale",
            "binary_classification_usage": True,
            "multiclass_classification_usage": True,
            "anomaly_detection_usage": True,
            "exclusion_status": False,
            "exclusion_reason": None
        },
        'ct_state_ttl': {
            "original_column": 'ct_state_ttl',
            "role": "feature",
            "data_type": "numeric",
            "transformation": "standard_scale",
            "binary_classification_usage": True,
            "multiclass_classification_usage": True,
            "anomaly_detection_usage": True,
            "exclusion_status": False,
            "exclusion_reason": None
        },
        'ct_flw_http_mthd': {
            "original_column": 'ct_flw_http_mthd',
            "role": "feature",
            "data_type": "numeric",
            "transformation": "standard_scale",
            "binary_classification_usage": True,
            "multiclass_classification_usage": True,
            "anomaly_detection_usage": True,
            "exclusion_status": False,
            "exclusion_reason": None
        },
        'is_ftp_login': {
            "original_column": 'is_ftp_login',
            "role": "feature",
            "data_type": "numeric",
            "transformation": "standard_scale",
            "binary_classification_usage": True,
            "multiclass_classification_usage": True,
            "anomaly_detection_usage": True,
            "exclusion_status": False,
            "exclusion_reason": None
        },
        'ct_ftp_cmd': {
            "original_column": 'ct_ftp_cmd',
            "role": "feature",
            "data_type": "numeric",
            "transformation": "standard_scale",
            "binary_classification_usage": True,
            "multiclass_classification_usage": True,
            "anomaly_detection_usage": True,
            "exclusion_status": False,
            "exclusion_reason": None
        },
        'ct_srv_src': {
            "original_column": 'ct_srv_src',
            "role": "feature",
            "data_type": "numeric",
            "transformation": "standard_scale",
            "binary_classification_usage": True,
            "multiclass_classification_usage": True,
            "anomaly_detection_usage": True,
            "exclusion_status": False,
            "exclusion_reason": None
        },
        'ct_srv_dst': {
            "original_column": 'ct_srv_dst',
            "role": "feature",
            "data_type": "numeric",
            "transformation": "standard_scale",
            "binary_classification_usage": True,
            "multiclass_classification_usage": True,
            "anomaly_detection_usage": True,
            "exclusion_status": False,
            "exclusion_reason": None
        },
        'ct_dst_ltm': {
            "original_column": 'ct_dst_ltm',
            "role": "feature",
            "data_type": "numeric",
            "transformation": "standard_scale",
            "binary_classification_usage": True,
            "multiclass_classification_usage": True,
            "anomaly_detection_usage": True,
            "exclusion_status": False,
            "exclusion_reason": None
        },
        'ct_src_ltm': {
            "original_column": 'ct_src_ltm',
            "role": "feature",
            "data_type": "numeric",
            "transformation": "standard_scale",
            "binary_classification_usage": True,
            "multiclass_classification_usage": True,
            "anomaly_detection_usage": True,
            "exclusion_status": False,
            "exclusion_reason": None
        },
        'ct_src_dport_ltm': {
            "original_column": 'ct_src_dport_ltm',
            "role": "feature",
            "data_type": "numeric",
            "transformation": "standard_scale",
            "binary_classification_usage": True,
            "multiclass_classification_usage": True,
            "anomaly_detection_usage": True,
            "exclusion_status": False,
            "exclusion_reason": None
        },
        'ct_dst_sport_ltm': {
            "original_column": 'ct_dst_sport_ltm',
            "role": "feature",
            "data_type": "numeric",
            "transformation": "standard_scale",
            "binary_classification_usage": True,
            "multiclass_classification_usage": True,
            "anomaly_detection_usage": True,
            "exclusion_status": False,
            "exclusion_reason": None
        },
        'ct_dst_src_ltm': {
            "original_column": 'ct_dst_src_ltm',
            "role": "feature",
            "data_type": "numeric",
            "transformation": "standard_scale",
            "binary_classification_usage": True,
            "multiclass_classification_usage": True,
            "anomaly_detection_usage": True,
            "exclusion_status": False,
            "exclusion_reason": None
        },
        'attack_cat': {
            "original_column": 'attack_cat',
            "role": "target",
            "data_type": "categorical",
            "transformation": "label_encode",
            "binary_classification_usage": False,
            "multiclass_classification_usage": False,
            "anomaly_detection_usage": False,
            "exclusion_status": True,
            "exclusion_reason": "Supervised multiclass target column."
        },
        'Label': {
            "original_column": 'Label',
            "role": "target",
            "data_type": "numeric",
            "transformation": "none",
            "binary_classification_usage": False,
            "multiclass_classification_usage": False,
            "anomaly_detection_usage": False,
            "exclusion_status": True,
            "exclusion_reason": "Supervised binary target column."
        },
    }
}

def get_role_columns(dataset_name: str, role: str) -> List[str]:
    """Retrieve columns by their defined role for a given dataset."""
    schema = FEATURE_SCHEMA.get(dataset_name.lower())
    if not schema:
        return []
    return [col for col, meta in schema.items() if meta["role"] == role]

def get_features_by_usage(dataset_name: str, task: str) -> List[str]:
    """
    Retrieve feature column names that are approved for use in a specific task.
    task: 'binary_classification', 'multiclass_classification', or 'anomaly_detection'
    """
    schema = FEATURE_SCHEMA.get(dataset_name.lower())
    if not schema:
        return []
    
    task_key = f"{task}_usage"
    features = []
    for col, meta in schema.items():
        if meta["role"] == "feature" and meta.get(task_key, False):
            features.append(col)
    return features
