# XGBoost Intrusion Prediction - CICIDS2017 MULTICLASS (VALIDATION)

Generated on: 2026-08-16T23:51:51.242256
Preprocessing Pipeline Version: 1.0

> [!WARNING]
> The current results are based on the Phase 1 development samples of approximately 5,000 rows and are not final full-dataset or production performance.

## 1. Split Overview
- **Dataset**: CICIDS2017
- **Task Type**: MULTICLASS
- **Evaluation Split**: VALIDATION
- **Total Samples**: 741
- **Features Count**: 77

## 2. Supervised Performance Metrics
- **Overall Accuracy**: 0.9973
- **Attack Classification Accuracy (Outliers Only)**: 0.9861
- **Macro Precision**: 0.6665
- **Macro Recall**: 0.6667
- **Macro F1-Score**: 0.6666
- **Weighted Precision**: 0.9960
- **Weighted Recall**: 0.9973
- **Weighted F1-Score**: 0.9966

### Per-Class Performance Table:

| Class Name | Precision | Recall | F1-Score | Support |
| --- | --- | --- | --- | --- |
| **BENIGN** | 0.9983 | 1.0000 | 0.9992 | 597 |
| **DDoS** | 1.0000 | 1.0000 | 1.0000 | 58 |
| **DoS GoldenEye** | 1.0000 | 1.0000 | 1.0000 | 2 |
| **DoS Hulk** | 1.0000 | 1.0000 | 1.0000 | 26 |
| **FTP-Patator** | 1.0000 | 1.0000 | 1.0000 | 1 |
| **PortScan** | 1.0000 | 1.0000 | 1.0000 | 55 |
| **SSH-Patator** | 0.0000 | 0.0000 | 0.0000 | 1 |
| **Web Attack � Brute Force** | 0.0000 | 0.0000 | 0.0000 | 1 |
| **Web Attack � XSS** | 0.0000 | 0.0000 | 0.0000 | 0 |

## 3. Feature Importance Analysis
Top 10 features sorted by XGBoost `feature_importances_` metric:

| Rank | Feature Name | Importance Score |
| --- | --- | --- |
| 1 | Idle Mean | 0.149391 |
| 2 | Avg Bwd Segment Size | 0.081772 |
| 3 | Subflow Fwd Bytes | 0.072127 |
| 4 | Bwd Packet Length Std | 0.071608 |
| 5 | Bwd Packet Length Mean | 0.070388 |
| 6 | Max Packet Length | 0.067912 |
| 7 | Total Length of Fwd Packets | 0.066601 |
| 8 | Bwd Header Length | 0.044829 |
| 9 | Average Packet Size | 0.040619 |
| 10 | Flow Bytes/s | 0.033770 |

> [!NOTE]
> **Causality Notice**: Feature importance represents the model's contribution/association with predictions and does NOT establish causal relationships or physical network-attack causation.

## 4. Visualizations
- **Confusion Matrix**: [confusion_matrix.png](confusion_matrix.png)
- **Feature Importance Plot**: [feature_importance.png](feature_importance.png)
