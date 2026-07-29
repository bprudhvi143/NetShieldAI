# XGBoost Intrusion Prediction - CICIDS2017 MULTICLASS (TEST)

Generated on: 2026-08-16T23:51:51.741763
Preprocessing Pipeline Version: 1.0

> [!WARNING]
> The current results are based on the Phase 1 development samples of approximately 5,000 rows and are not final full-dataset or production performance.

## 1. Split Overview
- **Dataset**: CICIDS2017
- **Task Type**: MULTICLASS
- **Evaluation Split**: TEST
- **Total Samples**: 741
- **Features Count**: 77

## 2. Supervised Performance Metrics
- **Overall Accuracy**: 0.9933
- **Attack Classification Accuracy (Outliers Only)**: 0.9792
- **Macro Precision**: 0.7669
- **Macro Recall**: 0.8163
- **Macro F1-Score**: 0.7840
- **Weighted Precision**: 0.9913
- **Weighted Recall**: 0.9933
- **Weighted F1-Score**: 0.9921

### Per-Class Performance Table:

| Class Name | Precision | Recall | F1-Score | Support |
| --- | --- | --- | --- | --- |
| **BENIGN** | 0.9966 | 0.9966 | 0.9966 | 597 |
| **Bot** | 1.0000 | 1.0000 | 1.0000 | 1 |
| **DDoS** | 1.0000 | 1.0000 | 1.0000 | 55 |
| **DoS GoldenEye** | 0.0000 | 0.0000 | 0.0000 | 1 |
| **DoS Hulk** | 0.9565 | 1.0000 | 0.9778 | 22 |
| **DoS Slowhttptest** | 1.0000 | 1.0000 | 1.0000 | 1 |
| **FTP-Patator** | 1.0000 | 1.0000 | 1.0000 | 2 |
| **PortScan** | 0.9828 | 0.9828 | 0.9828 | 58 |
| **SSH-Patator** | 1.0000 | 1.0000 | 1.0000 | 2 |
| **Web Attack � Brute Force** | 0.5000 | 1.0000 | 0.6667 | 1 |
| **Web Attack � XSS** | 0.0000 | 0.0000 | 0.0000 | 1 |

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
