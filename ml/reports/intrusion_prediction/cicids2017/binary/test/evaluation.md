# XGBoost Intrusion Prediction - CICIDS2017 BINARY (TEST)

Generated on: 2026-08-16T23:51:50.876165
Preprocessing Pipeline Version: 1.0

> [!WARNING]
> The current results are based on the Phase 1 development samples of approximately 5,000 rows and are not final full-dataset or production performance.

## 1. Split Overview
- **Dataset**: CICIDS2017
- **Task Type**: BINARY
- **Evaluation Split**: TEST
- **Total Samples**: 741
- **Features Count**: 77

## 2. Security Performance Metrics
- **Accuracy**: 0.9946
- **Precision**: 0.9795
- **Recall (Detection Rate / TPR)**: 0.9931
- **F1-Score**: 0.9862
- **False Positive Rate (FPR)**: 0.0050
- **True Negative Rate (Specificity)**: 0.9950
- **False Negative Rate (FNR)**: 0.0069

### Confusion Matrix:

| | Predicted Normal | Predicted Attack |
| --- | --- | --- |
| **Actual Normal** | **TN**: 594 | **FP**: 3 |
| **Actual Attack** | **FN**: 1 | **TP**: 143 |

*Semantic Definitions*:
- **TP (True Positive)**: Attack flow correctly identified as Attack.
- **TN (True Negative)**: Normal flow correctly identified as Normal.
- **FP (False Positive)**: Normal flow incorrectly identified as Attack (triggers false alert).
- **FN (False Negative)**: Attack flow incorrectly identified as Normal (escapes detection).

## 3. Feature Importance Analysis
Top 10 features sorted by XGBoost `feature_importances_` metric:

| Rank | Feature Name | Importance Score |
| --- | --- | --- |
| 1 | Bwd Packet Length Std | 0.294886 |
| 2 | Max Packet Length | 0.143447 |
| 3 | Average Packet Size | 0.116334 |
| 4 | Bwd Header Length | 0.099048 |
| 5 | Bwd Packet Length Mean | 0.043032 |
| 6 | Bwd Packet Length Min | 0.036093 |
| 7 | Subflow Fwd Bytes | 0.032120 |
| 8 | Total Backward Packets | 0.026673 |
| 9 | Fwd Packet Length Mean | 0.024837 |
| 10 | Fwd Packet Length Std | 0.018592 |

> [!NOTE]
> **Causality Notice**: Feature importance represents the model's contribution/association with predictions and does NOT establish causal relationships or physical network-attack causation.

## 4. Visualizations
- **Confusion Matrix**: [confusion_matrix.png](confusion_matrix.png)
- **Feature Importance Plot**: [feature_importance.png](feature_importance.png)
