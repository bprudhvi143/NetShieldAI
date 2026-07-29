# XGBoost Intrusion Prediction - UNSW_NB15 BINARY (VALIDATION)

Generated on: 2026-08-16T23:51:52.298605
Preprocessing Pipeline Version: 1.0

> [!WARNING]
> The current results are based on the Phase 1 development samples of approximately 5,000 rows and are not final full-dataset or production performance.

## 1. Split Overview
- **Dataset**: UNSW_NB15
- **Task Type**: BINARY
- **Evaluation Split**: VALIDATION
- **Total Samples**: 748
- **Features Count**: 79

## 2. Security Performance Metrics
- **Accuracy**: 0.9826
- **Precision**: 0.9135
- **Recall (Detection Rate / TPR)**: 0.9596
- **F1-Score**: 0.9360
- **False Positive Rate (FPR)**: 0.0139
- **True Negative Rate (Specificity)**: 0.9861
- **False Negative Rate (FNR)**: 0.0404

### Confusion Matrix:

| | Predicted Normal | Predicted Attack |
| --- | --- | --- |
| **Actual Normal** | **TN**: 640 | **FP**: 9 |
| **Actual Attack** | **FN**: 4 | **TP**: 95 |

*Semantic Definitions*:
- **TP (True Positive)**: Attack flow correctly identified as Attack.
- **TN (True Negative)**: Normal flow correctly identified as Normal.
- **FP (False Positive)**: Normal flow incorrectly identified as Attack (triggers false alert).
- **FN (False Negative)**: Attack flow incorrectly identified as Normal (escapes detection).

## 3. Feature Importance Analysis
Top 10 features sorted by XGBoost `feature_importances_` metric:

| Rank | Feature Name | Importance Score |
| --- | --- | --- |
| 1 | ct_state_ttl | 0.791598 |
| 2 | sttl | 0.120883 |
| 3 | sbytes | 0.010800 |
| 4 | dsport | 0.007014 |
| 5 | ackdat | 0.006562 |
| 6 | dmeansz | 0.005210 |
| 7 | synack | 0.004212 |
| 8 | Dpkts | 0.004073 |
| 9 | tcprtt | 0.003326 |
| 10 | res_bdy_len | 0.003314 |

> [!NOTE]
> **Causality Notice**: Feature importance represents the model's contribution/association with predictions and does NOT establish causal relationships or physical network-attack causation.

## 4. Visualizations
- **Confusion Matrix**: [confusion_matrix.png](confusion_matrix.png)
- **Feature Importance Plot**: [feature_importance.png](feature_importance.png)
