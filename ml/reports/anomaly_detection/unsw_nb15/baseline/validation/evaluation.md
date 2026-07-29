# Anomaly Detection Evaluation - UNSW_NB15 (VALIDATION)

Generated on: 2026-08-16T23:33:22.023230
Preprocessing Pipeline Version: 1.0

> [!WARNING]
> The current results are based on the Phase 1 development samples of approximately 5,000 rows and are not final full-dataset or production performance.

## 1. Split Overview
- **Dataset**: UNSW_NB15
- **Evaluation Split**: VALIDATION
- **Total Samples**: 748
- **Normal Samples**: 649
- **Attack Samples**: 99
- **Features Used**: 79

## 2. Security Performance Metrics
- **Accuracy**: 0.9398
- **Precision**: 0.6901
- **Recall (Detection Rate / TPR)**: 0.9899
- **F1-Score**: 0.8133
- **False Positive Rate (FPR)**: 0.0678
- **True Negative Rate (Specificity)**: 0.9322
- **False Negative Rate (FNR)**: 0.0101

### Confusion Matrix:

| | Predicted Normal | Predicted Anomaly |
| --- | --- | --- |
| **Actual Normal** | **TN**: 605 | **FP**: 44 |
| **Actual Attack** | **FN**: 1 | **TP**: 98 |

*Semantic Definitions*:
- **TP (True Positive)**: Attack flow correctly identified as Anomaly.
- **TN (True Negative)**: Normal flow correctly identified as Normal.
- **FP (False Positive)**: Normal flow incorrectly identified as Anomaly (triggers false alert).
- **FN (False Negative)**: Attack flow incorrectly identified as Normal (escapes detection).

## 3. Anomaly Score Numerical Statistics
Isolation Forest decision function values (raw scores) are smaller for anomalies and larger/positive for normal traffic.

| Statistic | Normal Traffic Scores | Attack Traffic Scores |
| --- | --- | --- |
| **Count** | 649 | 99 |
| **Minimum** | -0.107172 | -0.141990 |
| **Maximum** | 0.152590 | 0.005274 |
| **Mean** | 0.086819 | -0.045393 |
| **Median** | 0.104322 | -0.035225 |
| **Std Dev** | 0.051061 | 0.026522 |

## 4. Visualizations
- **Confusion Matrix**: [confusion_matrix.png](confusion_matrix.png)
- **Anomaly Score Distributions**: [anomaly_score_distribution.png](anomaly_score_distribution.png)
