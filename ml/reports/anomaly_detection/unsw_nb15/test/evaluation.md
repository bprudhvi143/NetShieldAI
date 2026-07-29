# Anomaly Detection Evaluation - UNSW_NB15 (TEST)

Generated on: 2026-08-16T23:33:22.296015
Preprocessing Pipeline Version: 1.0

> [!WARNING]
> The current results are based on the Phase 1 development samples of approximately 5,000 rows and are not final full-dataset or production performance.

## 1. Split Overview
- **Dataset**: UNSW_NB15
- **Evaluation Split**: TEST
- **Total Samples**: 748
- **Normal Samples**: 649
- **Attack Samples**: 99
- **Features Used**: 79

## 2. Security Performance Metrics
- **Accuracy**: 0.9345
- **Precision**: 0.6689
- **Recall (Detection Rate / TPR)**: 1.0000
- **F1-Score**: 0.8016
- **False Positive Rate (FPR)**: 0.0755
- **True Negative Rate (Specificity)**: 0.9245
- **False Negative Rate (FNR)**: 0.0000

### Confusion Matrix:

| | Predicted Normal | Predicted Anomaly |
| --- | --- | --- |
| **Actual Normal** | **TN**: 600 | **FP**: 49 |
| **Actual Attack** | **FN**: 0 | **TP**: 99 |

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
| **Minimum** | -0.120848 | -0.150246 |
| **Maximum** | 0.152532 | -0.014002 |
| **Mean** | 0.082374 | -0.045676 |
| **Median** | 0.097198 | -0.037062 |
| **Std Dev** | 0.053923 | 0.025669 |

## 4. Visualizations
- **Confusion Matrix**: [confusion_matrix.png](confusion_matrix.png)
- **Anomaly Score Distributions**: [anomaly_score_distribution.png](anomaly_score_distribution.png)
