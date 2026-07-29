# Anomaly Detection Evaluation - CICIDS2017 (VALIDATION)

Generated on: 2026-08-16T23:33:21.388935
Preprocessing Pipeline Version: 1.0

> [!WARNING]
> The current results are based on the Phase 1 development samples of approximately 5,000 rows and are not final full-dataset or production performance.

## 1. Split Overview
- **Dataset**: CICIDS2017
- **Evaluation Split**: VALIDATION
- **Total Samples**: 741
- **Normal Samples**: 597
- **Attack Samples**: 144
- **Features Used**: 77

## 2. Security Performance Metrics
- **Accuracy**: 0.8043
- **Precision**: 0.4958
- **Recall (Detection Rate / TPR)**: 0.4097
- **F1-Score**: 0.4487
- **False Positive Rate (FPR)**: 0.1005
- **True Negative Rate (Specificity)**: 0.8995
- **False Negative Rate (FNR)**: 0.5903

### Confusion Matrix:

| | Predicted Normal | Predicted Anomaly |
| --- | --- | --- |
| **Actual Normal** | **TN**: 537 | **FP**: 60 |
| **Actual Attack** | **FN**: 85 | **TP**: 59 |

*Semantic Definitions*:
- **TP (True Positive)**: Attack flow correctly identified as Anomaly.
- **TN (True Negative)**: Normal flow correctly identified as Normal.
- **FP (False Positive)**: Normal flow incorrectly identified as Anomaly (triggers false alert).
- **FN (False Negative)**: Attack flow incorrectly identified as Normal (escapes detection).

## 3. Anomaly Score Numerical Statistics
Isolation Forest decision function values (raw scores) are smaller for anomalies and larger/positive for normal traffic.

| Statistic | Normal Traffic Scores | Attack Traffic Scores |
| --- | --- | --- |
| **Count** | 597 | 144 |
| **Minimum** | -0.233679 | -0.172058 |
| **Maximum** | 0.184812 | 0.172783 |
| **Mean** | 0.121790 | 0.052341 |
| **Median** | 0.158048 | 0.119549 |
| **Std Dev** | 0.079763 | 0.120197 |

## 4. Visualizations
- **Confusion Matrix**: [confusion_matrix.png](confusion_matrix.png)
- **Anomaly Score Distributions**: [anomaly_score_distribution.png](anomaly_score_distribution.png)
