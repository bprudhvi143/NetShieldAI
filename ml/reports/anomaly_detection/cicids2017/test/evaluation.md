# Anomaly Detection Evaluation - CICIDS2017 (TEST)

Generated on: 2026-08-16T23:33:21.768376
Preprocessing Pipeline Version: 1.0

> [!WARNING]
> The current results are based on the Phase 1 development samples of approximately 5,000 rows and are not final full-dataset or production performance.

## 1. Split Overview
- **Dataset**: CICIDS2017
- **Evaluation Split**: TEST
- **Total Samples**: 741
- **Normal Samples**: 597
- **Attack Samples**: 144
- **Features Used**: 77

## 2. Security Performance Metrics
- **Accuracy**: 0.7854
- **Precision**: 0.4227
- **Recall (Detection Rate / TPR)**: 0.2847
- **F1-Score**: 0.3402
- **False Positive Rate (FPR)**: 0.0938
- **True Negative Rate (Specificity)**: 0.9062
- **False Negative Rate (FNR)**: 0.7153

### Confusion Matrix:

| | Predicted Normal | Predicted Anomaly |
| --- | --- | --- |
| **Actual Normal** | **TN**: 541 | **FP**: 56 |
| **Actual Attack** | **FN**: 103 | **TP**: 41 |

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
| **Minimum** | -0.230707 | -0.173161 |
| **Maximum** | 0.185777 | 0.172783 |
| **Mean** | 0.125896 | 0.080991 |
| **Median** | 0.158290 | 0.141149 |
| **Std Dev** | 0.079346 | 0.109824 |

## 4. Visualizations
- **Confusion Matrix**: [confusion_matrix.png](confusion_matrix.png)
- **Anomaly Score Distributions**: [anomaly_score_distribution.png](anomaly_score_distribution.png)
