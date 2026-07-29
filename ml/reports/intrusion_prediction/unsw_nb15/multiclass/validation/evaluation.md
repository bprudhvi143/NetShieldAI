# XGBoost Intrusion Prediction - UNSW_NB15 MULTICLASS (VALIDATION)

Generated on: 2026-08-16T23:51:53.052273
Preprocessing Pipeline Version: 1.0

> [!WARNING]
> The current results are based on the Phase 1 development samples of approximately 5,000 rows and are not final full-dataset or production performance.

## 1. Split Overview
- **Dataset**: UNSW_NB15
- **Task Type**: MULTICLASS
- **Evaluation Split**: VALIDATION
- **Total Samples**: 748
- **Features Count**: 79

## 2. Supervised Performance Metrics
- **Overall Accuracy**: 0.9612
- **Attack Classification Accuracy (Outliers Only)**: 0.7778
- **Macro Precision**: 0.4788
- **Macro Recall**: 0.5064
- **Macro F1-Score**: 0.4886
- **Weighted Precision**: 0.9622
- **Weighted Recall**: 0.9612
- **Weighted F1-Score**: 0.9613

### Per-Class Performance Table:

| Class Name | Precision | Recall | F1-Score | Support |
| --- | --- | --- | --- | --- |
| **Analysis** | 0.0000 | 0.0000 | 0.0000 | 1 |
| **Backdoor** | 0.0000 | 0.0000 | 0.0000 | 1 |
| **DoS** | 0.2500 | 0.1429 | 0.1818 | 7 |
| **Exploits** | 0.2857 | 0.3636 | 0.3200 | 11 |
| **Fuzzers** | 0.4615 | 0.6000 | 0.5217 | 10 |
| **Generic** | 1.0000 | 0.9683 | 0.9839 | 63 |
| **Normal** | 0.9907 | 0.9892 | 0.9900 | 649 |
| **Reconnaissance** | 0.8000 | 1.0000 | 0.8889 | 4 |
| **Shellcode** | 1.0000 | 1.0000 | 1.0000 | 1 |
| **Worms** | 0.0000 | 0.0000 | 0.0000 | 1 |

## 3. Feature Importance Analysis
Top 10 features sorted by XGBoost `feature_importances_` metric:

| Rank | Feature Name | Importance Score |
| --- | --- | --- |
| 1 | ct_state_ttl | 0.494326 |
| 2 | dttl | 0.167202 |
| 3 | sbytes | 0.078919 |
| 4 | sttl | 0.060256 |
| 5 | service_- | 0.022942 |
| 6 | synack | 0.021163 |
| 7 | service_dns | 0.017592 |
| 8 | dsport | 0.016879 |
| 9 | dmeansz | 0.009747 |
| 10 | ackdat | 0.007218 |

> [!NOTE]
> **Causality Notice**: Feature importance represents the model's contribution/association with predictions and does NOT establish causal relationships or physical network-attack causation.

## 4. Visualizations
- **Confusion Matrix**: [confusion_matrix.png](confusion_matrix.png)
- **Feature Importance Plot**: [feature_importance.png](feature_importance.png)
