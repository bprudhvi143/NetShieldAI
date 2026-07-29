# Milestone 2 Phase 2 - Isolation Forest Anomaly Detection

This document provides a comprehensive overview of the design, training strategy, performance metrics, and limitations of the unsupervised anomaly detection subsystem using Isolation Forest.

---

## 1. Objective
The goal of this phase is to train and evaluate independent **Isolation Forest** models to detect anomalous network traffic. The model addresses the question: *"Does this network flow behave differently from the normal/benign traffic observed during training?"* 

---

## 2. Why Isolation Forest Was Selected
Isolation Forest is a tree-based, unsupervised/semi-supervised learning algorithm specifically designed for anomaly detection. Unlike standard density-based estimators (like Local Outlier Factor or One-Class SVM) which attempt to model the normal instances and identify outliers by low density, Isolation Forest:
1. Explicitly isolates anomalies rather than profiling normal data points.
2. Isolates anomalies by randomly partitioning features. Anomalies require fewer partitions (i.e. shorter paths in the trees) to isolate.
3. Scales extremely well to large network datasets (low computational complexity: $O(n \log n)$).

---

## 3. Dataset-Specific Model Strategy
Because the feature spaces of **CICIDS2017** and **UNSW-NB15** are fundamentally different in terms of packet header fields, timing metrics, and categorical mappings, we train independent models:
- **Model A**: Trained and evaluated exclusively on the preprocessed CICIDS2017 features.
- **Model B**: Trained and evaluated exclusively on the preprocessed UNSW-NB15 features.

The feature matrices are kept strictly separate.

---

## 4. Training Data Strategy
To ensure the model learns a boundary representing purely normal traffic, **fitting is performed exclusively on benign traffic** (labels representing `BENIGN` or `Normal`).
- **Programmatic Guard**: Before fitting, the indices of the anomaly training split are cross-referenced with target binary labels (`y_train_binary.csv`). If any attack flows are found, training fails loudly.
- Attack traffic is strictly reserved for the validation and test splits for evaluation purposes.

---

## 5. Feature Source & Preprocessing Reuse
- **Feature Names**: Loaded directly from Phase 1 metadata JSON files under `final_anomaly_features`.
- **Preprocessors**: Saved in Phase 1 (ColumnTransformers containing StandardScalers and OneHotEncoders) are loaded and applied to validation/test sets consistently. No fitting is performed on validation or test sets.

---

## 6. Hyperparameter Configuration
The default model hyperparameters are configured deterministically:
- `n_estimators = 100`
- `contamination = "auto"` *(no assumptions are made about dataset attack percentage; contamination is not tuned using test labels)*
- `max_samples = "auto"`
- `random_state = 42`
- `n_jobs = -1`

---

## 7. Prediction Semantics & Score Interpretation

### Prediction Mapping:
- Scikit-Learn `predict()` returns `1` for inliers (normal) and `-1` for outliers (anomalous).
- **Application Semantic Mapping**:
  - Native `1` $\rightarrow$ Normal (`0`)
  - Native `-1` $\rightarrow$ Anomaly (`1`)

### Score Mapping:
- `decision_function()` values are preserved exactly as `raw_anomaly_score` (negative means anomalous, positive means normal).
- A relative 0-1 normalized score is defined based on the training scores range:
  $$\text{normalized\_score} = \text{clip}\left(\frac{\text{train\_score\_max} - \text{raw\_score}}{\text{train\_score\_max} - \text{train\_score\_min}}, 0.0, 1.0\right)$$
  - **Important**: This normalized score represents a relative anomaly distance and is **NOT** a probability.

---

## 8. Evaluation Metrics Semantics
- **TP**: Attack predicted as Anomaly
- **TN**: Normal predicted as Normal
- **FP**: Normal predicted as Anomaly *(triggers false alarm)*
- **FN**: Attack predicted as Normal *(escapes detection)*
- **FPR (False Positive Rate)**: $FP / (FP + TN)$
- **Detection Rate (TPR / Recall)**: $TP / (TP + FN)$
- **Specificity (TNR)**: $TN / (TN + FP)$
- **FNR (False Negative Rate)**: $FN / (FN + TP)$

---

## 9. Model Results (Development Samples)

> [!WARNING]
> The current results are based on the Phase 1 development samples of approximately 5,000 rows and are not final full-dataset or production performance.

### CICIDS2017 Performance (77 Features)

| Metric | Validation Set | Test Set |
| --- | --- | --- |
| **Total Samples** | 741 | 741 |
| **Normal / Attack** | 597 / 144 | 597 / 144 |
| **Accuracy** | 0.8192 | 0.7854 |
| **Precision** | 0.5517 | 0.4227 |
| **Recall / Detection Rate** | 0.3333 | 0.2847 |
| **F1-Score** | 0.4156 | 0.3402 |
| **False Positive Rate (FPR)** | 0.0637 | 0.0938 |
| **True Negative Rate (Specificity)** | 0.9363 | 0.9062 |
| **Confusion Matrix** | TN: 559, FP: 38, FN: 96, TP: 48 | TN: 541, FP: 56, FN: 103, TP: 41 |

### UNSW-NB15 Performance (79 Features)

| Metric | Validation Set | Test Set |
| --- | --- | --- |
| **Total Samples** | 748 | 748 |
| **Normal / Attack** | 649 / 99 | 649 / 99 |
| **Accuracy** | 0.9291 | 0.9345 |
| **Precision** | 0.6556 | 0.6689 |
| **Recall / Detection Rate** | 1.0000 | 1.0000 |
| **F1-Score** | 0.7920 | 0.8016 |
| **False Positive Rate (FPR)** | 0.0801 | 0.0755 |
| **True Negative Rate (Specificity)** | 0.9199 | 0.9245 |
| **Confusion Matrix** | TN: 597, FP: 52, FN: 0, TP: 99 | TN: 600, FP: 49, FN: 0, TP: 99 |

---

## 10. Interpretation of Results
- **UNSW-NB15 Model**: Demonstrates exceptional detection rate (100.0% recall) on the development sample. It successfully flags all attack instances as outliers, while maintaining a reasonable False Positive Rate of ~7.5%.
- **CICIDS2017 Model**: Shows lower detection rates (~28.5%). This is common for unsupervised models on CICIDS2017 because several attack vectors (like Brute Force or Infiltration) exhibit patterns highly similar to normal traffic on a packet-by-packet level. This highlights the importance of the upcoming **XGBoost supervised training phase** for detecting specific attack signatures.

---

## 11. Artifact Locations
- **Saved Models**:
  - `ml/models/cicids2017/isolation_forest.joblib`
  - `ml/models/unsw_nb15/isolation_forest.joblib`
- **Model Metadata**:
  - `ml/artifacts/metadata/cicids2017_anomaly_model_metadata.json`
  - `ml/artifacts/metadata/unsw_nb15_anomaly_model_metadata.json`
- **Visual & Written Reports**:
  - [`ml/reports/anomaly_detection/cicids2017/validation/`](file:///c:/NetShieldAI/ml/reports/anomaly_detection/cicids2017/validation/)
  - [`ml/reports/anomaly_detection/cicids2017/test/`](file:///c:/NetShieldAI/ml/reports/anomaly_detection/cicids2017/test/)
  - [`ml/reports/anomaly_detection/unsw_nb15/validation/`](file:///c:/NetShieldAI/ml/reports/anomaly_detection/unsw_nb15/validation/)
  - [`ml/reports/anomaly_detection/unsw_nb15/test/`](file:///c:/NetShieldAI/ml/reports/anomaly_detection/unsw_nb15/test/)

---

## 12. Next Phase
**Next Phase: Supervised Intrusion Prediction and Attack Classification using XGBoost.**
This phase will leverage labels to train multi-class classifiers to identify the specific attack categories that unsupervised models struggle to categorize.
