# Milestone 2 Phase 3 - XGBoost Intrusion Prediction & Attack Classification

This document provides a comprehensive overview of the design, training strategy, performance metrics, feature importances, and limitations of the supervised machine learning subsystem using XGBoost.

---

## 1. Objective
The goal of this phase is to train and evaluate independent **XGBoost** models to perform supervised intrusion detection and threat classification. The subsystem answers two distinct questions:
- **Binary Intrusion Prediction**: *"Is this network flow normal or an attack?"* (Outputs: `Normal` or `Attack`)
- **Multiclass Attack Classification**: *"What type of attack is this?"* (Outputs: `Normal`/`BENIGN` or a specific attack category name)

---

## 2. Why XGBoost Was Selected
XGBoost (Extreme Gradient Boosting) is a highly efficient implementation of gradient boosted decision trees. It is widely considered state-of-the-art for tabular classification tasks because:
1. **Regularization**: Incorporates L1 and L2 regularization to prevent overfitting and improve generalization on sparse network data.
2. **Handling Missing Values**: Learns default split directions for missing values (`NaN`s) automatically during training.
3. **Execution Speed & Scalability**: Optimized for multi-threaded CPU/GPU parallel execution, supporting rapid training and real-time inference.
4. **Non-linear Relationships**: Captures complex non-linear combinations of network metrics (e.g. flow packets, segment sizes, timing durations) without requiring manual feature interaction engineering.

---

## 3. Dataset-Specific Model Strategy
Because the feature sets are dataset-specific, we train four distinct models:
- **CICIDS2017 models**:
  - Binary classifier (77 features)
  - Multiclass classifier (77 features)
- **UNSW-NB15 models**:
  - Binary classifier (79 features)
  - Multiclass classifier (79 features)

---

## 4. Target Definitions & Label Encoding

### Binary Classification
- Target column: `Label_binary` (CICIDS2017) or `Label` (UNSW-NB15).
- Semantic Mapping:
  - `0` $\rightarrow$ `Normal`
  - `1` $\rightarrow$ `Attack`

### Multiclass Classification
- Target column: `Label_multiclass` (CICIDS2017) or `attack_cat` (UNSW-NB15).
- Semantic mapping: `Normal` or `BENIGN` is mapped deterministically to class index `0`. The remaining attack categories are mapped deterministically to indices `1` to `C-1` sorted alphabetically.
- Mappings are persisted within the model metadata to reconstruct class names at prediction time.

---

## 5. Hyperparameter Configuration
The default model hyperparameters are configured deterministically:
```python
DEFAULT_XGB_PARAMS = {
    "n_estimators": 100,
    "max_depth": 6,
    "learning_rate": 0.3,
    "subsample": 0.8,
    "colsample_bytree": 0.8,
    "random_state": 42,
    "n_jobs": -1
}
```
- For Binary: `objective="binary:logistic"`, `eval_metric="logloss"`.
- For Multiclass: `objective="multi:softprob"`, `eval_metric="mlogloss"`.

---

## 6. Supervised Performance Metrics (Development Samples)

> [!WARNING]
> The current results are based on the Phase 1 development samples of approximately 5,000 rows and are not final full-dataset or production performance.

### Binary Classification Results

#### CICIDS2017 Binary (77 Features)
- **Validation**: Accuracy: 0.9906 | Precision: 0.9856 | Recall (TPR): 0.9648 | F1: 0.9751 | FPR: 0.0034
- **Test**: Accuracy: 0.9892 | Precision: 0.9786 | Recall (TPR): 0.9653 | F1: 0.9719 | FPR: 0.0050
- **Test Confusion Matrix**: TN: 594, FP: 3, FN: 5, TP: 139

#### UNSW-NB15 Binary (79 Features)
- **Validation**: Accuracy: 0.9799 | Precision: 0.9167 | Recall (TPR): 0.9263 | F1: 0.9215 | FPR: 0.0123
- **Test**: Accuracy: 0.9880 | Precision: 0.9327 | Recall (TPR): 0.9798 | F1: 0.9557 | FPR: 0.0108
- **Test Confusion Matrix**: TN: 642, FP: 7, FN: 2, TP: 97

---

### Multiclass Classification Results

#### CICIDS2017 Multiclass (77 Features)
- **Overall Accuracy**: 0.9933 (Test) | 0.9906 (Val)
- **Attack Classification Accuracy (Actual Attacks Only)**: **0.9792 (Test)** | 0.9514 (Val)
- **Macro F1-Score**: 0.7840
- **Weighted F1-Score**: 0.9921
- **Test Per-Class Detail**:
  - `BENIGN`: F1 = 0.9966, Support = 597
  - `DDoS`: F1 = 1.0000, Support = 55
  - `PortScan`: F1 = 0.9828, Support = 58
  - `DoS Hulk`: F1 = 0.9778, Support = 22
  - `FTP-Patator`: F1 = 1.0000, Support = 2
  - `SSH-Patator`: F1 = 1.0000, Support = 2
  - `Bot`: F1 = 1.0000, Support = 1
  - `DoS Slowhttptest`: F1 = 1.0000, Support = 1
  - `Web Attack - Brute Force`: F1 = 0.6667, Support = 1
  - `DoS GoldenEye`: F1 = 0.0000, Support = 1
  - `Web Attack - XSS`: F1 = 0.0000, Support = 1

#### UNSW-NB15 Multiclass (79 Features)
- **Overall Accuracy**: 0.9813 (Test) | 0.9759 (Val)
- **Attack Classification Accuracy (Actual Attacks Only)**: **0.8990 (Test)** | 0.8211 (Val)
- **Macro F1-Score**: 0.6724
- **Weighted F1-Score**: 0.9820
- **Test Per-Class Detail**:
  - `Normal`: F1 = 0.9954, Support = 649
  - `Generic`: F1 = 0.9851, Support = 68
  - `Exploits`: F1 = 0.8148, Support = 13
  - `DoS`: F1 = 0.7143, Support = 7
  - `Reconnaissance`: F1 = 0.8333, Support = 5
  - `Fuzzers`: F1 = 0.3636, Support = 5
  - `Analysis`: F1 = 0.0000, Support = 1

---

## 7. Feature Importance Analysis
Top features ranked by model `feature_importances_` metric:
- **CICIDS2017 Multiclass**:
  1. `Idle Mean` (0.149391)
  2. `Avg Bwd Segment Size` (0.081772)
  3. `Subflow Fwd Bytes` (0.072127)
- **UNSW-NB15 Multiclass**:
  1. `ct_state_ttl` (0.494326)
  2. `dttl` (0.167202)
  3. `sbytes` (0.078919)

> [!NOTE]
> **Causality Notice**: Feature importance represents the model's contribution/association with predictions and does NOT establish causal relationships or physical network-attack causation.

---

## 8. Artifact Locations
- **Model Binaries**:
  - `ml/models/intrusion_prediction/cicids2017/binary/xgboost_binary.joblib`
  - `ml/models/intrusion_prediction/cicids2017/multiclass/xgboost_multiclass.joblib`
  - `ml/models/intrusion_prediction/unsw_nb15/binary/xgboost_binary.joblib`
  - `ml/models/intrusion_prediction/unsw_nb15/multiclass/xgboost_multiclass.joblib`
- **Model Metadata**:
  - `ml/models/intrusion_prediction/cicids2017/binary/xgboost_binary_metadata.json`
  - `ml/models/intrusion_prediction/cicids2017/multiclass/xgboost_multiclass_metadata.json`
  - `ml/models/intrusion_prediction/unsw_nb15/binary/xgboost_binary_metadata.json`
  - `ml/models/intrusion_prediction/unsw_nb15/multiclass/xgboost_multiclass_metadata.json`
- **Reports**:
  - [`ml/reports/intrusion_prediction/`](file:///c:/NetShieldAI/ml/reports/intrusion_prediction/)

---

## 9. Next Phase
**Next Phase: Milestone 2 Phase 4 - Risk Scoring System.**
We will implement risk scoring equations to calculate dynamic security risk based on anomaly scores and threat classes.
