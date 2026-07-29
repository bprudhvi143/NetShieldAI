# Milestone 2: ML Preprocessing & Feature Engineering Foundation

This document details the design, data-quality findings, and implementation of the data preprocessing, target validation, feature engineering, and splitting pipelines developed in Phase 1 of Milestone 2.

---

## 1. Objective
Establish a clean, reproducible, leakage-resistant, and mathematically sound preprocessing pipeline for the **CICIDS2017** and **UNSW-NB15** datasets. This lays the groundwork for training anomaly detection (Isolation Forest) and supervised threat classification (XGBoost) models in subsequent phases.

---

## 2. Dataset Inspection & Quality Findings

We performed a complete, non-assumptive inspection of the raw datasets:

### CICIDS2017 Data Findings
- **Raw Files**: 8 CSV files (Friday DDoS, Friday PortScan, Friday Morning, Monday, Thursday Afternoon, Thursday Morning, Tuesday, Wednesday).
- **Total Records**: 2,830,743 rows.
- **Features**: 79 columns.
- **Labels**: `' Label'` column (with leading whitespace, containing values like `BENIGN`, `DDoS`, `PortScan`, etc.).
- **Missing Values**: 1,358 missing values inside the `Flow Bytes/s` column.
- **Infinite Values**:
  - `Flow Bytes/s`: 1,509 infinite values.
  - `Flow Packets/s`: 2,867 infinite values.
- **Duplicate Columns**: `Fwd Header Length.1` was verified to be 100% identical to `Fwd Header Length` and was dropped to ensure feature consistency.

### UNSW-NB15 Data Findings
- **Raw Files**: 4 headerless CSV files (`UNSW-NB15_[1-4].csv`) + feature definition file (`NUSW-NB15_features.csv`).
- **Total Records**: 2,540,047 rows.
- **Features**: 49 columns.
- **Binary Label**: `Label` (0 for normal, 1 for attack).
- **Multi-Class Label**: `attack_cat` (containing categories like `Generic`, `Exploits`, `Fuzzers`, etc.).
- **Missing Values**:
  - `attack_cat`: 2,218,764 missing values (corresponds exactly to `Label == 0` rows).
  - `is_ftp_login`: 1,429,879 missing values.
  - `ct_flw_http_mthd`: 1,348,145 missing values.
- **Port Column Anomalies**: Both `sport` and `dsport` contain non-numeric placeholders like `-`, and hex string values (e.g. `0x000b`, `0xc0a8`, etc.).

---

## 3. Preprocessing & Imputation Decisions

### Missing and Infinite Values
- **Infs to NaNs**: All infinite values in `Flow Bytes/s` and `Flow Packets/s` are converted to `NaN`.
- **Train-Set Median Imputation**: To prevent data leakage, missing values in numerical columns are imputed using the median computed **only** on the training split, which is then applied statically to validation and test splits.
- **FTP and HTTP Columns (UNSW-NB15)**: A semantic check revealed that missing values in `is_ftp_login` and `ct_flw_http_mthd` represent "not applicable" (i.e. not an FTP/HTTP connection). Therefore, they are imputed as `0.0` rather than the training set median, reflecting the true data semantics.

### UNSW-NB15 `attack_cat` Target Validation
- If `attack_cat` is missing and `Label == 0`, it is mapped to `'Normal'`.
- If `attack_cat` is missing and `Label != 0`, it is flagged as a data-quality inconsistency and mapped to `'Unknown_Inconsistent'` to prevent silent data corruption.

### UNSW-NB15 Port Parsing
- Ports are cleaned deterministically: hex strings are parsed in base-16 (e.g., `'0x000b'` -> 11.0), and invalid placeholders (like `'-'`) are mapped to `NaN` (subsequently imputed with the training median) rather than silently converted to 0.

---

## 4. Target Leakage Prevention & Feature Schema

### Temporal & Environment Exclusions
To ensure high real-world generalization, we exclude the following fields from model training:
- **UNSW-NB15**:
  - `srcip`, `dstip` (IP addresses): Excluded because specific IPs are artifacts of the simulation testbed, risking memorization instead of learning network behavior.
  - `Stime`, `Ltime` (timestamps): Excluded to prevent the model from overfitting to specific days or temporal segments of the simulation.
  - `Label`, `attack_cat`: Kept strictly as targets, never as inputs.

### Explicit Metadata Separation
Metadata and identifiers are kept entirely separate from the ML feature matrices. During pipeline execution, features are saved to `X_train.csv`, labels to `y_train.csv`, and metadata/identifiers to `meta_train.csv`.

---

## 5. Splitting Strategy

- **Ratios**: 70% Train / 15% Validation / 15% Test.
- **Method**: Stratified splitting based on `Label` (or `attack_cat` if performing multiclass) with `random_state=42`.
- **Class Sufficiency Validation**: Prior to splitting, classes are validated. If any class has fewer than 3 samples, splitting is aborted and raises an error to prevent silent stratification failure.
- **Anomaly Detection Splits**:
  - **Training set**: Filtered to contain **only** normal/benign records (where `Label == 0` or `'BENIGN'`).
  - **Validation and Test sets**: Retain both normal and attack traffic to enable correct anomaly detection metric evaluation.

---

## 6. Preprocessing Artifacts Layout

```
ml/
├── models/                     # Reserved for future trained models
├── artifacts/
│   ├── preprocessors/          # Joblib files for fitted StandardScalers and OneHotEncoders
│   ├── schemas/                # Feature schema definitions
│   └── metadata/               # JSON files containing pipeline version, feature counts, and labels
└── reports/                    # Data quality reports (JSON and Markdown formats)
```

---

## 7. How to Execute Preprocessing and Tests

### 1. Run Preprocessing Pipeline
To generate the preprocessed splits, preprocessor artifacts, and quality reports on the development sample:
```bash
c:\NetShieldAI\backend\venv\Scripts\python.exe -m ml.preprocessing.run_pipeline
```

### 2. Run Preprocessing Tests
To verify all pipeline logic, leakage constraints, and imputation correctness:
```bash
c:\NetShieldAI\backend\venv\Scripts\pytest -v tests/ml/test_preprocessing.py
```
