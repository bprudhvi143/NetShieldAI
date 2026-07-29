# Data Quality & Preprocessing Report - UNSW_NB15

Generated on: 2026-08-16T23:24:15.799679

## 1. Dataset Overview
- **Number of Raw Files**: 4
- **Total Raw Rows (Estimated)**: 2,540,047
- **Total Raw Columns**: 49
- **Processed Rows**: 4,985
- **Processed Features (after encoding)**: 79

## 2. Data Quality Details
- **Duplicate Rows Removed**: 15
- **Inconsistencies Found**: 0
- **NaNs Imputed**: {}

## 3. Label & Class Distributions
- **Target Column**: `Label / attack_cat`
- **Normal Records Count**: 4,324
- **Attack Records Count**: 661
- **Attack Percentage**: 13.26%
- **Number of Attack Classes**: 10

### Samples Per Multi-Class Category:
- **Normal**: 4,324 samples
- **Generic**: 444 samples
- **Exploits**: 87 samples
- **Fuzzers**: 52 samples
- **Reconnaissance**: 30 samples
- **DoS**: 29 samples
- **Analysis**: 8 samples
- **Shellcode**: 5 samples
- **Backdoor**: 3 samples
- **Worms**: 2 samples
- **Backdoors**: 1 samples

## 4. Feature Selection & Leakage Prevention
Below is the list of excluded fields along with the target leakage and temporal generalization reasons:

| Field Name | Role | Reason | Leakage Risk? |
| --- | --- | --- | --- |
| `srcip` | Metadata | Excluded from baseline features due to potential dataset-specific target leakage, memorization risk, or poor generalization to unseen network environments. | Yes |
| `dstip` | Metadata | Excluded from baseline features due to potential dataset-specific target leakage, memorization risk, or poor generalization to unseen network environments. | Yes |
| `Stime` | Metadata | Excluded from baseline features due to potential dataset-specific target leakage, memorization risk, or poor generalization to unseen network environments. | Yes |
| `Ltime` | Metadata | Excluded from baseline features due to potential dataset-specific target leakage, memorization risk, or poor generalization to unseen network environments. | Yes |
| `attack_cat` | Target | Supervised multiclass target column. | Yes |
| `Label` | Target | Supervised binary target column. | Yes |

## 5. Splits & Stratification
- **Train Set Count**: 3,489
- **Validation Set Count**: 748
- **Test Set Count**: 748
- **Split Ratio**: 70% Train / 15% Validation / 15% Test
- **Anomaly Detection Training Set Count (Benign Only)**: 3,026

> [!NOTE]
> This is a baseline stratified evaluation split. It establishes the initial model assessment criteria. Future work may incorporate group-aware or temporal splits to validate generalization to different network environments.
