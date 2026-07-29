# Data Quality & Preprocessing Report - CICIDS2017

Generated on: 2026-08-16T23:24:04.238176

## 1. Dataset Overview
- **Number of Raw Files**: 8
- **Total Raw Rows (Estimated)**: 2,830,743
- **Total Raw Columns**: 79
- **Processed Rows**: 4,939
- **Processed Features (after encoding)**: 77

## 2. Data Quality Details
- **Duplicate Rows Removed**: 61
- **Inconsistencies Found**: 0
- **NaNs Imputed**: {"Flow Bytes/s": 4, "Flow Packets/s": 4}

## 3. Label & Class Distributions
- **Target Column**: `Label`
- **Normal Records Count**: 3,978
- **Attack Records Count**: 961
- **Attack Percentage**: 19.46%
- **Number of Attack Classes**: 11

### Samples Per Multi-Class Category:
- **BENIGN**: 3,978 samples
- **PortScan**: 365 samples
- **DDoS**: 358 samples
- **DoS Hulk**: 182 samples
- **DoS GoldenEye**: 13 samples
- **FTP-Patator**: 12 samples
- **Bot**: 8 samples
- **Web Attack � Brute Force**: 7 samples
- **SSH-Patator**: 6 samples
- **DoS Slowhttptest**: 4 samples
- **Web Attack � XSS**: 3 samples
- **DoS slowloris**: 3 samples

## 4. Feature Selection & Leakage Prevention
Below is the list of excluded fields along with the target leakage and temporal generalization reasons:

| Field Name | Role | Reason | Leakage Risk? |
| --- | --- | --- | --- |
| `Fwd Header Length.1` | Excluded Feature | Duplicate column of Fwd Header Length. | No |
| `Label` | Target | Target label column | Yes |

## 5. Splits & Stratification
- **Train Set Count**: 3,457
- **Validation Set Count**: 741
- **Test Set Count**: 741
- **Split Ratio**: 70% Train / 15% Validation / 15% Test
- **Anomaly Detection Training Set Count (Benign Only)**: 2,784

> [!NOTE]
> This is a baseline stratified evaluation split. It establishes the initial model assessment criteria. Future work may incorporate group-aware or temporal splits to validate generalization to different network environments.
