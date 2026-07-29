# Risk Scoring Calibration Report - UNSW_NB15 MULTICLASS (VALIDATION)

Generated on: 2026-08-17T20:33:49.530053
Preprocessing Pipeline Version: 1.0

> [!WARNING]
> **Diagnostic & Calibration Notice**: 
> This evaluation is currently based on the Phase 1 development samples (approximately 5,000 rows) and represents a calibration/diagnostic analysis. 
> It should NOT be interpreted as final production risk-calibration performance, and the scoring thresholds are project-defined initial configurations.

## 1. Split & Model Overview
- **Dataset**: UNSW_NB15
- **Supervised Task Type**: MULTICLASS
- **Evaluation Split**: VALIDATION
- **Total Samples**: 748

## 2. Threat Score Calibration Statistics

| Statistic | Normal Traffic | Attack Traffic |
| --- | --- | --- |
| **Count** | 649 | 99 |
| **Minimum** | 0.12 | 14.38 |
| **Maximum** | 85.83 | 89.71 |
| **Mean** | 5.09 | 70.24 |
| **Median** | 3.24 | 71.09 |

### Separation Analysis:
- **Mean Score Separation**: 65.15
- **Median Score Separation**: 67.85

---

## 3. Risk Level Distribution

Project-defined thresholds are:
* **Low**: `0 - 29`
* **Medium**: `30 - 59`
* **High**: `60 - 84`
* **Critical**: `85 - 100`

### Distribution Table:

| Risk Level | Normal Traffic Count (%) | Attack Traffic Count (%) |
| --- | --- | --- |
| **Low** | 641 (98.8%) | 4 (4.0%) |
| **Medium** | 1 (0.2%) | 4 (4.0%) |
| **High** | 6 (0.9%) | 88 (88.9%) |
| **Critical** | 1 (0.2%) | 3 (3.0%) |

### Security Coverage Metrics:
* **Attack High/Critical Coverage Rate**: 91.92% (Percentage of true attacks classified as High/Critical Risk)
* **Normal High/Critical False Alarm Rate**: 1.08% (Percentage of true normal traffic incorrectly classified as High/Critical Risk)

---

## 4. Visualizations
- **Threat Score Distribution Plot**: [threat_score_distribution.png](threat_score_distribution.png)
