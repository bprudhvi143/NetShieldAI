# Risk Scoring Calibration Report - UNSW_NB15 MULTICLASS (TEST)

Generated on: 2026-08-17T20:33:52.000276
Preprocessing Pipeline Version: 1.0

> [!WARNING]
> **Diagnostic & Calibration Notice**: 
> This evaluation is currently based on the Phase 1 development samples (approximately 5,000 rows) and represents a calibration/diagnostic analysis. 
> It should NOT be interpreted as final production risk-calibration performance, and the scoring thresholds are project-defined initial configurations.

## 1. Split & Model Overview
- **Dataset**: UNSW_NB15
- **Supervised Task Type**: MULTICLASS
- **Evaluation Split**: TEST
- **Total Samples**: 748

## 2. Threat Score Calibration Statistics

| Statistic | Normal Traffic | Attack Traffic |
| --- | --- | --- |
| **Count** | 649 | 99 |
| **Minimum** | 0.13 | 20.16 |
| **Maximum** | 74.23 | 87.85 |
| **Mean** | 5.06 | 72.94 |
| **Median** | 3.70 | 71.72 |

### Separation Analysis:
- **Mean Score Separation**: 67.88
- **Median Score Separation**: 68.02

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
| **Low** | 644 (99.2%) | 1 (1.0%) |
| **Medium** | 2 (0.3%) | 1 (1.0%) |
| **High** | 3 (0.5%) | 91 (91.9%) |
| **Critical** | 0 (0.0%) | 6 (6.1%) |

### Security Coverage Metrics:
* **Attack High/Critical Coverage Rate**: 97.98% (Percentage of true attacks classified as High/Critical Risk)
* **Normal High/Critical False Alarm Rate**: 0.46% (Percentage of true normal traffic incorrectly classified as High/Critical Risk)

---

## 4. Visualizations
- **Threat Score Distribution Plot**: [threat_score_distribution.png](threat_score_distribution.png)
