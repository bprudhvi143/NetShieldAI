# Risk Scoring Calibration Report - UNSW_NB15 BINARY (VALIDATION)

Generated on: 2026-08-17T20:33:43.638535
Preprocessing Pipeline Version: 1.0

> [!WARNING]
> **Diagnostic & Calibration Notice**: 
> This evaluation is currently based on the Phase 1 development samples (approximately 5,000 rows) and represents a calibration/diagnostic analysis. 
> It should NOT be interpreted as final production risk-calibration performance, and the scoring thresholds are project-defined initial configurations.

## 1. Split & Model Overview
- **Dataset**: UNSW_NB15
- **Supervised Task Type**: BINARY
- **Evaluation Split**: VALIDATION
- **Total Samples**: 748

## 2. Threat Score Calibration Statistics

| Statistic | Normal Traffic | Attack Traffic |
| --- | --- | --- |
| **Count** | 649 | 99 |
| **Minimum** | 0.12 | 16.44 |
| **Maximum** | 72.41 | 77.54 |
| **Mean** | 5.13 | 69.38 |
| **Median** | 3.25 | 70.98 |

### Separation Analysis:
- **Mean Score Separation**: 64.24
- **Median Score Separation**: 67.73

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
| **Low** | 640 (98.6%) | 4 (4.0%) |
| **Medium** | 1 (0.2%) | 0 (0.0%) |
| **High** | 8 (1.2%) | 95 (96.0%) |
| **Critical** | 0 (0.0%) | 0 (0.0%) |

### Security Coverage Metrics:
* **Attack High/Critical Coverage Rate**: 95.96% (Percentage of true attacks classified as High/Critical Risk)
* **Normal High/Critical False Alarm Rate**: 1.23% (Percentage of true normal traffic incorrectly classified as High/Critical Risk)

---

## 4. Visualizations
- **Threat Score Distribution Plot**: [threat_score_distribution.png](threat_score_distribution.png)
