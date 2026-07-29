# Risk Scoring Calibration Report - UNSW_NB15 BINARY (TEST)

Generated on: 2026-08-17T20:33:46.555150
Preprocessing Pipeline Version: 1.0

> [!WARNING]
> **Diagnostic & Calibration Notice**: 
> This evaluation is currently based on the Phase 1 development samples (approximately 5,000 rows) and represents a calibration/diagnostic analysis. 
> It should NOT be interpreted as final production risk-calibration performance, and the scoring thresholds are project-defined initial configurations.

## 1. Split & Model Overview
- **Dataset**: UNSW_NB15
- **Supervised Task Type**: BINARY
- **Evaluation Split**: TEST
- **Total Samples**: 748

## 2. Threat Score Calibration Statistics

| Statistic | Normal Traffic | Attack Traffic |
| --- | --- | --- |
| **Count** | 649 | 99 |
| **Minimum** | 0.13 | 21.77 |
| **Maximum** | 71.90 | 75.81 |
| **Mean** | 5.27 | 70.53 |
| **Median** | 3.70 | 71.05 |

### Separation Analysis:
- **Mean Score Separation**: 65.26
- **Median Score Separation**: 67.35

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
| **Low** | 641 (98.8%) | 2 (2.0%) |
| **Medium** | 4 (0.6%) | 0 (0.0%) |
| **High** | 4 (0.6%) | 97 (98.0%) |
| **Critical** | 0 (0.0%) | 0 (0.0%) |

### Security Coverage Metrics:
* **Attack High/Critical Coverage Rate**: 97.98% (Percentage of true attacks classified as High/Critical Risk)
* **Normal High/Critical False Alarm Rate**: 0.62% (Percentage of true normal traffic incorrectly classified as High/Critical Risk)

---

## 4. Visualizations
- **Threat Score Distribution Plot**: [threat_score_distribution.png](threat_score_distribution.png)
