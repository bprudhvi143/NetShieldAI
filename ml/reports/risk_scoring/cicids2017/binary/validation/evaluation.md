# Risk Scoring Calibration Report - CICIDS2017 BINARY (VALIDATION)

Generated on: 2026-08-17T20:33:41.532034
Preprocessing Pipeline Version: 1.0

> [!WARNING]
> **Diagnostic & Calibration Notice**: 
> This evaluation is currently based on the Phase 1 development samples (approximately 5,000 rows) and represents a calibration/diagnostic analysis. 
> It should NOT be interpreted as final production risk-calibration performance, and the scoring thresholds are project-defined initial configurations.

## 1. Split & Model Overview
- **Dataset**: CICIDS2017
- **Supervised Task Type**: BINARY
- **Evaluation Split**: VALIDATION
- **Total Samples**: 741

## 2. Threat Score Calibration Statistics

| Statistic | Normal Traffic | Attack Traffic |
| --- | --- | --- |
| **Count** | 597 | 144 |
| **Minimum** | 0.05 | 10.96 |
| **Maximum** | 19.41 | 75.26 |
| **Mean** | 3.07 | 64.55 |
| **Median** | 1.33 | 61.86 |

### Separation Analysis:
- **Mean Score Separation**: 61.47
- **Median Score Separation**: 60.53

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
| **Low** | 597 (100.0%) | 1 (0.7%) |
| **Medium** | 0 (0.0%) | 28 (19.4%) |
| **High** | 0 (0.0%) | 115 (79.9%) |
| **Critical** | 0 (0.0%) | 0 (0.0%) |

### Security Coverage Metrics:
* **Attack High/Critical Coverage Rate**: 79.86% (Percentage of true attacks classified as High/Critical Risk)
* **Normal High/Critical False Alarm Rate**: 0.00% (Percentage of true normal traffic incorrectly classified as High/Critical Risk)

---

## 4. Visualizations
- **Threat Score Distribution Plot**: [threat_score_distribution.png](threat_score_distribution.png)
