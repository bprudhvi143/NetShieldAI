# Risk Scoring Calibration Report - CICIDS2017 BINARY (TEST)

Generated on: 2026-08-17T20:33:41.858839
Preprocessing Pipeline Version: 1.0

> [!WARNING]
> **Diagnostic & Calibration Notice**: 
> This evaluation is currently based on the Phase 1 development samples (approximately 5,000 rows) and represents a calibration/diagnostic analysis. 
> It should NOT be interpreted as final production risk-calibration performance, and the scoring thresholds are project-defined initial configurations.

## 1. Split & Model Overview
- **Dataset**: CICIDS2017
- **Supervised Task Type**: BINARY
- **Evaluation Split**: TEST
- **Total Samples**: 741

## 2. Threat Score Calibration Statistics

| Statistic | Normal Traffic | Attack Traffic |
| --- | --- | --- |
| **Count** | 597 | 144 |
| **Minimum** | 0.01 | 12.43 |
| **Maximum** | 59.32 | 75.45 |
| **Mean** | 3.14 | 63.13 |
| **Median** | 1.33 | 60.62 |

### Separation Analysis:
- **Mean Score Separation**: 59.99
- **Median Score Separation**: 59.29

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
| **Low** | 594 (99.5%) | 1 (0.7%) |
| **Medium** | 3 (0.5%) | 38 (26.4%) |
| **High** | 0 (0.0%) | 105 (72.9%) |
| **Critical** | 0 (0.0%) | 0 (0.0%) |

### Security Coverage Metrics:
* **Attack High/Critical Coverage Rate**: 72.92% (Percentage of true attacks classified as High/Critical Risk)
* **Normal High/Critical False Alarm Rate**: 0.00% (Percentage of true normal traffic incorrectly classified as High/Critical Risk)

---

## 4. Visualizations
- **Threat Score Distribution Plot**: [threat_score_distribution.png](threat_score_distribution.png)
