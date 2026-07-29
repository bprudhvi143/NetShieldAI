# Risk Scoring Calibration Report - CICIDS2017 MULTICLASS (TEST)

Generated on: 2026-08-17T20:33:42.511138
Preprocessing Pipeline Version: 1.0

> [!WARNING]
> **Diagnostic & Calibration Notice**: 
> This evaluation is currently based on the Phase 1 development samples (approximately 5,000 rows) and represents a calibration/diagnostic analysis. 
> It should NOT be interpreted as final production risk-calibration performance, and the scoring thresholds are project-defined initial configurations.

## 1. Split & Model Overview
- **Dataset**: CICIDS2017
- **Supervised Task Type**: MULTICLASS
- **Evaluation Split**: TEST
- **Total Samples**: 741

## 2. Threat Score Calibration Statistics

| Statistic | Normal Traffic | Attack Traffic |
| --- | --- | --- |
| **Count** | 597 | 144 |
| **Minimum** | 0.01 | 8.48 |
| **Maximum** | 69.81 | 96.13 |
| **Mean** | 3.06 | 73.27 |
| **Median** | 1.32 | 76.88 |

### Separation Analysis:
- **Mean Score Separation**: 70.21
- **Median Score Separation**: 75.56

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
| **Low** | 595 (99.7%) | 2 (1.4%) |
| **Medium** | 1 (0.2%) | 30 (20.8%) |
| **High** | 1 (0.2%) | 72 (50.0%) |
| **Critical** | 0 (0.0%) | 40 (27.8%) |

### Security Coverage Metrics:
* **Attack High/Critical Coverage Rate**: 77.78% (Percentage of true attacks classified as High/Critical Risk)
* **Normal High/Critical False Alarm Rate**: 0.17% (Percentage of true normal traffic incorrectly classified as High/Critical Risk)

---

## 4. Visualizations
- **Threat Score Distribution Plot**: [threat_score_distribution.png](threat_score_distribution.png)
