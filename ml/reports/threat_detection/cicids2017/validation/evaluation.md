# Unified Threat Detection Pipeline Evaluation Report

* **Dataset**: CICIDS2017
* **Split**: VALIDATION
* **Generated At**: 2026-08-17T22:42:56.867684
* **Pipeline Version**: 1.0

---

## 1. Overview & Data Split
* **Total Evaluation Samples**: 741
* **Normal Traffic Samples**: 597
* **Attack Traffic Samples**: 144

## 2. Detection Performance (Orchestrated Pipeline Status)
The pipeline categorizes traffic into three statuses: `Normal`, `Suspicious` (anomaly only), or `Attack`.

| Status | Total Mapped | Percentage |
| --- | --- | --- |
| **Normal** | 538 | 72.60% |
| **Suspicious** | 60 | 8.10% |
| **Pipeline Attack Status Count** | 143 | 19.30% |

*Note: The Pipeline Attack Status Count represents model predictions (including false positives), not ground-truth attack samples.*

### Signal Consistency Distribution
* **Normal (`normal`)**: 538
* **Suspicious/Anomaly-Only (`anomaly_only`)**: 60
* **Intrusion-Only (`intrusion_only`)**: 84
* **Confirmed Attack (`confirmed_attack`)**: 59

## 3. Anomaly Detector Diagnostics
* **Overall Anomaly Rate**: 16.06%
* **Normal False Anomaly Rate**: 10.05% (Normal flagged anomalous: 60 / 597)
* **Attack Anomaly Detection Rate**: 40.97% (Attack flagged anomalous: 59 / 144)

## 4. Supervised Intrusion Prediction (Binary Classifier)
Evaluation of the XGBoost Binary Classifier.

* **Accuracy**: 0.9987
* **Precision**: 1.0000
* **Recall (Detection Rate)**: 0.9931
* **F1-Score**: 0.9965
* **False Positive Rate**: 0.0000

### Confusion Matrix
* **True Positives (TP)**: 143
* **True Negatives (TN)**: 597
* **False Positives (FP)**: 0
* **False Negatives (FN)**: 1

## 5. Supervised Attack Classification (Multiclass Classifier)
Distinct metrics separating standalone classifier performance from pipeline-gated execution.

* **Standalone Multiclass Model Accuracy**: 0.9973 (Evaluated on all samples)
* **Standalone Multiclass Model Macro F1**: 0.6666
* **Pipeline Gated Multiclass Accuracy**: 0.9973 (Pipeline prediction vs ground truth)
* **True-Attack Classification Accuracy**: 0.9861 (Accuracy of the pipeline's multiclass output on true attacks)
* **Pipeline Multiclass Invocations**: 143 (Number of times multiclass was run because Binary = Attack)
* **Multiclass Actions**:
  * Multiclass Classifier Performed: 143
  * Multiclass Classifier Not Run (Skipped for Normal): 598

## 6. Risk Scoring Diagnostics
Risk Score calibration and risk level distributions.

### Threat Score Statistics
* **All Traffic**: Mean `17.15`, Median `2.43`
* **Normal Traffic**: Mean `3.07`, Median `1.33`
* **Attack Traffic**: Mean `75.50`, Median `82.72`

### Risk Level Distribution
* **Normal Traffic**:
  * Low: 597
  * Medium: 0
  * High: 0
  * Critical: 0
* **Attack Traffic**:
  * Low: 1
  * Medium: 26
  * High: 58
  * Critical: 59

### Safety Coverage & False Alarms
* **Attack High/Critical Coverage Rate**: 81.25% (Percentage of true attacks rated High/Critical)
* **Normal High/Critical False Alarm Rate**: 0.00% (Percentage of true normal traffic rated High/Critical)

## 7. Performance Benchmarks
* **Single Inference Latency**: 0.262 ms / flow
* **Batch Throughput**: 3810.8 flows / second

---
> [!NOTE]
> This unified threat-detection workflow is currently evaluated on static development-sample splits.
