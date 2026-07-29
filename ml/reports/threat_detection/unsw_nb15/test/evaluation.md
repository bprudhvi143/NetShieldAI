# Unified Threat Detection Pipeline Evaluation Report

* **Dataset**: UNSW_NB15
* **Split**: TEST
* **Generated At**: 2026-08-17T22:42:57.526890
* **Pipeline Version**: 1.0

---

## 1. Overview & Data Split
* **Total Evaluation Samples**: 748
* **Normal Traffic Samples**: 649
* **Attack Traffic Samples**: 99

## 2. Detection Performance (Orchestrated Pipeline Status)
The pipeline categorizes traffic into three statuses: `Normal`, `Suspicious` (anomaly only), or `Attack`.

| Status | Total Mapped | Percentage |
| --- | --- | --- |
| **Normal** | 600 | 80.21% |
| **Suspicious** | 44 | 5.88% |
| **Pipeline Attack Status Count** | 104 | 13.90% |

*Note: The Pipeline Attack Status Count represents model predictions (including false positives), not ground-truth attack samples.*

### Signal Consistency Distribution
* **Normal (`normal`)**: 600
* **Suspicious/Anomaly-Only (`anomaly_only`)**: 44
* **Intrusion-Only (`intrusion_only`)**: 0
* **Confirmed Attack (`confirmed_attack`)**: 104

## 3. Anomaly Detector Diagnostics
* **Overall Anomaly Rate**: 19.79%
* **Normal False Anomaly Rate**: 7.55% (Normal flagged anomalous: 49 / 649)
* **Attack Anomaly Detection Rate**: 100.00% (Attack flagged anomalous: 99 / 99)

## 4. Supervised Intrusion Prediction (Binary Classifier)
Evaluation of the XGBoost Binary Classifier.

* **Accuracy**: 0.9880
* **Precision**: 0.9327
* **Recall (Detection Rate)**: 0.9798
* **F1-Score**: 0.9557
* **False Positive Rate**: 0.0108

### Confusion Matrix
* **True Positives (TP)**: 97
* **True Negatives (TN)**: 642
* **False Positives (FP)**: 7
* **False Negatives (FN)**: 2

## 5. Supervised Attack Classification (Multiclass Classifier)
Distinct metrics separating standalone classifier performance from pipeline-gated execution.

* **Standalone Multiclass Model Accuracy**: 0.9813 (Evaluated on all samples)
* **Standalone Multiclass Model Macro F1**: 0.6724
* **Pipeline Gated Multiclass Accuracy**: 0.9813 (Pipeline prediction vs ground truth)
* **True-Attack Classification Accuracy**: 0.8990 (Accuracy of the pipeline's multiclass output on true attacks)
* **Pipeline Multiclass Invocations**: 104 (Number of times multiclass was run because Binary = Attack)
* **Multiclass Actions**:
  * Multiclass Classifier Performed: 104
  * Multiclass Classifier Not Run (Skipped for Normal): 644

## 6. Risk Scoring Diagnostics
Risk Score calibration and risk level distributions.

### Threat Score Statistics
* **All Traffic**: Mean `14.07`, Median `4.67`
* **Normal Traffic**: Mean `5.09`, Median `3.70`
* **Attack Traffic**: Mean `72.89`, Median `71.72`

### Risk Level Distribution
* **Normal Traffic**:
  * Low: 643
  * Medium: 3
  * High: 3
  * Critical: 0
* **Attack Traffic**:
  * Low: 2
  * Medium: 0
  * High: 91
  * Critical: 6

### Safety Coverage & False Alarms
* **Attack High/Critical Coverage Rate**: 97.98% (Percentage of true attacks rated High/Critical)
* **Normal High/Critical False Alarm Rate**: 0.46% (Percentage of true normal traffic rated High/Critical)

## 7. Performance Benchmarks
* **Single Inference Latency**: 0.200 ms / flow
* **Batch Throughput**: 4996.0 flows / second

---
> [!NOTE]
> This unified threat-detection workflow is currently evaluated on static development-sample splits.
