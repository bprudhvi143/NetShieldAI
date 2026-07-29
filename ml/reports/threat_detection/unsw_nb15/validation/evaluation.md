# Unified Threat Detection Pipeline Evaluation Report

* **Dataset**: UNSW_NB15
* **Split**: VALIDATION
* **Generated At**: 2026-08-17T22:42:57.329493
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
| **Normal** | 604 | 80.75% |
| **Suspicious** | 40 | 5.35% |
| **Pipeline Attack Status Count** | 104 | 13.90% |

*Note: The Pipeline Attack Status Count represents model predictions (including false positives), not ground-truth attack samples.*

### Signal Consistency Distribution
* **Normal (`normal`)**: 604
* **Suspicious/Anomaly-Only (`anomaly_only`)**: 40
* **Intrusion-Only (`intrusion_only`)**: 2
* **Confirmed Attack (`confirmed_attack`)**: 102

## 3. Anomaly Detector Diagnostics
* **Overall Anomaly Rate**: 18.98%
* **Normal False Anomaly Rate**: 6.78% (Normal flagged anomalous: 44 / 649)
* **Attack Anomaly Detection Rate**: 98.99% (Attack flagged anomalous: 98 / 99)

## 4. Supervised Intrusion Prediction (Binary Classifier)
Evaluation of the XGBoost Binary Classifier.

* **Accuracy**: 0.9826
* **Precision**: 0.9135
* **Recall (Detection Rate)**: 0.9596
* **F1-Score**: 0.9360
* **False Positive Rate**: 0.0139

### Confusion Matrix
* **True Positives (TP)**: 95
* **True Negatives (TN)**: 640
* **False Positives (FP)**: 9
* **False Negatives (FN)**: 4

## 5. Supervised Attack Classification (Multiclass Classifier)
Distinct metrics separating standalone classifier performance from pipeline-gated execution.

* **Standalone Multiclass Model Accuracy**: 0.9612 (Evaluated on all samples)
* **Standalone Multiclass Model Macro F1**: 0.4886
* **Pipeline Gated Multiclass Accuracy**: 0.9599 (Pipeline prediction vs ground truth)
* **True-Attack Classification Accuracy**: 0.7677 (Accuracy of the pipeline's multiclass output on true attacks)
* **Pipeline Multiclass Invocations**: 104 (Number of times multiclass was run because Binary = Attack)
* **Multiclass Actions**:
  * Multiclass Classifier Performed: 104
  * Multiclass Classifier Not Run (Skipped for Normal): 644

## 6. Risk Scoring Diagnostics
Risk Score calibration and risk level distributions.

### Threat Score Statistics
* **All Traffic**: Mean `13.66`, Median `4.13`
* **Normal Traffic**: Mean `5.09`, Median `3.25`
* **Attack Traffic**: Mean `69.89`, Median `71.09`

### Risk Level Distribution
* **Normal Traffic**:
  * Low: 641
  * Medium: 1
  * High: 6
  * Critical: 1
* **Attack Traffic**:
  * Low: 5
  * Medium: 3
  * High: 88
  * Critical: 3

### Safety Coverage & False Alarms
* **Attack High/Critical Coverage Rate**: 91.92% (Percentage of true attacks rated High/Critical)
* **Normal High/Critical False Alarm Rate**: 1.08% (Percentage of true normal traffic rated High/Critical)

## 7. Performance Benchmarks
* **Single Inference Latency**: 0.228 ms / flow
* **Batch Throughput**: 4394.1 flows / second

---
> [!NOTE]
> This unified threat-detection workflow is currently evaluated on static development-sample splits.
