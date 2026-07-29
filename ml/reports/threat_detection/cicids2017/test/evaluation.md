# Unified Threat Detection Pipeline Evaluation Report

* **Dataset**: CICIDS2017
* **Split**: TEST
* **Generated At**: 2026-08-17T22:42:57.084082
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
| **Normal** | 539 | 72.74% |
| **Suspicious** | 56 | 7.56% |
| **Pipeline Attack Status Count** | 146 | 19.70% |

*Note: The Pipeline Attack Status Count represents model predictions (including false positives), not ground-truth attack samples.*

### Signal Consistency Distribution
* **Normal (`normal`)**: 539
* **Suspicious/Anomaly-Only (`anomaly_only`)**: 56
* **Intrusion-Only (`intrusion_only`)**: 105
* **Confirmed Attack (`confirmed_attack`)**: 41

## 3. Anomaly Detector Diagnostics
* **Overall Anomaly Rate**: 13.09%
* **Normal False Anomaly Rate**: 9.38% (Normal flagged anomalous: 56 / 597)
* **Attack Anomaly Detection Rate**: 28.47% (Attack flagged anomalous: 41 / 144)

## 4. Supervised Intrusion Prediction (Binary Classifier)
Evaluation of the XGBoost Binary Classifier.

* **Accuracy**: 0.9946
* **Precision**: 0.9795
* **Recall (Detection Rate)**: 0.9931
* **F1-Score**: 0.9862
* **False Positive Rate**: 0.0050

### Confusion Matrix
* **True Positives (TP)**: 143
* **True Negatives (TN)**: 594
* **False Positives (FP)**: 3
* **False Negatives (FN)**: 1

## 5. Supervised Attack Classification (Multiclass Classifier)
Distinct metrics separating standalone classifier performance from pipeline-gated execution.

* **Standalone Multiclass Model Accuracy**: 0.9933 (Evaluated on all samples)
* **Standalone Multiclass Model Macro F1**: 0.7840
* **Pipeline Gated Multiclass Accuracy**: 0.9933 (Pipeline prediction vs ground truth)
* **True-Attack Classification Accuracy**: 0.9792 (Accuracy of the pipeline's multiclass output on true attacks)
* **Pipeline Multiclass Invocations**: 146 (Number of times multiclass was run because Binary = Attack)
* **Multiclass Actions**:
  * Multiclass Classifier Performed: 146
  * Multiclass Classifier Not Run (Skipped for Normal): 595

## 6. Risk Scoring Diagnostics
Risk Score calibration and risk level distributions.

### Threat Score Statistics
* **All Traffic**: Mean `16.74`, Median `1.93`
* **Normal Traffic**: Mean `3.10`, Median `1.33`
* **Attack Traffic**: Mean `73.30`, Median `76.88`

### Risk Level Distribution
* **Normal Traffic**:
  * Low: 595
  * Medium: 1
  * High: 1
  * Critical: 0
* **Attack Traffic**:
  * Low: 2
  * Medium: 30
  * High: 72
  * Critical: 40

### Safety Coverage & False Alarms
* **Attack High/Critical Coverage Rate**: 77.78% (Percentage of true attacks rated High/Critical)
* **Normal High/Critical False Alarm Rate**: 0.17% (Percentage of true normal traffic rated High/Critical)

## 7. Performance Benchmarks
* **Single Inference Latency**: 0.224 ms / flow
* **Batch Throughput**: 4469.1 flows / second

---
> [!NOTE]
> This unified threat-detection workflow is currently evaluated on static development-sample splits.
