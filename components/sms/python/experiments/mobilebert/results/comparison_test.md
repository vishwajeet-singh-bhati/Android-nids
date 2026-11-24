# MobileBERT vs TF-IDF — aggregate comparison

Evaluation split: `test` (869 rows).
Both models were evaluated on the same rows in the same order; the message-id and prediction hashes are recorded in the JSON result.

MobileBERT is the documented 22-layer stability variant of `google/mobilebert-uncased`; it is not a standard 24-layer result.
Only classifier outputs are compared. The existing risk-policy thresholds are not applied to MobileBERT.

| Metric | TF-IDF E1b | MobileBERT-22 | Difference |
|---|---:|---:|---:|
| Accuracy | 0.9620 | 0.9724 | +0.0104 |
| Macro-F1 | 0.8910 | 0.9142 | +0.0232 |
| Smishing recall | 0.8163 | 0.9388 | +0.1224 |
| Smishing precision | 0.8333 | 0.7797 | -0.0537 |
| Ham false-positive rate | 0.0127 | 0.0042 | -0.0085 |

## Per-class metrics

| Class | Model | Precision | Recall | F1 | Support |
|---|---|---:|---:|---:|---:|
| ham | TF-IDF | 0.9873 | 0.9873 | 0.9873 | 709 |
| ham | MobileBERT-22 | 0.9888 | 0.9958 | 0.9923 | 709 |
| spam | TF-IDF | 0.8571 | 0.8649 | 0.8610 | 111 |
| spam | MobileBERT-22 | 0.9688 | 0.8378 | 0.8986 | 111 |
| smishing | TF-IDF | 0.8333 | 0.8163 | 0.8247 | 49 |
| smishing | MobileBERT-22 | 0.7797 | 0.9388 | 0.8519 | 49 |

## Caveats

- The 24-layer pretrained model produced extreme final-layer activations in the Hugging Face implementation; the final two encoder layers were omitted for this run.
- Scores are classifier outputs, not calibrated probabilities.
- The test split was loaded only by this evaluation script, after model selection and early stopping were complete.
- This is a single test evaluation; no test-set tuning was performed.
