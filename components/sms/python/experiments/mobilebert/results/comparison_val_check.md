# MobileBERT vs TF-IDF — aggregate comparison

Evaluation split: `val` (869 rows).
Both models were evaluated on the same rows in the same order; the message-id and prediction hashes are recorded in the JSON result.

MobileBERT is the documented 22-layer stability variant of `google/mobilebert-uncased`; it is not a standard 24-layer result.
Only classifier outputs are compared. The existing risk-policy thresholds are not applied to MobileBERT.

| Metric | TF-IDF E1b | MobileBERT-22 | Difference |
|---|---:|---:|---:|
| Accuracy | 0.9724 | 0.9689 | -0.0035 |
| Macro-F1 | 0.9034 | 0.8772 | -0.0262 |
| Smishing recall | 0.8085 | 0.7872 | -0.0213 |
| Smishing precision | 0.8261 | 0.7115 | -0.1145 |
| Ham false-positive rate | 0.0056 | 0.0028 | -0.0028 |

## Per-class metrics

| Class | Model | Precision | Recall | F1 | Support |
|---|---|---:|---:|---:|---:|
| ham | TF-IDF | 0.9944 | 0.9944 | 0.9944 | 709 |
| ham | MobileBERT-22 | 0.9972 | 0.9972 | 0.9972 | 709 |
| spam | TF-IDF | 0.8947 | 0.9027 | 0.8987 | 113 |
| spam | MobileBERT-22 | 0.9074 | 0.8673 | 0.8869 | 113 |
| smishing | TF-IDF | 0.8261 | 0.8085 | 0.8172 | 47 |
| smishing | MobileBERT-22 | 0.7115 | 0.7872 | 0.7475 | 47 |

## Caveats

- The 24-layer pretrained model produced extreme final-layer activations in the Hugging Face implementation; the final two encoder layers were omitted for this run.
- Scores are classifier outputs, not calibrated probabilities.
- The test split was loaded only by this evaluation script, after model selection and early stopping were complete.
- This is a single test evaluation; no test-set tuning was performed.
