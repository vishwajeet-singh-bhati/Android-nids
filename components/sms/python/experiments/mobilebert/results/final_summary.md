# MobileBERT-22 vs TF-IDF — final summary

## Locked test split (869 rows, one evaluation)

| Metric | TF-IDF E1b | MobileBERT-22 | Difference |
|---|---:|---:|---:|
| Accuracy | 0.9620 | 0.9724 | +0.0104 |
| Macro-F1 | 0.8910 | 0.9142 | +0.0232 |
| Smishing recall | 0.8163 | 0.9388 | +0.1224 |
| Smishing precision | 0.8333 | 0.7797 | -0.0537 |
| Ham false-positive rate | 0.0127 | 0.0042 | -0.0085 |

MobileBERT-22 caught 46 of 49 smishing messages, with 13 spam/smishing
confusions. It predicted 714 ham, 96 spam, and 59 smishing messages.

## Validation split (used for model selection)

TF-IDF led on validation macro-F1: `0.9034` versus `0.8772` for
MobileBERT-22. The locked-test result therefore should not be treated as a
stable or universal improvement; the test has only 49 smishing examples.

## Size and latency (CPU, 8 threads)

| Measurement | TF-IDF E1b | MobileBERT-22 |
|---|---:|---:|
| Stored model size | 0.80 MiB | 88.4 MiB |
| Single-message end-to-end latency | 1.24 ms | 42.2 ms |
| Batched latency | 0.029 ms/message | 27.0 ms/message |

MobileBERT-22 has 22,898,947 parameters. The baseline has 13,545 features.

## ExecuTorch

- Fixed `1 × 128` export and runtime execution: **verified**
- `.pte` size: 87.7 MiB
- Maximum absolute logit difference from PyTorch: `3.58e-6`
- Dynamic batch/sequence export: **failed** at `torch.export`
- No claim is made for dynamic shapes, Android deployment, or phone latency

## Critical caveat

This is a **22-layer stability variant**, not a standard 24-layer MobileBERT
result. The published 24-layer checkpoint produced extreme activations in its
final two encoder layers in the Hugging Face implementation, so those layers
were omitted.

## Primary artifacts

- `results/test_metrics_test.json`
- `results/comparison_test.md`
- `results/training_summary_mobilebert22_lr5e5_bs16_e4.json`
- `results/executorch_export_static.json`
- `README.md`
