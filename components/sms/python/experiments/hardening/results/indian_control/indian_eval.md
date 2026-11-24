# Indian SMS Benchmark Evaluation — hardening_current_indian_control

Generated: 2026-11-11T08:59:00.739301+00:00
Model: `sms-model-0.1`

## Benchmark

- Evaluated rows: **1,994**
- Input rows: **2,014**
- Excluded uncertain rows: **0**
- Dropped empty rows: **0**
- Dropped leakage rows: **20**
- Sample smishing prevalence: **0.0%**

| Label | Rows |
|---|---:|
| `ham` | 1,295 |
| `spam` | 699 |
| `smishing` | 0 |

> **No smishing labels in this benchmark.** Smishing-specific metrics are not estimable. The binary spam/ham view below is the interpretable result for this source.

### Leakage check

- Checked: **True**
- Overlap rows: **20**
- Overlap groups: **7**
- Overlap by split: `{'train': 14, 'val': 6, 'test': 0, 'external': 0}`

## Headline policy metrics

| Metric | Value | 95% interval |
|---|---:|---:|
| Macro-F1 | 0.523 | 0.511–0.535 |
| Smishing recall | 0.0% | n/a |
| Smishing precision | 0.0% | 0.0–1.6% |
| Ham false-positive rate | 13.8% | 12.0–15.8% |
| High-band smishing recall | 0.0% | n/a |
| High-band precision | 0.0% | 0.0–5.6% |
| Ham high-risk rate | 0.0% | 0.0–0.3% |

## Classifier-only diagnostics

| Metric | Value |
|---|---:|
| Macro-F1 | 0.544 |
| Smishing recall | 0.0% |
| Smishing precision | 0.0% |
| Ham false-positive rate | 13.2% |

## Binary spam/ham view

This source has no smishing labels. `any non-ham` treats either `spam` or `smishing` as flagged; `exact spam` requires the policy to say `spam` and therefore exposes smishing overclassification.

| View | Precision | Recall | F1 | Ham FP rate |
|---|---:|---:|---:|---:|
| Policy: any non-ham | 78.8% | 95.4% | 0.863 | 13.8% |
| Policy: exact spam | 70.8% | 61.1% | 0.656 | 13.6% |
| Classifier: any non-ham | 79.2% | 93.0% | 0.855 | 13.2% |
| Classifier: exact spam | 74.5% | 70.1% | 0.722 | 13.0% |

## Slices

### language

| Slice | Rows | Smishing recall | High-band recall | Ham high-risk |
|---|---:|---:|---:|---:|
| `en/hi-Latn` | 1994 | n/a | n/a | 0.0% |

### sender_type

| Slice | Rows | Smishing recall | High-band recall | Ham high-risk |
|---|---:|---:|---:|---:|
| `unknown` | 1994 | n/a | n/a | 0.0% |

### scam_type

| Slice | Rows | Smishing recall | High-band recall | Ham high-risk |
|---|---:|---:|---:|---:|
| `unspecified` | 1994 | n/a | n/a | 0.0% |

### collection_month

| Slice | Rows | Smishing recall | High-band recall | Ham high-risk |
|---|---:|---:|---:|---:|
| `unknown` | 1994 | n/a | n/a | 0.0% |

### source

| Slice | Rows | Smishing recall | High-band recall | Ham high-risk |
|---|---:|---:|---:|---:|
| `kaggle_india_spam_sms` | 1994 | n/a | n/a | 0.0% |

## Limitations

- This benchmark is not a random sample of all Indian SMS traffic.
- This benchmark has no smishing labels, so smishing recall, smishing precision and high-band smishing metrics are not estimable. Use the binary spam/ham view and per-class diagnostics instead.
- Do not tune thresholds on this benchmark if it is a final test set.
- External and Indian datasets may contain campaign/template duplication.
- Scores are uncalibrated; precision depends on real-world prevalence.
- Small slices and small smishing counts have wide confidence intervals.
- The detector is a screening aid, not a certainty engine.
