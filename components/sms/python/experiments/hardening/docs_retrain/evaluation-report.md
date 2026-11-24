# Evaluation Report — SMS Scam Detection Baseline

Generated: 2026-11-10T19:26:21.559377+00:00
Model: `sms-model-0.1` · selected experiment: `E1b_word_lr_balanced`

## Headline results — product policy output

The policy output is what `SmsDetector` returns: classifier scores, deterministic
evidence and risk fusion. A `high` verdict normally needs a strong evidence cue;
a smishing score at or above the evidence-free threshold can stand alone.

| Split | Policy macro-F1 | Policy smishing recall | Policy smishing precision | Smishing flagged (any band) | High-risk smishing recall | High-risk precision | Ham flagged (any band) | Ham high-risk |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `val` | 0.888 | 0.809 | 0.776 | 1.000 | 0.532 | 0.926 | 0.048 | 0.000 |
| `test` | 0.869 | 0.837 | 0.745 | 1.000 | 0.449 | 0.733 | 0.069 | 0.000 |
| `external` | 0.576 | 0.844 | 0.999 | 1.000 | 0.806 | 1.000 | 0.082 | 0.004 |

The high band is deliberately narrow and precision-oriented. The recall-oriented
suspicious band is where uncertain messages are surfaced for review. The locked
test is small for smishing and wide confidence intervals apply.

## Classifier-only (argmax) metrics

These are the raw three-class classifier results before rule/risk fusion. They are
diagnostics, not the product output.

| Split | Macro-F1 | Smishing recall | Smishing FNR | Smishing FPR | Ham false-positive rate |
|---|---:|---:|---:|---:|---:|
| `val` | 0.903 | 0.809 | 0.191 | 0.010 | 0.006 |
| `test` | 0.891 | 0.816 | 0.184 | 0.010 | 0.013 |
| `external` | 0.395 | 0.275 | 0.725 | 0.017 | 0.016 |

`external` is **not** a clean independent benchmark: it combines source-held-out
NCSU campaigns with held-out classic ham/spam and the hand-written Hinglish seed.
NCSU campaigns include gambling/promotional spam, so the source-level `smishing`
label is noisy. Read external results as a stress test, not as proof of real-world
accuracy.

## Per-class policy metrics (locked test)

| Class | Precision | Recall | F1 | Support |
|---|---:|---:|---:|---:|
| `ham` | 0.989 | 0.987 | 0.988 | 709 |
| `spam` | 0.849 | 0.811 | 0.829 | 111 |
| `smishing` | 0.745 | 0.837 | 0.788 | 49 |

## Policy confusion matrix (locked test)

| True \ Predicted | ham | spam | smishing |
|---|---:|---:|---:|
| `ham` | 700 | 9 | 0 |
| `spam` | 7 | 90 | 14 |
| `smishing` | 1 | 7 | 41 |

## Threshold policy

- High-risk threshold: **0.385**
- Suspicious threshold: **0.101**
- Evidence-free high threshold: **0.800**
- Cost assumptions: C_FN=10.0, C_FP=1.0
- Validation recall floor for high risk: **0.85**
- Validation precision floor for high risk: **0.8**
- Thresholds are selected on validation only; the locked test split was not used.
- The suspicious band uses a discounted false-positive cost because it prompts review, not blocking.

## Calibration

| Metric | Raw | Calibrated |
|---|---:|---:|
| Log loss | 0.1985 | 0.0887 |
| Brier (multiclass) | 0.0753 | 0.0457 |
| ECE (10 bins) | 0.1250 | 0.0076 |
| High-band precision | 0.800 | 0.529 |
| High-band recall | 0.851 | 0.957 |

Temperature scaling applied: **False** (T=1.000).
Fitted temperature: 0.407.
Reason not applied: calibrated high-risk threshold missed the recall/precision floor.

Temperature scaling was fitted but rejected because it did not preserve the high-band policy floors. Scores remain uncalibrated; thresholds were selected on raw validation probabilities. Revisit with a rank-preserving calibrator and more validation data.

## Candidate experiments (validation)

| Experiment | Macro-F1 | Smishing recall @ default | Smishing recall @ high | Precision @ high | Feasible | FPR @ high | Expected cost | Train s |
|---|---:|---:|---:|---:|---|---:|---:|---:|
| `E1_word_lr` | 0.782 | 0.383 | 1.000 | 0.412 | **no** | 0.082 | 67.0 | 0.5 |
| `E1b_word_lr_balanced` | 0.903 | 0.809 | 0.851 | 0.800 | yes | 0.012 | 80.0 | 0.6 |
| `E2_word_char_lr` | 0.857 | 0.596 | 1.000 | 0.431 | **no** | 0.075 | 62.0 | 1.7 |
| `E2b_word_char_lr_balanced` | 0.898 | 0.809 | 1.000 | 0.423 | **no** | 0.078 | 64.0 | 1.7 |
| `E3_word_char_ind_lr` | 0.863 | 0.638 | 0.979 | 0.418 | **no** | 0.078 | 74.0 | 54.7 |
| `E3b_word_char_ind_lr_balanced` | 0.868 | 0.745 | 0.915 | 0.589 | **no** | 0.036 | 70.0 | 55.5 |

## E0 rules-only baseline

| Split | Macro-F1 | Smishing recall | Ham false-positive rate |
|---|---:|---:|---:|
| `val` | 0.446 | 0.106 | 0.013 |
| `test` | 0.457 | 0.143 | 0.008 |
| `external` | 0.376 | 0.801 | 0.019 |

## Risks and honest limitations

- The locked test split is small for smishing (49 examples); confidence intervals are wide.
- NCSU campaign templates are source-labelled `smishing` but include gambling and promotional spam; external exact 3-class metrics are label-noisy.
- The external split is 97.7% NCSU smishing by construction, so its macro-F1 is not comparable to the balanced test split.
- Hinglish coverage is 63 hand-written rows; no robust Hinglish claim is made.
- UCI is old and geographically mismatched with current Indian SMS scams.
- The high-risk band is intentionally narrow; most recall comes from the suspicious band. Do not describe it as full smishing coverage.
- Calibration was rejected because it worsened the high-band precision/recall trade-off; scores should not be described as calibrated probabilities.
- Thresholds and costs are provisional and must be agreed with the team.
- The detector is a screening aid, not a certainty engine. No auto-delete or auto-click.

## False-positive controls

- Routine `salary credited`, `EMI debited`, `payment successful` and delivered-order alerts are suppressed only when no link, request, threat or fee is present.
- A high-risk verdict normally needs a strong evidence cue; a very high smishing score can stand alone.
- Account-reset/login/password lures require a URL; `if this wasn't you` security alerts are excluded.

## Reproduce

```powershell
python scripts/download_data.py
python scripts/prepare_data.py
python scripts/audit_data.py
python scripts/train.py
```
