# TSANet classwise analysis - 18 November 2026

Descriptive analysis of the completed frozen test. No model, split, feature, checkpoint or threshold changed. Each metric triple is **precision / recall / F1**, in percent. Precision measures correctness among predictions of a class; recall measures how many true members receive that class. F1 balances both.

| Class | Training rows | Test rows | Baseline P/R/F1 | Pruned 30% P/R/F1 | Pruned 40% P/R/F1 |
|---|---:|---:|---:|---:|---:|
| Benign | 1,589,924 | 681,396 | 98.00 / 98.31 / 98.15 | 98.82 / 97.84 / 98.33 | 98.80 / 97.88 / 98.33 |
| Bot | 1,369 | 587 | 99.12 / 38.50 / 55.46 | 97.01 / 38.67 / 55.30 | 96.64 / 39.18 / 55.76 |
| Brute Force | 9,682 | 4,150 | 97.64 / 77.90 / 86.66 | 99.57 / 78.43 / 87.75 | 99.63 / 78.14 / 87.59 |
| DDoS | 89,618 | 38,407 | 99.91 / 98.57 / 99.24 | 99.71 / 99.55 / 99.63 | 99.87 / 99.54 / 99.70 |
| DoS | 176,198 | 75,514 | 91.03 / 88.77 / 89.89 | 88.20 / 95.05 / 91.50 | 88.40 / 94.86 / 91.52 |
| Port Scan | 111,163 | 47,641 | 90.31 / 94.09 / 92.16 | 90.03 / 95.39 / 92.63 | 90.04 / 95.38 / 92.63 |
| Web Attack | 1,526 | 654 | 89.83 / 8.10 / 14.87 | 98.15 / 8.10 / 14.97 | 100.00 / 4.28 / 8.21 |

## Confusion breakdown for the 30% pruned model

Predicting another attack type still flags an attack. Most weak-class errors instead predict Benign.

| True attack | Correct type | Predicted Benign | Predicted another attack type | Of the Benign predictions, identical features also occur in Benign training |
|---|---:|---:|---:|---:|
| Bot | 227 | 360 | 0 | 207 |
| Brute Force | 3,255 | 893 | 2 | 872 |
| DDoS | 38,236 | 171 | 0 | 13 |
| DoS | 71,778 | 3,736 | 0 | 1,720 |
| Port Scan | 45,446 | 2,176 | 19 | 2,146 |
| Web Attack | 53 | 599 | 2 | 42 |

Of 681,396 Benign test flows, 666,652 are correctly Benign; 14,744 are falsely flagged (2.16379%). False labels: DoS 9,590, Port Scan 5,030, DDoS 102, Brute Force 14, Bot 7 and Web Attack 1. DoS/scan account for 14,620 of the flags.

## Confirmed input ambiguity

`validation/analyze_tsanet_classwise.py` hashes to locate candidate matches, then directly compares all 32 stored raw float32 values. All reported hash matches passed direct equality. Attack test flows identical to at least one Benign training vector: Bot 207, Brute Force 902, DDoS 13, DoS 17,032, Port Scan 22,107 and Web Attack 43.

Differently labeled flows can therefore present the same selected input. A deterministic classifier cannot distinguish every such individual example using these values alone. This establishes ambiguity of the representation, not necessarily publisher label errors or duplicate complete flow records. Cross-split equality does not prove the cause of each prediction or impose these counts as a test-only error floor.

## Possible explanations and their limits

- **Bot:** Only 1,369 training rows against 1,589,924 Benign rows, with unweighted loss. The model predicts Bot selectively (high precision, low recall). Input ambiguity is directly measured in 207 of 360 missed flows. Missing cross-flow periodicity/session context is a plausible additional limitation, not an isolated causal finding.
- **Web Attack:** Only 1,526 training rows and no URL, request body or application content in these timing/size/count/flag features. Minority suppression and insufficient information are plausible. Exact Benign matches cover only 42/599 misses, so they explain a limited part of the error pattern; near-overlap has not been measured. At 40% pruning correct Web predictions drop from 53 to 28, showing degradation without isolating its mechanism.
- **Brute Force:** High precision but incomplete recall. Of 893 flows called Benign, 872 match Benign training inputs exactly. Authentication outcomes and repeated-attempt context are absent. Their value requires a separate controlled experiment.
- **DoS:** Recall improves after fine-tuning, but precision declines: 9,590 Benign flows receive the DoS label. Substantial cross-label feature equality shows that insufficient row count is not the whole issue. The family merges four DoS labels; subtype performance has not been computed here.
- **Port Scan:** About 95% recall and 90% precision; 5,030 Benign flows receive the scan label. Of 2,176 missed scans, 2,146 match Benign training inputs. One-flow features omit explicit destination-port diversity and scan history across flows. Adding these signals may help; benefit is unmeasured.
- **DDoS:** Strongest class on this split, ample training support and very few exact Benign feature matches. More separable flow patterns are plausible; no feature-attribution experiment proves that mechanism. These results do not establish every DDoS form or Android generalization.
- **Benign:** Large support makes headline accuracy strong despite thousands of false flags. Errors concentrate in DoS/scan, consistent with the ambiguity/context limitations above. The 2.16% rate is per dataset flow, not phone alerts per day.

The unweighted natural-frequency objective and absent inputs are design facts; their individual error contributions have not been measured through ablations. The LSTMs traverse the 32 feature positions within one flow, not chronological packets or flows. A larger model or more epochs cannot supply missing information. Pruned 30% has the highest macro F1 (77.16%) and binary attack recall (95.25%) here; pruned 40% has slightly higher accuracy but weaker Web recall. This is a descriptive comparison, not deployment selection.

Evidence: `classwise.csv`, `baseline_results.json`, `classwise_diagnostics.json`, `data_report.json` and `experiments/tsanet_paper/PROTOCOL.md`. No training or phone installation followed this analysis.
