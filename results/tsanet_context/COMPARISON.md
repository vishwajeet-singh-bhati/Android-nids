# TSANet: adding connection context

Measured local comparison on the same frozen 70/30 flow rows; this is an already-opened development benchmark.

| Model | Accuracy | Macro F1 | Attack recall | Benign false positives | Benign FPR |
|---|---:|---:|---:|---:|---:|
| Historical paper baseline | 97.0256% | 76.6327% | 91.7953% | 11,511 | 1.68933% |
| Historical paper pruned 30% | 97.3240% | 77.1588% | 95.2472% | 14,744 | 2.16379% |
| control_baseline | 97.1808% | 76.9501% | 91.9570% | 10,454 | 1.53420% |
| control_pruned_30 | 97.2454% | 76.1135% | 95.1855% | 15,305 | 2.24612% |
| context_baseline | 99.9815% | 98.1405% | 99.9311% | 33 | 0.00484% |
| context_pruned_30 | 99.9850% | 98.6028% | 99.9491% | 38 | 0.00558% |

## Same-capacity effects

| Stage | Accuracy change (pp) | Macro F1 change (pp) | Attack recall change (pp) | Benign FPR change (pp) |
|---|---:|---:|---:|---:|
| baseline | +2.80073 | +21.19038 | +7.97410 | -1.52936 |
| pruned_30 | +2.73967 | +22.48935 | +4.76362 | -2.24055 |

## Classwise recall

| Class | Historical pruned 30% | Control baseline | Context baseline | Control pruned 30% | Context pruned 30% | Test rows |
|---|---:|---:|---:|---:|---:|---:|
| Benign | 97.84% | 98.47% | 100.00% | 97.75% | 99.99% | 681,396 |
| Bot | 38.67% | 38.67% | 81.09% | 38.67% | 85.86% | 587 |
| Brute Force | 78.43% | 78.53% | 100.00% | 78.19% | 99.98% | 4,150 |
| DDoS | 99.55% | 99.31% | 99.99% | 99.60% | 99.99% | 38,407 |
| DoS | 95.05% | 88.52% | 100.00% | 95.11% | 100.00% | 75,514 |
| Port Scan | 95.39% | 94.38% | 99.99% | 95.12% | 100.00% | 47,641 |
| Web Attack | 8.10% | 7.95% | 99.08% | 4.13% | 99.85% | 654 |

## Scope and controls

- History windows: 2, 5 and 15 minutes, for source and destination hosts; 78 aggregate features. No literal identities, calendar times or labels enter the tensors.
- Only training rows populate history, for both train and test queries. Entire completion intervals must precede the query and lie within the window. Minute-rounded uncertain flows are omitted.
- Both arms have 46,841 parameters, identical initial weights and training orders. Original paper model has 42,761 parameters. No class weighting, threshold or optimizer change.
- Fixed 10 baseline and 5 pruning epochs per arm; all epochs retained. Four final checkpoints frozen before test scoring. No test-selected winner.
- Full-flow completion benchmark, sampled history and one training seed; no independent-session, Android latency or alerts/day claims. No APK installed.
- See experiments/tsanet_context/PROTOCOL.md and context_data_report.json for exact timing, inclusion rules and coverage.
