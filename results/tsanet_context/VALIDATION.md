# Context comparison: independent validation

All checks passed. Frozen sources, all four final checkpoints/exports, original flow-row ordering and all 30 epoch files verified. Context normalization independently reproduced from training rows only. Every saved prediction was used to recompute confusion matrices and main metrics. Each export matched 512 additional sampled saved decisions with zero flips.

## Exact input ambiguity

| Class | Test inputs matching Benign training: 32 features | After adding 78 context values |
|---|---:|---:|
| Benign | 209,820 | 34,949 |
| Bot | 207 | 0 |
| Brute Force | 902 | 0 |
| DDoS | 13 | 0 |
| DoS | 17,032 | 0 |
| Port Scan | 22,107 | 0 |
| Web Attack | 43 | 0 |

## Descriptive paired block intervals

2,000 paired resamples of 15-minute time blocks from this same opened benchmark. These are not independent-capture or population guarantees. Changes below are context minus matched control in percentage points; lower FPR is better.

| Stage | Metric | 95% lower change (pp) | 95% upper change (pp) |
|---|---|---:|---:|
| baseline | accuracy | +1.6283 | +4.1432 |
| baseline | macro_f1 | +19.3083 | +33.2260 |
| baseline | binary_attack_recall | +4.0293 | +13.0287 |
| baseline | benign_false_positive_rate | -2.2921 | -0.8687 |
| pruned_30 | accuracy | +2.0726 | +3.4529 |
| pruned_30 | macro_f1 | +20.7091 | +34.9501 |
| pruned_30 | binary_attack_recall | +2.9932 | +9.7198 |
| pruned_30 | benign_false_positive_rate | -3.0234 | -1.5587 |

No checkpoint selection, new optimization or phone installation occurred. Full numeric evidence: validation.json.
