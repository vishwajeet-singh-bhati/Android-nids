# TSANet paper-based baseline: measured comparison

User-defined 70% training / 30% testing, stratified seed 42. This reconstructs the paper architecture with documented assumptions; the original feature list and split are unavailable.

| Model | Paper test accuracy | Measured test accuracy | Difference (pp) | Macro F1 | Binary attack recall | Benign false-positive rate |
|---|---:|---:|---:|---:|---:|---:|
| baseline | 97.35% | 97.03% | -0.32 | 0.76633 | 91.80% | 1.68933% |
| pruned_30 | 98.30% | 97.32% | -0.98 | 0.77159 | 95.25% | 2.16379% |
| pruned_40 | not stated numerically | 97.33% | n/a | 0.76249 | 95.14% | 2.12343% |

## Per-class recall

| Class | baseline | pruned 30% | pruned 40% | Test support |
|---|---:|---:|---:|---:|
| Benign | 98.31% | 97.84% | 97.88% | 681,396 |
| Bot | 38.50% | 38.67% | 39.18% | 587 |
| Brute Force | 77.90% | 78.43% | 78.14% | 4,150 |
| DDoS | 98.57% | 99.55% | 99.54% | 38,407 |
| DoS | 88.77% | 95.05% | 94.86% | 75,514 |
| Port Scan | 94.09% | 95.39% | 95.38% | 47,641 |
| Web Attack | 8.10% | 8.10% | 4.28% | 654 |

## Precision / recall / F1 averaging

The paper reports full-feature precision 98.6%, recall 97.9%, F1 98.1% without specifying averaging. Both macro and weighted results are given below; they must not be silently substituted for an unknown paper average.

| Model | Macro precision | Macro recall | Macro F1 | Weighted precision | Weighted recall | Weighted F1 |
|---|---:|---:|---:|---:|---:|---:|
| baseline | 95.12% | 72.04% | 76.63% | 97.02% | 97.03% | 96.98% |
| pruned_30 | 95.93% | 73.29% | 77.16% | 97.43% | 97.32% | 97.31% |
| pruned_40 | 96.20% | 72.75% | 76.25% | 97.43% | 97.33% | 97.32% |

## Random-split feature overlap

277,034/848,349 test rows (32.66%) have the same selected 32-feature vector as at least one training row. This is not proof that their complete publisher flow records are duplicates. The protocol retained duplicates and reports this dependence.

| Model | Overlap subset accuracy | Novel-feature subset accuracy | Novel-feature macro F1 |
|---|---:|---:|---:|
| baseline | 92.70% | 99.12% | 0.72710 |
| pruned_30 | 93.31% | 99.27% | 0.77184 |
| pruned_40 | 93.35% | 99.26% | 0.76151 |

## Exports and work-PC timing

| Model | Matrix weights masked | Dense parameters | TorchScript bytes | PC GPU batch-one mean ms | Export decision flips |
|---|---:|---:|---:|---:|---:|
| baseline | 0/41,696 | 42,761 | 199,038 | 0.4571 | 0 |
| pruned_30 | 12,508/41,696 | 42,761 | 200,925 | 0.4783 | 0 |
| pruned_40 | 16,678/41,696 | 42,761 | 201,117 | 0.4717 | 0 |

Timing is on the work-PC CUDA GPU and is not comparable to the paper's Android per-flow number. Unstructured masks retain dense dimensions and did not establish the paper's claimed latency reduction. Export checks cover 64 inputs per model, not every test row.


These are descriptive subsets of the same opened test. They did not choose a model, change the split, or trigger further training. The full benchmark is not evidence of phone accuracy, attack-session recall or alerts/day.

Every baseline epoch and every pruning fine-tuning epoch is saved. Fixed final epochs are used. Reported differences were not tuned away. TorchScript checks and work-PC timings are in `baseline_results.json`; no Android timings or missing-feature adaptation are claimed.

Implementation assumptions and exact selected features: `experiments/tsanet_paper/PROTOCOL.md`. Detailed classwise values: `classwise.csv`. No model was installed.
