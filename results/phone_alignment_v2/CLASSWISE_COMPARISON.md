# Classwise comparison: previous context model and phone-aligned v2

The previous model here is context_pruned_30 (the weights used by the installed context detector). Current is the validation-selected gate_s0 + diagnosis64_s1. All metrics below are percentages. These are saved offline test results, not phone test results.

## Different-cohort historical comparison

Previous:848,349 publisher CSV test rows from a random70/30 split. Current:1,098,929 re-extracted raw-flow watched-host views, grouped70/15/15 with Android benign controls. Input semantics/context, optimization, model sizes and decision policy also differ. Therefore this comparison does not isolate input alignment or prove improvement/regression on identical traffic.

Each cell is previous -> current. Support counts are views/rows, not independent attack sessions.

| Class | Precision % | Recall % | F1 % | Support |
|---|---:|---:|---:|---:|
| Benign | 99.988 -> 99.940 | 99.994 -> 99.922 | 99.991 -> 99.931 | 681,396 -> 940,095 |
| Bot | 95.817 -> 54.286 | 85.860 -> 92.031 | 90.566 -> 68.290 | 587 -> 640 |
| Brute Force | 100.000 -> 99.959 | 99.976 -> 99.672 | 99.988 -> 99.815 | 4,150 -> 2,442 |
| DDoS | 99.995 -> 99.627 | 99.992 -> 97.220 | 99.993 -> 98.408 | 38,407 -> 17,840 |
| DoS | 99.988 -> 99.932 | 100.000 -> 99.960 | 99.994 -> 99.946 | 75,514 -> 90,084 |
| Port Scan | 99.987 -> 99.971 | 99.998 -> 99.996 | 99.993 -> 99.983 | 47,641 -> 47,688 |
| Web Attack | 99.543 -> 95.385 | 99.847 -> 88.571 | 99.695 -> 91.852 | 654 -> 140 |

| Overall metric | Previous | Current |
|---|---:|---:|
| Typed accuracy | 99.9850% | 99.8782% |
| Typed macro F1 | 98.6028% | 94.0323% |
| Binary attack precision | 99.9772% | 99.5415% |
| Binary attack recall | 99.9491% | 99.6424% |
| Benign false-positive rate | 0.00558% | 0.07755% |
| Falsely flagged benign rows/views | 38/681,396 | 729/940,095 |

## Same-cohort width-32 reference comparison

The aligned32_s0 best-validation checkpoint is a TSANet-style width-32 reference retrained on the new data. It shares data and40-epoch budget with the new campaign; it is not the old context checkpoint or an exact paper rerun. Each cell below is reference -> selected pipeline. Typed metrics reflect their respective decision policies.

| Class | Precision % | Recall % | F1 % |
|---|---:|---:|---:|
| Benign | 99.986 -> 99.940 | 99.886 -> 99.922 | 99.936 -> 99.931 |
| Bot | 50.444 -> 54.286 | 97.656 -> 92.031 | 66.525 -> 68.290 |
| Brute Force | 99.632 -> 99.959 | 99.754 -> 99.672 | 99.693 -> 99.815 |
| DDoS | 98.261 -> 99.627 | 99.434 -> 97.220 | 98.844 -> 98.408 |
| DoS | 99.918 -> 99.932 | 99.999 -> 99.960 | 99.958 -> 99.946 |
| Port Scan | 99.941 -> 99.971 | 99.994 -> 99.996 | 99.968 -> 99.983 |
| Web Attack | 79.769 -> 95.385 | 98.571 -> 88.571 | 88.179 -> 91.852 |

Typed macro F1: 93.3004% -> 94.0323%.

## What these numbers establish

- Current Bot typing is the main deployment failure:589 true Bot views and496 benign views receive the Bot label, giving54.29% precision. The old benchmark had504 true Bot and22 benign Bot assignments; cohort differences prevent a direct causal attribution.
- On the same new cohort, selected-pipeline Bot/Web precision improves relative to the width-32 reference, but Bot/Web/DDoS recall declines. Those regressions are retained, not hidden by aggregate accuracy.
- Detection and exact typing are separate: the binary gate flags135/140 Web Attack views (96.43%);124/140 receive the correct Web type (88.57%). Ten flagged Web views remain unknown and one is labeled DoS. Unknowns retain their warning.
- Current Bot, Brute Force, DDoS, DoS, Port Scan and Web binary flag counts are590/640,2434/2442,17366/17840,90054/90084,47687/47688 and135/140 respectively.
- The earlier nearly perfect CSV benchmark did not translate into success in the recorded manual phone scan/login cases. New phone attack sensitivity remains untested; shared extraction fixes a known input mismatch but does not establish detection quality by itself.
- Fine SQL-injection test support is onlytwo views. Do not treat the broad Web family score as proof of reliable detection for every subtype.
- Deployment remains blocked by typed Bot precision and pending final phone validation. Source hashes and exact deltas are preserved in classwise_comparison.json.
