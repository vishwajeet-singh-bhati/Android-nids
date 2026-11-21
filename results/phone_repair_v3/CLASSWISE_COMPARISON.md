# Preserved v2 versus selected repair: classwise comparison

Same opened development test: **1,098,929 flow views**, comprising **940,095 Benign** and **158,834 attack-labeled views**. Counts are views, not independent attacks/devices. Both use the same 147-input cohort, model dimensions and 40-epoch budget. The repair also changes calibration/routing under the frozen protocol.

**V2:** gate_s0 + diagnosis64_s1. **Selected repair:** unweighted_gate_s2 epoch40 + unweighted_diagnosis_s2 epoch39. These were selected using validation, not swapped after viewing test outcomes.

## Attack-type identification

Precision: among views assigned this type, how many have that true label. Recall: among views with this true label, how many get that exact final type. F1 balances precision/recall. An alert with unknown or wrong type does not count as a correct identification. All metric values are percentages; deltas are percentage points.

| Class | Test views | V2 precision | Repair precision | V2 recall | Repair recall | V2 F1 | Repair F1 | F1 delta pp |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Benign | 940,095 | 99.940 | 99.962 | 99.922 | 99.968 | 99.931 | 99.965 | +0.034 |
| Bot | 640 | 54.286 | 79.755 | 92.031 | 60.938 | 68.290 | 69.088 | +0.798 |
| Brute Force | 2,442 | 99.959 | 99.918 | 99.672 | 99.672 | 99.815 | 99.795 | -0.020 |
| DDoS | 17,840 | 99.627 | 99.423 | 97.220 | 99.540 | 98.408 | 99.482 | +1.073 |
| DoS | 90,084 | 99.932 | 99.923 | 99.960 | 99.999 | 99.946 | 99.961 | +0.015 |
| Port Scan | 47,688 | 99.971 | 99.966 | 99.996 | 99.996 | 99.983 | 99.981 | -0.002 |
| Web Attack | 140 | 95.385 | 91.791 | 88.571 | 87.857 | 91.852 | 89.781 | -2.071 |

## Binary alert detection, regardless of assigned type

A view counts as detected whenever the complete pipeline raises an attack flag. Its type can be correct, wrong or unknown. This is different from exact-type recall above.

| True class | V2 detected / total | V2 detection % | Repair detected / total | Repair detection % | V2 missed | Repair missed |
|---|---:|---:|---:|---:|---:|---:|
| Bot | 590 / 640 | 92.188 | 391 / 640 | 61.094 | 50 | 249 |
| Brute Force | 2,434 / 2,442 | 99.672 | 2,436 / 2,442 | 99.754 | 8 | 6 |
| DDoS | 17,366 / 17,840 | 97.343 | 17,759 / 17,840 | 99.546 | 474 | 81 |
| DoS | 90,054 / 90,084 | 99.967 | 90,083 / 90,084 | 99.999 | 30 | 1 |
| Port Scan | 47,687 / 47,688 | 99.998 | 47,686 / 47,688 | 99.996 | 1 | 2 |
| Web Attack | 135 / 140 | 96.429 | 124 / 140 | 88.571 | 5 | 16 |

## Overall comparison

| Metric | Preserved v2 | Selected repair |
|---|---:|---:|
| Binary precision | 99.54150% | 99.81043% |
| Binary recall | 99.64239% | 99.77650% |
| Binary F1 | 99.59192% | 99.79346% |
| Benign false-positive rate | 0.07755% | 0.03202% |
| Typed macro F1 | 94.0323% | 94.0076% |
| Benign false alerts / 940,095 | 729 | 301 |
| Missed attack-labeled views / 158,834 | 568 | 355 |

## Interpretation

- Benign false alerts drop **729 -> 301** (428 fewer, **58.71% reduction**). Benign views assigned Bot drop **496 -> 99**, while correctly identified Bot views drop **589 -> 390**.
- Bot is the major regression: binary misses increase **50 -> 249**, and exact-type recall falls **31.094 pp**. Improved precision does not compensate for rejecting many more true Bot examples.
- DDoS improves: binary misses **474 -> 81**; exact-type recall **97.220% -> 99.540%**. DoS also improves; Brute Force and Port Scan typing are nearly unchanged.
- Web gets worse: binary misses **5 -> 16**, typed precision **95.385% -> 91.791%**, typed F1 **91.852% -> 89.781%**. Only 140 Web views are present; SQL subtype support remains two views, not enough for a reliability claim.
- Total missed positive views decrease **568 -> 355** because gains in larger families outweigh losses in Bot/Web. Aggregate recall therefore hides important family regressions; typed macro F1 declines slightly.

**Decision:** repair fails the prespecified validation and test comparison. Preserve v2 as the user-requested fallback; this does not mean v2 has passed production-readiness or fresh phone evaluation. No installation or attack traffic occurred.

These are development scores on the already-opened v2 test. Shared-stream/host/campaign and feature-overlap limitations remain; see [validity audit](../publication_validity_audit/AUDIT.md). Independent phone attack accuracy is not established.

## Evidence

- Frozen numeric source: [evaluation.json](evaluation.json), SHA256 `e4db74746365fc06bda1f7e4f8b5db52c8978019ec410247ad76da8084a978ad`.
- [Original comparison](COMPARISON.md), [completion verification](completion_verification.json), [native export checks](mobile_export.json).
