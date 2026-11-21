# Repair versus preserved phone-aligned v2

Matched fixed v2 rows/features/model sizes/40 epochs, controlled loss/sampling; joint routing/calibration learned on disjoint validation subgroups. Existing test is opened development data; phone evaluation pending.

Repair better by prespecified validation+test checks: False. Intended deployment: preserved_v2. No installation executed; native/phone/resource/manual checks remain.

| Class | V2 precision % | Repair precision % | V2 recall % | Repair recall % | V2 F1 % | Repair F1 % | Support |
|---|---:|---:|---:|---:|---:|---:|---:|
| Benign | 99.940 | 99.962 | 99.922 | 99.968 | 99.931 | 99.965 | 940,095 |
| Bot | 54.286 | 79.755 | 92.031 | 60.938 | 68.290 | 69.088 | 640 |
| Brute Force | 99.959 | 99.918 | 99.672 | 99.672 | 99.815 | 99.795 | 2,442 |
| DDoS | 99.627 | 99.423 | 97.220 | 99.540 | 98.408 | 99.482 | 17,840 |
| DoS | 99.932 | 99.923 | 99.960 | 99.999 | 99.946 | 99.961 | 90,084 |
| Port Scan | 99.971 | 99.966 | 99.996 | 99.996 | 99.983 | 99.981 | 47,688 |
| Web Attack | 95.385 | 91.791 | 88.571 | 87.857 | 91.852 | 89.781 | 140 |

| Metric | Preserved v2 | Selected repair |
|---|---:|---:|
| Binary precision | 99.54150% | 99.81043% |
| Binary recall | 99.64239% | 99.77650% |
| Binary benign_fpr | 0.07755% | 0.03202% |
| Typed macro F1 | 94.0323% | 94.0076% |
| Diagnosis routing | 14.468% | 14.567% |

Comparison failures: macro_f1_gain, Bot_typed_recall_regression, Web Attack_typed_precision_regression, Bot_binary_recall_regression, Web Attack_binary_recall_regression.

All arms use unchanged labels. No new verified application ground truth or independent attack sessions were invented. SQL support remains too small. Better offline numbers do not establish device accuracy. All720 training epochs and validation prediction snapshots are retained.
