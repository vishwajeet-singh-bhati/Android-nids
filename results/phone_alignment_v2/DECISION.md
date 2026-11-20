# Phone-aligned v2 completion and decision

Completed: 19 November 2026, 09:19:56 IST. All eight jobs finished all40 epochs;320 epoch files, best-validation/best-training-loss/last/final checkpoints are retained. Independent completion_verification.json checks saved-file hashes, original baseline assets, confusion accounting and selected mobile exports.

## Decision

Do not promote this candidate yet. The validation-selected gate_s0 + diagnosis64_s1 passes the configured binary recall/false-positive and per-source gates, but fails the typed Bot precision requirement:54.29% versus the required85%. The phone source/model reattestation and normal-use/manual attack checks are also pending. The installed NIDS0.11.3/code33 and model hashes are unchanged. No new attack or model installation was performed.

The selected binary detector detects158,266/158,834 positive views; it falsely flags729/940,095 benign views. Precision99.5415%, recall99.6424%, F199.5919%, benign FPR0.07755%. These are grouped raw-flow benchmark scores, not phone accuracy or alerts per day.

## Selected complete pipeline

| Class | Precision % | Recall % | F1 % | Support |
|---|---:|---:|---:|---:|
| Benign | 99.94 | 99.92 | 99.93 | 940,095 |
| Bot | 54.29 | 92.03 | 68.29 | 640 |
| Brute Force | 99.96 | 99.67 | 99.82 | 2,442 |
| DDoS | 99.63 | 97.22 | 98.41 | 17,840 |
| DoS | 99.93 | 99.96 | 99.95 | 90,084 |
| Port Scan | 99.97 | 100.00 | 99.98 | 47,688 |
| Web Attack | 95.38 | 88.57 | 91.85 | 140 |

The Bot label has589 true Bot views and496 benign views: the binary gate reduces the earlier standalone diagnosis problem but does not resolve it. These counts establish the error concentration; they do not establish a unique underlying cause. Unknown diagnosis retains its binary alert.

## Matched comparison limitations and regressions

Against the width-32 aligned reference best checkpoint on the same new cohort, the selected pipeline improves Bot precision by3.84 percentage points and Web precision by15.62 points, but reduces Bot recall by5.63 points, DDoS recall by2.21 points and Web recall by10.00 points. Preserve those regressions. This campaign changed extraction/context, architecture, optimization, data sources and splitting; it is not an isolated input-format experiment or a direct comparison with the old CSV99.985% result.

Connection/app/capture grouping prevents the same split group appearing in train and test, but causal unlabeled context crosses partitions; this is not independent-session generalization. Both endpoint views share a group, so row supports are not independent trials. Fine SQL-injection test support is onlytwo views. Android controls have publisher/weak benign labels and recorded corrupt-file exclusions. History caps and unknown/conflicting label exclusions remain in data_report.json.

## Export and deployment status

Both selected ExecuTorch exports matched960 class-balanced cases each with zero decision flips on the work-PC native runtime. Gate:18,913 parameters /82,820 bytes. Diagnosis:173,721 parameters /949,788 bytes. This is desktop native execution, not final Pixel verification. PTEs, fixtures and normalization are under runs/phone_alignment_v2/exports. Model/checkpoint/contract hashes are in mobile_export.json.

Training and final evaluation are complete; no automatic further training is scheduled. Preserve this frozen run and the opened test results. Any further optimization needs a separate declared experiment and fresh assessment rather than retuning and claiming a new blind result. Fix Bot diagnosis/recall tradeoffs and validate final source/weights on the phone before promotion.
