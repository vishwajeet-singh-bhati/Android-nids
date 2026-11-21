# Result validity audit - 19 November 2026

**Verdict:** the historical context-pruned-30 score is numerically reproducible. Its random-row test is dependent on training traffic and does not establish accuracy on independent attack sessions, new devices or real phone attacks. Direct label/scaler/future-history leakage was not found in the checks below; this is not an exhaustive certificate of leakage freedom.

## Scope and reproducibility

CPU-only independent checks of the frozen TSANet reproduction/context benchmark, plus a separate audit of the newer phone-aligned v2 data reused by the running v3 repair. No original dataset, weights, split, threshold, training source or installed app was changed. Existing GPU repair jobs continued separately.

Machine-readable evidence: [historical audit](audit.json), [post-hoc subsets](dependency_subsets.json), [historical endpoint coverage](host_novelty.json), [phone-aligned cohort audit](aligned_cohort_audit.json). Original model/ready-manifest hashes are recorded in these files. Prediction agreement audits execution; it does not prove that a dataset label describes a real successful attack.

## 1. Numerical and direct leakage checks

| Check | Measured outcome | Limit |
|---|---|---|
| Replay frozen context-pruned-30 on every test row, CPU | 848,349 predictions; zero differences; published confusion identical; accuracy 99.985029746% | Same opened benchmark, not new generalization data |
| Row-ID overlap | Zero train/test intersections | Different IDs may still describe dependent traffic |
| Flow and context scaler refit | All training rows; mean/scale maximum error 0 | Does not remove dependence between rows |
| Independent direct history reconstruction | 1,200 queries; 93,600 feature values; maximum error 0 | Sampled reference, not every query |
| History event references in that reconstruction | 67,796,128 uses; zero held-out-bank, future or self rows | Repeated uses are not independent observations |
| Source inspection | No target labels/predictions in context; literal IP/port/time identifiers excluded from model tensors | Aggregate traffic patterns can still encode lab identity/time |
| Integrity | Four selected original ready/freeze/checkpoint artifacts unchanged across audit | This is the recorded artifact set, not a hash of every file |

The history bank is restricted to training rows and strictly prior, definitely completed events. However, model fitting uses randomly selected rows throughout each capture. **Every test query has a later same-day training row.** Past-only feature construction therefore does not make this a forward-in-time learning experiment.

## 2. Confirmed dependence in the historical test

- **99,678/848,349 (11.7496%)** test rows exactly match a training row across all **110** input values. Hash candidates were followed by direct float-vector equality; zero rejected collisions. No cross-label full-vector matches were found in this test-to-train check.
- **277,034/848,349 (32.6557%)** test rows match all original **32** flow values. Equality of features does not establish identical complete packets or captures.
- **552,341/848,349 (65.1078%)** test rows share a same-day bidirectional endpoint/port/transport-bucket tuple with training. The bucket is TCP/UDP/other as available in the extracted metadata; this is not exact TCP-session identity, and ports can be reused.
- All capture days appear in training. Source endpoints are seen in training for **99.9834%** of test rows; destinations for **99.9592%**.
- **Every attack source and destination endpoint is already present somewhere in training.** Only Benign has unseen endpoints (141 source rows and 346 destination rows). These are endpoint occurrences, not counts of unique new devices.

| Class | Test rows | Exact 110-input matches | Match rate % |
|---|---:|---:|---:|
| Benign | 681,396 | 34,949 | 5.1290 |
| Bot | 587 | 35 | 5.9625 |
| Brute Force | 4,150 | 686 | 16.5301 |
| DDoS | 38,407 | 1 | 0.0026 |
| DoS | 75,514 | 16,961 | 22.4607 |
| Port Scan | 47,641 | 47,046 | 98.7511 |
| Web Attack | 654 | 0 | 0.0000 |

Port Scan's **98.7511%** feature-match rate is especially problematic for an independent-pattern claim. It is not proof that its entire score is caused by memorization.

## 3. Does accuracy disappear after excluding matching inputs?

No. Frozen predictions on descriptive subsets give:

| Same opened test, restricted after evaluation | Rows | Accuracy % | Macro F1 % | Benign FPR % |
|---|---:|---:|---:|---:|
| Original full test | 848,349 | 99.985030 | 98.602829 | 0.005577 |
| No identical 110-input training vector | 748,671 | 99.983037 | 98.429089 | 0.005878 |
| No identical 32-flow-input training vector | 571,315 | 99.980746 | 97.898657 | 0.006363 |
| Same-day canonical tuple absent from training | 296,008 | 99.966217 | 95.406532 | 0.009897 |

This shows that exact duplicate inputs alone do not explain the high score. **These subsets are not newly trained independent tests**: the weights still saw the other training rows from the same lab campaigns, hosts and periods. The tuple-unseen subset also has only **three DoS rows**; its macro F1 is sensitive to this changed support. Bot recall there is **74.49% (219/294)**, versus **85.86% (504/587)** on the full test. These are descriptive subgroup differences, not an estimate of the effect of changing the split.

## 4. Shortcut and context-reliance diagnostics

A training-label majority lookup using **excluded metadata** achieves **93.6710% accuracy / 50.3539% macro F1** with a 15-minute time bin, and **98.4910% / 92.0309%** with time bin plus endpoint pair. These probes diagnose predictable lab scheduling/topology. The actual model does not directly receive these keys; probe performance does not prove it uses those shortcuts.

On the same stratified capped subset of 25,391 test rows, frozen context-model accuracy is **99.6652%** normally, **40.6246%** with normalized context zeroed, and **19.6211%** with context shuffled. This confirms sensitivity to context disruption. These are input interventions on an already trained model, **not retrained controls or proof of leakage**. The original equal-capacity, retrained zero-context arm remains the appropriate architecture/control comparison.

## 5. Newer phone-aligned cohort: checked separately

The v2 extraction/147-input/grouped split is a different experiment. Its scores cannot measure the isolated effect of changing input format relative to the historical CSV benchmark. V3 reuses that cohort, so its eventual results inherit the cohort limitations.

- Independently confirmed **zero connection-group overlap** for train/validation, train/test and validation/test. Both endpoint views and segments remain grouped according to the declared day/tuple contract; a tuple group is not a whole attack campaign.
- Independently refit all **4,956,674 training rows** for normalization. Maximum mean error **1.193e-9**, maximum scale error **1.660e-9**, consistent with platform rounding; no validation/test scaler fitting indicated.
- Exact full **147-input** matches to training: **24,261/1,188,724 validation rows (2.0409%)** and **28,730/1,098,929 test rows (2.6144%)**. Direct equality checked; zero rejected hash candidates. Distinct connection groups can produce identical features.
- Test full-vector matches: Benign **26,266**, Bot **20**, DoS **2,444**; Brute Force, DDoS, Port Scan and Web **0** each. This is much less Port Scan overlap than the old test, but the cohorts differ.
- All attack watched-host identifiers are seen in training; **38,796 test Benign views** have unseen watched-host identifiers. This does not establish novel-device attack performance.
- Unlabeled history is computed chronologically before group partitioning, so earlier observations from other partitions can enter a query. There is no target label input. This is a declared **shared-stream** evaluation, not isolated held-out-capture history. Such updates can be legitimate for a specified online protocol; their visibility and chronological availability must be reproduced in deployment.
- Prior independent saved-model diagnostics reproduce the final confusion and check sample normalization/native export parity; see [drop analysis](../phone_alignment_v2/DROP_ANALYSIS.md). Typed Bot precision remains **54.29%**, a failed deployment target. These are not validated real-phone attack results.
- That final test has already informed repairs. New v3 comparisons are **development comparisons on an opened test**, even if v3 checkpoint selection itself uses calibration/selection only. They cannot be renamed a new blind final evaluation.

Earlier v5 and v6 final sets were also opened for diagnostics, and their documented deployment gates failed. This audit does not newly replay every historical candidate; see their preserved [v5 decision](../robust_v5_audit/DECISION.md) and [v6 results](../cascade_v6/RESULTS.md). Do not reuse them as untouched external tests.

## 6. What is still required

1. Freeze a new prospective protocol before looking at new outcomes. Keep the existing numbers as historical/development evidence, including failures.
2. Group all views/segments of a connection and related campaign together; audit exact and near-duplicate families before partitioning. Repeated feature vectors are not automatically repeated packets; declare how ambiguous groups are handled rather than silently deleting difficult labels.
3. Use independent later sessions/campaigns and, where possible, new devices. For time-block evaluation, purge boundary-spanning flows and embargo at least the maximum history horizon (900 seconds for the original extension, 300 seconds for v2), or explicitly declare an online warm-history protocol without future fitting. Fit transformations/weights only on the preceding training period.
4. Keep validation/calibration separate from one fresh final set. Same budget and paired seeds for flow-only, context-only, equal-capacity and window/visibility ablations; include strong simple tree/MLP baselines. Report 3-5 seeds and intervals resampled by independent episode/group, not millions of correlated rows.
5. Report class/subtype support and absent classes. Holding out a CIC day may remove an entire attack family from training; this cannot be presented as ordinary seven-class closed-set testing. SQL with two current test views cannot support a reliability claim.
6. Add representative normal phone activity and independently verified, manually user-launched controlled attack episodes. Report episode detection, false alerts per observation time, delay, app attribution, and extractor/model CPU/memory/battery cost. A benchmark FPR is not a measured phone false-alerts/day rate.

## Reproduce locally

Use the existing WSL training environment (it includes PyTorch, pandas and scikit-learn); no installs, downloads, GPU jobs or phone access are needed:

```powershell
cd <PROJECT_ROOT>
wsl -e <PROJECT_ROOT>/.venvs/traffic-pretrain/bin/python <PROJECT_ROOT>/validation/audit_tsanet_result_validity.py
wsl -e <PROJECT_ROOT>/.venvs/traffic-pretrain/bin/python <PROJECT_ROOT>/validation/analyze_tsanet_dependency_subsets.py
wsl -e <PROJECT_ROOT>/.venvs/traffic-pretrain/bin/python <PROJECT_ROOT>/validation/audit_aligned_result_validity.py
```

The complete historical CPU replay takes time. Reports are small/versioned; metadata and hash caches stay under ignored `runs/publication_validity_audit`. This audit does not install anything or launch test traffic.
