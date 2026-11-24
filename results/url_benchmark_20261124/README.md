# User URL benchmark - 24 November 2026

**2,048/2,048 unique URLs checked sequentially on the physical Pixel 6a**, using installed Rakshak code46 URL assets. Zero inference/input failures. No destination was opened, SMS sent, app warning generated or user history cleared. Only the test APK changed; deployed app weights, thresholds, preferences and version stayed unchanged. The monitor was disabled before the benchmark and remained disabled. Temporary URL input/output files were removed from the phone after private PC results were saved.

## Full deployed detector

| Outcome | URLs |
| --- | ---: |
| PHISHING | 325 |
| LIKELY_SAFE | 1,581 |
| UNCERTAIN | 142 |
| Failed/invalid | 0 |

Of325 phishing decisions, **271 came from saved threat intelligence and54 from the learned ensemble**. All inputs were full URLs. The measured total native run was9.417s. Per-row mean4.215ms, median3.940ms, p95 5.307ms; the first row703.793ms includes cold model initialization. These timings are detector-only, excluding SMS delivery, notification and Llama. Diagnostic forced scoring has separate timings and is not production latency.

## Input provenance and reference reuse

Input SHA256: `4285970866bd6812c27b2d68b18a09049425a63541d71e95d21e5f8ddf045f59`.

All2,048 URLs, in the same order, exactly match the **first2,048 inputs in the supplied URL model reference JSONL**. That reference records expected predictor outputs, not true phishing/benign labels. Using its outcomes as labels would be circular. They have already appeared in export/integration regression checks, so this is not a newly untouched test set. Original training/calibration overlap cannot be established from the supplied artifacts. There are1,033 unique hosts.

## Independent evidence labeling

Downloaded current public feeds without sending benchmark URLs to third parties:

- [PhishTank online-valid feed documentation](https://phishtank.net/developer_info.php):42,758 verified/online records, downloaded24 November IST. The HTTP Last-Modified timestamp was23 November21:21:50 UTC.
- [OpenPhish Community feed](https://www.openphish.com/phishing_feeds.html):300 entries.

Strict complete-string URL matching confirmed **218 phishing URLs**, all from PhishTank. OpenPhish added no exact matches. The218 URLs span184 hosts. The other **1,830 remain UNKNOWN**; there are **zero independently confirmed benign labels**. No model outputs, URL appearance, popular-site list, host-only matches or lack of feed entries were used as benign truth. Feed hashes, retrieval timestamps and row counts are in [results.json](results.json); private per-row annotations are under ignored runs.

Evidence-label coverage is **10.64%**. These feed labels support a known-positive subset, not full two-class evaluation. Feed records themselves may have errors and selection bias; they are not an exhaustive independent audit of live website behavior.

## Results on those218 known-positive URLs

| Detector/view | PHISHING | UNCERTAIN | LIKELY_SAFE | PHISHING detection rate |
| --- | ---: | ---: | ---: | ---: |
| Deployed model + lists/rules | 218 | 0 | 0 | 218/218 =100% |
| Learned ensemble before list/rule override | 172 | 30 | 16 | 172/218 =78.90% |

All218 deployed positives were **saved-list hits**, so100% here is a list-hit result, not an independent model-accuracy result. A second native diagnostic pass forced model scoring even for URLs production normally resolves by lists. Its final pipeline decisions matched the production pass on all2,048 rows, while exposing the underlying ensemble outcome.

For the learned ensemble's known-positive subset, counting UNCERTAIN as not detected: **TP172, FN46, recall78.90%, false-negative rate21.10%**. Of46 misses,30 were uncertain and16 scored likely safe. Excluding uncertain cases would yield172/188 =91.49%, but only86.24% decisive coverage; that selective result must not replace the primary recall.

**Full-file accuracy, precision, F1, specificity, false-positive rate, NPV, balanced accuracy, MCC, ROC-AUC and PR-AUC are not established.** They require independently supported negative labels and/or both classes. The325 total warnings cannot all be called true positives:107 have unknown truth. Similarly, the1,581 likely-safe verdicts cannot be called true negatives. Positive-only accuracy/precision/F1 fields are deliberately null in the scoring tool.

The source reference reuse and missing original split provenance also prevent claims of unseen-data generalization. No thresholds or weights were fitted on this benchmark.

## Reviewable local artifacts

- `runs/url_benchmark_20261124/comparison.csv`: every input URL in original order, evidence label/source, deployed verdict, raw ensemble verdict/score and timing.
- `runs/url_benchmark_20261124/labels.csv`:218 evidence-supported positives and1,830 unknowns.
- `runs/url_benchmark_20261124/confirmed_phishing_raw_misses.csv`:46 known-positive URLs the learned ensemble did not classify PHISHING.
- `runs/url_benchmark_20261124/results.jsonl` and `forced_model/results.jsonl`: native per-row outputs.
- `runs/url_benchmark_20261124/label_evidence`: private downloaded feed snapshots/provenance.

Raw URLs, datasets and feed snapshots are not committed. The public [aggregate results](results.json) retain hashes, counts, timings and explicit limitations.

## Reproduction

Build/install only the instrumentation APK against the same installed app version. The normal app is not upgraded by these commands.

```powershell
./android/gradlew.bat -p android :app:assembleDebugAndroidTest
adb -s <serial> install -r android/app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk
python validation/benchmark_phone_urls.py --input D:/Downloads/benchmark_urls.txt --serial <serial> --output runs/url_benchmark_20261124
python validation/label_url_benchmark.py --input D:/Downloads/benchmark_urls.txt --output runs/url_benchmark_20261124 --fetch
python validation/benchmark_phone_urls.py --input D:/Downloads/benchmark_urls.txt --serial <serial> --output runs/url_benchmark_20261124 --labels runs/url_benchmark_20261124/labels.csv --rescore
python validation/benchmark_phone_urls.py --input D:/Downloads/benchmark_urls.txt --serial <serial> --output runs/url_benchmark_20261124/forced_model --labels runs/url_benchmark_20261124/labels.csv --force-model
python -m unittest validation.test_url_benchmark_metrics
```

Feed snapshots change over time; use saved hashes/snapshots to reproduce these exact labels. The metric checks cover balanced confusion counts, uncertain-as-missed policy, abstention coverage and prevention of fabricated negative/single-class accuracy estimates. Four metric tests and both complete native passes succeeded.
