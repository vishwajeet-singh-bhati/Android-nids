# Paper-to-current development record

This file preserves the reasoning behind the current version. Historical benchmark pipelines are comparison stages; there is one current Android application source.

| Stage | What changed | What was learned |
|---|---|---|
| Paper reconstruction | TSANet architecture, cleaning, pruning; stratified 70/30,seed 42 where authors' artifacts were absent | Baseline 97.03%; document assumptions, not exact author-code replication |
| Context extension |78 historical connection features; matched data/split/epoch and model-size controls | Better benchmark numbers; dependence/leakage limits prevent a mobile-accuracy claim |
| Initial phone deployment | Android capture and local inference | Identical feature dimensions did not imply identical units/directions/timing/history |
| Phone-aligned v 2 | Shared Kotlin raw extraction,32+115 inputs, binary gate then diagnosis | Native parity improved; real scans detected but verified Web examples missed |
| Repair v 3 | Alternative weighting/calibration/routing; all fixed epochs retained | Class regressions caused rejection; no deployment |
| Real-phone dataset |20 sessions,1,216 verified request segments;848 train/184 val/184 test; training-only 8-fold replay | No automatic benign labels for background; independently confirm labels and exact native/offline inputs |
| Augmented v 1 | Same architectures/training recipe,6 jobs×40 epochs; validation-selected full cascade |62/64 phone attacks flagged,10/120 normal false flags; readiness failed |
| Code 37 trial | Explicit user request, exported/hash-verified augmented model installed experimentally | Useful Web/scan detections coexist with misses and benign false positives |
| Protocol campaign | Actual FTP/SSH, restricted emulator, dummy-resource DoS and 3-sourceDDoS | Transport/effects verified; normal SSH false alarms and missed classes remain |
| Code 38/39 | Immediate factual note, checked Llama guidance, persistent worker/reset, bounded callbacks | Warm real IPC~3.69 s; rejected smaller model/E 8/boot-warmup alternatives documented |
| Code 40 | Local loopback scope, ownership correction, preserved history | Repeated idle alerts stop; normal external SSH remains unfixed |

The full report contains preprocessing, class counts/splits, architecture shapes, dry runs, all comparisons, negative results and reproducibility limits. [Read the report](project_report/README.md), [paper-only professor summary](PAPER_AND_CONTEXT.md), and [results index](../results/README.md).

Git history retains the previously published source/report. `models/current` identifies the current weights; `models/references/aligned_v2` is solely the old comparison reference. Original source hashes and portability changes are recorded in `reproducibility/SOURCE_SNAPSHOT.json`. Workstation datasets, raw evidence, checkpoint history and rollback APKs remain local. They are not reconstructed from aggregate reports.

No later test was silently inserted into an earlier frozen cohort. Code 40's scope correction is not a retrained model or an accuracy gain. Later context-dependent changes in flags cannot be causally credited to it without a paired test. No accepted daily false-positive or production-readiness claim exists.
