# Phone real-capture v1 datasheet

## Methodology references

The [CIC-IDS2017 methodology](https://www.unb.ca/cic/datasets/ids-2017.html) motivates retaining captures, traffic/background diversity, attack metadata and labels tied to network identities and time. This implementation uses its own frozen phone extractor, not a claim of CICFlowMeter feature equivalence.

[Arp et al., USENIX Security 2022](https://www.usenix.org/conference/usenixsecurity22/presentation/arp) discusses sampling/label bias, data snooping, spurious correlations, baselines, measures and lab-only evaluation. The safeguards below are our project-specific implementation choices, not a claim of certification or a universal dataset standard.

## Intended use and coverage

Train an updated version of the existing lightweight binary gate and seven-family diagnosis model by supplementing the original training split. First collection focuses on real controlled cleartext HTTP credential guessing, password spraying, SQL injection and XSS on the owned Pixel6a. Spraying is a new fine subtype within Web Attack; the output families remain unchanged.

Controlled negatives include successful/incorrect logins, normal searches containing code-like text, safe pages of varied lengths, ordinary503responses and legitimate HTTP bursts. Positive and negative activity share the target app/services and have varied request/response lengths. No class/ground-truth headers are sent. Session-specific socket identities and confirmation events remain out-of-band.

No new Bot, distributed DoS, FTP/SSH or encrypted application-attack coverage is claimed. Fixed beacons/load probes do not supply those labels. Existing firewall and managed environment policy remain unchanged.

## Instrumentation and quality

- Separate target `nids.datasetlab`0.1.0; disposable in-memory database/accounts, isolated WebView with network/file access blocked, exact work-PC peer restriction,15-minute/1,024-connection cap. APK hash is checked against the installed package before each recording.
- The current NIDS0.12.2/code36 and both v2 weights stay installed. No feature implementation, cutoffs or original datasets are changed during capture.
- Sidecar records phone `any` interfaces at snaplen768 into a local phone file. Bulk PC transfer happens after capture stops, avoiding a streamed-capture feedback loop over wireless ADB. Maximum100,000records/session; an early stop/cap hit rejects the session.
- Restart diagnostic monitor state only after backing up its trace; retain activity SQLite/Llama. Warm340seconds (300s history+30s flow span+margin). Only known controlled requests are eligible for labels; background stays unlabeled.
- Raw capture container integrity, hash-verified transfer, zero kernel drops, healthy native/collector queues and exact per-tuple packet counts are required. Bounded parsing may omit unsupported/truncated evidence exactly as the deployed parser does; parser counters remain recorded.
- Replay uses the frozen v2 core JAR and the same watched phone addresses. Its start boundary is the earliest native observed TCP/UDP flow start, independent of labels/scores/error. This is necessary because sidecar and app start at different times and persistent TCP segmentation phase does not wash out with warm-up.
- All147eligible native/offline values must match within1e-4; no tolerance relaxation or label-driven row removal. Record exact input/label conflicts for review. An unconfirmed effect or ambiguous socket mapping rejects the intended positive example/session instead of inventing proof.

## Ground truth and limits

Controller records actual TCP endpoints/ports and intended action. Target independently records matching connection IDs, requests, responses and SQL/XSS effects or login outcomes. SQL/XSS positives require actual isolated effects; credential attack labels refer to verified controlled attack attempts, not successful compromise. Normal failures remain normal when they belong to the declared normal action. Labels never come from NIDS scores.

Mixed sessions include ordinary requests during attack history. Per-flow labels describe the current controlled request; reports retain session context and separately expose clean benign-only sessions. The same network evidence can be ambiguous about intent; a larger corpus cannot guarantee perfect discrimination. Background app activity is not labeled Benign merely because no test attack was scheduled.

## Split and sampling

Freeze20sessions before collection:14train (10mixed/4benign),3validation (2mixed/1benign),3test (2mixed/1benign). Train then validation then test chronologically, with predeclared held-out SQL/XSS forms/rate ranges. Keep complete sessions, flows, retransmissions and context in one partition. This is same-phone/same-app session generalization, not an unseen-day/device/network test. Dataset quality checks inspect identities/ground truth/features; held-out model scores are not reviewed for selection.

Planned controlled requests:1,216, comprising768normal and448attack attempts/effects; native segment counts may differ. Earlier11diagnostics, all smokes and the56-request development pilot are excluded from actual model fitting and final test. Original train/validation/test membership is preserved.

Only new training rows receive8-fold exact replay so a few phone sessions are not drowned by the original4.96million rows. This is declared resampling, not8times as many independent observations or fabricated data. Validation/test are not resampled. Normalization is fitted only on the combined training partition. Combined group overlap is checked explicitly.

## Training/evaluation and retention

Three seeds for each unchanged gate/diagnosis architecture;40epochs, two concurrent local jobs, every epoch/best/last/final checkpoint retained. Report the small update-count increase from added rows. Complete gate+diagnosis pairs/cutoffs are selected on validation; freeze checkpoint hashes before opening final model test predictions.

Report frozen-v2 and updated-model results separately on original and new phone cohorts, classwise support/precision/recall/F1, fine subtypes, unknowns and per-session flags. Source-normal FPR guards are selection criteria, not a proven population false-positive guarantee. Short, correlated lab sessions do not establish daily false-alert rates or general mobile accuracy. No automatic model deployment follows this experiment; native execution and further independent assessment remain required.

Raw packets, dummy account metadata, target/controller events, traces and resumable jobs stay on this work PC under `runs/` and `data/`. Public local reports contain provenance hashes/counts. No upload or GitHub push. Interrupted/rejected captures are retained for review; accepted recordings and completed epoch checkpoints support resume. An interrupted capture requires review before reuse and is never silently overwritten.
