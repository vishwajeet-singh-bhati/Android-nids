# Rakshak

[![Reproducibility checks](https://github.com/vishwajeet-singh-bhati/rakshak/actions/workflows/checks.yml/badge.svg)](https://github.com/vishwajeet-singh-bhati/rakshak/actions/workflows/checks.yml)

An Android research app for **network intrusion, SMS scams and phishing links**, with immediate factual warnings and checked local Llama guidance. Current source: **0.17.3-link-extraction / code46**. This is a development/submission draft, not a claim of complete protection or final mentor approval.

## Start here

| Goal | Documentation |
|---|---|
| Submission requirements, deadline and remaining gates | [Submission checkpoints](SUBMISSION_CHECKPOINTS.md) |
| Current state and measured limits | [Status](STATUS.md) |
| Separate SMS, URL and integration sections | [Component index](components/README.md) |
| Architecture from input to output | [Model architecture](docs/rakshak/architecture/README.md) |
| Install and use all three detectors | [Rakshak guide](docs/rakshak/README.md), [Android setup](docs/ANDROID_SETUP.md) |
| Full methodology, history, results and optimization | [Report PDF and Overleaf source](docs/project_report/README.md) |
| SMS training, data splits, PTQ/QAT and archived classwise results | [SMS component](components/sms/README.md) |
| URL training, inference, feed setup and benchmark limits | [URL component](components/phishing_url/README.md) |
| Shared notifications, Llama and privacy | [Integration](components/integration/README.md) |
| Network training and controlled phone testing | [Reproduction](docs/REPRODUCING_RESULTS.md), [phone tests](docs/PHONE_TESTING.md), [protocol tests](docs/PROTOCOL_TESTING.md) |
| Candidate improvement and acceptance plan | [Model improvement plan](docs/MODEL_IMPROVEMENT_PLAN.md) |

## What runs on the phone

- **Network:** rooted packet capture ->147 connection/history features -> binary gate -> diagnostic type -> warning. Known normal-traffic false positives and missed protocol classes remain.
- **SMS:** consented new carrier SMS -> normalization/evidence/word classifier -> selective INT8 MobileBERT-22 -> risk policy. No inbox/RCS/WhatsApp reader; share/paste supports other messages.
- **URLs:** links are automatically extracted from incoming SMS and checked before deeper SMS analysis. Character CNN + n-gram model + local rules return phishing, likely safe or uncertain. Bare links do not go through SMS semantics of a placeholder. No link means no URL inference.
- **Explanations:** immediate What happened / What you can do; optional local Llama rephrases approved guidance. It does not decide risk or receive raw SMS/OTPs/full private URLs.

The three detector switches are independent. Enable **Automatically check incoming SMS and links**, grant SMS/notification permissions and leave URL detection enabled for automatic message-link checks. Network root is not required for SMS/URL inference. The APK has no INTERNET permission and does not visit submitted URLs.

## Reproduce the app

Use Java21 and Android SDK34 with platform-tools on PATH.

    ./android/gradlew -p android :app:assembleDebug :app:assembleDebugAndroidTest
    adb -s YOUR_DEVICE_SERIAL install -r android/app/build/outputs/apk/debug/app-debug.apk
    python validation/validate_rakshak.py --serial YOUR_DEVICE_SERIAL --install

On Windows use android/gradlew.bat. The public build ships a valid **empty threat database** to avoid redistributing downloaded feeds. Model inference works; to add local list coverage, use the [feed setup instructions](components/phishing_url/README.md). Historical218/218 list hits require the original permitted snapshot and cannot be claimed from the empty public database.

Small deployed model artifacts and the selected SMS FP32 checkpoint are provided with provenance. Optional1.06GiB Llama weights are separately downloaded under their license using the [Android setup](docs/ANDROID_SETUP.md). No dataset, private capture/message, credentials, source archive or project ZIP is included.

## Results without inflated claims

| Evidence | Finding | Limit |
|---|---|---|
| Archived869-row SMS PTQ export test | Accuracy97.12%; smishing precision78.57%, recall89.80% | Archived classifier result; reused test, not new Android warning accuracy |
| Pixel SMS regressions |14/14 neural classes and230 authored scenario checks | Strict logit tolerance still fails; synthetic checks are not real-world accuracy |
|2,048-URL Pixel benchmark |325 phishing,1,581 likely safe,142 uncertain;0 failures | Inputs duplicate export references;1,830 labels unknown |
|218 externally supported phishing URLs | Raw model172 detected,30 uncertain,16 likely safe | Conditional positive-subset recall78.90%; no full-file precision/accuracy |
|Same218 with measured saved lists |218 flagged by list hits | List coverage, not independent learned-model accuracy; public default database is empty |
|Current network held-out development data |TP62/64, FP10/120 | Limited development cohort; readiness failed and protocol misses remain |

See [URL evidence](results/url_benchmark_20261124/README.md), [SMS archive provenance](components/sms/provenance/ARCHIVED_EVALUATION.json), [phone corrections](results/sms_followup_20261124/README.md) and the report before using these numbers.

## Repository structure

    android/                 Current app, shared network features and isolated labs
    components/sms/          SMS source, checkpoint, training/export provenance
    components/phishing_url/ URL source, learned models and local feed setup
    components/integration/  Combined routing and shared explanations
    experiments/             Original network paper/context/alignment/augmentation
    models/                  Network references and optional Llama manifest
    results/                 Aggregate evidence; no raw datasets/captures
    docs/                    Setup, architectures, improvement plan and report
    tools/                   Report generation and local feed preparation
    validation/              Native checks, URL evaluation and controlled tests
    reproducibility/         Portable configuration and source/model identities
    SUBMISSION_CHECKPOINTS.md Draft-to-review-to-submission gates

Run python -m pytest tests -q and python -m unittest validation.test_url_benchmark_metrics for dataset-free checks. Earlier network and SMS results retain their original cohorts; do not combine them into one app-accuracy percentage. Source licenses and missing provenance limits are documented per component.
