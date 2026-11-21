# Android NIDS

[![Reproducibility checks](https://github.com/vishwajeet-singh-bhati/Android-nids/actions/workflows/checks.yml/badge.svg)](https://github.com/vishwajeet-singh-bhati/Android-nids/actions/workflows/checks.yml)

An Android research prototype: capture phone-visible TCP/UDP traffic, extract connection statistics and recent history, use a lightweight binary detector, diagnose flagged connections, and show immediate facts with checked local Llama guidance.

**Current source: `0.14.2-network-scope` / code 40.** The included detector is the real-phone-augmented v 1 gate/diagnosis, with 147 inputs and cutoffs **0.5408333333 / 0.8**. It is installed for experimental evaluation and **has not passed normal-use readiness**. The old code 36 source remains in Git history; its frozen inference reference is retained only for scientific comparison.

## Start here

| Goal | Guide |
|---|---|
| Follow the entire project from the paper | [Complete report and Overleaf source](docs/project_report/README.md) |
| Understand the latest state and remaining issues | [Status](STATUS.md), [development history](docs/DEVELOPMENT_HISTORY.md) |
| Understand current inputs, architectures and outputs | [Current pipeline](docs/CURRENT_PIPELINE.md), [model card](models/current/MODEL_CARD.md) |
| Build/install on an owned rooted phone | [Android setup](docs/ANDROID_SETUP.md) |
| Reproduce paper, context, aligned and augmented experiments | [Reproduction](docs/REPRODUCING_RESULTS.md), [datasets](docs/DATASETS.md) |
| Run bounded HTTP/scan tests manually | [Phone testing](docs/PHONE_TESTING.md) |
| Repeat FTP/SSH, emulator and three-source resource tests | [Protocol testing](docs/PROTOCOL_TESTING.md) |
| Review measured results and caveats | [Results index](results/README.md) |
| Reproduce inference experiments | [Inference measurements](docs/INFERENCE_PERFORMANCE.md) |
| Review change history and software checks | [Changelog](CHANGELOG.md), [validation](reproducibility/VALIDATION.json) |

## Layout

```text
android/          Current app, shared Kotlin features, isolated labs and checks
experiments/      Paper, context, aligned v2, rejected repair, phone augmentation
validation/       Manual test controllers, correlation, audits and benchmarks
models/current/   Current inference references and training configuration
models/references/ Historical aligned-v2 reference for matched comparisons
results/          Published aggregate evidence; no raw dataset or packet capture
docs/             Setup, research methodology, results, full LaTeX report
tools/report/     Report builders using saved aggregate evidence
reproducibility/  Portable paths, pinned provenance and validation records
tests/            Dataset-free model/package/preview checks
reproduce.py      Common setup and experiment entry point
```

## Quick checks

Use Python 3.12. Training matches Linux/WSL; build/install can use Windows Python.

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python reproduce.py doctor
python -m pytest tests -q
python reproduce.py paper --smoke
python reproduce.py context --smoke
```

Live capture needs an **already-rooted test device** and compatible ARM 64 tcpdump with immediate mode. This is not an unrooted VPN monitor. Small classifiers are included; optional 1.06 GiB Llama weights have a pinned download manifest and separate license. Monitoring needs no Internet inference connection; LAN tests need working local connectivity.

## What is established

The declared paper 70/30 reconstruction reached 97.03% accuracy; context improved that historical benchmark. Those scores do not establish real-phone accuracy. The augmented model detected 62/64 held-out recorded Web segments but falsely flagged 10/120 normal segments. Later live protocol tests found ordinary SSH false positives, weak family typing and missed emulator/distributed resource-load cases.

Code 40 stops recurring idle-loopback alerts by observing on-device connections separately from default external-network assessment. This narrows scope and does not teach the model that local traffic is safe. Normal SSH false positives remain. Immediate factual notes and short local Llama guidance improve explanation latency, not detection accuracy. Read the denominators and experimental limits in [results](results/README.md).

No research datasets, private phone captures/histories, credentials, private keys, full training checkpoints, large Llama weights or ZIP are included. Public-data runs can be regenerated after obtaining the source files. Exact private-phone-cohort retraining requires the excluded recordings; repeating the procedure produces a new cohort. Third-party licenses remain in [notices](NOTICE.md); no project-wide open-source license has been assigned.
