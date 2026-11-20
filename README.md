# Android NIDS

[![Reproducibility checks](https://github.com/vishwajeet-singh-bhati/Android-nids/actions/workflows/checks.yml/badge.svg)](https://github.com/vishwajeet-singh-bhati/Android-nids/actions/workflows/checks.yml)

An Android research prototype that monitors connection statistics and recent connection history, flags suspicious activity with a small local model, assigns an estimated attack family with a larger model, and produces local guidance with Llama or an evidence-based fallback.

**Current app:** `0.12.2-aligned-v2-test` / code 36. **Current detector:** preserved v2 gate + diagnosis, 147 inputs. The additional real-phone-data training run is separate; see [current status](STATUS.md). This repository contains one current source snapshot with the baseline experiments needed to reproduce its comparisons.

## Start here

| Goal | Guide |
|---|---|
| Read the complete beginner report / Overleaf source | [Project report](docs/project_report/README.md) |
| Build and install on an owned test phone | [Android setup](docs/ANDROID_SETUP.md) |
| Reproduce the paper and context experiments | [Reproducing results](docs/REPRODUCING_RESULTS.md) |
| Obtain the required datasets yourself | [Dataset layout and provenance](docs/DATASETS.md) |
| Run each controlled phone test | [Phone testing](docs/PHONE_TESTING.md) |
| Understand inputs, labels and the pipeline | [Methodology](docs/METHODS.md) |
| Read measured results and their limits | [Results index](results/README.md) |
| Collect new phone data and retrain | [Phone dataset procedure](experiments/phone_capture_v1/DATASHEET.md) |
| Review version and validation records | [Changelog](CHANGELOG.md) and [validation](reproducibility/VALIDATION.json) |

## Repository layout

```text
android/          Current app, shared Kotlin features, isolated targets and checks
experiments/      Paper baseline, context extension, aligned models, new phone data
validation/       Bounded phone test runner and packet/flag correlation
reproducibility/  Portable paths, environment records and source provenance
models/           Current small inference models; optional Llama download manifest
results/          Published aggregate measurements, separate from generated runs
docs/             Installation, data, reproduction, methodology and test guides
tests/            Dataset-free packaging/model-contract checks
reproduce.py      Common setup and experiment entry point
```

## Quick checks

Use Python 3.12. For research training, Linux/WSL and an NVIDIA CUDA GPU match the measured environment. CPU smoke tests are available without research datasets.

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python reproduce.py doctor
python -m pytest tests -q
python reproduce.py paper --smoke
python reproduce.py context --smoke
```

Windows users can build/install through `reproduce.py` using Windows Python; use WSL for the paper/context training commands. See the guides for exact environment variables and commands.

## What the results mean

The paper reconstruction reached 97.03% baseline accuracy on its declared CSV 70/30 split. Context improved that benchmark, but related rows/campaigns limit its interpretation. Phone-aligned processing and real phone tests are separate evaluations. On the installed v2, scans were detected; confirmed HTTP guessing, SQL injection and XSS examples were missed. New phone data is intended to address that gap; unfinished training is not presented as an improvement.

**Live capture requires an already-rooted Android test device and compatible tcpdump.** This is not a VPN-based unrooted monitor. The small models are included; optional 1.06 GiB Llama weights are downloaded separately. The app does not decrypt TLS, block attacks or prove malware identity. Notifications may use evidence fallback when a Llama draft is unavailable or rejected.

Research datasets, real phone recordings, credentials and training caches are not included. Public-data runs can be regenerated after obtaining the specified source files. Private phone-session numbers cannot be independently retrained exactly without those recordings; the documented collection process produces a new cohort. See [reproducibility boundaries](docs/REPRODUCING_RESULTS.md).

Third-party components retain their licenses; see [notices](NOTICE.md). No project-wide open-source license has been assigned by this submission.
