> Current application is Rakshak code46. This document retains the network-core methodology; use the root component index and Rakshak guide for SMS/URL setup, current controls and the empty public-feed policy.

# Reproducing results

## Environment and scope

Measured training used Python 3.12.14, PyTorch 2.14.1+cu130, NumPy 2.2.6, pandas 3.0.6, scikit-learn 1.9.1 and an RTX 2000 Ada GPU. `requirements.txt` pins the packages; see the official [PyTorch installation guide](https://pytorch.org/get-started/locally/) for a compatible CUDA or CPU build. Matching seeds/data/code improves repeatability; different GPU kernels/platforms may still change floating-point results. Do not promise bit-identical retraining on arbitrary hardware.

Training commands below run inside Linux/WSL from the repository root. Create/activate a Python 3.12 virtualenv and install `requirements.txt`. Use `requirements-export.txt` only for ExecuTorch model export. These dependencies are independent of Android's ExecuTorch 1.5.1 AAR.

## A. Paper reconstruction

```bash
python reproduce.py paper --smoke
python reproduce.py paper
```

Full training requires `data/external/CICIDS2017/GeneratedLabelledFlows.zip`. The declared split is stratified 70/30, seed 42. Baseline trains 10 epochs; independent 30%/40% pruning branches fine-tune 5 epochs each. All checkpoints and split/normalization records are saved. No test-based checkpoint search is performed. Defaults match the measured CUDA run; `NIDS_TRAIN_DEVICE=cpu` permits a slower CPU reproduction.

Outputs: `runs/tsanet_paper_70_30/COMPARISON.md`, checkpoints and TorchScript exports; data/cache under `data/experiments/tsanet_paper_70_30`. Synthetic smoke fixtures only test software and are not detection results. [Assumptions and historical results](PAPER_AND_CONTEXT.md) distinguish missing author details from reconstructed choices.

## B. Connection-context comparison

```bash
python reproduce.py context --smoke
python reproduce.py context
```

Uses the same baseline data/split and fixed 10+5 epoch budget for each comparison arm. Historical context adds 78 features (2/5/15 minute windows) to the original 32. Outputs: `runs/tsanet_context_v1` and generated `results/tsanet_context`. Published references are under `results/tsanet_context`.

This is the historical random-row/related-campaign benchmark. Its high scores do not establish independent-session or phone accuracy.

## C. Phone-aligned baseline

```bash
python reproduce.py aligned prepare
python reproduce.py aligned train
pip install -r requirements-export.txt
python reproduce.py aligned export
```

For a dataset-free technical check of this training/evaluation/export chain, after installing export dependencies run `python -m experiments.phone_alignment_v2.preflight --smoke-only`. It uses a tiny generated software fixture and reports no research detection performance.

Requires the raw labeled CICIDS2017captures plus the specified Android control corpora. All are external downloads; see [DATASETS.md](DATASETS.md). Extraction uses the included checksum-verified frozen Kotlin JAR. It derives32 flow + 115 phone-visible context/protocol inputs, preserving the deployed contract. Group split is 70/15/15; scaling fits training only. Eight fixed 40-epoch jobs include the binary/diagnosis seeds and architecture controls; every epoch is retained.

The common CLI runs these jobs sequentially to avoid unexpected resource use. The scientific configurations/rows remain the same; concurrency only changes execution timing. Final validation selection precedes test reporting. Original grouped splits still share dataset campaigns and some causal context; they are not unseen-device/session proof.

## D. New phone recordings and updated-data models

Build/install using [ANDROID_SETUP.md](ANDROID_SETUP.md), put the original datasets/cache in place, then use the owned phone and PC on the same private LAN:

```bash
export NIDS_DEVICE_SERIAL=YOUR_SERIAL
python reproduce.py phone pilot
python reproduce.py phone collect
```

Pilot verifies independent target outcomes, packet counts and all 147 native/offline input values. Collection then uses 20 preassigned chronological sessions (14 train / 3 validation / 3 test), held-out request forms/rates and matched normal controls. Read the [dataset datasheet](../experiments/phone_capture_v1/DATASHEET.md) before running. Collection launches only bounded traffic against the selected phone's disposable app. No datasets are fabricated or labels inferred from predictions.

On Windows, collection can use Windows Python and train through WSL:

```powershell
$env:NIDS_DEVICE_SERIAL='YOUR_SERIAL'
$env:NIDS_TRAIN_BACKEND='wsl'
$env:NIDS_WSL_PYTHON='/home/YOUR_USER/venvs/nids/bin/python'
$env:NIDS_WSL_DISTRO='Ubuntu'
python reproduce.py phone pilot
python reproduce.py phone collect
```

Install the training environment inside that WSL virtualenv. On Linux, native training is the default. New train-phone rows receive declared 8-fold exact replay; validation/test are not resampled. Normalization fits only combined training data. Six fixed 40-epoch/3-seed jobs run at most two at a time and retain every epoch/best/last/final checkpoint. Full gate+diagnosis selection happens on validation; final comparison reports original and new-phone cohorts separately.

Outputs: `runs/phone_capture_v1` for private recordings/progress; `runs/phone_capture_training_v1` for checkpoints; generated `results/phone_capture_training_v1/RESULTS.md` for comparison. No automatic deployment occurs.

To inspect a running campaign in PowerShell:

```powershell
Get-Content runs\phone_capture_v1\campaign_status.json
Get-Content runs\phone_capture_training_v1\scheduler_status.json
Get-Content runs\phone_capture_training_v1\logs\diagnosis_s0.log -Tail 30 -Wait
```

Linux equivalents are `cat` for status JSON and `tail -f` for a selected job log. Keep the terminal/process alive, or use your own process manager. Completed sessions and saved epoch checkpoints allow a controlled resume; rejected or interrupted captures require review rather than automatic reuse.

## What can be reproduced without our private recordings?

- Source, architecture, preprocessing, split policy, model hashes and included inference behavior are available.
- Original public-data benchmark runs can be regenerated after acquiring matching publisher files. Historical aggregate reports retain counts/configurations/provenance.
- Real phone captures are excluded as requested. You can repeat the collection method on your own device, but timing/traffic/features will differ. Exact retraining/re-auditing of our private-phone cohort requires those original recordings; source alone cannot provide that claim.
- Full new-device accuracy, daily false-alert rate and every attack class are not established by a small single-phone lab study.


## Current release clarification

Current source is code40 with the augmented-v1 detector, not the historical code36 weights. Read [current pipeline](CURRENT_PIPELINE.md), [status](../STATUS.md), [completed training](../results/phone_capture_training_v1/RESULTS.md) and [protocol testing](PROTOCOL_TESTING.md). All six training jobs completed; readiness remains false. The old v2 reference is kept only for comparison. New cases must be kept separate from already examined development cohorts.

The rejected repair source is also included under `experiments/phone_repair_v3`. With the baseline cache/jobs regenerated, run its Linux runner for a separate experiment; it is never an automatic deployment. Augmented before/after evaluation loads the historical reference from `models/references/aligned_v2`, while `models/current` remains current. To regenerate the report from the shipped aggregate evidence, run `python tools/report/build_report.py`; it performs no training or phone actions. Collectors need the separately obtained original artifacts.
