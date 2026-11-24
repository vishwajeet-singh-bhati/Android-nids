# Phishing Detector

A Python project workspace for building and testing phishing URL detection tools.

## Current status

Phishing-detection module of the Bharat AI on-device security assistant.

| Area | Status |
|---|---|
| URL normalizer (`src/preprocessing/url_normalizer.py`) | done, tested |
| Character tokenizer (`src/preprocessing/tokenizer.py`) | done, tested |
| Structural features + scaler (`src/preprocessing/feature_extractor.py`) | done, tested |
| Feed downloader / parsers / dataset builder (`src/data/`) | done, tested |
| Benign full-URL sampler, Common Crawl (`src/data/commoncrawl_sample.py`) | done, tested |
| Cleaning + leakage-safe train/val/test split (`src/data/split_dataset.py`) | done, tested |
| Training data loader, metrics, classic baselines (`src/training/`) | done, tested |
| Char-CNN / hybrid model + resumable trainer (`src/models/`, `src/training/train_cnn.py`) | done, tested, trained on GPU (full_url) |
| Calibration + three-outcome thresholds (`src/training/calibrate.py`) | done, tested; full_url test run done (false-alarm budget not met, see below) |
| Per-website error inspection (`src/training/inspect_errors.py`) | done, tested |
| Per-website budgets, n-gram model without pickle, CNN + n-gram combination (`src/training/ensemble.py`) | done, tested; run on GPU: **hybrid + n-gram chosen for full_url** |
| Threat intelligence: local database + matcher (`src/intelligence/`) | done, tested; built from real feeds |
| Threat intelligence: answer cache with separate TTL policies (`src/intelligence/cache.py`) | done, tested |
| Threat intelligence: online lookups, Google Safe Browsing v5 (`src/intelligence/safe_browsing.py`) | done, tested; checked against the real API 2026-11-22 (protobuf answers, Google's test pages match); off by default |
| URLhaus feed | skipped (decided 2026-11-20): malware, not phishing; terms restrict AI products |
| Inference engine, step 1: model bundle, runtime, decision engine, single/batch predict (`src/inference/`) | done, tested; run on the real model |
| Popular-website guard, Tranco top 1,000 (decision rule 4) | done, tested; chosen 2026-11-21 |
| Inference engine, step 2: queue + micro-batches (`service.py`), background Google checks (`background.py`), benchmarks (`benchmark.py`) | done, tested; laptop benchmark done, Pi pending (Phase 5) |
| Arm test tooling: device package, parity check, thread sweep (`src/deploy/`, `src/inference/parity.py`) | done; Android phone run done (Pixel 6a, 2026-11-22): 433 tests pass, parity PASS; Pi 5 pending |
| HTTP API: FastAPI, `/predict` `/health` `/ready` `/model-info` `/metrics` (`src/api/`) | done, tested (32 API tests), run live on the laptop (Phase 6 step 1) |
| SMS module → link check bridge (`src/integration/sms_bridge.py`) | done, tested (45 tests), run with the team's real SMS model, in process and over HTTP (2026-11-23) |
| NIDS connection | reviewed 2026-11-23: needs a hostname reader on the NIDS side and our hostname model; plan below |
| API on the phone (Arm), Docker ARM64 image | next (Phase 6 steps 2–3); Pi 5 on hold |

## Requirements

- **64-bit** Python 3.10–3.12 (PyTorch has no 32-bit Windows build)
- Packages listed in `requirements.txt`
- PyTorch, installed separately for your operating system and hardware

## Setup

Create and activate a virtual environment, then install the project dependencies.
If `py --version` reports a 32-bit interpreter, pass a 64-bit one explicitly
(for example `py -3.11 -m venv .venv`).

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

Install PyTorch separately using the instructions at
[pytorch.org](https://pytorch.org/get-started/locally/) to select the
appropriate CPU or CUDA build.

## Check your environment

Run the environment check from the repository root:

```powershell
python scripts/check_env.py
```

The script reports the Python version, platform, installed project packages,
PyTorch/CUDA availability, and runs a small PyTorch `Embedding`/`Conv1d` smoke
test. It exits with an error if PyTorch is not installed.

## Data pipeline

Raw data is never committed; every step can be reproduced from these commands.

```powershell
# 1. Phishing feeds (PhishTank keyless, OpenPhish) and the Tranco top-1M list.
#    Run this once a day for a while: each snapshot adds new phishing URLs.
python -m src.data.download_datasets

# 2. Benign FULL URLs from the Common Crawl index (~1 GB of index blocks, one-time).
python -m src.data.commoncrawl_sample

# 3. Merge, normalize and deduplicate everything into data/processed/.
python -m src.data.build_dataset

# 4. Clean and split into leakage-safe train/val/test (data/processed/splits/).
python -m src.data.split_dataset
```

What step 4 does, and why:

- **Two datasets.** `full_url/` (host + path + query) and `domain/` (hostnames
  only, for DNS/SNI traffic) are trained separately, so "no path" can never
  become a shortcut for "benign".
- **Redirector links removed** (URL shorteners and QR-code services from the
  public list plus [config/redirectors_local.txt](config/redirectors_local.txt)).
  Their URL hides the destination; at inference they are reported as UNCERTAIN.
  `split_report.json` lists *candidate* redirectors found by pattern; a human
  reviews them before adding them to the local list.
- **Group split.** Every URL is assigned to train/val/test by its registered
  domain (PSL private suffixes honoured, so `a.web.app` and `b.web.app` are
  different sites), so the test set only contains websites the model never saw.
- **Per-site cap** (50 per split/label/site), so one abused platform cannot
  dominate training.
- **Shortcut monitors** in the report compare the two labels (length, paths,
  subdomains) to reveal remaining shortcuts.
- `--future-cutoff <ISO time>` puts sites first seen after that time in a
  separate `test_future` split for time-based evaluation.

| Source | Label | What it gives | Notes |
|---|---|---|---|
| PhishTank `online-valid` | phishing | full URLs, community-verified | new-user registration is closed, so keyless (a few downloads/day) |
| OpenPhish community feed | phishing | full URLs | non-commercial use only |
| Tranco top-1M | benign (weak) | domain names only | used for domain-only mode and as a popularity filter |
| Tranco homepages | benign (weak) | `https://<domain>/` for 20k sampled domains | balances bare-homepage phishing URLs |
| Common Crawl URL index | benign (weak) | full page URLs on top Tranco domains | only index metadata is read; no page is visited |
| PeterDaveHello/url-shorteners | reference | ~1,450 shortener domains | CC BY-SA 4.0; routing only, never a label |

`data/processed/build_report.json` summarizes counts, duplicates, rejects and
warnings, and contains no raw URLs.

## Baselines

```powershell
python -m src.training.baselines              # validation split only
python -m src.training.baselines --with-test  # final comparison only
```

The test split stays untouched until the final comparison, so it remains an
honest exam on unseen websites. Reports (aggregate numbers only, no URLs) go
to `reports/baselines_<mode>.json`, including per-slice results.

First run, **validation split**, 2026-11-14 (C grid up to 10). "Recall @1% FPR"
is the share of phishing caught while wrongly flagging at most 1 in 100 safe URLs.

| Mode | Model | PR-AUC | ROC-AUC | Recall @1% FPR |
|---|---|---|---|---|
| full_url | shortcut probe (4 length numbers) | 0.611 | 0.756 | 0.359 |
| full_url | structural features + LR | 0.759 | 0.899 | 0.392 |
| full_url | structural features + boosted trees | 0.845 | 0.949 | 0.539 |
| full_url | char 2–5-gram TF-IDF + LR | **0.914** | **0.967** | **0.727** |
| domain | shortcut probe | 0.740 | 0.913 | 0.695 |
| domain | char 2–5-gram TF-IDF + LR | 0.860 | 0.944 | 0.785 |

Known issue: in **domain mode** 84% of hosts with a subdomain are phishing, so
the length-only probe already scores well. On bare domains alone the best
model reaches only PR-AUC 0.30. The domain dataset needs more benign subdomain
hosts before its numbers mean much.

## Training the character CNN

```powershell
python -m src.training.train_cnn                    # full_url, plain char-CNN
python -m src.training.train_cnn --model hybrid     # CNN + structural features
python -m src.training.train_cnn --device cuda      # refuse to fall back to CPU
```

- Model: character embedding → Conv1d (widths 3/5/7) → masked max-pool →
  small MLP (~90k parameters, about 0.4 MB in float32). Padding is masked, so
  the result does not depend on how much padding follows the URL.
- **Data feeding:** a PyTorch `Dataset` (`URLDataset`) and `DataLoader`. A
  batch sampler hands over one whole batch per call, and the data stays on the
  GPU. Each epoch uses one shuffle from a seeded generator. The loader has its
  own private generator, so dropout's random numbers are untouched. Training
  is bit-identical to the earlier hand-written loop, which was checked on the
  CNN, the hybrid and the shipped model's predictions.
- **Reports:** accuracy and the confusion matrix `[[tn, fp], [fn, tp]]` are
  included at threshold 0.5, as reference points only. The three-outcome
  version is under `counts` in the calibration and ensemble reports.
- After every epoch the full state goes to `artifacts/runs/<mode>_<model>/last.pt`;
  running the same command again **resumes**. The best epoch (validation
  PR-AUC) is kept in `best.pt`, and training stops after `--patience` epochs
  without improvement.
- Reports: `reports/cnn_<mode>_<model>.json` (aggregates only), which also quote
  the baseline score to beat.

### First GPU results (full_url, validation split, 2026-11-15)

NVIDIA RTX 2000 Ada, about 9 s per epoch, 3 seeds each:

| Model | PR-AUC (3 seeds) | Recall @1% FPR (3 seeds) |
|---|---|---|
| char n-gram LR baseline | 0.9135 | 0.727 |
| char-CNN | 0.918 / 0.921 / 0.923 | 0.745 / 0.726 / 0.756 |
| **hybrid (CNN + features)** | **0.929 / 0.930 / 0.935** | **0.749 / 0.775 / 0.788** |

The hybrid's worst seed beats the CNN's best seed on PR-AUC. Raw neural-net
probabilities are less well calibrated (ECE ~0.03 vs 0.012 for LR), so they
are calibrated before thresholds are set.

### Calibration and the three outcomes

```powershell
python -m src.training.calibrate --run artifacts/runs/full_url_hybrid                # validation
python -m src.training.calibrate --run artifacts/runs/full_url_hybrid --with-test    # once, at the end
python -m src.training.summarize --split test
```

The results below were produced with per-URL budgets (`--unit url`).
Per-website budgets came later; see the next sections.

- `p = sigmoid(a·logit + b)` (Platt scaling) is fitted on validation. It is
  monotone, so ranking metrics do not change.
- **PHISHING** if `p > t_phishing`, chosen so at most `--max-false-alarm` of
  safe URLs get it. **LIKELY_SAFE** if `p < t_safe`, chosen so at most
  `--max-missed` of phishing URLs get it. Everything else is **UNCERTAIN**.
- These budgets are rates *within* each class, so they hold whatever the real
  phishing share is. The report also projects how often a PHISHING verdict is
  right when only 1% or 5% of traffic is phishing. With rare phishing, even a
  1% false-alarm rate makes most PHISHING verdicts wrong, so the false-alarm
  budget must be strict.
- Output: `<run>/calibration.json` (the `calibrator` block is what the
  inference engine loads) and `reports/calibration_<run>.json`.

#### Validation results (full_url hybrid, seed 13, 2026-11-15)

`p = sigmoid(0.477·logit − 0.418)`. The slope below 1 means the raw model
was over-confident. ECE 0.028 → 0.004, Brier 0.0375 → 0.0348. Validation has
10,178 safe and 2,160 phishing URLs.

| False-alarm budget | Phishing caught | PHISHING verdict right, 1% / 5% phishing traffic |
|---|---|---|
| 0.1% | 60.0% | 86.0% / 97.0% |
| 0.5% | 73.0% | 60.0% / 88.7% |
| 1.0% | 78.8% | 44.5% / 80.7% |

The missed budget sets the UNCERTAIN share (at 1% phishing traffic):
2% → ~39%, 5% → ~17%, 10% → ~5%.

Recommended: **0.1% false alarm, 5% missed**.

- Phishing is rare in real traffic, so looser budgets make most PHISHING
  verdicts false alarms.
- The benign data comes from popular sites, so real false alarms will likely
  be higher than validation shows.
- Phishing that misses the PHISHING verdict mostly lands in UNCERTAIN (35%),
  not LIKELY_SAFE (5%).

At 0.1% the threshold is set by only about 10 safe validation URLs.

### Final test results (full_url, 2026-11-16)

The test split was opened once, with the models, seeds and budgets fixed
beforehand. The neural models are seed 13 and calibrated. The baselines'
ECE is uncalibrated.

| Model | PR-AUC | Recall @1% FPR | Recall @0.1% FPR | ECE | PR-AUC homepage / path / www |
|---|---|---|---|---|---|
| shortcut probe | 0.649 | 0.355 | 0.013 | 0.028 | 0.908 / 0.274 / 0.394 |
| structural features + LR | 0.771 | 0.518 | 0.064 | 0.015 | 0.934 / 0.583 / 0.358 |
| structural features + boosted trees | 0.858 | 0.541 | 0.146 | 0.019 | 0.959 / 0.724 / 0.680 |
| char 2–5-gram TF-IDF + LR | 0.924 | **0.740** | **0.517** | **0.009** | 0.957 / **0.874** / 0.739 |
| char-CNN | 0.910 | 0.700 | 0.292 | 0.014 | 0.956 / 0.846 / 0.778 |
| hybrid (CNN + features) | **0.929** | 0.716 | 0.319 | 0.013 | **0.972** / 0.860 / **0.870** |

Three outcomes on test with the 0.1% false-alarm / 5% missed budgets:

| Model | Safe → PHISHING (budget 0.1%) | Phishing caught | Phishing → LIKELY_SAFE (budget 5%) | PHISHING right at 1% / 5% phishing traffic |
|---|---|---|---|---|
| hybrid | **0.56%** | 61.5% | 2.2% | 52.8% / 85.4% |
| char-CNN | **0.33%** | 61.1% | 3.0% | 64.9% / 90.6% |

What this shows:

- The hybrid's lead over the n-gram baseline shrank from 0.021 PR-AUC
  (validation) to 0.005 (test), about the size of the seed-to-seed spread.
  Choosing the best seed and epoch on validation probably flattered the
  neural models there.
- At strict false-alarm levels the baseline is clearly better (52% vs 32%
  caught at 0.1% FPR). The hybrid wins on homepage-only and `www.` URLs; the
  baseline wins on URLs with a path.
- The false-alarm budget did **not** hold on test, while the phishing-side
  budget did. Safe URLs come in groups of up to 21 per website and each split
  has only ~2,400 safe websites, so a 0.1% threshold rests on a handful of
  websites.

These numbers stay as reported. Any later model change is judged on
validation and confirmed on fresh data, not on this test split.

### Inspecting mistakes per website

```powershell
python -m src.training.inspect_errors --run artifacts/runs/full_url_hybrid --with-test
```

Counts false alarms and misses per URL **and per website**, with a range from
resampling whole websites. For validation it also lists the safe websites
with the highest scores, showing host and path only (no query strings). For
test it prints counts only. Nothing is written to disk.

Findings at the 0.1% budget (2026-11-16):

| Model | Val false alarms | Test false alarms | Test without the worst website |
|---|---|---|---|
| hybrid | 10 URLs from 4 of 2,402 safe websites | 60 URLs from 9 of 2,492 (worst: 20) | 0.37% |
| char-CNN | 10 URLs from 8 of 2,402 | 36 URLs from 4 of 2,492 (worst: 20) | 0.15% |

- **False alarms come in website-sized lumps**, so the per-URL rate jumps
  whenever one flagged website brings 20 URLs.
- **The highest-scoring "safe" websites are genuine.** Examples are webmail,
  extranet and app login pages, status pages with long incident IDs, and a
  Bitcoin explorer's address pages. The labels look right; this is a real
  blind spot of judging from the URL alone.
- **It is not a simple keyword shortcut in training.** Login-type words
  appear in 2.4% of safe and 2.9% of phishing training paths. Long random
  strings are more common in safe paths (39% vs 13%).
- **The two estimates are consistent.** The per-website ranges for
  validation (0.01–0.23%) and test (0.08–1.18%) overlap. A 0.1% budget is
  about 2–3 websites out of ~2,400, which is below what this much data can
  measure.

### Per-website budgets and combining models (validation only)

Calibration now counts **every website once** by default (`--unit website`),
with a 0.5% false-alarm budget. That is about 12 of the ~2,400 safe
validation websites. `--unit url` restores the old per-URL counting.

```powershell
python -m src.training.ensemble --cnn-run artifacts/runs/full_url_hybrid
python -m src.training.ensemble --cnn-run artifacts/runs/full_url_cnn     # reuses the n-gram model
```

`ensemble` compares three candidates on validation: the CNN run alone, the
n-gram model alone, and both combined as
`p = sigmoid(w1·cnn_logit + w2·ngram_logit + b)` with both weights > 0.

- **Never reads the test split.** It was used once, above. A new model is
  judged on validation and confirmed later on fresh data.
- **Honest validation numbers.** They are cross-fitted over websites: weights
  and thresholds are fitted on 4/5 of the validation websites and applied to
  the other 1/5, five times.
- **The n-gram model is the `char_ngram_lr` baseline**, with the same
  settings and C search. It is saved to `artifacts/runs/<mode>_ngram/model.npz`
  as plain arrays and loaded with `allow_pickle=False`, so opening a model
  file cannot run code. It is reused while the data is unchanged.
- **Final calibrators** for all three candidates, fitted on all of
  validation, go to `artifacts/runs/<cnn run>_ensemble/ensemble.json`. A
  report with aggregate numbers only goes to `reports/ensemble_<cnn run>.json`.
- **`calibrate` keeps the exam record.** It refuses to overwrite a
  `calibration.json` that holds test-split results unless you pass `--force`.

### Chosen full_url model (2026-11-16)

Validation numbers, cross-fitted over websites, with budgets of 0.5% false
alarm and 5% missed (every website counts once):

| Candidate | PR-AUC | Phishing caught | Safe websites flagged | PHISHING right @1% phishing | UNCERTAIN @1% |
|---|---|---|---|---|---|
| char n-gram LR | 0.911 | 76.4% | 17 / 2,402 | 60.5% | 27.3% |
| char-CNN | 0.922 | 80.9% | 31 / 2,402 | 59.6% | 34.3% |
| char-CNN + n-gram | 0.930 | 79.1% | 23 / 2,402 | 61.7% | 27.2% |
| hybrid | 0.933 | 83.6% | 29 / 2,402 | 60.0% | 21.5% |
| **hybrid + n-gram** | **0.938** | **83.6%** | 24 / 2,402 | **62.7%** | **18.2%** |

**Decision: hybrid + n-gram**,
`p = sigmoid(0.332·hybrid_logit + 0.391·ngram_logit + 0.037)`.

- **Rule set beforehand:** the combination had to beat the best single model
  by more than 0.005 PR-AUC. It passed narrowly (+0.0053).
- **It also helps elsewhere:** it gives fewer UNCERTAIN verdicts (18% vs 21%)
  and wrongly flags fewer safe websites (24 vs 29), within the 0.5% budget.
- **No test-set number yet.** The combination will get one from the fresh
  exam on new data.
- **What a verdict means in practice:** at 1% phishing traffic a PHISHING
  verdict is right about 63% of the time. The product should present it as
  "high risk, here is why", not as proof.
- **Deviation from the specification (decided 2026-11-18).** The spec says
  "the central detection mechanism must be a trained neural network". In this
  combination the neural hybrid is one of two learned members, each with a
  comparable say. Neither member uses keyword rules. It was kept because
  validation justified it. The hybrid alone (PR-AUC 0.933, 21% UNCERTAIN) is
  the documented fallback.
- **Cost on the device:** it runs the PyTorch hybrid (or its exported form)
  plus the scikit-learn n-gram member.

The shipped model is three files, kept out of Git under `artifacts/`:

- `artifacts/runs/full_url_hybrid/best.pt`
- `artifacts/runs/full_url_ngram/model.npz`
- `artifacts/runs/full_url_hybrid_ensemble/ensemble.json`

`ensemble.json` records each member's SHA-256 hash, so the inference engine
can refuse mismatched files.
- **Caveat:** the CNN's best epoch and the n-gram model's C were both chosen on
  validation, which flatters both members a little.

### Over SSH on Windows

Windows OpenSSH ends every program from a session when it disconnects. Start
training as a scheduled task instead:

```bat
scripts\train_background.cmd start --model cnn --device cuda
scripts\train_background.cmd status      &rem progress (safe to run any time)
scripts\train_background.cmd stop        &rem stop; "start" again resumes
```

Output is appended to `logs\train.log`.

## Threat intelligence (local database)

Known phishing URLs from the feeds in `data/raw/` go into one local SQLite
file, `data/intel/threat_intel.sqlite3` (Git-ignored: the OpenPhish feed is
for non-commercial use only). Settings are in
[config/threat_intel.json](config/threat_intel.json).

```powershell
python -m src.data.download_datasets                     # fresh feed snapshots (daily)
python -m src.intelligence.local_database update         # ingest only snapshots not seen yet
python -m src.intelligence.local_database stats
python -m src.intelligence.local_database lookup "https://example.com/login"
python -m src.intelligence.local_database lookup example.com --domain
```

- **Independent of the model and fully offline.** This module never makes a
  network request and never sends a URL anywhere. Downloading is a separate
  step.
- **Three match levels:**
  - `exact_url`: the same page. The scheme, `#fragment`, host case and
    default port are ignored.
  - `hostname`: another listed page on the same host.
  - `registered_domain`: a listed sibling host, such as `a.evil.xyz` vs
    `b.evil.xyz`.

  The last two apply only when the site is neither in the Tranco top 100k
  nor a URL shortener or QR redirector. PSL private suffixes count as
  separate sites, so `evil.github.io` is not `github.io`.
- **Source attribution:** every match names its feed, the number of listed
  URLs, first and last seen, expiry, and up to three feed IDs.
- **Expiry:** an entry expires 7 days after the newest snapshot that listed
  it. `update` deletes expired entries. Results carry `stale: true` if the
  newest snapshot is more than 48 hours old.
- **`no_match` never means safe.** It only means no feed knows the URL. A
  lookup that cannot run returns `unavailable` and never raises.
- **Speed:** lookups use an in-memory copy of the file, reloaded when the
  file changes. If a new file is damaged, the last good copy stays in use.
  Reading the file directly cost 13 ms per lookup on Windows because of file
  locking; the copy takes 0.22 ms, or 0.08 ms for an already-normalized URL.
  Measured on the development laptop under load, not on the Pi.

First real build (laptop, 2026-11-17; 3 PhishTank + 3 OpenPhish snapshots):

| | |
|---|---|
| Records read | 134,855 PhishTank + 900 OpenPhish (27 invalid URLs skipped) |
| Active entries | 46,579 on 19,757 hosts; file 15.7 MB |
| Host-level matching allowed | 39% of entries |
| Exact-only sites with the most entries | google.com 5,253 · qrco.de 4,586 · q-r.to 3,509 · ead.me 3,290 · bit.ly 1,594 · weebly.com 1,197 · adobe.com 1,113 |

Most phishing in the feeds sits on big abused platforms and QR-code
redirectors. Host-level matching there would flag legitimate services, so
those entries match exact URLs only.

### Answer cache

[src/intelligence/cache.py](src/intelligence/cache.py) stores recent answers
so repeated links cost neither a model run nor an online lookup. Settings are
in [config/cache.json](config/cache.json).

| Kind of answer | Kept for | Why |
|---|---|---|
| Model said PHISHING or UNCERTAIN | 1 hour | |
| Model said LIKELY_SAFE | 15 minutes | a safe page can be turned malicious later |
| Confirmed threat-intel match | 6 hours, never past the source's own expiry | |
| No feed or provider lists it | 15 minutes | |
| An online lookup failed | 60 seconds | retry soon without hammering the service |

- **Keys are the exact normalized URL**, including the scheme. There is no
  host or domain entry, so one safe page never makes its website safe.
- **Prediction keys include the model version**, so a new model never serves
  old answers.
- **Keys are SHA-256 digests**, so the cache holds no readable URLs.
- **Bounded size:** least-recently-used entries are evicted. The cache is
  thread-safe and uses a monotonic clock. Hit rate is reported in `stats()`.

### Online sources: research (2026-11-18)

What the official pages say today:

- **URLhaus (abuse.ch): not integrated.**
  - It lists *malware* URLs, and its own policy says "Phishing is not Malware".
  - Downloads need a free Auth-Key placed in the URL, and dumps must not be
    fetched more often than every 5 minutes.
  - The abuse.ch Terms of Use forbid using the data to "train, or otherwise
    improve any artificial intelligence model or product" without Spamhaus'
    written consent.
  - The CSV columns are only documented behind a login, so they could not be
    verified.

  Sources: [URLhaus API](https://urlhaus.abuse.ch/api/),
  [about](https://urlhaus.abuse.ch/about/),
  [abuse.ch Terms of Use](https://abuse.ch/terms-of-use/),
  [changelog](https://abusech-docs.spamhaus.com/changelog).
- **Google Safe Browsing v5 (`hashes:search`): the candidate.**
  - It sends only 4-byte prefixes of SHA-256 hashes of URL expressions,
    never the URL. It is free, with an API key.
  - Use is **non-commercial only** without a separate agreement.
  - Warnings must say "suspected" or "possible", carry "Advisory provided by
    Google", and state that accuracy cannot be guaranteed.
  - A URL must not be warned about on Google data older than 30 minutes.
  - Positive and negative answers must be cached for the given
    `cacheDuration`.

  Sources: [overview](https://developers.google.com/safe-browsing/reference),
  [hashes.search](https://developers.google.com/safe-browsing/reference/rest/v5/hashes/search),
  [usage limits](https://developers.google.com/safe-browsing/v4/usage-limits),
  [terms](https://developers.google.com/safe-browsing/terms).
- **Google Web Risk**, the commercial version: its Lookup API sends the full
  URL, and its Update API keeps a local database of hashes. Pricing could not
  be read from the page.
  Source: [overview](https://docs.cloud.google.com/web-risk/docs/overview).
- **VirusTotal public API: not used.** It allows 4 requests a minute and 500
  a day, and cannot be used in products or services that earn money.
  Source: [public vs premium API](https://docs.virustotal.com/reference/public-vs-premium-api).

### Online lookups: Google Safe Browsing v5 (optional, off by default)

[src/intelligence/safe_browsing.py](src/intelligence/safe_browsing.py) only
runs when the environment variable `SAFE_BROWSING_API_KEY` is set. Without
it, every check returns `unavailable` / `disabled:no_api_key`, and the rest
of the system is unaffected.

```bat
python -m src.intelligence.safe_browsing expressions "https://a.b.example.com/1/2.html?x=1"
set SAFE_BROWSING_API_KEY=your-key-here
python -m src.intelligence.safe_browsing check "https://example.com/"
```

`expressions` works offline and shows what would be hashed. `set` keeps the
key for this window only; don't use `setx`, which stores it permanently.

- **What leaves the device:** Google's canonicalization turns the URL into
  up to 30 host/path expressions, for example `a.b.com/1/` and `b.com/`.
  Only the first 4 bytes of each expression's SHA-256 hash are sent. The
  match is decided locally by comparing full 32-byte hashes. localhost,
  private IPs and names without a public suffix are never sent. The key
  travels in the `x-goog-api-key` header, which is Google Cloud's
  recommended form. `"api_key_in_header": false` in
  [config/safe_browsing.json](config/safe_browsing.json) switches to `?key=`.
- **Rules followed:**
  - Unknown threat types or attributes make the client ignore that detail.
  - `CANARY` and `FRAME_ONLY` details don't count as a match for a page.
  - Positive answers are cached for at most 30 minutes, because the terms
    forbid warning on older data. Empty answers are cached for
    `cacheDuration`.
  - Matches carry `threat_types` (`phishing`, `malware`, ...) and
    `attribution: "Advisory provided by Google"`.
  - Use is non-commercial only.
- **Failures:**
  - 2-second timeout.
  - One retry for network errors and 5xx.
  - No retry for 4xx.
  - Token-bucket rate limit, 60 requests a minute by default.
  - Exponential back-off: 60 s, doubling, up to 30 min. `Retry-After` on a
    429 is respected.

  Every failure is `unavailable`, never `no_match`.
- **Tests:** they cover all 33 canonicalization examples Google publishes,
  the v5 IPv6 and expression examples, and a fake Google server for caching,
  errors, rate limits and privacy.
- **Checked against the real API (2026-11-22, with a valid key):**
  - The key is accepted in the `x-goog-api-key` header.
  - URL-safe, unpadded base64 prefixes are accepted.
  - **Answers are protobuf only.**
    - The overview says "All of the response bodies are protocol-buffer
      formatted". Asking for JSON with `$alt=json`
      ([system parameters](https://docs.cloud.google.com/apis/docs/system-parameters))
      is refused with 400 "Unsupported Output Format".
    - With a *wrong* key, the error itself does come back as JSON. That misled
      a first fix.
    - The client reads protobuf with a small reader built on the field numbers
      in googleapis'
      [`safebrowsing/v5/safebrowsing.proto`](https://github.com/googleapis/googleapis/blob/master/google/security/safebrowsing/v5/safebrowsing.proto).
      No new dependency is needed.
    - A real answer captured from Google is part of the tests.
    - Before this fix, every lookup ended as `unavailable`.
  - Google's own test pages:

    | URL | Result |
    |---|---|
    | `http://testsafebrowsing.appspot.com/s/phishing.html` | **match**, exact URL, `phishing` |
    | `.../s/malware.html` | **match**, `malware` + `harmful_application` |
    | `https://www.google.com/` | `no_match` |

    Google's cache duration was 300 s.
  - End to end, `predict` says **PHISHING** for the test phishing page because
    Google lists it, while the model alone said UNCERTAIN (0.362). Threat
    intelligence works independently of the model.
  - Refusals carry Google's short reason, for example
    `http_400:API_KEY_INVALID` or `http_403:PERMISSION_DENIED`. Only an
    upper-case code is kept, never free text.
- **Not implemented:** the Global Cache and local hash lists of Real-Time and
  Local List Mode. This is the plain real-time check with a local cache.
  Host suffixes use the ICANN part of the Public Suffix List, which gives a
  superset of expressions, so nothing is missed.

## Inference (Phase 4)

```powershell
python -m src.inference.bundle build          # artifacts/runs -> models/full_url (Git-ignored)
python -m src.inference.bundle verify
python -m src.inference.predict "https://example.com/login" "https://bit.ly/abc"
python -m src.inference.predict example.com --domain
python -m src.inference.predict URL --json
python -m src.inference.benchmark             # speed + memory report -> reports/
```

- **Model bundle** (`models/full_url/`, format 2): `cnn.pt`, `ngram.npz`,
  `redirectors.txt`, `popular.txt` and `version.json`.
  - `popular.txt` is the newest Tranco top 1,000, used by the popular-website
    guard below. `--popular-top-n N` changes N, and 0 turns the guard off.
    The Pi needs no Tranco download.
  - A format-1 bundle is refused with "rebuild it". Run
    `python -m src.inference.bundle build` again.
  - `version.json` holds the calibrator, thresholds, validation numbers, data
    and library versions, and the SHA-256 of every file. It is the one
    manifest that replaces the spec's separate `model_config.json`,
    `tokenizer.json`, `feature_config.json` and `version.json`.
  - Loading refuses any file whose hash does not match.
  - The model version comes from the content (for example
    `full_url-edb8f2cc8642`), so the same model always has the same version.
  - To deploy, copy the whole folder.
- **Runtime** ([src/inference/runtime.py](src/inference/runtime.py)): CPU
  scoring that mirrors training exactly. A test checks it against the
  training code at batch sizes 1, 7 and 64.
- **Decision engine** ([src/inference/decision_engine.py](src/inference/decision_engine.py)),
  rules in order. Threat intelligence can only raise the risk.
  1. The exact page or host is listed as phishing: PHISHING.
  2. A link shortener or QR redirector: UNCERTAIN.
  3. No model result (domain-only input, model failure): UNCERTAIN.
  4. Otherwise the calibrated model. **Popular-website guard (chosen
     2026-11-21, top 1,000):** on a website in `popular.txt`, the model alone
     may not say PHISHING; it says UNCERTAIN. A threat-list match still gives
     PHISHING (rule 1). The guard never gives LIKELY_SAFE, so no website is
     marked safe for being popular.
     - The guard looks at the URL's own website. So `someone.github.io` and
       `x.blogspot.com` are not covered, and `gist.github.com` is.
     - It is a decision rule, not part of the model, so the model version
       and the cached model scores stay valid.
  5. A malware listing: at least UNCERTAIN, but never labelled phishing.
  6. A listed sibling host: LIKELY_SAFE becomes UNCERTAIN.

  "pending", "no_match" and "unavailable" never lower the risk.
- **Predictor** ([src/inference/predict.py](src/inference/predict.py)):
  - normalizes the input, de-duplicates it and checks the cache (exact URL +
    model version);
  - scores the misses in batches and looks them up in the local threat
    database and, if a key is set, in Google, in the background (see step 2);
  - gives invalid input its own error result and keeps the input order.
- **No domain-only model yet:** hostnames are checked against threat
  intelligence only and otherwise answered UNCERTAIN, as the spec requires.

Real runs on the laptop CPU (2026-11-20, without the guard; 2026-11-21, with it):

| Input | Without guard | With guard (top 1,000) |
|---|---|---|
| `https://en.wikipedia.org/wiki/Phishing` | LIKELY_SAFE (0.003) | LIKELY_SAFE (0.003) |
| `http://paypal-account-verify.secure-login-update.xyz/signin/webscr?cmd=_login` (made up) | PHISHING (0.998) | PHISHING (0.998) |
| `https://someone.github.io/paypal/login` (made up) | - | PHISHING (0.997): a user site, not covered |
| a page from the PhishTank feed / another page on that host | PHISHING (threat intel) | PHISHING (threat intel) |
| `https://bit.ly/3abcXYZ` | UNCERTAIN (rule: destination hidden) | UNCERTAIN |
| `https://www.google.com/` | UNCERTAIN (0.345) | UNCERTAIN (0.345) |
| **`https://github.com/login`** | **PHISHING (0.968): false alarm** | UNCERTAIN (rule) |
| **`https://accounts.google.com/signin`** | **PHISHING (0.910): false alarm** | UNCERTAIN (rule) |
| **`https://www.paypal.com/signin`** | **PHISHING (0.797): false alarm** | UNCERTAIN (rule) |

The bold rows are the "real login page" blind spot found in Phase 2. Real
sign-in pages of big websites look like phishing from the URL alone. The
guard was measured on validation (in-sample) before choosing it, with 2,402
safe and 1,525 phishing websites:

| Guard on Tranco top | Safe websites flagged PHISHING | Phishing websites called PHISHING |
|---|---|---|
| none | 24 | 1,290 (84.6%) |
| 1,000 | 23 | 1,286 (84.3%) |
| 10,000 | 21 | 1,278 (83.8%) |
| 100,000 | 10 | 1,257 (82.4%) |

Validation has few top-1,000 websites (7 safe), while real browsing is mostly
on them. The guard's real benefit is therefore larger than this table shows,
and so is its cost on phishing hosted on big platforms (a fake Google Form,
for example). Known phishing pages on those platforms are still caught by
the exact-URL threat lists. The lasting fix is in the data: real sign-in
pages as safe examples in the next dataset rebuild.

### Inference step 2: concurrent requests, background Google checks, benchmarks

```powershell
python -m src.inference.benchmark --save-urls data/processed/benchmark_urls.txt   # laptop
python -m src.inference.benchmark --urls benchmark_urls.txt --threads 4           # Pi (Phase 5)
python -m src.inference.benchmark --quick                                          # short smoke run
```

- **Service** ([src/inference/service.py](src/inference/service.py),
  settings in `config/inference.json`). This is what the API (Phase 6) will
  call.
  - One worker thread owns the model. Callers put requests on a queue, and
    the worker scores everything waiting (up to `max_batch_urls`, 64) as one
    batch. Each caller then gets its own slice of the results.
  - A URL sent by several callers is scored once.
  - `submit()` gives back a Future, `predict()` blocks, and
    `predict_async()` is for asyncio.
  - **Protection:**
    - A full queue (`max_queue_urls`, 2048) refuses new requests at once
      with `Overloaded`. The API will turn this into 503 + Retry-After.
    - One request holds at most `max_urls_per_request` URLs (256).
    - A request that waited longer than `queue_timeout_seconds` (10 s) gets
      `QueueTimeout` and is not scored.
    - Cancelled requests are skipped.
    - A failing batch fails only its own requests.
    - `close()` finishes the queued requests first.
  - `stats()` reports the queue depth, counters, latency P50/P95/P99, batch
    sizes, the cache and Google. It feeds `/metrics` later.
- **Background Google checks**
  ([src/intelligence/background.py](src/intelligence/background.py)). No
  answer waits for the network.
  - A URL that Google's prefix cache can answer gets that answer at once.
  - Otherwise the check runs in the background (2 workers, at most 1,000
    queued, one at a time per URL), and the answer says
    `pending: ["google_safe_browsing"]`. Asking again gives Google's answer.
  - A failed check is remembered for 60 s (`failure_seconds`), so a failing
    API is not hammered.
  - The in-flight list holds SHA-256 keys, not URLs.
  - Without `SAFE_BROWSING_API_KEY` Google is skipped, and this is noted.
  - The one-shot `predict` command waits up to 3 s for pending checks
    (`--wait-online`); the service never waits.
- **Queue wait measured, then set to 0.** First design: the worker waited
  2 ms for more requests to join a batch. On this Windows laptop, that
  "2 ms" wait really took 16 ms (timer resolution), and it made everything
  slower. With 1 caller: P50 17.8 ms with the wait, 4.5 ms without, so 41
  instead of 211 requests/s. Under load, batches form without waiting,
  because requests pile up while a batch runs. So `max_wait_ms` is now 0;
  it can be tuned on the Pi, where Linux timers are precise.

Laptop benchmark (2026-11-21; `reports/benchmark_AMD64_20261120T190545Z.json`,
UTC in the name):
- Machine: Windows, x86-64, 12 logical CPUs, PyTorch 2.15 CPU (8 threads).
- Workload: 2,048 validation URLs.
- Bundle: 11 MB, loaded in 0.21 s.
- Memory: 357 MB resident after loading, 510 MB peak. Python + PyTorch alone
  use 307 MB.

| Model alone, batch | P50 ms | P95 ms | P99 ms | ms per URL | URLs/s |
|---|---|---|---|---|---|
| 1 | 3.6 | 5.8 | 8.9 | 3.86 | 258 |
| 16 | 17.8 | 23.3 | 26.5 | 1.12 | 891 |
| 32 | 32.3 | 38.3 | 40.1 | 1.01 | 986 |
| 64 | 71.4 | 81.7 | 86.6 | 1.08 | 929 |
| 128 | 119.2 | 176.1 | 186.4 | 0.97 | 1,028 |

| Service, 1 URL per request, no cache | P50 ms | P95 ms | P99 ms | requests/s | mean batch |
|---|---|---|---|---|---|
| 1 caller | 5.3 | 7.9 | 11.1 | 180 | 1.0 |
| 4 callers | 16.3 | 22.2 | 26.0 | 239 | 2.0 |
| 16 callers | 43.5 | 67.6 | 95.1 | 342 | 7.9 |
| 64 callers | 101.7 | 126.2 | 135.5 | 588 | 28.6 |

Full path (normalize, cache, model, threat database, rules), calls of 64:
- cold cache: 765 URLs/s;
- warm cache (same URLs again): 2,645 URLs/s, cache hit rate 100%.

Caveats:
- Laptop timings vary by about ±30% between runs (power management,
  background apps). For example, 16 callers gave 538 requests/s in an
  earlier run. These numbers are a preview; Phase 5 measures the Pi 5.
- PyTorch keeps about 7.5 cores busy even for one URL. In one run, 4
  threads were as fast as 8 at batch size 1. Choose `--threads` on the Pi.
- Batching scores 3–4 times more URLs per second than one at a time.
- Scores can differ in the 8th decimal depending on which URLs share a
  batch (padding width changes the summation order). Decisions do not
  change; the test checks scores to 1e-6.

## Arm test on an Android phone (Phase 5 preview)

There is no Raspberry Pi 5 yet, so a 64-bit Arm Android phone is the first
Arm device. It runs Debian (aarch64) inside Termux with
[proot-distro](https://github.com/termux/proot-distro), with the same
Python packages from PyPI that a Pi uses.

A phone is not a Pi 5. It has a different chip, mixes fast and slow cores,
slows down when hot, and Android manages its power. proot also adds cost
to every system call, including thread coordination. So phone speeds are an
Arm preview, not Pi numbers. What the phone can show for certain:
- the code runs on Arm (the test suite);
- the model gives the same answers there (the parity check);
- how speed depends on the number of threads.

On the laptop (the reference machine):

```powershell
python -m src.inference.benchmark --save-urls data/processed/benchmark_urls.txt   # once
python -m src.inference.parity save --urls data/processed/benchmark_urls.txt       # reference scores
python -m src.deploy.package          # -> dist/phishing_device_<model_version>.zip (8.4 MB)
```

- **Package** ([src/deploy/package.py](src/deploy/package.py)): one zip
  with everything the device needs.
  - Contents: code, tests, config, the model bundle, the local threat
    database, the benchmark URLs, the reference scores, a short
    `DEVICE_README.txt`, and `MANIFEST.json` with the SHA-256 of every file.
  - It refuses secret-looking files (`.env*`, `*.key`, `*.pem`, `secrets.*`,
    ...). API keys never go to the device.
  - `python3 -m src.deploy.package verify` checks the unzipped files with
    plain Python, before anything is installed.
  - Tested: unzipped into an empty folder, the full test suite and the
    parity check passed from there.
- **Parity check** ([src/inference/parity.py](src/inference/parity.py)):
  - The reference machine saves P(phishing), the decision and each member's
    logit for the 2,048 URLs, in fixed batches of 64. It stores a SHA-256 of
    the URL list, not the URLs.
  - The device recomputes and compares. It passes when no decision differs
    and P(phishing) differs by at most 1e-4.
  - Laptop against itself: identical.
- **Benchmark additions:** `--thread-sweep 1,2,4,8` measures the model alone
  per thread count. On Linux the report lists core types (for example
  "Cortex-A55 @ 1800 MHz x 4") and the board name. No host names are recorded.
- **PyTorch on the device:** install from the CPU index,
  `pip install torch --index-url https://download.pytorch.org/whl/cpu`.
  Since PyTorch 2.11, a plain `pip install torch` on aarch64 Linux fetches
  the CUDA build
  ([PyTorch blog](https://pytorch.org/blog/vllm-and-pytorch-work-together-to-improve-the-developer-experience-on-aarch64/),
  [Arm install guide](https://learn.arm.com/install-guides/pytorch/)).
- **Termux** comes from F-Droid or GitHub, not Google Play (the Play build is
  experimental). Don't mix sources. On Android 12+, Android may kill
  processes that use a lot of CPU ("signal 9")
  ([termux-app README](https://github.com/termux/termux-app)).
- **Driving the phone from the laptop** (optional; nothing new is opened on
  the Wi-Fi):
  - Android's Wireless debugging (`adb pair`, Android 11+) connects the
    laptop and phone. A USB cable works the same way.
  - Termux's SSH server (`pkg install openssh`) listens only on the phone's
    `127.0.0.1:8022` and accepts only a key, not a password.
  - `adb forward tcp:8022 tcp:8022` carries SSH through the paired adb link.
    `ssh` and `scp` then work from the laptop.
  - Inside Debian, the Termux home folder is at
    `/data/data/com.termux/files/home`; proot-distro mounts it by default.
  - Root is not needed and not used.
  - If every download on the phone fails with "self-signed certificate in
    certificate chain", something on the phone's network path is replacing
    HTTPS certificates. Common causes: a Wi-Fi sign-in page, a VPN, proxy or
    HTTPS-filtering app, or a firewall that inspects HTTPS.
    - Look at the *issuer* in the chain the device receives. The site name
      alone proves nothing, because inspecting firewalls copy it.
    - On the college Wi-Fi (2026-11-22) the phone got certificates issued by
      "Sophos SSL CA". The phone had not signed in to the Wi-Fi's login page
      (a Sophos portal): a plain-HTTP request came back as a redirect to
      `https://10.10.10.2:8090/httpclient.html`.
    - The fix is to sign in with your own college account, the same way as
      on the laptop.
    - A Raspberry Pi has no browser to sign in with. Plan for this in
      Phase 5: ask IT how headless devices get access.
    - Fix the network (or use another one) instead of turning off
      certificate checks.
    - Only the install needs internet. The tests and checks run offline: web
      calls in the tests are faked, and tldextract uses its built-in suffix
      list.
  - Sources:
    [adb](https://developer.android.com/tools/adb),
    [Termux openssh package](https://github.com/termux/termux-packages/tree/master/packages/openssh),
    [proot-distro](https://github.com/termux/proot-distro).

### Phone results (Pixel 6a, 2026-11-22)

Device and setup:
- Google Pixel 6a, Android 17, Google Tensor: 2 × Cortex-X1 @ 2.80 GHz,
  2 × Cortex-A76 @ 2.25 GHz, 4 × Cortex-A55 @ 1.80 GHz.
- Debian 13 in proot-distro, Python 3.13.5.
- The same package versions as the laptop: PyTorch 2.15.0 CPU, numpy 2.4.6,
  scikit-learn 1.9.1, scipy 1.17.1. So the parity check compares Arm with x86
  and nothing else.
- Install took about 3 minutes. All checks took about 4 more.
- Reports (UTC in the names):
  - `reports/parity_check_aarch64_20261121T231845Z.json`;
  - `reports/benchmark_aarch64_20261121T232137Z.json` (run 1);
  - `reports/benchmark_aarch64_20261121T232533Z.json` (run 2).

Correctness:
- `package verify` and `bundle verify`: every file arrived intact.
- Test suite: **433 passed** in 33.5 s.
- Parity against the laptop: **PASS**.
  - P(phishing) differs by at most 4.1e-7 (tolerance 1e-4). The mean
    difference is 8.4e-9, and 472 of 2,048 scores are bit-identical.
  - **0 decisions differ.**
  - Largest logit difference: 5.2e-6 for the CNN, 5.3e-8 for the n-gram model.
- Demo: the same answers as the laptop. `github.com/login` is UNCERTAIN
  0.968 (popular-website guard); the Wikipedia page is LIKELY_SAFE 0.003.

Speed and memory. Two full runs, 4 minutes apart; the run-to-run spread was
up to about 20%:
- Memory: 366–370 MB resident after loading, 491 MB peak. The laptop used 357
  and 510 MB.
- Load time: 0.16–0.21 s.

Model alone, PyTorch default of 8 threads:

| Batch | P50 ms, run 1 / run 2 | URLs/s, run 1 / run 2 | Laptop URLs/s |
|---|---|---|---|
| 1 | 7.5 / 6.1 | 118 / 143 | 258 |
| 16 | 38.9 / 38.7 | 396 / 384 | 891 |
| 32 | 57.7 / 63.6 | 545 / 490 | 986 |
| 64 | 104.0 / 112.4 | 600 / 561 | 929 |
| 128 | 214.5 / 230.8 | 587 / 552 | 1,028 |

Thread sweep, model alone:

| Threads | Batch 1: P50 ms | Batch 1: URLs/s | Batch 64: URLs/s |
|---|---|---|---|
| 1 | **2.8 / 2.4** | **322 / 378** | 538 / 630 |
| 2 | 7.4 / 6.1 | 126 / 155 | 584 / 754 |
| 4 | 7.0 / 5.8 | 129 / 159 | **688 / 834** |
| 8 | 6.7 / 5.1 | 132 / 171 | 679 / 802 |

| Service, 1 URL per request, no cache | P50 ms | requests/s | Laptop requests/s |
|---|---|---|---|
| 1 caller | 11.3 / 11.4 | 85 / 84 | 180 |
| 4 callers | 34.1 / 36.4 | 115 / 108 | 239 |
| 16 callers | 77.5 / 81.9 | 198 / 196 | 342 |
| 64 callers | 212.5 / 204.0 | 286 / 284 | 588 |

Full path, calls of 64:
- cold cache: 505 / 452 URLs/s;
- warm cache: 5,087 / 4,564 URLs/s.

What this shows:
- **The code runs on Arm and gives the same answers.** This is the main
  result.
- **The thread count is a per-device setting.** For one URL at a time,
  1 thread was 2–3× faster than 4 or 8 in both runs. Splitting a tiny job
  across fast and slow cores costs more than it saves. For batches of 64,
  4 threads were best, and 8 were no better.
  - The service currently uses PyTorch's default (all cores).
  - Choose the setting from the Pi 5's own sweep in Phase 5. The Pi has
    4 equal cores, so its best setting may differ.
- At 8 threads the phone is roughly half as fast as the laptop.

Caveats:
- proot adds overhead to system calls.
- Android manages the phone's power. The phone ran on battery (60%, 37.9 °C
  at the end).
- One device, two runs. These are not Pi 5 numbers.
- The `android_kernel` field in these reports says `false`, which is wrong:
  inside proot the kernel name is fake ("6.17.0-PRoot-Distro").
  `machine_info()` now reports `proot` and `android` instead, detecting
  Android by its `/system/build.prop` file.

## HTTP API (Phase 6)

```powershell
python -m src.api.app                  # http://127.0.0.1:8000   interactive docs: /docs
python -m src.api.app --port 8123      # if port 8000 is taken (on the laptop it was)
uvicorn src.api.app:create_app --factory --workers 1 --port 8000   # the same with uvicorn's options
```

The API has **no login**. Keep it on `127.0.0.1` (the default) or on a private
Docker network, and never expose it to untrusted networks. `--host 0.0.0.0`
is for inside a container.

| Endpoint | What it does |
|---|---|
| `POST /predict` | `{"urls": [...], "input_type": "full_url" \| "domain"}` → one result per URL, in the same order |
| `GET /health` | The process is alive (liveness): always 200. |
| `GET /ready` | The model is loaded and its worker runs (readiness): 200, otherwise 503 with the reason. |
| `GET /model-info` | Model version, thresholds, validation numbers, threat-intel status (feed age, stale), limits. |
| `GET /metrics` | Counters in Prometheus' text format. |
| `GET /docs`, `/openapi.json` | The documented contract, generated from [src/api/schemas.py](src/api/schemas.py). |

Real response (laptop, 2026-11-22; the same URLs had been asked before, so `cache_hit` is true):

```json
{"results": [
  {"url": "https://en.wikipedia.org/wiki/Phishing", "input_type": "full_url",
   "decision": "likely_safe", "risk_score": 0.003273669661608283, "source": "model",
   "model_version": "full_url-edb8f2cc8642", "cache_hit": true,
   "reasons": ["model: LIKELY_SAFE (P(phishing) = 0.003)",
               "not on any threat list checked (this is not evidence of safety)"],
   "threat_types": [], "attributions": [], "threat_intel": [], "pending": [], "error": null},
  {"url": "http://paypal-account-verify.secure-login-update.xyz/signin/webscr?cmd=_login",
   "input_type": "full_url", "decision": "phishing", "risk_score": 0.9983436053570749,
   "source": "model", "...": "..."}],
 "model_version": "full_url-edb8f2cc8642", "request_id": "readme-example"}
```

- `decision` is `phishing`, `uncertain` or `likely_safe`. It is `null` only for
  invalid input, which then has an `error` such as
  `invalid_input:illegal_characters`.
- `risk_score` is the calibrated model P(phishing). It is `null` when no model
  ran: domain input, link shorteners, invalid input.
- `source` names what set the decision: `model`, `threat_intel` or `rule`.
- `reasons` are plain-language reasons. They can feed the Llama advisory.
- `pending` lists online checks still running. Ask again for their answer.
- One bad URL never fails the request; it only gets its own `error`.

| Status | When |
|---|---|
| 200 | Answered, including per-URL `error` results. |
| 413 | Body over `max_body_bytes` (refused before it is read), or more than `max_urls_per_request` URLs. |
| 422 | Malformed request: empty list, wrong types, unknown fields, broken JSON, unknown `input_type`. The submitted input is not echoed back. |
| 503 + `Retry-After` | Not ready, queue full, timed out, or shutting down. |
| 500 | Internal error. Details go only to the server log. |

Every answer carries `X-Request-ID`. A caller's own ID (letters, digits,
`._-`, up to 64 characters) is kept, so NIDS logs can be matched.

How it is built ([src/api/app.py](src/api/app.py)):
- **No model code in the API.** It calls `InferenceService`, which also works
  without FastAPI.
- **Loaded once, at startup.** The model loads in FastAPI's
  [lifespan](https://fastapi.tiangolo.com/advanced/events/), before any request
  is accepted.
  - One worker thread owns the model, and all requests share its bounded
    queue. Concurrent requests cannot load the model twice or exhaust memory.
    A test sends 24 requests from 8 threads and checks that the model was
    loaded once.
  - Run **one** process (`--workers 1`): every extra process would load
    another copy.
  - If loading fails, the server still starts. `/health` says ok, and
    `/ready` and `/predict` give 503 with the reason.
- **Limits:**
  - [config/api.json](config/api.json): `max_body_bytes` 4 MiB,
    `request_timeout_seconds` 15, `retry_after_seconds` 1, `docs_enabled`,
    `log_phishing_urls`.
  - [config/inference.json](config/inference.json): 256 URLs per request,
    queue size, queue timeout.
  - The body limit is Starlette's
    [`RequestBodyLimitMiddleware`](https://starlette.dev/middleware/), plus a
    check of `Content-Length` that answers in the API's JSON format.
  - `python -m src.api.app` also sets uvicorn's `--limit-concurrency 128`
    (uvicorn answers 503 above it), `--timeout-keep-alive 5`, and no
    `Server` header.
- **Logs:**
  - One line per `/predict` call: request ID, counts per decision, pending,
    cache hits, time.
  - URLs are not logged, except PHISHING verdicts, and those only after
    [src/utils/redact.py](src/utils/redact.py). Query values, user:password
    and the fragment are removed, odd parameter names are hidden, control
    characters are replaced, and the URL is cut at 200 characters. Example:
    `phishing id=live-check-1 source=model url=http://paypal-account-verify.secure-login-update.xyz/signin/webscr?cmd=REDACTED`.
  - Not caught: a secret inside the path itself.
- **Metrics** follow Prometheus'
  [text format](https://prometheus.io/docs/instrumenting/exposition_formats/)
  and [naming guide](https://prometheus.io/docs/practices/naming/), with no
  client library:
  - `phishing_ready`, `phishing_model_info{model_version}`;
  - `phishing_http_requests_total{endpoint,code}`,
    `phishing_http_request_duration_seconds`;
  - `phishing_urls_total{decision}`, `phishing_cache_hits_total`,
    `phishing_pending_answers_total`;
  - `phishing_queue_urls`, `phishing_service_requests_total{result}`,
    `phishing_service_batches_total`,
    `phishing_service_recent_latency_seconds{quantile}`.
- **Network:** none, unless `SAFE_BROWSING_API_KEY` is set.

Live run on the laptop (2026-11-22). Real HTTP to the running server, the real
model, unique URLs from the benchmark sample, nothing cached:

| Load | P50 | P95 | Throughput |
|---|---|---|---|
| 1 caller, 1 URL per request | 11.1 ms | 14.3 ms | 89 requests/s |
| 16 callers, 1 URL per request | 95.3 ms | 141.9 ms | 155 requests/s |
| 1 caller, 64 URLs per request | 94.0 ms | 108.7 ms | 667 URLs/s |

- HTTP + JSON add about 6 ms per request on Windows. The service alone
  answered one URL in 5.3 ms.
- **Callers should send URLs in batches.** 64 per request scored 4–7 times
  more URLs per second than one at a time.
- Laptop timings vary by about ±30%. Phone and Pi numbers will be measured
  there.
- Tests ([tests/test_api.py](tests/test_api.py), 32): normal, single, batch,
  duplicate, Unicode (IDN) and too-long URLs, domain input, empty and
  malformed input, broken JSON, too many URLs, body over the limit (with and
  without `Content-Length`), a full queue, a timeout, an internal error that
  is not leaked, a failed model load, shutdown, concurrent callers,
  `/model-info`, valid Prometheus text, request IDs, logs without query
  values, and the redaction rules.
- Known warning in the tests only: Starlette 1.10 deprecates `httpx` in its
  `TestClient` in favour of a package named `httpx2`. It is left as is until
  that package is checked.

## Connecting the team's modules (Phase 7)

Bharat AI has three detectors: SMS scams, network intrusions (NIDS) and this
link checker. The team plan makes **SMS + links** the main end-to-end path, and
it says the explanation layer may call a link malicious only when this module
says so. The NIDS joins once it can name the websites it sees.

### SMS scam detector → link check (done)

[src/integration/sms_bridge.py](src/integration/sms_bridge.py) connects the
SMS module (package `sms_detection`) to this detector. For one message:

1. The SMS module scores the text: label `ham`/`spam`/`smishing`, risk band
   `low`/`suspicious`/`high`, evidence codes. Its answer is kept unchanged.
2. The SMS module's own extractor lists the links (`normalize_text(text).urls`).
   That is the same list behind its `URL_PRESENT` code; its Kotlin copy on the
   phone uses the same pattern.
3. The bridge tidies each link. The extractor keeps the sentence's punctuation
   (`github.com/login.`, `bit.ly/3xYzAbc,`, `...?id=88213.`), so that is
   removed. Then duplicates are dropped and at most 10 links are checked.
4. This detector checks the links, either in the same process or over
   `POST /predict`. Both give the same answers (checked).
5. The rule: **the link check can only raise the message's risk, never lower
   it.**

| Link answer | Message risk | Evidence code added |
|---|---|---|
| any link phishing | raised to `high`, high-risk advice | `URL_FLAGGED_PHISHING` (+ `URL_KNOWN_THREAT` if a threat list matched) |
| any link uncertain | unchanged | `URL_CHECK_UNCERTAIN` |
| a link not checked (service down, unparseable, over the cap) | unchanged; **not** read as safe | `URL_CHECK_UNAVAILABLE` |
| every link likely safe | unchanged: a clean link does not make "share your OTP" safe | `URL_NOT_FLAGGED` |

Set up once in this project's venv. The SMS model was saved with scikit-learn
1.9.1, the same version as this project:

```powershell
pip install -e <path>\sms-detection --no-deps
python -m src.integration.sms_bridge "Your KYC is pending. Update at https://sbi-kyc-verify.in/login" --sender +919876543210
python -m src.integration.sms_bridge --file messages.json        # [{"text": "...", "sender": "..."}]
Get-Content msg.txt -Raw | python -m src.integration.sms_bridge  # from stdin: no quoting trouble
python -m src.integration.sms_bridge --file messages.json --api http://127.0.0.1:8123   # via the running API
```

The output has three parts:
- `sms`: the SMS module's answer, untouched;
- `links`: per link `display_url`, `decision`, `risk_score`, `source`, `reasons`, `pending`;
- `combined`: `risk_level`, `raised_by_links`, evidence codes and advice codes, for the UI and the Llama explanation.

It holds **no message text**. Links appear only through `redact_url`: query
values, passwords and `#fragments` are removed. Links are never opened.

**Live run** (2026-11-23, laptop): the team's real SMS model and this project's
real model, on six messages written for the demo. These are not real people's
messages and not an accuracy measurement.

| Message | SMS module alone | Link check | Combined |
|---|---|---|---|
| KYC pending, `https://sbi-kyc-verify.in/login` | smishing / high | phishing (model 0.926) | high |
| Parcel on hold, pay at `www.indiapost-redelivery.top/pay?id=…` | smishing / high | uncertain (0.359) | high |
| "Here are the photos", `http://paypal-account-verify.xyz/signin.php` | spam / **low** | phishing (0.997) | **high (raised)** |
| Airtel bill, `https://www.airtel.in/pay` | spam / low | uncertain (0.238) | low |
| OTP, no link | ham / low | no links | low |
| `bit.ly/3xYzAbc`, `github.com/login` | spam / low | uncertain (shortener rule; popular-website guard) | low |

The third row shows why the modules are connected. Alone, the SMS module
filed that scam as quiet spam, and the link check caught it.

Tests ([tests/test_sms_bridge.py](tests/test_sms_bridge.py), 45):
- link tidying;
- every row of the rule;
- links over the cap, an unparseable link, a pending Google answer;
- no message text or query values in the output;
- the HTTP client: retry on 503 with a capped `Retry-After`, errors, timeouts, bad answers, redirects not followed, proxies ignored;
- the bridge through the real API app and in process;
- the real SMS module (skipped when it is not installed);
- the command line.

**On the phone (Android).** The SMS app is Kotlin, and it deliberately has
**no `INTERNET` permission**; its `verify_apk.ps1` fails if one appears.
Android needs that permission even for `127.0.0.1`. Two ways to connect:

1. **Quick (demo):** the app sends only the extracted links to this API
   running in Termux on the same phone (`http://127.0.0.1:8000/predict`). It
   needs `INTERNET` plus a network-security config that allows plain HTTP to
   `127.0.0.1` only. That is a team decision, because it changes the app's
   privacy promise from "cannot" to "does not".
2. **Proper (PoC, due 5 Feb 2027):** run this model inside the app. Export the
   char-CNN with ExecuTorch (the SMS and NIDS apps already use
   `executorch-android` 1.5.1), and port the URL normaliser, features and
   decision rules to Kotlin. Check it against Python with parity files, the
   way the SMS module did for its model.

### NIDS (reviewed 2026-11-23, [Android-nids](https://github.com/vishwajeet-singh-bhati/rakshak) at `2d805bd`)

How it works:
- On the rooted phone it runs `tcpdump` and keeps the first 768 bytes of each
  packet (`TsanetCaptureService`).
- It turns them into **numbers only**: 32 flow values and 115 history values.
  A gate and a diagnosis model then name the pattern: Bot, BruteForce, DDoS,
  DoS, PortScan, WebAttack or Unclassified.
- IPs and ports only group packets. HTTP headers give numeric facts only, and
  TLS is never decrypted.
- It reads **no hostnames, DNS names or URLs**, so today it has nothing to
  send to a link checker. Its alerts are about connection behaviour, a
  different threat from phishing.

How to connect it:

1. **NIDS side, new:** a small hostname reader.
   - **DNS query names**: UDP port 53 packets fit within 768 bytes.
   - **The HTTP `Host` header**: the NIDS already parses the header block.
   - Optionally **TLS SNI**: usually in the first packet, but Chrome's large
     post-quantum ClientHello with shuffled extensions can push it past 768
     bytes. Measure before relying on it.

   Android's Private DNS (DNS over TLS) and browser DNS-over-HTTPS hide
   lookups, so coverage will be partial.
2. **Send** the hostnames in batches as `{"urls": [...], "input_type": "domain"}`.
3. **Today's answer for a hostname:** `phishing` when it is on a threat list,
   otherwise `uncertain` (source `rule`, "no hostname model yet"). A
   hostname-level model needs safe hostnames with subdomains in the data
   first; see Phase 2.
4. **Keep the verdicts separate.** A phishing hostname and an intrusion
   pattern are different findings. The team plan says unrelated network
   events must not be merged into one score. They can share a timeline, linked
   by the DNS answer (hostname → IP) and the flow's destination IP.
5. **Same Android limit.** The NIDS app also has no `INTERNET` permission,
   with the same two options as the SMS app.

The NIDS already runs **Llama 3.2-1B on ExecuTorch** in its own process
(`LlamaWorkerService`). The team's explanation layer can reuse it for link
results. The input is `combined.evidence`; Llama may phrase the result, but
must not change it.

## Training on a GPU PC (Windows)

1. Clone the repo, create a 64-bit venv, run `pip install -r requirements.txt`,
   then install the CUDA build of PyTorch from pytorch.org.
2. If `import torch` fails with **WinError 126/448**, install the *Microsoft
   Visual C++ 2015–2022 Redistributable (x64)*. **WinError 4551** means an
   Application Control policy is blocking the DLLs; ask the machine's
   administrator for an allow rule.
3. Copy `data/processed/splits/` from the machine that built the dataset
   (data is not in Git), then run `python scripts/check_env.py`.

## Project layout

```text
data/          Local data directories (ignored by Git)
logs/          Local logs (ignored by Git)
models/        Local model files
scripts/       Development and environment-check scripts
src/           Application source package
  api/           HTTP API (FastAPI): app, schemas, config, metrics
  data/          feed downloads, Common Crawl sample, dataset build and split
  deploy/        device package for Arm test devices
  inference/     model bundle, runtime, decision engine, predictor, service, benchmarks
  integration/   connections to the team's modules (SMS scam detector bridge)
  intelligence/  threat-intel database, cache, Google Safe Browsing, background checks
  models/        char-CNN, n-gram model, calibration
  preprocessing/ URL normalizer, tokenizer, structural features
  training/      training, calibration, ensembles, error inspection
  utils/         shared helpers (URL redaction for logs)
config/        JSON settings (api, inference, cache, threat intel, Safe Browsing)
reports/       evaluation, benchmark and parity reports
tests/         Test package
```

## Dependencies

Runtime and development Python dependencies are listed in `requirements.txt`.
PyTorch is intentionally managed separately because the appropriate package
depends on the platform and hardware.
