# Phase 1 indicator hardening report

Generated: 2026-11-11

## Verdict

- The 100-message Indian handmade benchmark improved from **74/100 (74%)** to
  **89/100 (89%)** after the context-gated rule changes. The execution plan's
  `>88%` Tier-1 target is met **on that benchmark only**.
- Validation and locked-test **policy metrics are unchanged** from the baseline.
  No model weights, calibration values, or policy thresholds were changed.
- The frozen PTQ `.pte` reached **92/100** on the handmade set; FP32 MobileBERT
  reached **93/100**. The quantized artifact is hybrid INT8/FP32, not fully INT8.
- The production portable model remains **word-only** (`13,545 / 0 / 0`
  feature blocks). The Python Tier-1 path now has a desktop-JVM Kotlin parity
  port covering normalization, all 31 indicator flags, the portable model, risk
  fusion, reason codes, and action codes.
- A previously observed external Indian control benchmark (1,295 ham, 699 spam,
  no smishing labels) measured a **13.82% ham false-positive rate**, **78.84%**
  any-non-ham precision, and **70.81%** exact-spam precision on the 1,994-row
  leakage-filtered view. The new rules fired only on spam; ham false positives
  were unchanged, while 21 more spam messages were labelled smishing. This is a
  diagnostic control result, not a blind test.
- The 2,014-row external run exposed and fixed two JVM/Python regex differences;
  after the fixes, flags, model, and policy match **2,014/2,014**.
- The local-only Android scaffold now compiles to a debug APK with the production
  portable model and no `INTERNET` permission. No device latency, thermal, RAM,
  or Pixel 6a runtime evidence exists yet.

## What changed

### `src/sms_detection/preprocessing/indicators.py`

Added append-only evidence codes:

- `DTH_UTILITY_THREAT`
- `TASK_SCAM`
- `TELECOM_LURE`
- `DATA_HARVESTING`
- `HIGH_DEMAND_GADGET_SCAM`
- `APK_DOWNLOAD_LURE`
- `DELIVERY_UPDATE_LURE`
- `SERVICE_INTERRUPTION_LURE`

Each rule requires a combination of context, not a single keyword:

- DTH/utility provider + disconnection/suspension language + link, payment, or
  urgency.
- Paid task/review/like/survey language + earning promise + link or remote
  channel.
- Telecom context + link + `.apk`/patch or an unrealistic data/price offer.
- Document/KYC language + upload/submit action + corruption/expiry context +
  link.
- High-demand gadget + scarcity/discount + booking commitment + link.
- URL with `.apk` or an explicit APK/patch download lure.
- Delivery problem/address update/import-duty context + link.
- Service interruption + recovery action + link.

The TRAI DLT sender check now covers bare 10-digit Indian mobile senders as well
as `+91` senders, and applies to impersonation, KYC, or account-threat messages.
The previous regex handled `+91` but not the bare 10-digit form.

### `src/sms_detection/policy/risk_fusion.py`

- The new codes are treated as strong evidence.
- They can override a weak model disagreement only when the message has a link
  or the model already gives meaningful smishing support.
- Existing `ham`/`spam`/`smishing` labels and thresholds are unchanged.

### `experiments/handmade_evaluation/evaluate_handmade.py`

- Added `--model-dir` and `--output-dir` so a candidate can be evaluated without
  overwriting the original reports.
- The generated report now records the evaluated model path.

### Tests

- Added positive and benign controls for every new rule family.
- Added a bare-10-digit DLT sender regression test.
- Result: **66 passed**.

## Handmade benchmark

Source:
`experiments/mobilebert/handmade_dataset/smishing_dataset.csv`
(SHA-256 `df8cd4460c5ed50d6c28ba451092fb5942d9d855a6e5eff931480fa0b75697d5`).

| Model / path | Detected | Rate | Missed |
|---|---:|---:|---:|
| TF-IDF full detector, after rules | 89 | 89.0% | 11 |
| TF-IDF classifier only (diagnostic) | 61 | 61.0% | 39 |
| MobileBERT-22 FP32 | 93 | 93.0% | 7 |
| PTQ `.pte`, batch 1 | 92 | 92.0% | 8 |
| PTQ `.pte`, batch 16 | 92 | 92.0% | 8 |

The benchmark is all-positive. The 89% figure is coverage/recall, **not**
precision or accuracy. There are no non-smishing controls in this set. The
external Indian control benchmark below adds spam/ham controls, but it has no
smishing labels and is not blind; it cannot validate smishing precision.

The rule families were designed after inspecting this benchmark's misses.
Therefore **89% is development-set coverage, not an unbiased held-out result**.
The original 74% is the pre-change baseline on the same set. Do not treat either
number as production evidence until a fresh independent Indian set and device
tests are available. The external control result is a diagnostic tradeoff, not
a substitute for that fresh set.

Remaining TF-IDF misses:

- Financial reputation anxiety
- Fake toll/FASTag blacklist
- Fake premium card offer
- Fake welfare scheme
- Fake business renewal
- Fake premium subscription
- Predatory fake loan
- Debt collection threat
- Unrealistically good loan terms
- Ponzi/Pyramid scheme
- Fake student welfare scheme

These are mostly loan, welfare, subscription, and financial-threat patterns. No
further rules were added because the set has no negatives and more pattern
chasing would overfit the benchmark. They should be evaluated against a
negative/control set before inclusion.

## Validation and locked-test impact

Policy metrics after the change, using the existing model and thresholds:

| Split | Accuracy | Macro-F1 | Smishing recall | Smishing precision | Ham FPR | Smishing FPR |
|---|---:|---:|---:|---:|---:|---:|
| Validation | 0.967779 | 0.888438 | 0.808511 | 0.775510 | 0.007052 | 0.013382 |
| Test | 0.956272 | 0.868652 | 0.836735 | 0.745455 | 0.012694 | 0.017073 |

These are exactly the baseline policy metrics. The new indicators did not fire
on any validation or test row at all. That is good for regression safety. The
external Indian control run below did fire on spam, not ham, and left ham false
positives and any-non-ham flagging unchanged; it did increase smishing
overclassification of spam. The 89% handmade gain still lacks smishing-precision
validation on a fresh Indian set.

The locked test split has only 49 smishing examples and has already been
inspected during earlier work. It was not used to select these rules or tune
thresholds; this table is a post-change regression check, not a blind test.

## External Indian control benchmark

Source: `data/indian/india_spam_sms.csv` (`kaggle_india_spam_sms`), 2,014 input
rows. After removing 20 rows that overlapped the training/validation splits,
1,994 rows were evaluated: **1,295 ham, 699 spam, 0 smishing**. The set has no
smishing labels and was observed in an earlier evaluation, so this is a
previously observed control benchmark, not a blind held-out test. It was not
used to tune the rules or thresholds.

| View | Precision | Recall | F1 | Ham FPR |
|---|---:|---:|---:|---:|
| Policy: any non-ham | 78.84% | 95.42% | 0.8634 | 13.82% |
| Policy: exact spam | 70.81% | 61.09% | 0.6559 | 13.59% |
| Classifier: any non-ham | 79.17% | 92.99% | 0.8553 | 13.20% |
| Classifier: exact spam | 74.47% | 70.10% | 0.7222 | 12.97% |

`any non-ham` treats spam or smishing as flagged; `exact spam` requires the
policy label `spam` and exposes smishing overclassification. The high-risk band
contained 65 rows, all non-ham; 405 of 1,295 ham rows were flagged
(`31.27%`), but none were high-risk.

The new flags fired only on spam rows: `TELECOM_LURE` 26 and `TASK_SCAM` 1.
The other six new codes did not fire. Ham false positives were unchanged from
the prior evaluation, and the any-non-ham precision/recall were identical.
Exact-spam metrics declined because 21 additional spam rows were labelled
smishing (222 to 243 predicted smishing; exact-spam precision `71.79%` to
`70.81%`, recall `64.09%` to `61.09%`; macro-F1 `0.5303` to `0.5232`). This is a
real precision/overclassification tradeoff, not a free improvement.

Limitations: the set has no smishing labels, so smishing precision and recall
are not estimable; the binary spam/ham precision and ham false-positive rate
above are the interpretable results. The set is not blind, and template or
campaign duplication may remain. Do not tune thresholds on it. Aggregate
results are in `experiments/hardening/results/indian_control/`; raw messages
remain local and are not committed.

## PTQ artifact check

Frozen artifact:
`experiments/mobilebert/qat/artifacts/ptq_int8_b1.pte`

- Size: `37,250,700` bytes (~35.5 MiB).
- Handmade coverage: 92/100.
- Argmax agreement with FP32: 99/100.
- Maximum absolute logit difference vs FP32: `1.436554193496704`.
- The artifact is hybrid INT8/FP32. It is not a full-INT8 deployment claim.
- Desktop PTE timing from earlier work was about `115 ms/message`; Pixel 6a
  latency remains unmeasured.

QAT is still not the deployment candidate because its locked-test smishing
recall was lower than PTQ's. PTQ is the quantized candidate for Tier 2, subject
to device verification.

## Portable export and retraining

The production artifact was not overwritten.

- Portable parity on 100 handmade messages: maximum logit difference
  `4.440892098500626e-16` (numerically exact).
- Portable size: `1,385,777` bytes (~1.32 MiB), not the plan's stated 0.8 MB.
- Feature blocks: word `13,545`, char `0`, indicators `0`.
- Production portable SHA-256:
  `39fc6e68b5270a828b3c52d02de6a46ac9e0443f8fa0dd07c2ab0119a421b997`.

An isolated retrain was run under `experiments/hardening/model_retrain`:

- Selected experiment: `E1b_word_lr_balanced` (same as production).
- Thresholds: high `0.385`, suspicious `0.1009090909090909`,
  evidence-free high `0.8`.
- Classifier-only validation macro-F1: `0.903414`, smishing recall `0.808511`.
- Classifier-only test macro-F1: `0.891012`, smishing recall `0.816327`.
- Exported portable model is byte-identical to the production portable model.
- Handmade prediction difference against the production model: `0.0`.

The retrained `model.joblib` byte hash differs because joblib/pickle metadata is
not canonical, but the exported weights and predictions are identical.

## Kotlin Tier-1 parity (desktop JVM)

A dependency-free Kotlin/JVM port now covers the Python Tier-1 path:

- normalization and entity masking;
- all 31 indicator flags, including the eight new hardening codes and DLT sender
  handling;
- the exported word-only `sms-linear-v1` TF-IDF model;
- production risk fusion (high `0.385`, suspicious `0.1009090909090909`,
  evidence-free high `0.8`), rule labels, reason codes, and action codes.

Verification used the 100 handmade messages plus 100 sampled validation and 100
sampled test rows, with 34 synthetic cases added for rule and policy coverage:

| Layer | Synthetic | Local wider | External Indian | Result |
|---|---:|---:|---:|---|
| Normalization + evidence | 34/34 | 334/334 | n/a | exact |
| Full 31-flag vector | 34/34 | 334/334 | 2,014/2,014 | exact |
| Portable model logits/probabilities | 34/34 | 334/334 | 2,014/2,014 | max logit diff `1.33e-15` |
| End-to-end policy | 34/34 | 334/334 | 2,014/2,014 | max score diff `3.33e-16` |

The local policy run exercised all labels (`ham=168`, `spam=40`,
`smishing=126`), all risk levels (`low=156`, `suspicious=101`, `high=77`), all
rule labels (`ham=238`, `spam=22`, `smishing=74`), and all 31 indicator flags.
Label, risk, action-code order, rule label, `rule_triggered`, and reason-code
order matched exactly.

The external 2,014-row run exposed two JVM/Python differences that the prior
332-case fixture had not exercised:

- Java `Pattern.COMMENTS` ignores literal spaces inside character classes,
  unlike Python `(?x)`. Spaced variants such as `top up`, `pre approved`, and
  `part time` were missed. The affected classes now use `\x20`.
- Java `(?U)\w` includes combining marks, unlike Python `\w`. The model
  tokenizer now uses `[\p{L}\p{N}_]+`.

Two synthetic regression cases cover these paths. After the fixes, the
2,014-case external flags, model, and policy fixtures all matched exactly
(maximum logit difference `1.33e-15`, maximum policy-score difference
`3.33e-16`). The external parity fixture includes all 2,014 rows; the metrics
above use the 1,994 leakage-filtered rows.

The Kotlin source is in `tier1-kotlin/`; the parity artifacts are
`experiments/hardening/results/kotlin_parity.json`,
`kotlin_flags_parity.json`, `kotlin_model_parity.json`,
`kotlin_policy_parity.json`, and
`kotlin_indian_control_parity.json`. Raw SMS fixtures are kept only in the
approved local temp workspace and are not committed.

This is desktop-JVM parity, not Android runtime evidence. It does not establish
Pixel 6a latency, thermal behavior, RAM use, INT8 parity, or a fresh blind
Indian precision estimate; the external control benchmark is previously observed
and has no smishing labels.

## Important limitation for Android

The Kotlin port is desktop-JVM code, and `android-app/` now compiles it into a
local-only debug APK (Gradle 9.9.1, AGP 9.5.0, JDK 17, SDK 37, Build Tools
36.0.0). The APK declares only `RECEIVE_SMS` and `POST_NOTIFICATIONS`, has no
`INTERNET` permission, and bundles the production portable model with a matching
SHA-256. It uses the word-only portable JSON, not the PTQ `.pte`.

No Pixel 6a was connected, so the app has **not** been installed or run on a
device. Android still needs:

1. ~~An app/service scaffold that keeps SMS bodies local.~~ Done and
   build-verified.
2. ~~Integration of the Kotlin evidence/model/policy core.~~ Done for the
   portable word TF-IDF path.
3. PTQ JNI/ExecuTorch integration and local explanation rendering.
4. Latency, thermal, RAM, operator-fallback, and output-parity measurements on
   the Pixel 6a.

The `.pte` MobileBERT artifact does not contain the SMS rules, and the portable
JSON is word-only.

Until those steps are complete, do not claim:

- full INT8 deployment;
- Android/Pixel 6a latency improvement;
- 89% handmade coverage on-device;
- smishing precision on a fresh blind Indian set;
- an end-to-end Android smishing guard.

## Reproduce

From `sms-detection/`:

```powershell
# Unit tests
.venv\Scripts\python.exe -m pytest tests -q

# Handmade report without overwriting the original results
experiments\mobilebert\.venv\Scripts\python.exe `
  experiments\handmade_evaluation\evaluate_handmade.py `
  --model-dir artifacts\model `
  --output-dir experiments\hardening\results\handmade_after_rules

# Frozen PTQ PTE coverage
experiments\mobilebert\.venv\Scripts\python.exe `
  experiments\hardening\evaluate_ptq_handmade.py

# Isolated retrain and export
.venv\Scripts\python.exe scripts\train.py `
  --model-dir experiments\hardening\model_retrain `
  --reports-dir experiments\hardening\reports_retrain `
  --docs-dir experiments\hardening\docs_retrain

# Kotlin desktop-JVM parity (requires a local JDK/Kotlin compiler)
$env:JAVA_HOME = "C:\path\to\jdk"
$env:KOTLINC = "C:\path\to\kotlinc\bin\kotlinc.bat"
.\tier1-kotlin\verify.ps1
.\tier1-kotlin\verify.ps1 -Flags -Fixture "fixtures/synthetic_flags_parity.tsv"
.\tier1-kotlin\verify.ps1 -Model -Fixture "fixtures/synthetic_model_parity.tsv"
.\tier1-kotlin\verify.ps1 -Policy -Fixture "fixtures/synthetic_policy_parity.tsv"

# External Indian control fixtures and parity (raw bodies stay local)
$dir = "$env:LOCALAPPDATA\Temp\opencode\bharat_parity"
.\.venv\Scripts\python.exe experiments\hardening\export_indian_parity.py `
  --output-dir "$dir"
.\tier1-kotlin\verify.ps1 -Flags -Fixture "$dir\indian_flags_parity_local.tsv"
.\tier1-kotlin\verify.ps1 -Model -Fixture "$dir\indian_model_parity_local.tsv"
.\tier1-kotlin\verify.ps1 -Policy -Fixture "$dir\indian_policy_parity_local.tsv"
```

## Evidence files

- `experiments/hardening/results/handmade_after_rules/summary.json`
- `experiments/hardening/results/handmade_after_rules/comparison_report.md`
- `experiments/hardening/results/ptq_handmade.json`
- `experiments/hardening/results/policy_eval.json`
- `experiments/hardening/results/portable_parity.json`
- `experiments/hardening/results/retrain_check.json`
- `experiments/hardening/results/gate0_provenance.json`
- `experiments/hardening/results/kotlin_parity.json`
- `experiments/hardening/results/kotlin_flags_parity.json`
- `experiments/hardening/results/kotlin_model_parity.json`
- `experiments/hardening/results/kotlin_policy_parity.json`
- `experiments/hardening/results/kotlin_indian_control_parity.json`
- `experiments/hardening/results/indian_control/indian_eval.json`
- `experiments/hardening/results/indian_control/indian_eval.md`
- `artifacts/reports/android_build.json`
- `tier1-kotlin/fixtures/synthetic_parity.tsv`
- `tier1-kotlin/fixtures/synthetic_flags_parity.tsv`
- `tier1-kotlin/fixtures/synthetic_model_parity.tsv`
- `tier1-kotlin/fixtures/synthetic_policy_parity.tsv`

## Recommended next action

The Python behavior is now frozen and has desktop-JVM Kotlin parity for the
Tier-1 evidence, portable model, and policy layers, including a 2,014-row
external Indian control run. That control set is previously observed and has no
smishing labels, so the next measurement needed is smishing precision on a
fresh blind Indian set. The Android toolchain is installed and the local-only
scaffold builds, but no device is attached. Connect the Pixel 6a, install the
APK, and measure device latency, thermal behavior, RAM, operator fallback, and
output parity before deciding whether the PTQ artifact can replace FP32.
