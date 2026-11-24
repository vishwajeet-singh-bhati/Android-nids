# Explainable On-Device SMS Scam Detector

> Current Android candidate: **v0.5.0**, with narrow routine-message routing,
> a simplified dashboard and a one-button 230-case synthetic benchmark.
> See [automated validation](experiments/automation_review/README.md),
> [dataset card](experiments/automation_review/DATA_CARD.md), and
> latest report (upstream historical document; see the [current SMS component](../README.md)).
> This version has desktop validation; installation/testing on the disconnected
> Pixel remains pending. The older scaffold/results below are historical.

> Current policy update (2026-11-11): ordinary spam is quiet; contextual service
> patterns request review without automatically asserting fraud. Android review
> notifications use a quiet channel. Older metrics below describe the historical
> policy. See current results and next steps (upstream historical document; see the [current SMS component](../README.md)) before
> interpreting accuracy or deployment claims.

A local-first SMS screening baseline that classifies messages as `ham`, `spam`,
or `smishing` and returns auditable evidence codes. It is designed for the Bharat
AI 2026 on-device pipeline: a compact detector makes the decision, and a separate
Llama layer only explains the structured result.

**Privacy rule: SMS bodies are never sent to a cloud service.** Inference runs
locally, and the JSON returned to the UI/explanation layer contains no raw SMS
text.

## What is in this repository

- A normalized, provenance-aware dataset pipeline for public SMS datasets.
- A separate Kaggle-sourced Indian ham/spam diagnostic, kept out of training.
- Exact, template, near-duplicate, and campaign-aware grouping to reduce leakage.
- A deterministic evidence/rules layer with stable machine-readable codes.
- A sparse TF-IDF + Logistic Regression classifier and an E0–E3 experiment
  harness.
- Cost-sensitive risk fusion with a high-precision `high` band and a
  recall-oriented `suspicious` band.
- Validation-only threshold selection, calibration gating, and a locked test
  split.
- A parity-tested Kotlin port and a compiled local-only Android scaffold
  (`android-app/`) that reuse the exported portable model.
- Tests covering normalization, indicators, policy behavior, schema, leakage,
  thresholds, and portable-model parity.

The selected baseline is `E1b_word_lr_balanced`: word TF-IDF (1–2 grams) plus
multiclass Logistic Regression with `class_weight="balanced"`. Character n-grams
and indicator features were evaluated but did not win under the high-band
precision/recall constraint.

## Android scaffold status

`android-app/` compiles the verified desktop-JVM core and packages the exact
production portable model. The debug APK built successfully with Gradle 9.9.1,
AGP 9.5.0, JDK 17, SDK Platform 37, and Build Tools 36.0.0:

- APK: `1,440,106` bytes; SHA-256
  `7d57b23728eef55380b2d21bee19900b6bfefc54c7c7bbc7afd8c91a1a02553f`
- permissions: `RECEIVE_SMS` and `POST_NOTIFICATIONS` only; no `INTERNET`
- bundled `portable_model.json` matches the production SHA-256
  `39fc6e68b5270a828b3c52d02de6a46ac9e0443f8fa0dd07c2ab0119a421b997`

This is build evidence only. No Pixel 6a was connected, so latency, thermal,
RAM, process-survival, operator fallback, and on-device output parity are still
unmeasured. The app uses the portable word TF-IDF model; the ExecuTorch PTQ
`.pte` path is not integrated. See `android-app/README.md` and
`artifacts/reports/android_build.json`.

## Quick start

### 1. Create the environment

Requires Python 3.11 or newer. The project was validated with Python 3.14.

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e ".[dev,report,data]"
```

If PowerShell blocks activation, call the interpreter directly, for example
`.venv\Scripts\python.exe -m pip ...`.

### 2. Run the tests

```powershell
python -m pytest -q
```

The data-integrity tests skip automatically when the processed splits are absent.
The trained-artifact integration test skips when `artifacts/model/model.joblib`
has not been generated yet.

### 3. Build the dataset and model

Run these commands from the project root, in order:

```powershell
python scripts\download_data.py
python scripts\prepare_data.py
python scripts\audit_data.py
python scripts\train.py
```

Raw downloads go to `data/raw/`, derived splits to `data/processed/`, and model
reports/model files to `artifacts/`. Raw data, processed data, audit examples,
and the binary `.joblib` model are git-ignored. The generated documentation is
`docs/data-card.md`, `docs/evaluation-report.md`, and `docs/model-card.md`; the
separate Indian source diagnostic is `docs/indian-source-benchmark.md`.

The training step prints the E0–E3 comparison, selects the winning experiment on
validation, checks calibration feasibility, and evaluates the locked test and
external stress split once.

## Using the detector

After a model has been trained:

```powershell
sms-detect info
sms-detect predict "Your KYC is pending. Update at https://sbi-kyc-verify.in or your account will be blocked."
sms-detect predict-batch examples\demo_messages.json
```

`predict` reads from stdin when the message is omitted:

```powershell
Get-Content .\message.txt -Raw | sms-detect predict
```

The output is a text-free JSON contract. A simplified illustration:

```json
{
  "label": "smishing",
  "risk_level": "high",
  "scores": {
    "ham": 0.04,
    "spam": 0.04,
    "smishing": 0.92
  },
  "evidence": [
    {"code": "URL_PRESENT", "present": true},
    {"code": "KYC_LANGUAGE", "present": true},
    {"code": "ACCOUNT_THREAT", "present": true}
  ],
  "recommended_action_codes": [
    "DO_NOT_CLICK",
    "VERIFY_USING_OFFICIAL_CHANNEL",
    "REPORT_AS_SCAM"
  ],
  "explanation_source": "detector_evidence"
}
```

The actual scores depend on the model and message. The explanation layer must
not invent evidence or override the detector label. It can only phrase the
provided codes and advice for the user.

### Python API

```python
from sms_detection.predictor import load_detector

detector = load_detector()
result = detector.predict_sms(
    "Your account is blocked. Verify at https://example.invalid/login",
    sender="+919876543210",
)
print(result.to_json())
```

## Output contract

The public schema is written to
`artifacts/schema/sms_detection_result.schema.json` by:

```powershell
sms-detect schema
```

The contract deliberately has no `message` or `raw` field. Stable evidence codes
include `URL_PRESENT`, `OTP_REQUEST`, `CREDENTIAL_REQUEST`, `ACCOUNT_THREAT`,
`ACCOUNT_ACCESS_LURE`, `PAYMENT_REQUEST`, `URGENCY_LANGUAGE`,
`PRIZE_OR_REWARD_BAIT`, `DELIVERY_BAIT`, `KYC_LANGUAGE`,
`SENDER_CLAIM_MISMATCH`, and `OBFUSCATED_TEXT`. Action codes are advisory; the
detector never clicks, deletes, replies, or blocks anything automatically.

Risk bands:

| Band | Intended use |
|---|---|
| `low` | Normal inbox treatment; no interruption |
| `suspicious` | Ask the user to verify before acting; do not claim certainty |
| `high` | Strong interruption/review prompt with safe next-step actions |

The high band normally requires a strong evidence cue. A smishing score at or
above the evidence-free threshold (**0.800**) can stand alone. This prevents a
weak model score plus a single URL from producing an alarm.

## Current results

Product-policy output (classifier + evidence + risk fusion), selected on
validation and reported once on the locked test:

| Split | Macro-F1 | Smishing recall | Smishing precision | Ham flagged (any band) | Ham high-risk | High-band recall |
|---|---:|---:|---:|---:|---:|---:|
| Validation | 0.888 | 0.809 | 0.776 | 4.8% | 0.0% | 0.532 |
| Locked test | 0.869 | 0.837 | 0.745 | 6.9% | 0.0% | 0.449 |
| External stress | 0.575 | 0.843 | 0.999 | 8.2% | 0.4% | 0.804 |

Classifier-only locked-test diagnostics: macro-F1 **0.891**, smishing recall
**0.816**, and ham false-positive rate **0.013**.

The locked test is small (49 smishing examples), so the confidence intervals are
wide. The high band is intentionally narrow and precision-oriented; most recall
comes from the suspicious band. All 49 smishing messages in the locked test are
flagged in at least one band.

Thresholds: high **0.385**, suspicious **0.101**, evidence-free high **0.800**.
They are selected on validation only. Temperature scaling was fitted but rejected
because it degraded high-band precision at the feasible operating point; the
scores are therefore not presented as calibrated probabilities.

### Why the external result is not a clean benchmark

The external split is 97.7% NCSU source-labeled smishing. NCSU campaigns include
gambling and promotional spam, so the source-level `smishing` label is noisy. The
split also combines source-held-out campaigns, held-out classic messages, and the
small Hinglish seed. Read its exact-class macro-F1 as a stress-test diagnostic,
not as an estimate of real-world prevalence or accuracy.

## Testing on Indian SMS

To build the human-reviewed development dataset, start with
the Indian annotation workflow (upstream historical document; see the [current SMS component](../README.md)). It prepares a
private review pool, keeps source labels separate, requires two reviewers and
preserves observed data as development-only. Preparation does not train or
automatically assign verified labels.

A representative, independently sampled Indian **smishing** benchmark is still
missing. The repository now downloads and evaluates a separate Kaggle-sourced
Indian ham/spam diagnostic (2,267 raw rows; 2,014 after exact deduplication;
1,994 after leakage filtering). It is **not** used for training or threshold
selection, it has no `smishing` labels, and it is not a random sample of Indian
traffic. It therefore cannot support a claim of Indian smishing performance.

```powershell
python scripts\download_data.py
python scripts\prepare_india_source.py
python scripts\evaluate_indian.py `
  --input data\indian\india_spam_sms.csv `
  --name kaggle_india_spam_sms
```

The frozen baseline's binary diagnostic on this source:

| View | Precision | Recall | F1 | Ham flagged |
|---|---:|---:|---:|---:|
| Policy: any non-ham | 78.8% | 95.4% | 0.863 | 13.8% |
| Policy: exact `spam` | 71.8% | 64.1% | 0.677 | 13.6% |
| Classifier: any non-ham | 79.2% | 93.0% | 0.855 | 13.2% |
| Classifier: exact `spam` | 74.5% | 70.1% | 0.722 | 13.0% |

Most spam is surfaced when either `spam` or `smishing` counts as a warning, but
219 of 699 spam rows are over-escalated to `smishing`, and 179 of 1,295 ham rows
are flagged. The high band is not validated for Indian smishing because the
source has no smishing labels. See `docs/indian-source-benchmark.md` for the full
diagnostic and caveats.

After the eight context-gated hardening rules, the same previously observed
control set gives policy any-non-ham precision `78.84%` and recall `95.42%`,
exact-spam precision `70.81%` and recall `61.09%`, and ham flagged `13.82%`. The
new rules fired only on spam (`TELECOM_LURE` 26, `TASK_SCAM` 1), so ham false
positives and any-non-ham flagging were unchanged; 21 additional spam rows were
labelled `smishing`, which reduced exact-spam precision/recall. This remains a
diagnostic, not a blind or smishing-labelled benchmark. Aggregate results are in
`experiments/hardening/results/indian_control/`.

For a consented, independently sampled benchmark, use the same local evaluator:

```powershell
python scripts\evaluate_indian.py `
  --input data\indian\benchmark.csv `
  --name pilot `
  --target-prevalence 0.02 `
  --audit-output data\indian\audit_pilot.csv
```

Expected columns are `text` and `label` (`ham`, `spam`, `smishing`, or
`uncertain`), with optional `language`, `sender`, `sender_type`, `scam_type`,
`collection_date`, `group_id`, `source`, and `known_sender`. The evaluator
checks for exact, template, and near-duplicate leakage against the processed
splits, reports policy and classifier metrics with confidence intervals, and
writes aggregate reports plus an optional private audit. `data/indian/` is
git-ignored.

See `docs/indian-test-guide.md` for the sampling, consent, labelling, leakage,
and interpretation protocol.

## Data and leakage controls

Sources:

- UCI SMS Spam Collection — old English ham/spam baseline.
- Mishra & Soni LSDST-2022 — English/Indian SMS with ham, spam, and smishing.
- NCSU SMS Phishing campaign corpus — external stress test only.
- Hinglish scam-text dataset — external seed, mostly UCI-derived; only 63
  hand-written rows are independent.
- Kaggle India Spam SMS Classification — separate binary ham/spam diagnostic;
  no smishing labels; not used for training or threshold selection.

Split groups combine exact normalized text, a masked template, MinHash near
duplicate clusters, and NCSU campaign IDs. No group is shared across train,
validation, test, or external. External rows that collide with a group in the
main pool are removed and reported. See `docs/data-card.md` and
`data/processed/split_manifest.json` after running the pipeline.

## Privacy and safety guarantees

- The inference path performs no network requests.
- The returned contract contains no SMS body and no extracted URL/phone/email.
- Evidence is represented by stable codes, not free-form hidden reasoning.
- Raw datasets, processed splits, audit examples, logs, and the binary model are
  excluded from Git.
- The detector is a screening aid, not a certainty engine.
- No automatic click, delete, reply, payment, or blocking action is performed.
- A downstream explanation model must receive only the structured result, not
  the raw message.

## Repository layout

```text
sms-detection/
├── scripts/                    # data, audit, train, and Indian evaluation entry points
├── src/sms_detection/
│   ├── data/                   # source loading, label mapping, deduplication, Indian benchmark loader
│   ├── preprocessing/          # normalization and deterministic indicators
│   ├── models/                 # classifier, calibration, evaluation, Indian evaluation, export
│   ├── policy/                 # rules, risk fusion, safe action codes
│   ├── interface/schema.py     # text-free public JSON contract
│   ├── predictor.py            # local inference facade
│   └── cli.py                  # sms-detect command
├── tests/                      # unit, leakage, parity, and artifact tests
├── docs/                       # cards, evaluation reports, and Indian benchmark guide
├── artifacts/                  # generated model/reports/schema (mostly ignored)
└── data/                       # raw/interim/processed/Indian data (ignored)
```

## Limitations and next steps

- The locked smishing test set is small; collect more modern Indian English and
  Hinglish examples with group-aware splits.
- The Kaggle Indian source is binary ham/spam and convenience-sampled. It shows
  a 13.8% ham flag rate and smishing over-escalation, so it is a diagnostic, not
  an Indian validation claim; do not tune on it.
- UCI is old and geographically mismatched; do not generalize its performance to
  current Indian SMS traffic.
- The high band has limited recall. Do not describe the detector as covering all
  smishing; the suspicious band carries most of the recall.
- Scores are uncalibrated. Revisit calibration with a rank-preserving method and
  more validation data.
- Sender metadata is sparse; sender checks are weak heuristics, not reputation.
- Android/Kotlin inference parity is the next implementation step. Use
  `artifacts/model/portable/portable_model.json` and its parity tests as the
  starting point.
- Compare against a neural/OpenTextShield baseline only after preserving the
  same leakage-resistant splits and privacy constraints.

## License

MIT. See `LICENSE`.
