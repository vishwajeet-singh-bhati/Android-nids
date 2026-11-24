# Model Card — SMS Scam Detector

Version: `sms-model-0.1`  
Created: 2026-11-10T19:26:21.559377+00:00  
Selected experiment: `E1b_word_lr_balanced`

## Intended use

Local, on-device screening of SMS into `ham`, `spam` and `smishing`, with
structured evidence and safe action codes for a separate Llama explanation
layer. The detector makes the threat classification; the LLM must not invent
or override detections.

## Out of scope

- URL reputation or domain intelligence (owned by the URL teammate).
- Network-flow anomaly detection (owned by another teammate).
- Auto-deleting messages, auto-clicking links, or claiming certainty.
- Sending SMS bodies to a cloud API.

## Architecture

- Selected model: word TF-IDF (1–2 grams) + multiclass Logistic Regression with `class_weight="balanced"`.
- Character n-grams and indicator features were evaluated (E2/E3) but did not win under the high-band precision/recall constraint.
- Deterministic indicators are still computed at inference and used by rule/risk fusion: URL, OTP/credential request, account threat, account-access lure, payment demand, urgency, prize/loan/delivery bait, sender mismatch and obfuscation.
- Cost-sensitive risk thresholds select a narrow high-risk band and a recall-oriented suspicious band on validation only.
- High-risk escalation normally requires a strong evidence cue; a smishing score at or above the evidence-free cutoff can stand alone.
- Conservative guards suppress routine salary/EMI/payment and delivered-order notifications unless a link, request, threat or fee is present.
- Temperature scaling is fitted and evaluated but is applied only if it preserves the high-band operating point.

## Training data

- Training rows: 4,055
- Validation rows: 869
- Locked test rows: 869
- External rows: 27,885
- Feature count: 13,545
- Model file size: 839,350 bytes

Sources: UCI SMS Spam Collection, Mishra & Soni LSDST-2022, NCSU SMS Phishing
(external only), and the Hinglish seed corpus (external only). See `docs/data-card.md`.

## Evaluation summary — product policy output

| Split | Policy macro-F1 | Policy smishing recall | Policy smishing precision | Ham flagged | High-risk recall | High-risk precision | Ham high-risk |
|---|---:|---:|---:|---:|---:|---:|---:|
| `val` | 0.888 | 0.809 | 0.776 | 0.048 | 0.532 | 0.926 | 0.000 |
| `test` | 0.869 | 0.837 | 0.745 | 0.069 | 0.449 | 0.733 | 0.000 |
| `external` | 0.576 | 0.844 | 0.999 | 0.082 | 0.806 | 1.000 | 0.004 |

Classifier-only locked-test metrics: macro-F1 0.891, smishing recall 0.816, ham false-positive rate 0.013.

The two bands have different jobs. The high band is safe to interrupt on and
therefore has lower recall. The suspicious band carries most of the recall and
always asks the user to verify through an official channel.

## Calibration

- Fitted temperature: 0.407
- Applied: **False**
- Reason: calibrated high-risk threshold missed the recall/precision floor
- Raw/calibrated ECE: 0.1250 / 0.0076
- Scores are therefore not presented as calibrated probabilities.


## Limitations

- Small locked smishing test set (49 examples); wide uncertainty.
- Old UCI corpus and limited modern Indian English/Hinglish coverage.
- NCSU campaign templates are source-labelled phishing but include gambling/promotional spam; external exact-class metrics are noisy.
- The external split is dominated by NCSU campaigns, so its macro-F1 is not comparable to the balanced locked test.
- Sender metadata is sparse; `SENDER_ID_UNVERIFIED` is a weak signal only.
- Scores are not calibrated; thresholds need re-validation on the target Pixel 6a data.
- The high-risk band is intentionally narrow. Most recall comes from the suspicious band.

## Safety and privacy

- Inference is local; the returned JSON contains no raw SMS text.
- Evidence codes are stable and auditable.
- Recommended actions are conservative; no automatic destructive action.
- Raw datasets and audit examples are excluded from Git.

## Artefacts

- `artifacts/model/model.joblib` — scikit-learn model.
- `artifacts/model/metadata.json` — thresholds, calibration, version, hashes.
- `artifacts/model/portable/portable_model.json` — export for future Kotlin parity.
- `artifacts/reports/baseline_metrics.json` — full experiment report.
