# Model improvement phase: preserve the submission baseline

Status:24 November2026. Current deployed baseline is Rakshak0.17.3/code46. No new candidate is accepted by this plan. 

## Evidence that determines the priorities

- The SMS full archive supplies the selected22-layer FP32 checkpoint, trainer, PTQ/QAT scripts and the exact deployed PTQ hash. Training/validation/test source hashes match the archive and declared split groups are disjoint.
- Archived869-row comparison: FP32 smishing recall46/49, precision46/59; deployed PTQ export44/49 and44/56; QAT export37/49 and37/43. FP32 detects two more positives but adds one false positive; QAT reduces false positives but loses seven positives. Neither is automatically a better deployed pipeline. These are archived classifier results on a reused test set, not new app-warning measurements.
- Current URL raw ensemble finds172/218 known positives;30 uncertain and16 likely safe. Saved lists rescue those cases. The other1,830 supplied URLs have unknown truth; no valid overall precision estimate exists. All2,048 repeat export-reference inputs.
- Existing network weights still have ordinary-traffic false positives and protocol misses. Previously tried agreement/suppression rules lost detections or had inadequate fresh controls. A model size increase is not evidence of repair.

## Phase A: baseline and validation discipline

1. Pin code46, all model hashes, exact preprocessing and warning policy; retain rollback.
2. Preserve archived train/validation/test file hashes. Use training for fitting and validation for thresholds/model selection. Existing tests have already been opened; label further runs as reused regression checks.
3. Define outcomes separately: raw classifier class, combined risk, actual notification and confirmed attack/scam evidence. Report TP/FP/TN/FN at the same unit and do not equate an uncertainty review with a confirmed phishing decision.
4. Build a new independently labeled, grouped/time-separated phone cohort before claiming generalization. Keep raw personal text/URLs private and publish aggregate provenance/hashes only.

## Phase B: SMS candidates, smallest change first

Run the same validation examples through the frozen linear, FP32, PTQ and current cascade. Compare classwise precision/recall/F1 and ham/spam warning counts, latency and memory. Inspect disagreements that create warnings without supporting requests/links. The known `url_present` and standalone-congratulations bugs are already corrected; do not add a broad short-message or sender/domain exemption.

Candidates to evaluate on validation:

- Evidence-sensitive fusion/calibrated review thresholds; retain explicit secret/payment deception warnings and compare uncertain neural-only warnings separately.
- FP32 or an alternate PTQ calibration/export scope if it recovers recall at an acceptable measured runtime/FP cost. Use training-only calibration data and the matching tokenizer.
- A bounded additional fine-tuning run with training-only hard negatives (legitimate OTP, delivery, payment, congratulations, promotions and links), only if their labels/provenance are verified. Do not train from model predictions or current private test messages by default.

Choose the operating point on validation, freeze it, and perform one final regression comparison. Then test new carrier SMS with matched normal controls. Repeatedly adapting to the same869-row test does not create a fresh result.

## Phase C: URL data and model repair

Acquire fresh permitted phishing snapshots and independently reviewed benign pages, particularly genuine login/payment/tracking/redirect links. Absence from a feed is UNKNOWN. Split by website/campaign and collection time, deduplicate canonical/path templates, and audit train/validation/test overlap. Keep the previous2,048 reference cases as regression data only.

Compare fixed baselines: current CNN, current n-gram model and current calibrated ensemble. Evaluate model-only and list-assisted decisions independently. Refit scalers/features and the calibrator on training/validation only. Use held-out benign false-positive rate, phishing recall with uncertainty counted as missed, decisive coverage and latency/memory; do not optimize overall accuracy on a ham-heavy sample.

First candidates are calibration/threshold and representative hard-negative data changes. Increase capacity only if held-out errors show missing representation and a matched control demonstrates a gain. Never hardcode the user-reported live URL into a threat list without independent evidence.

## Phase D: network and runtime safeguards

Any network candidate must retain exact phone feature semantics and pass normal/attack protocol controls, classwise regression, capture health and alert grouping. Research authentication/context specialists remain separate unless they pass those gates. No blanket app/port/control-packet suppression.

For every candidate measure the same cold/warm CPU latency and RAM/PSS conditions; record hardware/runtime/thread count. Llama advice quality, bounded generation and privacy are separate checks. A more fluent explanation cannot justify a detector change.

## Promotion gates

- Same data/split/preprocessing/measurement conditions as the baseline, or explicitly documented differences.
- Lower verified benign warning counts without an unacceptable recall loss; report uncertainty and small sample limits.
- No privacy, history, permission, notification or model-loading regression; native model/reference checks pass, with known numerical drift retained.
- Runtime/memory fits the actual phone; model hashes and report tables correspond to the tested APK.
- User selects the candidate, then the mentor reviews the frozen evidence packet before the once-only submission.

If fresh labels, validation or time are insufficient before25November23:59IST, keep the documented baseline and its limitations. A rushed unvalidated candidate is not a completed improvement. Record the outcome rather than relabeling failed readiness as success.

For any new training run, retain every epoch checkpoint plus best/last, run the agreed epoch budget, and record validation curves. Do not let early stopping discard an unfinished promising candidate; use resumable checkpoints and an explicit extension decision. No new training is launched by this planning document.
