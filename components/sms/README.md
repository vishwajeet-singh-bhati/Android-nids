# SMS scam detector

## Available source and artifacts

`python/` contains the supplied Python preprocessing, source loading, deduplication, baseline training, calibration, evaluation, export, prediction and schema code. Its original LICENSE is retained. `models/` contains the supplied fitted Tier-1 `model.joblib`, metadata and portable coefficient export. Android uses the portable coefficients and the separately bundled MobileBERT PTE under `android/app/src/main/assets/sms/`.

The Python reference retains the original policy. Current Android includes the later link-only and guarded-congratulations routing fixes and URL/email extraction correction; the original Python policy should not be assumed to have those changes. Android is the current app implementation.

## Architecture and data

The message body is normalized; links/emails/phones are extracted and replaced in model text. Word unigram/bigram TF-IDF has13,545 features, followed by a three-class logistic classifier (ham/spam/smishing). Evidence and risk rules determine whether deeper analysis is required. The current MobileBERT-22 artifact uses hybrid INT8/FP32, three int64 `[1,128]` tensors and three output logits. A rule-based cascade fuses results; raw scores are not calibrated fraud probabilities.

Tier-1 metadata records4,055 training,869 validation,869 test and27,885 external rows. The selected experiment uses balanced classes, C=1 and seed42. Original datasets and exact split files are not distributed. The split-manifest hash is preserved in `models/metadata.json`. Supplied code enables preprocessing/training after obtaining permitted source data; it does not guarantee the original exact split without those files.

The full archive supplied on24 November also provides the neural trainer, evaluator, PTQ/QAT code, selected FP32 checkpoint/config/tokenizer and archived comparison metrics under `python/experiments/mobilebert/`. Its selected22-layer checkpoint contains22,898,947 tensor elements. Training uses `google/mobilebert-uncased`, omits its final two encoder blocks for the documented stability issue, and fine-tunes4 epochs at learning rate5e-5, batch16, maximum128 tokens, seed42. Best validation checkpoint: epoch3. The archived PTQ batch-one hash exactly matches the deployed PTE.

[Archived provenance and evaluation](provenance/ARCHIVED_EVALUATION.json) records the original split, training settings, classwise FP32/PTQ/QAT results and artifact hashes. Original train/validation/test CSV hashes were independently checked inside the supplied archive; datasets themselves are not published. Those archived test scores are not newly rerun phone/cascade results. Exact dataset reproduction still requires obtaining permitted source data and matching the recorded hashes/split procedure.

## Desktop reference inference

Use a separate Python environment for this component, install `python/requirements.txt`, then from `components/sms/python` run:

```bash
python -m sms_detection.cli info --model-dir ../models
python -m sms_detection.cli predict "Your OTP is 123456. Do not share it." --model-dir ../models
python -m sms_detection.models.train_baseline --help
```

The model artifact was supplied by the project handoff; compare its recorded hash before loading. Python library versions can affect joblib compatibility. Android inference does not need desktop scikit-learn or Python.

## Validation limits

Native checks cover4 x34 Tier-1 fixtures,14 neural token/class matches and230 authored scenarios. The observed maximum neural logit difference0.449647 exceeds the strict0.05 criterion, despite matching classes. Scenario regression agreement is not real-world scam accuracy. Carrier SMS examples have been observed, but this is not a representative independent SMS dataset. Read the [app guide](../../docs/rakshak/README.md) and report for exact results and failure cases.
