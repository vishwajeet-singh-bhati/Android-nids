# Portable linear model

This directory contains `portable_model.json`, a runtime-neutral export of the
TF-IDF + Logistic Regression baseline. It is intended for the Android/Kotlin
phase, where scikit-learn is unavailable and ExecuTorch is not appropriate for a
sparse linear model.

## Contents

- Word and character n-gram vocabularies with fitted IDF values.
- Indicator feature names and block order.
- Coefficients (one row per label, in `ham`, `spam`, `smishing` order) and intercepts.
- One temperature value for calibration.

Feature block sizes: word=13545, char_wb=0, indicators=0.

## Required on-device behaviour

1. Reimplement `normalize_text` exactly, including URL/email/phone masking and
   leetspeak handling.
2. Build word 1–2 grams and `char_wb` 3–5 grams from the normalized model text.
3. Apply sublinear term frequency, multiply by the exported IDF vector and L2
   normalize each block.
4. Append the deterministic indicator features in the exported order.
5. Compute `logits = coefficients @ features + intercepts`, then
   `softmax(logits / temperature)`.

Do not silently update these weights. Bundle them with a version and checksum,
and verify predictions against `SmsClassifier` before release.

`PortableLinearClassifier` in `src/sms_detection/models/export.py` is the Python
reference implementation used by the parity test.
