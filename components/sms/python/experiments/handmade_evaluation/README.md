# Handmade smishing evaluation

This folder contains the read-only evaluation of the two existing models on the
handmade smishing messages.

## Dataset

The requested path:

```text
experiments/handmade_evaluation/smishing_dataset.csv
```

was not present when the evaluation ran. The only matching source file was:

```text
experiments/mobilebert/handmade_dataset/smishing_dataset.csv
```

That fallback file was used read-only. It has 100 rows and the columns `ID`,
`Category`, `Message`, and `Tactic`. The source hash before and after the run is
recorded in `results/manifest.json`.

## Models

- **TF-IDF full detector (primary):** `artifacts/model`, loaded through
  `SmsDetector.from_artifact(...)`, including the saved risk-policy thresholds.
  No threshold was changed.
- **TF-IDF classifier-only (diagnostic):** the classifier argmax before the risk
  policy, recorded to separate model behaviour from policy behaviour.
- **MobileBERT-22:** the existing checkpoint at
  `experiments/mobilebert/checkpoints/mobilebert22_lr5e5_bs16_e4/best`, using
  `normalize_text(message).model_text`, `max_length=128`, and softmax argmax.
  MobileBERT has no policy layer, so no threshold was applied to it.

No model was retrained.

## Run

From the `sms-detection/` directory:

```powershell
experiments\mobilebert\.venv\Scripts\python.exe experiments\handmade_evaluation\evaluate_handmade.py
```

## Results

- `results/comparison_report.md` — overall, category-wise, and tactic-wise
  comparison.
- `results/predictions.csv` — every message with both models' labels, class
  probabilities, confidence scores, TF-IDF risk/evidence fields, and the
  provisional `smishing` label. This file contains raw SMS text.
- `results/predictions_text_free.csv` — the same predictions without SMS bodies,
  suitable for sharing or review.
- `results/category_comparison.csv` — category aggregates.
- `results/tactic_comparison.csv` — all tactic aggregates.
- `results/summary.json` — machine-readable overall and agreement summary.
- `results/manifest.json` — dataset/model hashes, environment, thresholds, and
  output inventory.

## Interpretation

All 100 messages are provisionally treated as smishing. There are no
non-smishing controls, so the detection rate is a coverage/recall measure.
Precision, specificity, and false-positive rate cannot be estimated from this
dataset. The dataset is small and most tactics occur once, so category and
tactic rates are descriptive rather than statistical.

The TF-IDF primary result includes its saved risk policy, while MobileBERT-22
uses a classifier argmax only. The TF-IDF classifier-only row is included to
make that difference explicit.
