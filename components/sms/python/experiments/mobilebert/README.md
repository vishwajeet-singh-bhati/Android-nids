# MobileBERT SMS Experiment

This directory contains a separate experiment that fine-tunes a compact transformer
for the existing three-class SMS task (`ham`, `spam`, `smishing`) and compares it
with the unchanged TF-IDF + Logistic Regression baseline.

## Isolation rules

- The baseline model, datasets, splits, prediction pipeline, and risk-policy
  thresholds are read-only inputs.
- Training uses only `data/processed/train.csv` and `data/processed/val.csv`.
- The locked test split is loaded only by the single-use evaluation script after
  model selection and early stopping are complete.
- No raw SMS text is written to results. Aggregate metrics are the default.
  Per-example predictions are opt-in via `--write-per-example`.
- No cloud inference is used.

## Important MobileBERT limitation

The published `google/mobilebert-uncased` checkpoint produces numerically
unstable activations in its final encoder layers in the Hugging Face PyTorch
implementation. In this environment:

- 24 encoder layers: last hidden-state standard deviation around `2.9e7`
- 23 encoder layers: already unstable
- 22 encoder layers: stable, initial cross-entropy around `1.14`

The experiment therefore uses the first **22 layers** of the pretrained model,
with a freshly initialized three-class classification head. This is a documented
stability variant, **not a standard 24-layer MobileBERT result**. Do not describe
it as a full MobileBERT benchmark without this caveat.

## Data and preprocessing

- Existing grouped train/validation/test splits are reused unchanged.
- Train: 4,055 rows (`ham` 3,309; `spam` 539; `smishing` 207)
- Validation: 869 rows (`ham` 709; `spam` 113; `smishing` 47)
- Locked test: 869 rows (`ham` 709; `spam` 111; `smishing` 49)
- Model input: `normalize_text(raw).model_text`, the same privacy-preserving
  normalization used by the TF-IDF model (URLs, emails, and phone numbers are
  masked; text is normalized).
- Maximum sequence length: 128 tokens.
- Loss: class-weighted cross-entropy using inverse-frequency weights computed
  from the full training split.
- Model selection: validation macro-F1, with early stopping after two epochs
  without improvement.
- Seed: 42.
- CPU threads: 8.

## Environment

- Isolated virtual environment: `experiments/mobilebert/.venv`
- Python 3.14.3
- CPU only; no NVIDIA GPU/CUDA
- PyTorch 2.15.0 CPU
- Transformers 4.57.6
- ExecuTorch 1.6.0 (installed without the optional hydra dependency; see
  `requirements-executorch.txt`)
- Hugging Face cache: `experiments/mobilebert/cache/`

The isolated environment is not committed. The experiment does not install
anything into the project's baseline `.venv`.

## Files

- `common.py`: shared data, normalization, model-loading, metric, and batching utilities.
- `probe_environment.py`: hardware/model probe and the original 24-layer instability evidence.
- `probe_training.py`: 22-layer speed and memory probe.
- `debug_logits.py`: full 24-layer logit/loss diagnostic.
- `debug_activations.py`: layer-by-layer hidden-state diagnostic.
- `debug_weight_outliers.py`: checkpoint weight-outlier check.
- `debug_stable_variants.py`: comparison of 22- and 23-layer variants.
- `train_mobilebert.py`: fine-tuning, validation, early stopping, and checkpointing.
- `evaluate_mobilebert.py`: single-use comparison on the locked test split.
- `export_executorch.py`: dynamic-shape ExecuTorch export attempt.
- `export_executorch_static.py`: verified fixed-shape ExecuTorch export/runtime check.
- `requirements-executorch.txt`: optional ExecuTorch verification dependencies.
- `logs/`: local-only training and diagnostic logs.
- `checkpoints/`: local-only model checkpoints.
- `results/`: aggregate JSON/Markdown results and diagnostics.

## Commands

From the repository root:

```powershell
# Speed and memory probe
experiments\mobilebert\.venv\Scripts\python.exe experiments\mobilebert\probe_training.py

# Full fine-tune (train + validation only)
experiments\mobilebert\.venv\Scripts\python.exe -u experiments\mobilebert\train_mobilebert.py `
  --run-name mobilebert22_lr5e5_bs16_e4

# Validate the evaluation script on validation data (not the test split)
experiments\mobilebert\.venv\Scripts\python.exe experiments\mobilebert\evaluate_mobilebert.py `
  --split val --output-suffix val_check

# Single locked-test evaluation
experiments\mobilebert\.venv\Scripts\python.exe experiments\mobilebert\evaluate_mobilebert.py `
  --split test

# ExecuTorch fixed-shape export and runtime check
experiments\mobilebert\.venv\Scripts\python.exe experiments\mobilebert\export_executorch_static.py
```

## Training configuration

- 22 encoder layers, 3-class head
- Batch size: 16
- Evaluation batch size: 32
- Maximum epochs: 4
- Early-stopping patience: 2
- Learning rate: `5e-5`
- Weight decay: `0.01`
- Warmup: 10% of training steps
- Gradient clipping: 1.0
- Class weights: computed from the full training split
- Best checkpoint selected by validation macro-F1
- Training completed in 26 min 22 s; best epoch was 3 of 4

## Results

### Locked test split (869 rows, evaluated once)

| Metric | TF-IDF E1b | MobileBERT-22 | Difference |
|---|---:|---:|---:|
| Accuracy | 0.9620 | **0.9724** | +0.0104 |
| Macro-F1 | 0.8910 | **0.9142** | +0.0232 |
| Smishing recall | 0.8163 | **0.9388** | +0.1224 |
| Smishing precision | **0.8333** | 0.7797 | -0.0537 |
| Ham false-positive rate | 0.0127 | **0.0042** | -0.0085 |

MobileBERT-22 test confusion matrix (rows are true `ham`, `spam`, `smishing`;
columns are predicted):

| | ham | spam | smishing |
|---|---:|---:|---:|
| ham | 706 | 0 | 3 |
| spam | 8 | 93 | 10 |
| smishing | 0 | 3 | 46 |

The baseline artifact was reproduced exactly on this split (accuracy
`0.962025`, macro-F1 `0.891012`, smishing recall `0.816327`). Both models were
evaluated on the same 869 `message_id` values in the same order. The test
CSV SHA-256 is `603a2ae34179388c7e66bac757859f1719830434c00f3f8658b7a3c2242e7fcf`.

### Validation split (model-selection result)

| Metric | TF-IDF E1b | MobileBERT-22 |
|---|---:|---:|
| Accuracy | 0.9724 | 0.9689 |
| Macro-F1 | **0.9034** | 0.8772 |
| Smishing recall | **0.8085** | 0.7872 |
| Ham false-positive rate | 0.0056 | **0.0028** |

Validation favored the baseline on macro-F1, while the locked test favored
MobileBERT-22. Because the test has only 49 smishing rows, this single test
comparison should not be described as a stable or universal improvement.

### Size and latency

Measured on this CPU-only machine with 8 PyTorch threads. Latency is not a phone
measurement.

| Measurement | TF-IDF E1b | MobileBERT-22 |
|---|---:|---:|
| Stored model size | 0.80 MiB | 88.4 MiB checkpoint |
| Parameters / features | 13,545 features | 22,898,947 parameters |
| Single-message latency, end to end | **1.24 ms** | 42.2 ms |
| Batched latency | **0.029 ms/message** | 27.0 ms/message |
| ExecuTorch `.pte` | n/a | 87.7 MiB (fixed `1 × 128`) |

The batched baseline number excludes normalization and indicator extraction;
the MobileBERT number includes tokenization. The single-message numbers are the
fairer end-to-end comparison.

## ExecuTorch

- **Fixed `1 × 128` export and runtime execution: verified.**
- The `.pte` file is `checkpoints/mobilebert22_executorch_static.pte`.
- Runtime logits matched PyTorch with maximum absolute difference `3.58e-6`.
- Runtime execution was checked for correctness, not benchmarked for speed.
- **Dynamic batch/sequence export: failed** at `torch.export` with a constraint
  violation because the graph specialized those dimensions.
- This verifies a fixed-shape export on this Windows CPU environment. It is not
  a claim of dynamic-shape support, Android deployment, or phone performance.

Evidence:

- `results/final_summary.md`: concise final summary.
- `results/instability_evidence_24layer.json`: measured 24-layer activation/logit failure.
- `results/test_metrics_test.json`: full locked-test result and hashes.
- `results/comparison_test.md`: aggregate comparison tables.
- `results/test_metrics_val_check.json`: validation sanity check.
- `results/training_summary_mobilebert22_lr5e5_bs16_e4.json`: training history.
- `results/executorch_export.json`: dynamic-shape failure.
- `results/executorch_export_static.json`: fixed-shape runtime verification.
