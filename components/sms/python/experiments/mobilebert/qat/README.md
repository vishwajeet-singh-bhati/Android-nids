# MobileBERT-22 QAT / ExecuTorch INT8

This experiment starts from the existing FP32 MobileBERT-22 stability variant and
tests whether static INT8 quantization can be deployed through ExecuTorch without
changing the architecture, labels, preprocessing, or dataset splits.

## Read-only inputs

- FP32 checkpoint:
  `experiments/mobilebert/checkpoints/mobilebert22_lr5e5_bs16_e4/best`
- Train split: `data/processed/train.csv`
- Validation split: `data/processed/val.csv`
- Locked test split: `data/processed/test.csv`

The locked test split and the 100-message handmade dataset are **not** used for
QAT training, PTQ calibration, or model selection. The test split is loaded only
by the final comparison script after all models and artifacts are frozen.

## Method

- PT2E static QAT with `torchao.quantization.pt2e.prepare_qat_pt2e`.
- `XNNPACKQuantizer` with
  `get_symmetric_quantization_config(is_per_channel=True, is_qat=True)`.
- Per-channel symmetric INT8 weights, per-tensor affine INT8 activations.
- Fixed `[batch, 128]` graph; QAT training uses batch 16.
- QAT fine-tuning from the FP32 checkpoint, validation macro-F1 model selection,
  best-checkpoint restore, and short early stopping.
- ExecuTorch XNNPACK `STATIC_QUANT` lowering, exported at batch 1 and 16.
- PTQ baseline uses the same quantizer configuration with `is_qat=False` and
  calibrates only on the train split.

The XNNPACK quantized scope covers `Linear` weights and activations. `aten.add`,
`aten.mul`, embeddings, attention `bmm`, `softmax`, `div`, and other fallback
operators remain FP32, so the result is a **hybrid INT8/FP32 model**, not a fully
INT8 model.

## Smoke-test finding and correction

The first 20-step smoke run used the first 10 training batches for observer
warmup. `train.csv` is label-sorted, and those batches are 160 ham-only rows, so
the activation observers never saw spam or smishing before optimization. That
smoke run reached validation macro-F1 `0.5844` with smishing recall `0.0`; it is
kept only for audit and is not used for the final comparison.

The corrected run shuffles the train rows before observer warmup, uses 50
batches, and freezes observers after warmup so the fixed INT8 ranges cannot drift
during QAT. The smoke test is repeated with this corrected setup before full QAT.

## Quantization scope finding

Even with class-balanced observer warmup, global XNNPACK static quantization
reduced validation macro-F1 from `0.8772` to about `0.572` and removed every
smishing prediction. Excluding only the final classifier did not help, so the
problem was earlier in the encoder. Keeping linear quantization while leaving
`aten.add` and `aten.mul` activation quantization in FP32 restored validation
macro-F1 to `0.8737`, smishing recall to `0.7872`, and smishing precision to
`0.7115`.

The configured quantization scope is therefore refined to `linear_only`: linear weights
and activations are INT8, while residual adds and layer-norm multiplies remain
FP32. This is still a selective INT8 deployment, not a fully INT8 model. The
final report records the exact quantized and fallback operator counts.

The corrected 20-step smoke test reached validation macro-F1 `0.8820`, accuracy
`0.9701`, smishing recall `0.7234`, smishing precision `0.7907`, and ham FPR
`0.00282`. Its batch-16 `.pte` is `37,260,556` bytes, loaded and executed,
produced finite output, had argmax agreement `1.0` with quantized PyTorch, and
had a maximum logit difference of `0.312`.

The full two-epoch QAT run improved on the smoke checkpoint: validation
macro-F1 `0.887748`, accuracy `0.971231`, smishing recall `0.723404`,
smishing precision `0.829268`, and ham FPR `0.001410`. Epoch 2 was selected;
the checkpoint is `checkpoints/qat_lr1e5_bs16_e2_best.pt`.

The linear-only PTQ baseline calibrated on all 4,055 train rows reached
validation macro-F1 `0.872999`, accuracy `0.967779`, smishing recall `0.787234`,
smishing precision `0.698113`, and ham FPR `0.002821`. It trades QAT's higher
macro-F1 for slightly higher smishing recall and lower smishing precision.

Final QAT exports are `37,260,556` bytes at batch 16 and `37,250,700` bytes at
batch 1. Both were loaded and executed by the ExecuTorch runtime, produced finite
output, and agreed with quantized PyTorch argmax on the verification batch. Their
converted graphs contain 332 INT8 tensors and 135 XNNPACK delegate calls.

The PTQ batch-16 `.pte` is `37,260,556` bytes and was also runtime verified, with
maximum logit difference `0.224823` and argmax agreement `1.0` against converted
PTQ PyTorch. The matched batch-1 PTQ export is `37,250,700` bytes and was
verified with the same synthetic-batch result.

## Final locked-test comparison

The final comparison used the same 869 test examples for every model. The test
split was loaded only after all artifacts were frozen; it was not used for
training or model selection. Full details and confusion matrices are in
`results/final_report.md` and `results/comparison_test.md`.

| Model | Accuracy | Macro-F1 | Smishing precision | Smishing recall | Ham FPR |
|---|---:|---:|---:|---:|---:|
| FP32 PyTorch | 0.972382 | 0.914224 | 0.779661 | 0.938776 | 0.004231 |
| PTQ PyTorch | 0.971231 | 0.905372 | 0.781818 | 0.877551 | 0.004231 |
| PTQ `.pte` batch 16 | 0.971231 | 0.908534 | 0.785714 | 0.897959 | 0.004231 |
| QAT PyTorch | 0.966628 | 0.889932 | 0.860465 | 0.755102 | 0.004231 |
| QAT `.pte` batch 16 | 0.967779 | 0.891486 | 0.860465 | 0.755102 | 0.002821 |

The QAT `.pte` batch-1 aggregate metrics are the same as batch 16. QAT's
validation gain did not transfer: test macro-F1 and smishing recall are below
FP32. PTQ is closer to FP32 on test macro-F1 and smishing recall.

The full-test `.pte` execution is not bit-exact with converted PyTorch: argmax
agreement was `0.996548` to `0.998849`, with one to three changed predictions
across the four artifacts. The synthetic export check had `1.0` agreement.

Model size is `35.53 MiB` for the final `.pte`, versus `87.66 MiB` for the prior
FP32 `.pte`. The hybrid graph is slower on this Windows CPU, not faster: QAT
`.pte` batch-16 median was `1,851.50 ms` total (`115.72 ms/message`) versus
`676.60 ms` total (`42.29 ms/message`) for FP32 eager PyTorch. No latency
improvement is claimed.

## Environment requirement

The venv bundles `flatc.exe` but it is not on `PATH`. The scripts set:

```powershell
$env:FLATC_EXECUTABLE = (Resolve-Path "experiments\mobilebert\.venv\Scripts\flatc.exe").Path
```

Without it, XNNPACK `.pte` serialization fails with `FileNotFoundError: flatc`.

## Commands

Run from `sms-detection/` with the experiment venv Python:

```powershell
# 20-step smoke test, validation, and best smoke checkpoint
python experiments/mobilebert/qat/scripts/train_qat.py --smoke --tag qat_smoke_linear

# Smoke export at batch 16
python experiments/mobilebert/qat/scripts/export_quantized.py `
  --kind qat --batch-size 16 `
  --checkpoint experiments/mobilebert/qat/checkpoints/qat_smoke_linear_best.pt `
  --tag qat_smoke_linear_b16

# Full QAT run (2 epochs maximum, early stopping on validation macro-F1)
python experiments/mobilebert/qat/scripts/train_qat.py

# PTQ baseline, calibrated on train only
python experiments/mobilebert/qat/scripts/run_ptq.py

# Final artifacts at batch 1 and 16
python experiments/mobilebert/qat/scripts/export_quantized.py --kind qat --batch-size 16
python experiments/mobilebert/qat/scripts/export_quantized.py --kind qat --batch-size 1
python experiments/mobilebert/qat/scripts/export_quantized.py --kind ptq --batch-size 16
python experiments/mobilebert/qat/scripts/export_quantized.py --kind ptq --batch-size 1

# Final comparison; this is the only script that loads test.csv
python experiments/mobilebert/qat/scripts/evaluate_compare.py
```

## Layout

```text
experiments/mobilebert/qat/
├── config.json
├── README.md
├── scripts/
│   ├── qat_common.py
│   ├── train_qat.py
│   ├── run_ptq.py
│   ├── export_quantized.py
│   └── evaluate_compare.py
├── checkpoints/
├── logs/
├── results/
└── artifacts/
```

## Expected artifacts

- `checkpoints/qat_lr1e5_bs16_e2_best.pt`
- `checkpoints/ptq_static_int8_prepared.pt`
- `artifacts/qat_int8_b1.pte`
- `artifacts/qat_int8_b16.pte`
- `artifacts/ptq_int8_b1.pte`
- `artifacts/ptq_int8_b16.pte`
- `results/comparison_test.md`
- `results/comparison_test.json`
- `results/final_report.md`
- `results/resources_*.json`
- `results/provenance.json`

The final report distinguishes graph-level INT8 evidence from runtime execution.
A `.pte` is not called a deployment success unless ExecuTorch loads it and
executes it on the recorded CPU environment. The final `.pte` files were loaded,
executed, and measured; they are nevertheless hybrid INT8/FP32 artifacts, not
fully INT8 models.

## Known limitations

- The 22-layer model is a stability variant, not standard 24-layer MobileBERT.
- QAT graph capture is eval-mode, so dropout is disabled during QAT fine-tuning.
- XNNPACK generated many delegate segments; the measured quantized latency is
  slower than FP32 eager on this CPU, so no latency improvement is claimed.
- Full-test `.pte` output is not bit-exact with converted PyTorch: argmax
  agreement is `99.65-99.88%`, with one to three changed test predictions.
- Fixed shapes only; batch-and-sequence dynamic export previously failed.
- Windows CPU results do not establish Android or phone performance.
- The test split was already evaluated once for FP32; the final comparison is a
  repeated final evaluation, not a fresh blind test.
