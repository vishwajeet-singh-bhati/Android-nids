# Final report: MobileBERT-22 FP32 / INT8 PTQ / INT8 QAT

## 1. Objective and safety constraints

This experiment tested whether the existing MobileBERT-22 SMS classifier could be
quantized to INT8, exported through ExecuTorch XNNPACK, and compared fairly with
FP32 and post-training quantization (PTQ).

Constraints preserved throughout:

- Source model: `experiments/mobilebert/checkpoints/mobilebert22_lr5e5_bs16_e4/best`
  was treated as read-only. Its six files still match the pre-run SHA-256 values.
- Labels are unchanged: `ham=0`, `spam=1`, `smishing=2`.
- Dataset, preprocessing, architecture, and split definitions are unchanged.
- QAT training used only the existing train split. Model selection used only the
  existing validation split.
- The locked test split and the 100-message handmade dataset were not used for
  training, calibration, or model selection. The test split was loaded once by
  the final comparison after all artifacts were frozen.
- No SMS bodies were sent to a cloud service.

The model is the existing 22-layer MobileBERT stability variant, not standard
24-layer MobileBERT. The test split was already evaluated once for FP32, so the
final test result is a repeated evaluation, not a fresh blind test.

## 2. Frozen configuration

| Item | Value |
|---|---|
| Seed | 42 |
| Max sequence length | 128 |
| QAT batch size | 16 |
| QAT epochs / patience | 2 maximum / 1 |
| QAT learning rate | `1e-5` |
| Optimizer | AdamW, weight decay `0.01` |
| Warmup ratio / gradient clip | `0.10` / `1.0` |
| Observer warmup | 50 shuffled train batches |
| Observers after warmup | Frozen |
| Selection metric | Validation macro-F1 |
| QAT quantizer | `XNNPACKQuantizer` |
| QAT config | `get_symmetric_quantization_config(is_per_channel=True, is_qat=True)` |
| Quantization scope | `linear_only` |
| PTQ config | Same scope; static PTQ, `is_qat=False` |
| PTQ calibration | All 4,055 train rows |
| Export backend | ExecuTorch XNNPACK `STATIC_QUANT` |
| Export shapes | Fixed `[1,128]` and `[16,128]` |

QAT graph capture was performed in eval mode, so dropout was disabled during QAT
fine-tuning. The best QAT checkpoint was epoch 2:
`checkpoints/qat_lr1e5_bs16_e2_best.pt`.

Environment:

- Windows 11, AMD Ryzen 7 5700U, 8 physical / 16 logical cores, 15.3 GiB RAM
- Python `3.14.3`
- PyTorch `2.15.0+cpu`
- Transformers `4.57.6`
- torchao `0.18.0`
- ExecuTorch `1.6.0`
- flatc `24.3.25`
- No CUDA; CPU only, 8 measurement threads

## 3. Validation results

These were the model-selection results. The locked test split was not used here.

| Model | Accuracy | Macro-F1 | Smishing precision | Smishing recall | Ham FPR |
|---|---:|---:|---:|---:|---:|
| FP32 base | 0.968930 | 0.877177 | 0.711538 | 0.787234 | 0.002821 |
| INT8 PTQ | 0.967779 | 0.872999 | 0.698113 | 0.787234 | 0.002821 |
| INT8 QAT | 0.971231 | 0.887748 | 0.829268 | 0.723404 | 0.001410 |

QAT improved validation macro-F1 over FP32 by about `0.0106` and reduced ham
false positives. It did this at the cost of smishing recall: `0.7234` versus
`0.7872` for FP32. PTQ was slightly below FP32 on validation macro-F1, with the
same smishing recall as FP32.

The QAT validation gain did **not** transfer to the test split.

## 4. Locked-test results

The final comparison used the same 869 test examples for every model:

- 709 ham, 111 spam, 49 smishing
- SHA-256: `603a2ae34179388c7e66bac757859f1719830434c00f3f8658b7a3c2242e7fcf`
- Same normalized text, tokenizer, truncation, and fixed padding for all models
- Batch-1 and batch-16 `.pte` aggregate metrics are reported separately

### 4.1 Metrics

| Model | Accuracy | Macro-F1 | Smishing precision | Smishing recall | Ham FPR |
|---|---:|---:|---:|---:|---:|
| FP32 PyTorch | 0.972382 | 0.914224 | 0.779661 | 0.938776 | 0.004231 |
| PTQ PyTorch | 0.971231 | 0.905372 | 0.781818 | 0.877551 | 0.004231 |
| PTQ `.pte` batch 16 | 0.971231 | 0.908534 | 0.785714 | 0.897959 | 0.004231 |
| PTQ `.pte` batch 1 | 0.971231 | 0.908534 | 0.785714 | 0.897959 | 0.004231 |
| QAT PyTorch | 0.966628 | 0.889932 | 0.860465 | 0.755102 | 0.004231 |
| QAT `.pte` batch 16 | 0.967779 | 0.891486 | 0.860465 | 0.755102 | 0.002821 |
| QAT `.pte` batch 1 | 0.967779 | 0.891486 | 0.860465 | 0.755102 | 0.002821 |

The QAT `.pte` is not better than FP32 on test accuracy, macro-F1, or smishing
recall. Its test macro-F1 is lower by `0.0227`, and its smishing recall is lower
by `0.1837` (37/49 versus 46/49). It has higher smishing precision and a lower
ham false-positive rate. The `.pte`/PyTorch differences come from runtime
execution, not retraining; the batch-1 and batch-16 `.pte` aggregate metrics
happen to be identical.

PTQ is closer to FP32 on test macro-F1 (`0.9085` versus `0.9142`) and retains more
smishing recall (`0.8980` versus `0.9388`).

### 4.2 Confusion matrices

Cell order is `predicted ham / spam / smishing`; rows are true classes in
`ham, spam, smishing` order. The matrices sum to the 869 test examples.

| Model | True ham | True spam | True smishing |
|---|---|---|---|
| FP32 PyTorch | 706 / 0 / 3 | 8 / 93 / 10 | 0 / 3 / 46 |
| PTQ PyTorch | 706 / 0 / 3 | 7 / 95 / 9 | 0 / 6 / 43 |
| PTQ `.pte` batch 16 | 706 / 0 / 3 | 8 / 94 / 9 | 0 / 5 / 44 |
| QAT PyTorch | 706 / 2 / 1 | 9 / 97 / 5 | 0 / 12 / 37 |
| QAT `.pte` batch 16 | 707 / 1 / 1 | 9 / 97 / 5 | 0 / 12 / 37 |

The QAT `.pte` misses 12 of 49 smishing messages by classifying them as spam.
PTQ misses 5, and FP32 misses 3.

## 5. Export and precision verification

All four final `.pte` artifacts were exported through the supported ExecuTorch
workflow:

1. PT2E quantization and conversion in PyTorch.
2. Explicit `ExportRecipe`.
3. `XnnpackPartitioner(config_precisions=ConfigPrecisionType.STATIC_QUANT)`.
4. Serialization to `.pte`.
5. Loading and execution through `executorch.runtime.Runtime`.

| Artifact | Bytes | Export status |
|---|---:|---|
| `artifacts/qat_int8_b16.pte` | 37,260,556 | Runtime verified |
| `artifacts/qat_int8_b1.pte` | 37,250,700 | Runtime verified |
| `artifacts/ptq_int8_b16.pte` | 37,260,556 | Runtime verified |
| `artifacts/ptq_int8_b1.pte` | 37,250,700 | Runtime verified |

There were no final `.pte` export failures.

### 5.1 Actual precision in the serialized artifact

Each final export summary reports:

- `332` INT8 tensors in the serialized state
- `332` INT64 tensors for quantization parameters
- `1,354` FP32 tensors
- `22,898,947` parameters
- `135` XNNPACK delegate calls
- `332` `aten.linear.default` ops in the graph
- `333` `aten.add.Tensor` and `178` `aten.mul.Tensor` ops

This is a **hybrid INT8/FP32** artifact, not a fully INT8 model. Linear weights
and activations are quantized. Residual adds, layer-norm multiplies, embeddings,
attention `bmm`, `softmax`, `div`, and other fallback operations remain FP32
outside the quantized-linear scope. The final exports contain these non-delegate
operations:

| Operation | Count |
|---|---:|
| `aten.bmm.out` | 44 |
| `aten._softmax.out` | 22 |
| `aten.div.out` | 22 |
| `aten.embedding.out` | 3 |
| `aten.constant_pad_nd.out` | 2 |
| `aten.expand_copy.out` | 88 |
| `aten.select_copy.int_out` | 1 |
| `aten.slice_copy.Tensor_out` | 1 |
| `aten.unsqueeze_copy.out` | 2 |

The PTQ export reports zero fake-quant modules because PTQ prepares observers
rather than QAT fake-quant modules. Its converted state still contains 332 INT8
tensors; this is not a contradiction and does not weaken the precision evidence.

### 5.2 Runtime agreement

The exporter's synthetic single-batch verification passed:

| Export | Max abs logit difference vs quantized PyTorch | Argmax agreement |
|---|---:|---:|
| QAT batch 16 | 0.311827 | 1.000000 |
| QAT batch 1 | 0.311827 | 1.000000 |
| PTQ batch 16 | 0.224823 | 1.000000 |
| PTQ batch 1 | 0.224823 | 1.000000 |

On the full 869-row test set, the `.pte` runtime was **not bit-exact** with
converted PyTorch:

| Comparison | Max abs logit difference | Mean abs logit difference | Argmax agreement |
|---|---:|---:|---:|
| QAT `.pte` b16 vs QAT PyTorch b16 | 4.98923 | 0.382637 | 0.998849 |
| QAT `.pte` b1 vs QAT PyTorch b1 | 3.43010 | 0.402493 | 0.997698 |
| PTQ `.pte` b16 vs PTQ PyTorch b16 | 2.69788 | 0.372032 | 0.997698 |
| PTQ `.pte` b1 vs PTQ PyTorch b1 | 2.69788 | 0.346851 | 0.996548 |

The QAT batch-16 `.pte` changed one test argmax relative to converted QAT
PyTorch; the QAT batch-1 and PTQ artifacts changed two or three. These are small
runtime differences, but they are real and the deployment metrics above are
therefore reported from the `.pte` executions themselves.

## 6. Size, latency, and RAM

### 6.1 Size

| Artifact | Bytes | MiB |
|---|---:|---:|
| FP32 ExecuTorch `.pte` (prior) | 91,918,900 | 87.66 |
| FP32 checkpoint directory | 92,668,242 | 88.38 |
| PTQ prepared checkpoint | 97,974,109 | 93.44 |
| QAT best checkpoint | 95,625,513 | 91.20 |
| QAT `.pte` batch 16 | 37,260,556 | 35.53 |
| QAT `.pte` batch 1 | 37,250,700 | 35.53 |
| PTQ `.pte` batch 16 | 37,260,556 | 35.53 |
| PTQ `.pte` batch 1 | 37,250,700 | 35.53 |

The final `.pte` is about `2.47x` smaller than the prior FP32 `.pte` and about
`2.49x` smaller than the FP32 checkpoint directory. The prepared PyTorch
checkpoints are larger than the FP32 checkpoint because they contain prepared
quantization state; they are not deployment artifacts.

### 6.2 CPU latency

All values are model-forward medians on the Windows CPU above, using 2 warmups
and 5 timed repeats. Tokenization is excluded. FP32 is eager PyTorch; the INT8
rows are ExecuTorch XNNPACK `.pte` execution.

| Model | Batch 1 (ms) | Batch 16 total (ms) | Batch 16 ms/message |
|---|---:|---:|---:|
| FP32 PyTorch | 70.90 | 676.60 | 42.29 |
| PTQ PyTorch | 293.93 | 1,370.50 | 85.66 |
| QAT PyTorch | 287.50 | 1,402.20 | 87.64 |
| PTQ `.pte` | 281.53 | 1,817.94 | 113.62 |
| QAT `.pte` | 262.16 | 1,851.50 | 115.72 |

The quantized `.pte` is slower than FP32 eager on this CPU: about `2.7x` slower
per message at batch 16 and about `3.7x` slower at batch 1 for QAT. No latency
improvement is claimed. The hybrid graph, 135 delegate calls, and fallback
operators are plausible contributors, but this experiment does not isolate the
cause.

### 6.3 RAM

Isolated process RSS measurements, in MiB. These are not peak-RSS measurements.
The PyTorch measurements include the base model, tokenizer, and converted graph;
the `.pte` measurements include only the ExecuTorch runtime and artifact, so they
are not a phone-RAM comparison.

| Measurement | Baseline | After load | After inference | Total delta |
|---|---:|---:|---:|---:|
| FP32 PyTorch | 429.9 | 464.1 | 606.5 | +176.7 |
| PTQ PyTorch | 430.2 | 820.3 | 902.9 | +472.7 |
| QAT PyTorch | 430.0 | 845.3 | 905.1 | +475.1 |
| PTQ `.pte` batch 16 | 431.1 | 475.6 | 482.8 | +51.8 |
| QAT `.pte` batch 16 | 429.7 | 474.5 | 481.7 | +52.0 |

The cumulative final-comparison process, which loaded FP32, both converted
PyTorch models, and all `.pte` artifacts, reached `1,486.5 MiB` RSS. That number
is reported in the JSON but is not an isolated model measurement.

## 7. Failures, unsupported operations, and limitations

### 7.1 Quantization failures found and resolved

- **Global add/mul quantization failed.** Quantizing all eligible activations,
  including `aten.add` and `aten.mul`, reduced validation macro-F1 to about
  `0.572-0.578` and produced zero smishing validation predictions. Excluding only
  the final classifier did not fix it. The final scope keeps linear quantization
  and leaves add/mul activation quantization in FP32.
- **The first observer warmup was invalid.** `train.csv` is label-sorted. The
  first 10 batches were 160 ham-only rows, so activation observers never saw
  spam or smishing. The 20-step smoke run reached validation macro-F1 `0.5844`
  with smishing recall `0.0`. The corrected run shuffles train rows, uses 50
  batches, and freezes observers. That smoke run is retained for audit only.
- **Dynamic batch+sequence export failed.** The final artifacts are fixed-shape
  `[1,128]` and `[16,128]` only.
- **`prepared.eval()` raised `NotImplementedError`.** The evaluation path uses
  `torchao.quantization.pt2e.move_exported_model_to_eval` or explicit observer
  toggling.
- **`torch.ao.quantization.disable_observer` did not affect torchao fake-quant
  modules.** Observer control was done manually.
- **`flatc` was not on `PATH`.** The bundled executable
  `experiments/mobilebert/.venv/Scripts/flatc.exe` was selected through
  `FLATC_EXECUTABLE`.

No final export failed after these fixes, and no operator caused an export-time
unsupported-operator exception. Unsupported-by-XNNPACK operators were handled by
fallback rather than by deleting them.

### 7.2 Remaining limitations

- The `.pte` is hybrid INT8/FP32, not fully INT8. The exact quantized and fallback
  operation counts are above.
- Full-test `.pte` execution is not bit-exact with converted PyTorch; argmax
  agreement was `99.65-99.88%`, with one to three changed predictions.
- QAT's validation macro-F1 gain did not generalize to the test macro-F1 or
  smishing recall.
- The quantized runtime is slower than FP32 eager on this Windows CPU. No
  Android or phone latency claim is made.
- The test split has only 49 smishing examples and was already used once for the
  prior FP32 evaluation. The final comparison is repeated, not blind.
- QAT graph capture disabled dropout during QAT.
- The 22-layer model is a stability variant, not standard 24-layer MobileBERT.
- PTQ and QAT PyTorch RSS includes both the base and converted models; `.pte` RSS
  includes only the runtime path. Neither is a phone-memory measurement.

## 8. Conclusion

A verified ExecuTorch INT8 artifact now exists for both QAT and PTQ at batch 1
and batch 16. The artifacts load and execute through the ExecuTorch runtime, and
their serialized graphs contain 332 INT8 tensors with 135 XNNPACK delegate calls.
The deployment claim must remain **hybrid INT8/FP32**, not fully INT8.

Quality result on the repeated locked test:

- **QAT `.pte`:** accuracy `0.967779`, macro-F1 `0.891486`, smishing precision
  `0.860465`, smishing recall `0.755102`, ham FPR `0.002821`.
- **PTQ `.pte`:** accuracy `0.971231`, macro-F1 `0.908534`, smishing precision
  `0.785714`, smishing recall `0.897959`, ham FPR `0.004231`.
- **FP32:** accuracy `0.972382`, macro-F1 `0.914224`, smishing precision
  `0.779661`, smishing recall `0.938776`, ham FPR `0.004231`.

QAT is not a drop-in accuracy improvement over FP32 on this test. It trades
smishing recall for smishing precision and a lower ham false-positive rate. PTQ
is the closer quantized option to FP32 on test macro-F1 and smishing recall. No
quantized artifact is recommended for replacement of FP32 on the basis of these
CPU results alone; Android/device benchmarking and a larger smishing evaluation
would be required.

## 9. Artifacts

- QAT best checkpoint: `experiments/mobilebert/qat/checkpoints/qat_lr1e5_bs16_e2_best.pt`
- PTQ prepared checkpoint: `experiments/mobilebert/qat/checkpoints/ptq_static_int8_prepared.pt`
- QAT `.pte` batch 16: `experiments/mobilebert/qat/artifacts/qat_int8_b16.pte`
- QAT `.pte` batch 1: `experiments/mobilebert/qat/artifacts/qat_int8_b1.pte`
- PTQ `.pte` batch 16: `experiments/mobilebert/qat/artifacts/ptq_int8_b16.pte`
- PTQ `.pte` batch 1: `experiments/mobilebert/qat/artifacts/ptq_int8_b1.pte`
- Final comparison JSON: `experiments/mobilebert/qat/results/comparison_test.json`
- Final comparison Markdown: `experiments/mobilebert/qat/results/comparison_test.md`
- Per-example predictions: `experiments/mobilebert/qat/results/predictions_*.csv`
- Export summaries: `experiments/mobilebert/qat/results/export_*.json`
- QAT training log: `experiments/mobilebert/qat/logs/train_qat_lr1e5_bs16_e2.log`
- PTQ calibration log: `experiments/mobilebert/qat/logs/ptq_static_int8.log`
- Export logs: `experiments/mobilebert/qat/logs/export_qat_int8_b*.log` and `export_ptq_int8_b*.log`
- Final comparison log: `experiments/mobilebert/qat/logs/comparison_test.log`
- Isolated resource measurements: `experiments/mobilebert/qat/results/resources_*.json`
- Provenance and hashes: `experiments/mobilebert/qat/results/provenance.json`
