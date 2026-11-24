# MobileBERT-22 FP32 / PTQ / QAT comparison

Created: `2026-11-10T16:58:02.998567+00:00`

## Test set

- Locked test rows: **869**
- Label counts: `{'ham': 709, 'spam': 111, 'smishing': 49}`
- SHA-256: `603a2ae34179388c7e66bac757859f1719830434c00f3f8658b7a3c2242e7fcf`
- Test loaded only for this final comparison; no QAT training or model selection used it.

## Accuracy and error metrics

| Model | Accuracy | Macro-F1 | Smishing precision | Smishing recall | Ham FPR | Latency (ms) |
|---|---:|---:|---:|---:|---:|---:|
| FP32 PyTorch | 0.972382 | 0.914224 | 0.779661 | 0.938776 | 0.004231 | 676.60 |
| PTQ PyTorch | 0.971231 | 0.905372 | 0.781818 | 0.877551 | 0.004231 | 1370.50 |
| QAT PyTorch | 0.966628 | 0.889932 | 0.860465 | 0.755102 | 0.004231 | 1402.20 |
| QAT `.pte` b16 | 0.967779 | 0.891486 | 0.860465 | 0.755102 | 0.002821 | 1851.50 |
| QAT `.pte` b1 | 0.967779 | 0.891486 | 0.860465 | 0.755102 | 0.002821 | 262.16 |
| PTQ `.pte` b16 | 0.971231 | 0.908534 | 0.785714 | 0.897959 | 0.004231 | 1817.94 |
| PTQ `.pte` b1 | 0.971231 | 0.908534 | 0.785714 | 0.897959 | 0.004231 | 281.53 |

Latency values are PyTorch/ExecuTorch model-forward medians, not end-to-end tokenization latency.

## Confusion matrices

### FP32

| true \ predicted | ham | spam | smishing |
|---|---:|---:|---:|
| ham | 706 | 0 | 3 |
| spam | 8 | 93 | 10 |
| smishing | 0 | 3 | 46 |

### PTQ

| true \ predicted | ham | spam | smishing |
|---|---:|---:|---:|
| ham | 706 | 0 | 3 |
| spam | 7 | 95 | 9 |
| smishing | 0 | 6 | 43 |

### QAT

| true \ predicted | ham | spam | smishing |
|---|---:|---:|---:|
| ham | 706 | 2 | 1 |
| spam | 9 | 97 | 5 |
| smishing | 0 | 12 | 37 |

### QAT ExecuTorch `.pte`, batch 16

| true \ predicted | ham | spam | smishing |
|---|---:|---:|---:|
| ham | 707 | 1 | 1 |
| spam | 9 | 97 | 5 |
| smishing | 0 | 12 | 37 |

## ExecuTorch runtime verification

| Comparison | Max abs logit diff | Mean abs logit diff | Argmax agreement |
|---|---:|---:|---:|
| qat_pte_b16_vs_qat_pytorch_b16 | 4.98923 | 0.382637 | 0.998849 |
| qat_pte_b1_vs_qat_pytorch_b1 | 3.4301 | 0.402493 | 0.997698 |
| ptq_pte_b16_vs_ptq_pytorch_b16 | 2.69788 | 0.372032 | 0.997698 |
| ptq_pte_b1_vs_ptq_pytorch_b1 | 2.69788 | 0.346851 | 0.996548 |
| qat_pte_b16_vs_fp32 | 9.4137 | 2.41859 | 0.980437 |
| qat_pte_b1_vs_fp32 | 9.4137 | 2.41859 | 0.980437 |

## Size

| Artifact | Bytes | MiB |
|---|---:|---:|
| FP32 checkpoint directory | 92668242 | 88.38 |
| PTQ prepared checkpoint | 97974109 | 93.44 |
| QAT best checkpoint | 95625513 | 91.20 |
| QAT `.pte` b16 | 37260556 | 35.53 |
| QAT `.pte` b1 | 37250700 | 35.53 |
| PTQ `.pte` b16 | 37260556 | 35.53 |
| PTQ `.pte` b1 | 37250700 | 35.53 |

## Latency

| Model | Batch 1 median (ms) | Batch 16 median (ms) | Batch 16 ms/message |
|---|---:|---:|---:|
| FP32 PyTorch | 70.90 | 676.60 | 42.29 |
| PTQ PyTorch | 293.93 | 1370.50 | 85.66 |
| QAT PyTorch | 287.50 | 1402.20 | 87.64 |
| QAT `.pte` | 262.16 | 1851.50 | 115.72 |
| PTQ `.pte` | 281.53 | 1817.94 | 113.62 |

## Precision and unsupported operators

- QAT b16: `.pte` 37260556 bytes; delegate calls 135; int8 tensors 332; state dtypes {'torch.float32': 1354, 'torch.int64': 332, 'torch.int8': 332}.
  - Non-delegate ops: `{'aten._softmax.out': 22, 'aten.bmm.out': 44, 'aten.constant_pad_nd.out': 2, 'aten.div.out': 22, 'aten.embedding.out': 3, 'aten.expand_copy.out': 88, 'aten.select_copy.int_out': 1, 'aten.slice_copy.Tensor_out': 1, 'aten.unsqueeze_copy.out': 2}`
- QAT b1: `.pte` 37250700 bytes; delegate calls 135; int8 tensors 332; state dtypes {'torch.float32': 1354, 'torch.int64': 332, 'torch.int8': 332}.
  - Non-delegate ops: `{'aten._softmax.out': 22, 'aten.bmm.out': 44, 'aten.constant_pad_nd.out': 2, 'aten.div.out': 22, 'aten.embedding.out': 3, 'aten.expand_copy.out': 88, 'aten.select_copy.int_out': 1, 'aten.slice_copy.Tensor_out': 1, 'aten.unsqueeze_copy.out': 2}`
- PTQ b16: `.pte` 37260556 bytes; delegate calls 135; int8 tensors 332; state dtypes {'torch.float32': 1354, 'torch.int64': 332, 'torch.int8': 332}.
  - Non-delegate ops: `{'aten._softmax.out': 22, 'aten.bmm.out': 44, 'aten.constant_pad_nd.out': 2, 'aten.div.out': 22, 'aten.embedding.out': 3, 'aten.expand_copy.out': 88, 'aten.select_copy.int_out': 1, 'aten.slice_copy.Tensor_out': 1, 'aten.unsqueeze_copy.out': 2}`

## RAM

Cumulative process RSS (MiB): `{'baseline': 430.59765625, 'after_test_load': 470.765625, 'after_fp32': 621.67578125, 'after_ptq_qat_pytorch': 1104.1328125, 'after_pte_load': 1486.4609375, 'note': 'Cumulative process RSS; not an isolated peak-RSS measurement.'}`

## Limitations

- QAT graph was captured in eval mode, so dropout was disabled during QAT fine-tuning.
- The exported model is hybrid INT8/FP32, not fully INT8.
- Global add/mul activation quantization collapsed validation smishing recall to 0; the final QAT/PTQ models therefore use the linear-only scope.
- XNNPACK partitioning produced many delegate segments; latency improvement is not assumed.
- The locked test split was already evaluated once for FP32; this is a repeated final comparison.
- Only 49 smishing examples are present in the test split.
- Windows CPU only; no Android or phone latency claim.

## Artifact paths

- QAT `.pte` batch 1: `<USER_HOME>\Pictures\bharat_ai_2026\sms-detection\experiments\mobilebert\qat\artifacts\qat_int8_b1.pte`
- QAT `.pte` batch 16: `<USER_HOME>\Pictures\bharat_ai_2026\sms-detection\experiments\mobilebert\qat\artifacts\qat_int8_b16.pte`
- PTQ `.pte` batch 1: `<USER_HOME>\Pictures\bharat_ai_2026\sms-detection\experiments\mobilebert\qat\artifacts\ptq_int8_b1.pte`
- PTQ `.pte` batch 16: `<USER_HOME>\Pictures\bharat_ai_2026\sms-detection\experiments\mobilebert\qat\artifacts\ptq_int8_b16.pte`
- Full JSON: `<USER_HOME>\Pictures\bharat_ai_2026\sms-detection\experiments\mobilebert\qat\results\comparison_test.json`
