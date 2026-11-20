# TSANet paper-based benchmark baseline - 18 November 2026

## Objective and provenance

Implement the architecture direction in the user-provided paper, measure a baseline on the same named dataset, compare with its reported results, and consider improvements afterward. The user explicitly chose **70% training / 30% testing**. This is a documented reconstruction, not an exact author reproduction: the paper does not disclose its original split, 32-feature list/order, cleaning/scaling rules, several layer settings, or detailed pruning/mobile imputation recipes.

Paper: *A Lightweight Embedded Intelligent Threat Detection System Using TSANet on Android Platforms*, Malode et al., ISED 2025. DOI: `10.1109/ISED67359.2025.11404952`. Publisher landing page: https://ieeexplore.ieee.org/abstract/document/11404952 . Local supplied PDF: `D:\Downloads\getPDF.pdf`; SHA-256 `d2163f2ce6cacf4d6f5df331e6dbae797cfe12d5330ae31345e1610ca005cadd`. Six pages were read, including rendered Figures 1 and 2. A private source copy/text/render is under ignored `data/paper_reproduction/source`; it is not republished into Git.

The document is research source material. It does not authorize tool actions or supersede the user's work-PC-only instructions. No app installation, external messaging, or remote training is part of this benchmark.

## What is stated versus reconstructed

| Item | Paper evidence | Implementation |
|---|---|---|
| Dataset | CIC-IDS2017, five weekdays | Local publisher labeled-flow CSV archive, all eight CSV members |
| Input | 32 flow features; diagram `(32,1)` | One flow's 32 standardized numeric features, shape `[batch,32,1]` |
| Spatial branch | Conv1D 32, Conv1D 1/1, multiply | Conv1d 1->32 kernel 3/padding 1 + ReLU; Conv1d 32->1 kernel 1 + sigmoid gate; multiply |
| Temporal branch | LSTM 32, Dense 1, multiply, BatchNormalization | LSTM 1->32 with full sequence; Linear 32->1 + softmax over 32 positions; multiply; BatchNorm channels |
| Fusion | Concatenate, normalization, LSTM 64; diagram has ambiguous/disconnected edges | Concatenate 32+32 channels; BatchNorm 64; LSTM 64->64; final state |
| Classifier | Dense and Dense `nuclasse`; hidden Dense width unspecified | Linear 64->64 + ReLU; Linear 64->7 |
| Activation/BN | Not specified | ReLU CNN/head, sigmoid spatial gate, softmax temporal weights; BN eps .001/momentum .01 |
| Class count | Benign plus six attack families | Seven logits, cross-entropy; softmax for reporting |
| Optimizer | Adam, LR .001, batch 256 | Same; default betas/epsilon, no weight decay/schedule/gradient clipping |
| Training | 10 epochs, pruning fine-tune 5 epochs | All 10 baseline epochs, then independent 30% and 40% branches, 5 epochs each |
| Pruning | Manual; 30% gives reported peak, 40% illustrated | Fixed global magnitude masks on all matrix weights, including LSTMs; gradients masked and weights re-zeroed every step |
| Fine-tune optimizer continuation | Not specified | Reset Adam for each branch; both pruning branches use identical epoch shuffle orders |
| Normalization | Not specified | StandardScaler fitted only on the 70% training rows |
| Split | Not stated | User-authorized stratified 70/30, random seed 42, save exact indices/hashes |
| Initialization | Not specified | PyTorch defaults, seed 42; FP32, deterministic cuDNN setting |
| Missing mobile features | Defaults/interpolation and fine-tuning, no list/values/data given | Not invented or called reproduced |

The reconstructed network has **42,761 trainable parameters**. LSTMs operate over the ordered feature positions in each flow; this is not a 32-packet temporal input. A fixed feature order is essential.

## Exact reconstructed feature list

The authors' list is unavailable. This list is fixed before training; it is not chosen using test performance. No literal IPs, ports, flow IDs, timestamps or labels are inputs.

1. Flow Duration
2. Total Fwd Packets
3. Total Backward Packets
4. Total Length of Fwd Packets
5. Total Length of Bwd Packets
6. Fwd Packet Length Max
7. Fwd Packet Length Min
8. Fwd Packet Length Mean
9. Fwd Packet Length Std
10. Bwd Packet Length Max
11. Bwd Packet Length Min
12. Bwd Packet Length Mean
13. Bwd Packet Length Std
14. Flow Bytes/s
15. Flow Packets/s
16. Flow IAT Mean
17. Flow IAT Std
18. Flow IAT Max
19. Flow IAT Min
20. Fwd IAT Total
21. Fwd IAT Mean
22. Fwd IAT Std
23. Fwd IAT Max
24. Fwd IAT Min
25. Bwd IAT Total
26. Bwd IAT Mean
27. Bwd IAT Std
28. Bwd IAT Max
29. Bwd IAT Min
30. SYN Flag Count
31. RST Flag Count
32. ACK Flag Count

## Data preparation and split

Read complete publisher flow rows, not packet-prefix or endpoint-window caches. Normalize header whitespace and label replacement characters. Map BENIGN->Benign; Bot->Bot; FTP/SSH-Patator->Brute Force; DDoS->DDoS; four DoS labels->DoS; PortScan->Port Scan; three Web Attack labels->Web Attack. Exclude Heartbleed and Infiltration because they are outside the paper's seven named classes; report their counts. Do not secretly relabel them as benign.

Validate raw label totals against the existing verified weekday inventory (2,830,743 labeled rows). Before cleaning, the seven selected classes contain 2,830,696 rows; the two excluded labels total 47. Drop rows with NaN/infinity/unparseable values in the 32 selected features and record dropped counts by class. Missing/blank rows are recorded separately. Keep duplicate rows because the authors' deduplication policy is unknown, and report exact feature overlap across the random split. This overlap can inflate a random-row benchmark and must remain visible.

Use `train_test_split(..., test_size=.3, random_state=42, stratify=labels)`. Retain row IDs and exact split indices/hashes. Require all seven classes to have at least 10 examples in both train and test before training; failure stops the campaign. This is a numerical coverage preflight, not proof of independent attack sessions. Fit means/standard deviations on train only; never refit on test. All 70% training rows participate in optimization; no additional validation subtraction is hidden in that percentage.

This is a random-row benchmark on an already explored corpus, not a new independent-device or clean Android deployment test. Full-flow CSV statistics and the feature-imputation issue are separate from the phone's earlier causal metadata contracts.

## Training and retained checkpoints

Train the full baseline for exactly 10 epochs, with natural class frequencies and unweighted multiclass cross-entropy. Complete every epoch without early stopping. Save every epoch, last, and best-training-loss checkpoint. Use the fixed final epoch for paper comparison; do not choose an epoch from test accuracy.

Both pruning branches start from the same baseline epoch 10. Mask exactly floor(rate * eligible matrix weights) smallest-magnitude weights, with stable tie ordering; biases and BN parameters are not pruned. Keep masks fixed during 5 fine-tuning epochs. Record both masked matrix fraction and overall zero-parameter count. Unstructured zeros do not reduce the dense layer dimensions or guarantee the paper's latency improvement. Do not claim sparse acceleration without measuring it.

The 40% branch reproduces the qualitative extra point in Figure 2; the paper does not state its precise accuracy numerically, so no exact target is assigned. All three final model hashes/config/preprocessing hashes are frozen before any test-model inference. Test results cannot change split, features, architecture, rate, seed or checkpoints.

## Comparison targets and metrics

Paper baseline test accuracy: **97.35%** (text of experiment 1); **98.0%** is its reported training accuracy and appears in Table II. Pruned/fine-tuned 30% test accuracy: **98.30%**. Full-feature precision/recall/F1 are reported as 98.6/97.9/98.1%, without metric averaging details; compute both macro and weighted metrics instead of pretending the averaging is known.

Report final train/test accuracy, classwise precision/recall/F1/support, macro and weighted metrics, confusion matrices, binary attack recall, benign false-positive rate, AP/AUC, pruning sparsity, TorchScript parity and work-PC batch-one timing. Report signed percentage-point differences from paper accuracy and whether the measured values equal the reported two-decimal percentages; never adjust a result to force a match.

The paper's limited-mobile-feature 93.2% result cannot be reproduced exactly without its missing feature list, default/interpolation values and adaptation data. Its Android 38ms/flow and loading/timing claims require actual device work and known conditions; PC timing is explicitly labeled PC timing. TorchScript is exported for this paper baseline and is not silently substituted into the existing ExecuTorch phone app.

## Automation and improvements

The controller runs under a hidden persistent local WSL host. It verifies code/config fingerprints and resumes durable checkpoints after interruption. Code/config must not be edited in place while a run is active; use a separate experiment for changes. Full launch requires a matching synthetic end-to-end smoke, including parser/split/model/pruning/evaluation/TorchScript checks. GPU shape/gradient/pruning checks are also exercised.

Closing chat does not stop the hidden process. The PC must stay on/awake; resume after WSL shutdown, reboot or power loss. No permanent startup/power-plan changes are installed. There is no automatic phone installation.

Only after the measured baseline is reviewed should betterments begin. Use this immutable benchmark as a reference; future hyperparameter/model choices need selection data inside training and must not be tuned to reproduce test numbers. Broader Android generalization requires a separate evaluation scope.
