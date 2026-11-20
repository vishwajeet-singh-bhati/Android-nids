# TSANet Paper Reproduction and Connection-Context Improvement

Scope: paper-based TSANet reconstruction, followed by the connection-context extension.

**Paper:** *A Lightweight Embedded Intelligent Threat Detection System Using TSANet on Android Platforms*, Malode et al., ISED 2025. [DOI: 10.1109/ISED67359.2025.11404952](https://ieeexplore.ieee.org/abstract/document/11404952).

## 1. What the paper specifies and what we assumed

Retained paper settings: **CIC-IDS2017; 32 inputs; seven classes; CNN/LSTM attention; Adam 0.001; batch 256; 10 training + 5 pruning fine-tuning epochs**.

| Missing or insufficiently specified information | Our documented choice |
|---|---|
| Author code; train/test ratio, seed and split indices | Project-chosen stratified **70/30 train/test**, seed **42**; saved indices. |
| Exact names/order of the 32 features | Fixed list below, chosen before training. |
| CNN kernel/padding, attention activations and hidden Dense width | Kernel 3/padding 1; sigmoid spatial attention; softmax temporal attention; Dense width 64. |
| Fusion connections/BatchNorm | Parallel branches; concatenate + BatchNorm; epsilon 0.001, momentum 0.01. |
| Cleaning/scaling/initialization | Drop nonfinite rows; train-only StandardScaler; retain duplicates; PyTorch defaults, seed 42, FP32. |
| Pruning algorithm/framework integration | PyTorch global magnitude masks, including LSTMs; exclude biases/BatchNorm; enforce masks after updates. |
| Other optimizer details | Adam defaults; no scheduler, weight decay or gradient clipping; reset Adam for each pruning branch. |
| Precision/recall/F1 averaging | Report macro and weighted metrics separately. |
| Quantization recipe and missing-mobile-feature defaults/interpolation/adaptation data | Not reproduced; no claim of quantization, missing-feature adaptation or Android latency. |

**This is a documented reconstruction, not an exact author-code reproduction.**

## 2. Dataset and preprocessing

- Source: eight publisher flow CSVs, five weekdays; completed-flow statistics.
- Normalize headers/labels; group FTP/SSH-Patator as Brute Force, four DoS variants as DoS, three Web variants as Web Attack.
- Ignore blanks; exclude **36 Infiltration + 11 Heartbleed** rows; drop **2,867** nonfinite selected-feature rows. Keep duplicates.
- **2,830,743** labeled source rows -> **2,827,829** retained rows -> **1,979,480 training / 848,349 testing**.
- Fit StandardScaler on training only; reuse for test. No separate validation split.
- Natural class frequencies, unweighted cross-entropy; no resampling.

The 32 selected inputs, in order (`Fwd`/`Bwd`: forward/backward; `IAT`: inter-arrival time):

| Positions | Features |
|---|---|
| 1 | Flow duration |
| 2-5 | Forward packet count, backward packet count, forward total bytes, backward total bytes |
| 6-9 | Forward packet-length maximum, minimum, mean, standard deviation |
| 10-13 | Backward packet-length maximum, minimum, mean, standard deviation |
| 14-15 | Flow bytes/second, packets/second |
| 16-19 | Flow IAT mean, standard deviation, maximum, minimum |
| 20-24 | Forward IAT total, mean, standard deviation, maximum, minimum |
| 25-29 | Backward IAT total, mean, standard deviation, maximum, minimum |
| 30-32 | SYN, RST, ACK flag counts |

No literal IP addresses, port numbers, timestamps or labels are model inputs.

## 3. Reconstructed architecture and training

```text
32 standardized flow features, shape (32, 1)
  -> parallel [Conv1D-32 + spatial attention] and [LSTM-32 + temporal attention + BatchNorm]
  -> concatenate + BatchNorm -> LSTM-64 -> Dense-64/ReLU -> Dense-7 logits
```

- **42,761 parameters**; LSTMs process feature positions, not 32 packets.
- Seven outputs: **Benign, Bot, Brute Force, DDoS, DoS, Port Scan, Web Attack**. Argmax selects the class; non-Benign means attack.
- Baseline: **10 epochs**. Independently prune its final weights by **30%/40%**, fine-tuning each for **5 epochs**.
- No early stopping; save all epochs; evaluate fixed finals.
- Unstructured pruning keeps dense dimensions unchanged; no assumed runtime savings.

## 4. Paper reproduction results

All values below are percentages; **pp** means percentage points. Macro F1 gives each class equal weight.

| Variant | Paper test accuracy | Our test accuracy | Difference (pp) | Our macro F1 | Attack recall | Benign FPR |
|---|---:|---:|---:|---:|---:|---:|
| Baseline | 97.35 | 97.0256 | -0.32 | 76.6327 | 91.7953 | 1.68933 |
| 30% pruned + fine-tuned | 98.30 | 97.3240 | -0.98 | 77.1588 | 95.2472 | 2.16379 |
| 40% pruned + fine-tuned | Not stated numerically | 97.3340 | n/a | 76.2494 | 95.1364 | 2.12343 |

Paper baseline **training** accuracy is 98.0%; **test** accuracy is 97.35%. Our test figures differ; unavailable implementation/split details prevent exact attribution.

The paper reports precision/recall/F1 of **98.6/97.9/98.1%** without an averaging rule. Our separate averages are:

| Variant | Macro P/R/F1 % | Weighted P/R/F1 % |
|---|---:|---:|
| Baseline | 95.12 / 72.04 / 76.63 | 97.02 / 97.03 / 96.98 |
| 30% pruned | 95.93 / 73.29 / 77.16 | 97.43 / 97.32 / 97.31 |
| 40% pruned | 96.20 / 72.75 / 76.25 | 97.43 / 97.33 / 97.32 |

## 5. Why we added connection context

The 30%-pruned model had **38.67% Bot recall**, **78.43% Brute Force recall**, **8.10% Web recall** and **14,744 benign false positives**.

**207/360 missed Bot** and **2,146/2,176 missed scan** flows matched Benign training vectors in all 32 inputs: evidence of input ambiguity, not proven label errors.

**Addition:** recent connection counts, distinct peers/ports and response patterns supplement individual-flow statistics.

## 6. Context features and architecture

For both source and destination hosts, compute **13 aggregates** over **2, 5 and 15 minutes**:

- Log1p counts: completed-flow occurrences; outgoing/incoming packets and bytes; distinct peers; distinct remote/local ports (**8 values**).
- Fractions: no peer-direction packets, RST present, SYN present, TCP, UDP (**5 values**). These are traffic proxies, not authentication outcomes.

**3 windows x 2 endpoint roles x 13 values = 78 context features; total input = 32 + 78 = 110.**

Context handling:

- **Training rows only** populate the unlabeled history bank for both cohorts; test rows never update it.
- Include only definitely prior completed flows inside the window; exclude self/future/tied/uncertain events.
- Respect one-second/minute CSV timestamp precision. Interpret ambiguous hours 1-7 as afternoon using the observed daytime schedule.
- Clamp negative durations for timing only; preserve original flow inputs. Context scaling fits training only.
- IPs/ports group history; literal identities, absolute time, labels and predictions are excluded from tensors.

```text
Original 32-feature TSANet -> 64-value flow representation
78 context features -> Dense-32/ReLU -> Dense-16/ReLU
Concatenate (64 + 16) -> Dense-64/ReLU -> Dense-7 logits
```

**46,841 parameters.** A control of exactly the same size receives zero context after normalization.

## 7. Fair comparison and results

Both arms preserve the exact original rows/order, 32 flow values, split, seed, optimizer, batch size, loss and decision rule. Identical initialization; **10 + 5 epochs per arm**, independent 30% pruning. No extra data or test-selected checkpoints.

| Same-size variant | Accuracy % | Macro F1 % | Attack recall % | Benign false positives | Benign FPR % |
|---|---:|---:|---:|---:|---:|
| Context disabled, unpruned | 97.1808 | 76.9501 | 91.9570 | 10,454 | 1.53420 |
| Context enabled, unpruned | 99.9815 | 98.1405 | 99.9311 | 33 | 0.00484 |
| Context disabled, 30% pruned | 97.2454 | 76.1135 | 95.1855 | 15,305 | 2.24612 |
| Context enabled, 30% pruned | 99.9850 | 98.6028 | 99.9491 | 38 | 0.00558 |

Classwise comparison of the reproduced 30%-pruned model and its context extension. **P/R/F1 = precision / recall / F1, in percent; values are rounded.**

| Class | Training rows | Test rows | Reproduced P/R/F1 | With context P/R/F1 |
|---|---:|---:|---:|---:|
| Benign | 1,589,924 | 681,396 | 98.82 / 97.84 / 98.33 | 99.99 / 99.99 / 99.99 |
| Bot | 1,369 | 587 | 97.01 / 38.67 / 55.30 | 95.82 / 85.86 / 90.57 |
| Brute Force | 9,682 | 4,150 | 99.57 / 78.43 / 87.75 | 100.00 / 99.98 / 99.99 |
| DDoS | 89,618 | 38,407 | 99.71 / 99.55 / 99.63 | 99.99 / 99.99 / 99.99 |
| DoS | 176,198 | 75,514 | 88.20 / 95.05 / 91.50 | 99.99 / 100.00 / 99.99 |
| Port Scan | 111,163 | 47,641 | 90.03 / 95.39 / 92.63 | 99.99 / 100.00 / 99.99 |
| Web Attack | 1,526 | 654 | 98.15 / 8.10 / 14.97 | 99.54 / 99.85 / 99.69 |

- Against the original pruned model: accuracy **97.3240% -> 99.9850%**, macro F1 **77.1588% -> 98.6028%**, benign false positives **14,744 -> 38**, all measured on the same test rows.
- Against the equally sized context-disabled pruned control: accuracy **+2.7397 pp**, macro F1 **+22.4894 pp**, benign FPR **-2.24055 pp**. This control separates added information from added parameter capacity.
- Bot remains the weakest class: **85.86% recall**, despite improvement from 38.67%.

## 8. Verification and scope

- CPU replay reproduced all **848,349** context-pruned-30 decisions and the published confusion exactly. Independently refitted training-only scalers: mean/scale error **0**. Recomputed **93,600 context values** across 1,200 queries: **0** mismatches or future/self/test-bank events.
- **One-seed, already-opened random-row benchmark.** Exact train/test feature overlap: **32.66%** across original 32 inputs; **11.75%** across all 110 inputs, including **98.75%** of Port Scan test rows. Feature equality is not proof of identical complete packets/captures.
- Same-day canonical tuple overlap is **65.11%**; all attack endpoints are seen in training. Model fitting includes later capture rows relative to every test query, even though history features use only prior events.
- Excluding identical 110-input matches retains **99.9830% accuracy / 98.4291% macro F1**, but this post-hoc subset still shares lab campaigns and does not create an independent final test.
- Network-wide context and these dependent benchmark scores do **not** establish independent-session/device accuracy or Android timing. The gain is measured within this protocol; its prospective generalization remains unverified.

## Code and numeric evidence

- [Paper implementation](../experiments/tsanet_paper/) and [documented protocol](../experiments/tsanet_paper/PROTOCOL.md).
- [Reproduction results](../results/tsanet_paper/RESULTS.md) and [full classwise numbers](../results/tsanet_paper/classwise.csv).
- [Context implementation](../experiments/tsanet_context/) and [documented protocol](../experiments/tsanet_context/PROTOCOL.md).
- [Context comparison](../results/tsanet_context/COMPARISON.md), [numeric results](../results/tsanet_context/comparison.json) and [independent validation](../results/tsanet_context/VALIDATION.md).
