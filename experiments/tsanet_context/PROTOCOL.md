# TSANet connection-context comparison - 18 November 2026

The user authorized adding context across connections and measuring improvement over the frozen paper baseline. This experiment changes context inputs and the necessary fusion branch only. It does not change class weighting, labels, optimizer settings, training budget or decision thresholds, and does not install a phone model.

## Fixed comparison

- Preserve the paper benchmark's exact 1,979,480 train / 848,349 test row IDs, order, original 32 input values and train-fitted normalization.
- Fit new context normalization on training rows only. No labels, literal IPs/ports, calendar/day/file identifiers, absolute timestamps or previous model predictions are context tensor values.
- Context uses **training rows as an unlabeled history bank for both training and test queries**. Held-out rows never update history. This avoids test features entering training context and gives both cohorts the same 70%-sampled history density. It is a conservative bank experiment, not a complete live-traffic history or independent-session test.
- Original test results are already opened. These comparisons are development results on the existing random-row benchmark, not a fresh blind test or evidence of Android generalization.
- Train two identical 46,841-parameter fusion models: context enabled and context disabled. The disabled control receives zero context after normalization. Both use identical initialization, epoch orders and budgets. This separates context information from increased network capacity.
- Both start from scratch: Adam .001, batch 256, natural-frequency unweighted seven-class cross entropy, seed 42, 10 epochs. Each independently receives 30% global magnitude pruning and 5 fine-tuning epochs starting from its own epoch 10. No 40% branch, threshold search, loss change or model search. Every epoch is saved; fixed final epochs are compared. All four final checkpoints freeze before test inference.
- Historical original baseline and pruned-30 results are retained in comparisons. Primary context effects are context versus the matching disabled control at the same pruning stage.

## Causal context and timestamp precision

Publisher timestamps have one-second precision on Monday and mostly one-minute precision elsewhere, with a 12-hour clock lacking AM/PM. Parse day/month/year and map hours 1..7 to 13..19 using the observed daytime capture interval; dates must match the file's weekday. Context calculation needs relative time only; no PCAP UTC-offset assumption is needed. Unexpected hours/date values fail preflight.

For a flow with displayed start `s`, precision `p` and duration `d`, define completion bounds `[s + max(d,0), s + p + max(d,0)]`. Negative publisher durations are counted and clamped only for history timing; original flow features remain unchanged. The query anchor is the current flow's lower completion bound. A bank flow enters a history window W only when its upper completion bound is **strictly before** the query anchor and its lower completion bound is **at least** `anchor - W`. Therefore its entire completion interval is certainly inside the window. Same-time/uncertain completions, the current row, and possible future completions cannot enter context.

Windows are **120, 300 and 900 seconds** (2, 5 and 15 minutes), chosen before training because minute-rounded timestamps cannot support faithful 5-second history. Edge-uncertain flows are omitted rather than ordered by arbitrary CSV row order. This undercounts history, especially for the 2-minute window. Prediction remains at full-flow completion, as in the original benchmark; early packet-prefix performance is not claimed.

For each window, summarize history separately for the current flow's source host and destination host. Each host has 13 values:

1. log1p completed-flow endpoint occurrences
2. log1p outgoing packet count
3. log1p incoming packet count
4. log1p outgoing bytes
5. log1p incoming bytes
6. log1p distinct peers
7. log1p distinct remote ports
8. log1p distinct local ports
9. fraction with zero peer-direction packets (response absence proxy)
10. fraction containing RST
11. fraction containing SYN
12. TCP fraction
13. UDP fraction

Total context dimension: 3 windows * 2 endpoint roles * 13 = **78**. Port/IP values are grouping keys only. RST/SYN counts are flow-wide indicators, not proof of direction-specific connection failure. The response proxy is not an authentication outcome. Empty history is represented by zeros before train-only standardization.

## Fusion model

Keep the reconstructed TSANet's 32-feature CNN/LSTM attention encoder and final LSTM64. Encode context with Linear78->32, ReLU, Linear32->16, ReLU; concatenate its 16 values with the 64-dimensional flow state. Classifier becomes Linear80->64, ReLU, Linear64->7. There are 46,841 parameters versus 42,761 in the paper reconstruction. Disabled control uses the identical architecture and parameter count.

Prune all matrix weights, including the context branch, using the frozen paper implementation. Mask gradients and re-zero weights after every optimizer step; reset Adam for each fine-tune. Export contracts take raw float32 flow `[batch,32]` and raw context `[batch,78]`, embed both normalizers and return seven logits. No mobile integration, quantization, app identity or Llama changes are part of this task.

## Validation and reporting

Before full training, run synthetic end-to-end extraction/training/pruning/evaluation/export plus meaningful checks: direct slow-reference window comparison, future/tie/self exclusion, held-out bank exclusion, expiry, disabled-control independence, gradient/pruning and source-row alignment. Fail on missing metadata, unexpected dates, baseline-row/feature mismatch, nonfinite inputs or absent classes. Persist source/config/cache hashes and support resumable hidden background execution.

Report accuracy, macro F1, per-class precision/recall/F1, true detections, benign false-positive counts/rates, binary recall and confusion matrices. Include signed context-control and context-historical changes, export parity and retained epoch counts. A reduction in false positives with worse rare-class recall is not automatically an improvement. Contextless, shuffled-context or other later checks are diagnostics only and cannot select a checkpoint. Preserve every result even when the context model regresses.
