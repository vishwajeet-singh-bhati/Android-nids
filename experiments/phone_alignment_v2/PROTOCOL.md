# Phone-aligned retraining v2 - 19 November 2026

User authorized comprehensive device/contract diagnostics, alignment, retraining and classwise regression evaluation. Work PC only. Baseline commit6806be1 / tag checkpoint/pre-alignment-20261119 preserves NIDS0.11.3/code33 and all evidence. No existing weights/results are overwritten. Live attacks remain individually user-launched; passive observation and offline/synthetic fixtures are automatic.

## Frozen input contract

One Kotlin implementation is compiled for offline extraction and Android validation. `AlignedPacketParser` normalizes link framing to a640-byte IP prefix and keeps at most512 payload bytes temporarily; only numeric protocol counters leave the parser. Android candidate capture will use snaplen768. IPv4/IPv6, TCP/UDP, VLAN/SLL/SLL2 and fragmentation follow the shared parser. No TLS decryption. Bounded two-direction header reassembly detects generic HTTP status/auth errors, request families and limited SQL/script indicators; no test-only proof strings or credentials become model features.

Raw32 flow features preserve observed per-packet TCP flag counts and IP-derived payload lengths, sample standard deviations and microsecond timing. Undefined rates for zero-duration flows are0 with duration0 (flows are retained). Retransmissions remain observed; TCP sequence-aware tuple reuse prevents confusing identical SYN retransmits with a new session. RST, both FIN plus1s quiet,30s maximum/TCP idle and10s UDP idle end segments. A50ms/65,536-packet stable reorder buffer precedes extraction; residual late/forced records and state limits are reported.

Context115 = sixteen statistics for source/destination roles across5/30/300 seconds (96), eighteen per-flow bounded wire observations, and log history age capped300s. Completed decisions enter only strictly subsequent decisions; no coarse minute rounding or label-driven sampling. Each watched-host view sees only traffic incident to that host, including its pair-specific observations of the remote endpoint. Traffic between that remote endpoint and third parties is invisible. Both watched views of a network flow share the same split group. This is a deliberate new contract, not a claim that old32+78 weights accept it.

## Data and labeling

Re-extract all five local CICIDS raw PCAPNGs with shared Kotlin code. Publisher CSVs provide tentative canonical-tuple/time labels only, using the independently audited+3h clock and explicit minute/second uncertainty. Exclude unknown/conflicting/out-of-family labels rather than defaulting to Benign. Match the whole resegmented flow interval; report original class/fine-label support and exclusions before any training. The prior V6 zero-DDoS/window-contamination problem is avoided by flow-level joins and hard class coverage gates.

PARROT ordinary captures and publisher-benign CIC-AAGM are weak Android controls, not verified-clean truth. Group PARROT by app and AAGM by capture. Do not convert malware-family or unknown captures to positive network labels. New passive phone recordings and opened manual attack captures are diagnostic-only; they do not enter training or selection.

An independent full container audit excludes an entire corrupt/unsupported Android control before extraction; do not retain its readable prefix or invent repaired records. Versioned integrity reports preserve excluded file hashes, byte offsets/reasons and complete input inventories. Initial audit excludes one corrupt PARROT capture (319/320 accepted) and one truncated AAGM capture (172/173 accepted). No CICIDS weekday is excluded. Abort if Android exclusions exceed10% or fewer than20 captures remain.

Connection groups (day + canonical tuple, both endpoint views together) are stratified into70% training,15% validation and15% final evaluation. App/capture groups remain intact for Android controls. Normalization/log transforms fit training rows only, with a0.05 standard-deviation floor. History is an unlabeled causal stream feature computed before partitioning; test labels never enter features, but this is not an independent capture/session benchmark. Report this limitation and reserve fresh user-run phone sessions for later deployment assessment.

## Training and selection

Train a lightweight binary MLP gate and richer seven-class diagnosis model for three seeds, plus same-architecture aligned TSANet and context-disabled controls. All jobs use the same frozen rows, fixed40 epochs, no early stopping, all epoch/best/last checkpoints retained, resumable state and bounded concurrency. Weighting uses training class counts only. Compare matched data/budgets; original CSV benchmark scores remain historical references and cannot promise unchanged precision/recall on a different raw-flow cohort.

Checkpoint and thresholds are selected on validation only. Eligibility requires both recall and false-positive targets; never select a silent gate for low false positives alone. Diagnosis may return unknown and never vetoes a binary warning. Freeze selected checkpoints before final evaluation. Report per-class precision/recall/F1/support/confusion, macro metrics, PR/ROC diagnostics, benign FPR, per-source/fine-label/time scopes and regressions. Missing or insufficient class support blocks a full training run. Failed validation blocks automatic deployment.

## Validation and execution

Before extraction/training: legacy regressions, new unit/negative-control/visibility/reorder/zero-duration tests, PCAPNG container checks, desktop/Android feature parity on saved and synthetic packets, metadata/container snap-length parity and phone resource/capture inventory. Before deployment: model export/native parity, classwise gates, ordinary-use/resource checks and fresh manual attack tests. No claim that this eliminates every possible future issue; unsupported encrypted application semantics and label/data limits remain explicit.
