> Current application is Rakshak code46. This document retains the network-core methodology; use the root component index and Rakshak guide for SMS/URL setup, current controls and the empty public-feed policy.

# Current shipped detector — code 40

App`0.14.2-network-scope`; real-phone-augmented v 1`gate_s0_final`+`diagnosis_s1_best`. This is an **experimental trial bundle**, with offline readiness false and known normal SSH false positives/missed attack behaviours.

| Item | Value |
|---|---|
|Raw inputs|float 32`[1,32]`flow +`[1,115]`context |
|Gate|147→96→48→1 MLP;18,913 parameters;82,820-bytePTE |
|Diagnosis|CNN/attention/LSTM/context;173,721 parameters;949,788-bytePTE |
|Cutoffs|Gate 0.5408333333333333; type 0.8 |
|Gate PTE SHA 256|`733187848e41b5d28c58af4df0a779646c9388d8c010d0e217d9fd9ad47a2b2e` |
|Diagnosis PTE SHA 256|`e91e6fe319f459b54c657ac1964c66f2c848bbd2e0b202f07aef03377bce752e` |
|Feature contract SHA 256|`0a6f7c956c3fe8cc8329395c62098eefd735d9f49b82176ebcce42c7f609993c` |

Both CPU TorchScript references here accept raw flow/context and embed the same training-fitted preprocessing. The actual current Android PTEs/manifests/self-checks are in`android/app/src/main/assets/aligned_v2_*`. Diagnosis runs only after a positive gate; seven-logit order: Benign,Bot,BruteForce,DDoS,DoS,PortScan,WebAttack. Unclassified is a routing fallback and retains the binary alert. The app verifies file hashes; native 21-row checks passed. Export manifests retain their original pending marker as historical provenance; later native evidence supersedes it.

Training combined unchanged original splits with 20 verified phone sessions:848 unique new train rows(8-fold exact replay),184 validation,184 test. New-phone classes are Benign/Web only. Six jobs×40 epochs, no early stopping, validation selection before final evaluation. [Classwise results](../../results/phone_capture_training_v1/RESULTS.md) report legacy and phone separately. Phone 62/64 attacks flagged with 10/120 normal false flags failed readiness; installation was subsequently explicitly authorized only for controlled testing.

Code 40 separately counts both-endpoint loopback by default; it does not establish local safety and also excludes malicious loopback from default alerts. Normal external SSH false positives remain. The classifier cannot decrypt HTTPS/SSH, confirm compromise, guarantee app ownership or detect every subtype sharing its seven family names. [Actual protocol tests](../../results/protocol_phone_tests/RESULTS.md), [false-positive investigation](../../results/false_positive_audit_20261121/README.md), [current pipeline](../../docs/CURRENT_PIPELINE.md).

The frozen historicalv 2 comparison lives under`models/references/aligned_v2`, not the default current bundle. Large Llama weights are optional separate downloads with their own license; Llama explains detector evidence rather than classifying traffic.
