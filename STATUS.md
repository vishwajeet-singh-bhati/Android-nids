# Current snapshot — 21 November 2026

App **0.14.2-network-scope / code 40**, current experimental augmented-v1 detector: `gate_s0_final` + `diagnosis_s1_best`; thresholds 0.5408333333333333/0.8. Six 40-epoch jobs completed, all 240 epoch checkpoints retained locally. This is the current source, not the earlier code 36 snapshot.

- Offline:62/64 recorded phone Web segments flagged;10/120 normal false flags; failed readiness. [Full classwise comparison](results/phone_capture_training_v1/RESULTS.md).
- Actual protocol sequence: FTP 29/32 flags but 0 BruteForce types; SSH 32/32 flags and 6 correct types; restricted emulator 0/12; DoS 18/96 actual load requests; three-source DDoS 0/96 actual load requests. Availability-probe flags are separate. [Reviewed protocol results](results/protocol_phone_tests/RESULTS.md).
- Normal controls: initial/final protocol cases 3/9 and 4/9 false flags; later 20:16 case 4/9(twoSSH/twoHTTP); latest 22:59 case 2/9(bothSSH). These are small development cases, not an everyday FPR estimate.
- Explanations: immediate verified facts/app role/warnings; existing 1 B local Llama adds a checked short guidance sentence. Actual code 39 IPC cold 14.047 s(n 1),warm median 3.690 s(n 7),7/8 guidance accepted, one default retained. No new detection-accuracy claim.
- Code 40: both-loopback traffic counted separately by default; no external port/app allowlist or threshold change. All 104 old activity IDs retained;57 local rows reclassified without deleting evidence. Legitimate UID 0 sockets retained; inode-zero/TIME_WAIT records no longer prove an app owner.
- New eight-request HTTP control quiet;714-second post-install window had zero flags,11 local summaries counted separately and 159 external checks at heartbeat. A later normal SSH failure remains, so this is not zero-FPR proof.

Models/normalization remain frozen during these cases. No new detector repair is trained or promoted. The next repair requires varied independently labelled normal sessions plus attacks, disjoint session/day/device cohorts, and classwise regression checks.

[Complete chronological report](docs/project_report/README.md) · [current pipeline](docs/CURRENT_PIPELINE.md) · [history](docs/DEVELOPMENT_HISTORY.md) · [validation record](reproducibility/VALIDATION.json).

Fresh hosted validation passed for source `2cbfcac`: [GitHub Actions run](https://github.com/vishwajeet-singh-bhati/Android-nids/actions/runs/44934776454). Both Python contracts/paper-context smokes and the Android/protocol build succeeded. A later documentation-only commit records that result without changing the validated executable sources or models.
