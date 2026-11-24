# Normal-traffic false-positive investigation — 21 November 2026

Goal: ordinary activity should stay quiet while attack detection remains useful. **The recurring idle-alert cause is corrected. General normal-use readiness is still unproven: normal SSH/HTTP false positives remain in the frozen detector.**

## What happened

1. The saved current-session tail contains nine model flags. All nine have both endpoints on IPv4 loopback, inside the same phone. These were new model flags/activity IDs, not repeated playback of an old notification. The producing app was not identified; a port number does not establish an app or maliciousness. Capture counters were healthy.
2. The user's separate `20261121_201602_Benign_8c1433` case genuinely contains four false positives among nine connections: both ordinary SSH controls and two of five normal HTTP probes. Both FTP controls were quiet. Exact captured packet counts, native inputs and timestamps match. An Unclassified result is still a binary false alarm here.
3. The PasswordGuessing case flagged 21 of 31 failed dummy-account guesses: seven Web Attack and 14 Unclassified; ten guesses were missed. Its successful-login control stayed quiet. All 21 flags match the recorded test traffic. These are bounded development counts, not general attack recall or correct Brute Force classification.

These supplied cases predate the latest explanation releases. The detector weights are identical, so the detection findings remain relevant; the old explanation statuses do not measure the new hybrid Llama runtime.

## Installed correction: 0.14.2-network-scope / code40

- Both-endpoint loopback connections remain observed and counted, but are excluded from the external-network model assessment by default. This is a scope correction, **not a claim that local activity is safe or that the model has learned to distinguish it**. It also excludes malicious loopback traffic from default model alerts. Device → Network coverage exposes a local counter and an experimental opt-in for local model alerts.
- External traffic, including LAN connections and connections to the same port numbers, still goes through the same gate and diagnosis. No app/port allowlist, threshold increase, diagnosis veto, retraining or fabricated input was used.
- Existing local-only activities remain in seven-day history with the original raw model evidence and assessment. They are labelled outside the external assessment, removed from Active, and do not queue Llama or restore old notifications. External activities are retained unchanged. Late results cannot reactivate local-only rows.
- Socket ownership no longer treats TCP TIME_WAIT or inode-zero kernel records as live app ownership. A real UID0 socket with a positive inode remains eligible. This fixes a parser defect; the exact cause of each old “System/root process” label cannot be established from the saved records alone.
- The independent contract APK's generated source manifest now has its own declared Gradle output directory. The first run exposed a stale hash manifest; it was corrected and all six exact source hashes were checked before main installation. A later expanded contract also verifies identical external feature values with interleaved loopback traffic.

Main APK SHA256: `ab7f3ed45a635386ced5d58666efbd88e270887f9fc40bb70f6e995bff3b367e`. Both detector PTEs, thresholds, normalization, Llama weights/tokenizer and guidance path are unchanged. The code39 rollback APK and a consistent pre-install DB backup remain private under `runs/false_positive_audit_20261121/before_code40`.

## Why a checkpoint swap or hidden feature is insufficient

Offline replay uses eight previously observed protocol cases, 386 exact matched connections. They are development regression cases, not fresh held-out selection evidence. “Normal” below includes availability probes; probes affected by the dummy DoS resource are not attack requests. It is not an everyday FPR estimate.

| Frozen gate; same current threshold | Normal flags / 118 | Attack flags / 268 |
|---|---:|---:|
| seed0 best | 16 | 78 |
| **seed0 final, installed** | **13** | **79** |
| seed1 best | 15 | 65 |
| seed1 final | 14 | 52 |
| seed2 best | 15 | 46 |
| seed2 final | 22 | 93 |

The selected checkpoint's replay differs from native probabilities by at most `4.590e-6`. None of these alternatives eliminates normal false alarms. Current seed0 final has the fewest normal flags in this saved cohort; no new selection or general superiority claim is made.

Protocol evidence is a contributing signal, not a proven sole cause. Some normal SSH/FTP false positives have protocol-indicator values approximately 13.8 training standard deviations above the overall mean. Positive rare binary indicators can naturally have high standardized values; that alone does not establish invalid preprocessing. A counterfactual that zeros both protocol indicators changes normal flags 13→11 but attack flags 79→48, so it was rejected and never deployed.

There is already legacy benign protocol data: the actual augmented training rows with a positive SSH indicator comprise 7,322 Benign and 4,096 Brute Force; FTP comprises 3,490 Benign and 3,736 Brute Force. Therefore “no benign SSH/FTP data exists” would be false. The new-phone training addition contains 848 unique training request segments from HTTP/web scenarios, resampled eight times; it adds no modern phone FTP/SSH control cohort. A coverage/distribution gap in current phone protocol behaviour and model calibration is plausible. These audits do not isolate its exact causal contributions.

## Validation and evidence

- `initial_idle_audit.json`: saved nine-loopback-flag finding.
- `benign_case_audit.json`, `password_case_audit.json`: the user's exact case denominators and target/packet evidence.
- `frozen_checkpoint_regression.json`: all six checkpoints, hashes, role partitions, actual protocol training counts and rejected ablation. No training or threshold fitting.
- `isolated_contract.json`: pre-install source-hashed 14 category/name fixtures plus scope, history, stale-result and socket-state checks.
- `feature_scope_contract.json`: expanded exact-source contract; all 147 external values are bit-identical when loopback traffic is interleaved.
- `native_code40.json`: native feature/policy/delivery checks, 21 PTE self-check rows, zero decision changes.
- `deployment.json`, `passive_code40.json`: installed hash, frozen models, current live counters and history preservation. This post-install window includes the separately recorded normal web control; it is not a zero-FPR guarantee.
- `benign_web_code40.json`: new code40 normal HTTP control, launched by the agent for regression validation rather than an attack or a user-launched manual case. All eight requests completed, 80 captured packets/eight TCP tuples, eight target HTTP events, zero model flags/new activities/notifications. History was 318.9 seconds old at launch; normal 130-second observation completed. The target stopped afterward. The generic harness's default manual-invocation metadata was corrected in this new private run.

All 104 pre-install activity IDs were preserved; 57 local-only rows were reclassified with raw evidence intact; external rows were unchanged and database integrity passed. No feedback existed in that backup. No attack profile was launched. At the recorded 714-second post-install inspection, there were 11 local-only summaries, all excluded from external scoring, and zero model flags; the latest heartbeat recorded 159 external inferences, zero queue drops/late packets/evictions and an enabled foreground monitor. Background traffic was not assigned ground-truth Benign labels. Re-running the deployment helper with this exact reviewed APK already installed follows a read-only inspection path and does not restart the monitor.

Reproduce offline analysis (requires the private recorded cases and model checkpoints; does not contact the phone):

```powershell
wsl.exe -d Ubuntu --cd <PROJECT_ROOT> --exec <PROJECT_ROOT>/.venvs/edge-export/bin/python validation/audit_normal_traffic.py
```

Inspect the deployed app and saved-history preservation without sending test traffic:

```powershell
python validation/deploy_network_scope.py inspect
```

## Remaining detector repair

Normal SSH/HTTP failures are **not fixed by code40**. The next detector repair needs separately recorded, labelled normal phone sessions covering successful logins, occasional user mistakes, normal browsing/downloads/background services, and legitimate bursts, with rates, sizes and apps varied. Only independently verified controlled requests should receive Benign labels; idle/background traffic must not be labelled safe automatically. Add corresponding verified attack sessions and retain original attacks in evaluation; do not change known failures into benign labels.

Keep the already examined cases as development regressions. Allocate new sessions/devices/days to train, validation and an untouched test set before prediction inspection; prevent overlapping 300-second context windows across partitions. Fit normalization and checkpoint/threshold selection on training/validation only, keep full 40-epoch checkpoint history, and compare classwise attack recall, benign protocol false positives, false notifications per hour and calibration. Release only after a fresh normal-use holdout improves without an unacceptable classwise attack regression. This repair has not been trained or promoted during the scope correction.
