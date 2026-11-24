# Deployed hybrid pipeline — 0.14.0/code38

Installed and hash-verified on the owned Pixel6a,21November2026. This release follows the explicit request to replace code37 with immediate factual notes and short local Llama guidance. Production detector PTEs, thresholds, normalization and Llama/tokenizer files are unchanged. Details/reproduction/rollback: [release guide](../../docs/hybrid_guidance_v1/README.md).

## What passed

- Before the main APK was built/installed, a separate sandbox helper executed the exact new fact/presentation/store sources:14 category/app examples, both coverage warnings, receiving-port caveat, conflicting ownership, unsafe/invented guidance rejection, immediate factual notes, stale revisions and dismissal. Source hashes recorded in [predeploy_contract.json](predeploy_contract.json).
- Main app/instrumentation builds passed. The same contracts passed in the installed app. Native feature/policy/delivery-clock checks and21frozen model self-checks passed with zero decision changes: [hybrid_contract.json](hybrid_contract.json), [aligned_v2_native.json](aligned_v2_native.json).
- Real Llama IPC worker with monitoring active:8 declared evidence requests across all7flagged categories.7generated guidance sentences accepted; Web guidance added an unsupported sign-in purpose and was rejected. The full factual note and correct default Web guidance remained available. All8requests returned useful notes with no runtime errors; every trial had zero capture queue drops. [runtime.json](runtime.json), [summary.json](summary.json).
- A transient notification clearly labelled`TEST: explanation preview, no real incident` was posted and queried **before Llama started**. Its full text matched the factual note; post-and-query took10ms. It was removed immediately, and no test activity was inserted into live history. This is not packet-to-alert latency or a user-perception measurement.
- Real app ownership resolved as **NIDS Traffic Lab (`nids.trafficlab`)** for one benign HTTP connection. A separate synthetic IPv6 endpoint lookup against the app's real listener correctly identified its receiving port and stated that delivery was not established. No attack was generated. [attribution.json](attribution.json).

## Measured request times

| Installed production worker, monitoring active | Result |
|---|---:|
| First cold full client request, n=1 |15.522s |
| Warm full client median, n=7 |**3.707s** |
| Warm full client range |2.944–3.792s |
| Cold model verification / load |3.605s /7.831s |
| Factual note available |Before any Llama result |
| Actual notification post-and-query check |10ms |
| Accepted Llama guidance |7/8requests |
| Safe default guidance retained |1/8requests |

The full note includes activity, uncertainty, verified app role or missing-ownership reason, endpoint/phone port where known, packet/duration evidence, recent context/coverage and manual guidance. Llama generates only the final check; app identity and warning sentences are deterministic. This is more detailed than a one-sentence alert without making the model generate the whole explanation.

Earlier code37 production-worker measurements were38.254s warm median and54.605s cold median on three patterns. The new live-worker observations are substantially faster, but these sessions differ in evidence, temperature/background load and sample counts; do not call them a randomized paired benchmark. Existing1B model memory is still substantial. Process CPU/RAM/swap and whole-device GPU/battery resource aggregates are retained in summary.json with their scope labels.

## Limits and final state

The network detector's known false positives and misses remain; this release changes explanation delivery/ownership presentation, not detection accuracy. The class is a model hypothesis, not confirmed attack truth. An exact Android Service or the remote device's attacking program is not identified. Closed ports/very brief connections may have no app owner; shared/conflicting ownership is explained instead of naming a guessed app. Listening-port association is weaker than an exact connected-socket match.

Package identity: [package_review.json](package_review.json); installed version/models/monitor: [deployment.json](deployment.json). Existing history/preferences were retained with no schema change or data clearing. Private old-APK/history rollback snapshots and lab logs stay under ignored runs. Original manual attack-test instruction remains; allow300seconds of monitor history after an update/instrumentation restart. No next attack/profile is scheduled.

The later user-requested ForgeSight PR review is separate from this code38 deployment. Any additional candidate must be tested before altering this working release. No GitHub push or ZIP.
