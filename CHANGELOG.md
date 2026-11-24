# Changelog

##0.17.4-branding / code47 -24 November2026

- Create an original Rakshak logo inspired by the supplied protection/care theme. Add adaptive, round, density-specific and themed launcher assets plus the home header logo. Preserve model weights, thresholds, detection policy and explanation behavior.
- Code46 measurement history remains valid for its stated builds. Phone deployment of this branding build is pending device reconnection.


## Public build validation fix - 24 November 2026

- Include shared safety-note/result types in the isolated Android contract-check module. Move the unchanged result formatter into its own source file so the complete CI module set builds. App version and learned weights are unchanged.

## Submission preparation and full SMS source - 24 November 2026

- Recover the full SMS trainer/evaluator/PTQ/QAT source, selected22-layer checkpoint and split metadata; match the deployed PTQ hash and independently verify archive CSV hashes/group separation. Preserve archived scores as archived evidence.
- Expand the self-contained report to89 pages with separate SMS/URL/integration sections, hardware/optimization, classwise archived comparisons and current benchmark limits. Add submission checkpoints and a validation-first improvement plan.
- Rename the existing public repository to rakshak while retaining its history. Curate current source/checkpoints/aggregate evidence, omit datasets/private content and restricted feeds, and supply a local feed bootstrap with an empty public database. No final form/video submission or candidate promotion.


## URL benchmark and evidence labeling - 24 November 2026

- Run all2048 user URLs sequentially on Pixel and separately expose raw model scores behind list overrides. Save every verdict and timing. Confirm exact overlap with the existing export reference rather than presenting repeated predictions as independent ground truth.
- Add public-feed exact-match label tooling, preserving1830 unmatched URLs as unknown and218 as evidence-supported phishing. Report raw known-positive recall172/218 alongside list-assisted218/218, with full-file accuracy/precision unavailable. Four metric contracts prevent unknowns/single-class subsets from producing misleading accuracy claims. App/model behavior stays unchanged.


## 0.17.3 / code46 - 24 November 2026

- Preserve explicit URL spans during SMS email masking: userinfo and query email addresses stay inside their URLs. Verify ordinary emails remain email-only. Nine private phone replays and230 old SMS scenarios checked.
- Confirm the latest standalone celebration generated no new warning; retain historical alerts. Record synthetic URL verdicts and remaining live-link uncertainty. Make service notification validation await asynchronous visibility instead of taking one immediate snapshot; retain the initial failure evidence.


## 0.17.2 / code45 - 24 November 2026

- Route bare-link messages through independent URL checking rather than SMS semantics of the url_present placeholder. Keep narrowly guarded standalone celebration phrases quiet; instructions, links and other strong cues defeat that celebration path. Expose SMS routing reason.
- Review and privately replay the six recent user SMS messages. Preserve all230 old scenario outcomes and verify real notifications for a known phishing-model-positive bare link. The user-reported risky URL remains LIKELY_SAFE, so its earlier incidental SMS warning is lost; this is an unresolved URL coverage concern, not a demonstrated recall improvement. Record before/after evidence and retain original user history.


## 0.17.1 / code44 - 24 November 2026

- Check links extracted from incoming/pasted/shared SMS before the optional SMS cascade; emit a preliminary phishing warning and preserve link evidence through later updates. Link detection works with SMS classification disabled and skips model work when no links are present. Existing event-driven incoming-SMS permission/toggle remains required.
- Clarify automatic incoming SMS/link controls and advise against opening flagged links. Keep all model weights, thresholds and privacy controls unchanged. Add native service checks for URL-only message assessment, no-link messages and embedded-link notifications.


## SMS and URL architecture inspection - 24 November 2026

- Document the deployed URL CNN/ngram ensemble, SMS linear/MobileBERT-22 cascade and rule-based SMS/URL bridge, including preprocessing, layer dimensions, thresholds and saved example decisions. Verify the CNN's 92,577 parameters from its checkpoint and MobileBERT's 22 attention blocks from the compiled artifact. Preserve model/app behavior and distinguish regression fixtures from accuracy evidence.

## Deployment and saved-alert review - 24 November 2026

- Renew wireless ADB pairing and install/hash-verify Rakshak code43 on Pixel6a. Preserve all27 original activities, five original feedback records and private Llama. Complete native ARM reference and real Llama notification checks; record strict SMS numeric drift separately from matching classes.
- Correct the user's accidental WhatsApp Expected selection to Not sure, preserving the original feedback history. Retain the event as unverified and exclude the withdrawn label from benign interpretation.
- Replay27 saved model inputs and compare two fixed short-reset filters against legacy, phone and protocol cohorts. Reject broad filtering for positive-label losses; keep deployed detector weights, thresholds and alert policy unchanged. Record the audit and reproducible script with private data excluded.

## 0.17.0 / code43 - 23 November 2026

- Rename the app Rakshak and integrate the supplied SMS rules/linear/MobileBERT cascade and URL CNN/ngram/list pipeline with the existing network detector. Keep `nids.app`, network model hashes/thresholds and upgrade data compatibility.
- Add Home, Check, Activity and Settings navigation, manual/share message and link checks, independent network/SMS/link switches and permission-gated new-SMS delivery checks. No inbox, RCS or background browser-URL interception.
- Share immediate plain factual warnings, notifications, seven-day history, clearing and the existing local Llama advice queue. Keep SMS bodies, senders, OTPs and full URLs out of saved evidence and prompts. Make disabled, incomplete, stale-list and failed checks explicit; recover interrupted preliminary warnings after reopening.
- Verify all 192 handoff files, exact combination fixtures, 2,077 URL reference decisions, SMS normalization/rule/model/policy parity and actual Android foreground-service/Llama notifications with network capture paused. Validate incoming-SMS routing and detector controls on a dedicated local emulator. Full environment, counts, synthetic failure cases and Pixel deployment status are recorded in `validation/reports/rakshak_integration`.

## 0.16.0 / code42 — 22 November 2026

- Introduce a light theme, blue controls, selected navigation tabs and simpler Monitor, Activity and Settings screens. Place resource and research controls under Advanced settings and order activities newest first.
- Add confirmed history clearing for saved activities, feedback and related notifications. Reject late explanation callbacks and detector evidence queued before clearing.
- Structure alerts as What happened and What you can do. Show short verified app ownership wording, everyday Llama guidance and an uncertainty statement, with measurements under Technical details.
- Validate fourteen content fixtures, isolated history clearing and late-result handling, plus eight actual on-device Llama requests. Six generated guidance sentences accepted, two default guidance sentences retained; notification content available before generation.

## 0.15.0 / code41 preview

- Add an opt-in SSH/FTP authentication episode policy with bounded state, a capture-health fallback, and an evidence-based connection pattern alert. Preserve Code40 behavior when the switch is off.
- Replay the exact Kotlin policy against nine saved cases. Normal protocol flags fall from 13/36 to 2/36 with the preview enabled. Both guessing episodes alert, with a later first SSH warning. The Code41 APK is built and Code40 remains installed.

## Authentication episode v1 research

- Add causal multi-window peer and service authentication features for recorded HTTP, SSH and FTP observations. Separate Web semantic routing and keep verified outcomes outside the classifier inputs.
- Compare three small HTTP episode models on the frozen session split. Track premature and eventual warnings, and document that the fixed SSH/FTP rule falsely flags every normal-only HTTP episode in this cohort. Retain Code40 as the release baseline.

## Behavior context research — 2026-11-22

- Add causal authentication episode replay, passive inbound TCP service pressure features, and a lifecycle check in the replay tooling. Compare nine saved protocol cases and six separately recorded normal HTTP burst sessions.
- Add a training-space nearest-neighbor and feature-group sensitivity audit for 216 recorded errors. Evaluate session balancing and training-only hard-negative weighting on the existing phone HTTP cohort.
- Record the observed reduction in normal SSH/FTP flags and the early SSH detection loss. Retain code40 as the installed release after the HTTP candidates miss the recall target and pressure measurements lack matched multi-client negative controls.

## Current-source publication and report refresh — 2026-11-21

- Published/verified main `2d805bd`; fresh hosted run44934776454 passes Python and all current Android/protocol builds on source2cbfcac. Final follow-up records validation only. Curated checkout clean, prior Git history retained, no force push; canonical source manifest/private-file/link checks recorded.

- Bring curated GitHub source from code36 to code40 with current model references/thresholds, protocol labs, preprocessing/training/evaluation, inference studies and readable reproducibility/history guides. Keep the historical v2 inference reference solely for matched comparisons.
- Expand the self-contained report to73pages through completed augmentation, actual protocol tests, hybrid Llama timing and unresolved SSH false positives. Re-audit the later user-run normal case2/9 separately; preserve frozen prior cohorts and all historical caveats.
- Validate six model/package/preview checks, fresh paper/context smokes, Android/protocol builds and offline evidence/failure-cleanup checks. Fix performance smoke output-directory creation for fresh checkouts. Exclude datasets/raw recordings/private keys/credentials/Llama weights/ZIP; no phone changes during publication.

## 0.14.2 / code40 — 2026-11-21

- Observe on-device loopback separately from default external-network assessment, stopping recurring idle-loopback alerts. Add coverage counter and experimental opt-in. This narrows default scope; it does not establish local safety or improve the model's classification accuracy. External inputs/models/Llama unchanged.
- Preserve all 104 original activity IDs/raw evidence; move 57 local-only activities out of Active, pending explanations and notifications without deleting history. Protect against stale callbacks. Reject inode-zero/TIME_WAIT ownership while retaining real root-owned sockets.
- Pass exact-source scope/history/socket contracts and native 21 checks; retain identical 147 external inputs with loopback interleaved. Fix stale generated source manifest. Preserve rollback APK/DB and release hashes.
- Audit supplied normal 4/9 false flags and password 21/31 failed-guess detections; compare six frozen checkpoints. Reject indicator masking: only two fewer false flags but 31 lost attack detections. Document unresolved external false positives and required data repair. No retraining, threshold changes, attack suite, push or ZIP.
- Verify normal web regression: 8/8 requests, zero flags/activities/notifications. Post-install 714-second inspection remains quiet with 11 local summaries observed separately, 159 external checks and healthy capture counters. No everyday zero-FPR claim.

## 0.14.1 / code39 — 2026-11-21

- Reviewed ForgeSight PR5/17; retained existing persistent isolated runtime/reset/cache. Tested one-token boot warmup on Pixel: same-input output preserved, total startup+request time essentially shifted rather than reduced. Kept speculative warming disabled.
- Fixed the installed Android API's omitted maxNewTokens dispatch using a conservative callback stop guard; default guidance remains on budget truncation. Native ceilings1/3/48 and reset isolation pass; diagnostic failures/corrections preserved.
- Revalidated14fact/store contracts,21native checks and8production IPC fixtures. Warm full-client median3.690s;7generated guidance accepted/1safe default; zero capture drops. Installed SHA recorded, trained models unchanged,87original history IDs retained, monitor restored. Added offline public-evidence audit and reproduction/report links. No push/ZIP.

## 0.14.0 / code38 — 2026-11-21

- Deployed the explicitly requested hybrid explanation pipeline: detailed factual note immediately, optional checked Llama guidance afterward. Existing1B model/worker/cache and trained detector preserved.
- Show verified app display names/packages and incoming/outgoing roles; add fresh receiving-port association with delivery caveats and explain missing/ambiguous ownership. Never infer an exact service or causal app without evidence.
- Reject stale/dismissed Llama results, refresh notes on evidence changes, retain seven-day history and feedback. Reject invented names/numbers/causes and unsafe guidance; default advice remains available on failure.
- Passed isolated pre-build14fixture/source-hash contracts, installed contracts/native21checks,8real IPC requests, immediate notification preview and real benign/listener ownership checks. Installed full-client warm median3.707s; no attack campaign. Kept rollback APK/private data and release hashes; local changes only.

## Frozen-model inference performance study — 2026-11-21

- Added test-only Android detector/production-worker/component benchmarks and private device resource sampling, paired order controls, cold/warm timing, independent explanation evidence checks and preserved failure evidence. Main app0.13.0/code37 and all production model hashes remain unchanged; no deployment or attack traffic.
- Hoisted FP32 recurrent input projections:25.3% lower final paired median scoring time, zero changes on1125 validation diagnostics and2351 saved-phone inputs. E8 PTQ reconstructions rejected for numerical/decision degradation; no packed-kernel or QAT claim.
- Tested prompt shortening, assistant-prefilled continuation, fixed-fact guidance, plainer guidance, immediate plain rendering and pinned SmolLM2-135M alternatives. Selected existing1B hybrid as explanation candidate; rejected smaller model despite some faster requests. Kept component/live-worker timings distinct and recorded all quality failures.
- Documented CPU/PSS/RSS/swap/shared GPU/thermal/battery measurements, reproducibility and scope limits. Added offline native-failure cleanup/readiness regression; restored original healthy monitor. Local source/history only, no GitHub push or ZIP.

## Completed manual protocol evaluation - 2026-11-21

- Preserved all seven completed user-run cases and both earlier failed attempts; added a saved-evidence-only reviewer with frozen run IDs and exact packet/native/target correlations (377 connections, 4,270 matched packets).
- Separated load requests from availability probes: DoS18/96 flagged, DDoS0/96; the single DDoS console flag was a probe. Kept all benign false alerts, emulator misses, unknown labels and fallback explanation outcomes visible.
- Added readable/detailed completed results; no new traffic, training, model changes or threshold tuning.

## Protocol capture budget and early-stop repair - 2026-11-21

- Diagnosed a user-run DoS case stopping during warm-up: exactly 100,000 background packets captured in 235.309 seconds; no DoS target/traffic started. Preserved original evidence and documented stale prior-target snapshots.
- Increased only manual protocol capture budget to 2,000,000 packets with phone/PC storage preflight, five-second warm-up/observation liveness checks and explicit count/cap quality fields. Retained full warm-up, no rotation and original dataset-collection default.
- Added command/budget/storage/failure regressions using mocked transport; all existing loopback smokes pass. Avoided stale target events when startup never completed. No automatic retry, app/model/threshold changes or attack traffic.
- Preserved four preceding manual-case aggregate results, including benign false flags and unknown/missed family diagnoses.

## Protocol controller HTTP fix - 2026-11-21

- Fixed HTTP module/function shadowing that interrupted the first live normal control after FTP/SSH authentication succeeded.
- Added direct controller-helper loopback regression checks for HTTP200/503/202; the previous version reproduces the exact failure before networking. Existing technical smokes also pass.
- Preserved the incomplete control, independent authentication evidence and raw capture; added failure cleanup snapshots/quality. No automatic retry or model/APK change.

## Manual protocol test setup - 2026-11-21

- Added a separate inert Protocol Lab app/core with real dummy FTP/SSH authentication, restricted command responses and measurable two-slot application-resource denial/recovery.
- Prepared pinned-SSH helpers on both owned PCs and a one-profile manual controller with fresh history, synchronized bounded sources, exact packet/native audits and notification evidence. No phone attack case launched.
- Passed JVM/Windows loopback smokes, six zero-action previews, Android non-listening platform construction and installed-model/APK identity checks. Recorded redacted readiness evidence and full manual commands.
- Preserved NIDS 0.13.0/code37, frozen models/cutoffs, existing inbound blocks and automatic-suite STOP markers. Kept private keys/captures/build outputs out of version control.

## Existing manual phone cases independently reviewed - 2026-11-21

- Audited8user-launched runs/325native inputs/3248packets with exact per-connection accounting, unchanged hashes and clean capture-health counters.
- Added frozen-v2/current CPUreplay on identical saved native inputs:0currentphone decision flips; Webdetection improved0to22/35requests but correctWebtyping9/35. Preserved allmisses,load/resource limits,history overlap and notification/explanation caveats.
- Documented all8cases/retries, paired comparison and next validation priorities; no further test, training, model/threshold change or remote source job started.

## Authorized multi-PC lab access - 2026-11-21

- Verified public-key SSH and hostname/account identity on both additional Windows PCs. User configured source-restricted SSH firewall rules and installed the public key.
- Kept private authentication artifacts outside version control; no remote test jobs, model changes or automatic phone tests launched. Existing manual-only testing instruction retained.

## Manual remaining phone tests requested - 21 November 2026

The user changed the remaining tests to manual launches. Both automatic processes are stopped and runs/augmented_v1_phone_trial/STOP prevents restart. Do not resume automatic traffic without another explicit request. Preserve app0.13.0/code37 and both frozen models/cutoffs.

Recovered SlowScan without rerunning it: 124 native segments/252 packets,122 flags (86PortScan,34Unclassified,2Bot),31/32 connections flagged. Original check89flags missed33 in rotated monitor log. Preserved original check and recovered logs; check_reconciled.json keeps the original observation window. Independent packet/native audit passes. Monitor reader now merges both generations with reread deduplication; rotation/multiplicity regression passes. Prior fastscan512segments/510flags/7notifications and normal8requests/0flags remain valid.

State manual_remaining;3/10 entries executed,2scanprofiles verified. Remaining user commands: PasswordGuessing,SQLInjection,XSS,ConnectionExhaustion,HTTPFlood,Benign via validation/Run-ControlledPhoneTest.ps1. One at a time; wait305seconds after each completed command before the next. Beacon remains blocked by existing receiver policy; no rule changes. These HTTP profiles do not reproduce FTP/SSH, realBot or distributedDDoS. Models/phone monitor remain running; no further traffic launched during this repair. Summary.md/json updated, version history local only.

## 0.13.0 augmented v1 controlled phone trial - 2026-11-21

- Completed6trainingjobs/240epochs; frozen augmented cascade retained despite failed offlineFPRreadiness, then explicitly authorized for a phone trial.
- Exported exact selected checkpoints with embedded new normalization and frozen0.5408333333/0.8cutoffs;1125native desktop comparisons/zero flips. Installedcode37after v2backup;21Pixelselfchecks/zero flips,204passive rows/29988values exact.
- Added bounded ten-entry serial test automation, per-request controls/packetnative audits, persistent logs/status/stop and rollback notes. Initial normal control passed (8 requests, 0 flags, exact packet accounting); live attack outcomes pending. Existingreceiverblock preserved; Beaconexcluded, unsupported fullclassclaims explicit.
- Fixed activeWi-Fi interface selection(wlan1), companioncapture interface and Windowsdetached-consoleADBfailures. Added connection tuples to request records; no training extraction or thresholds changed.

## Complete development report and executed walkthroughs - 2026-11-21

- Added self-contained Overleaf LaTeX source: 63 compiled pages, 12 chapters plus six appendices, covering paper reconstruction through current phone/data work and historical RC4/v5/v6 context.
- Added source-hashed aggregate evidence, deterministic frozen-model CPU dry runs, an explicitly illustrative complete tensor fixture and exact numerical/classwise/candidate tables. New phone held-out predictions were not opened by reporting.
- Verified compilation, count consistency, references, zero text overflow and rendered figures/tables; preserve report/evidence byte hashes across Git checkouts.
- Published report and index to the authorized GitHub repository as `109a363`; no datasets/private recordings, model replacement, attack traffic or ZIP. Existing training continues separately (five/six jobs complete at the report cutoff).

## Current-source GitHub submission ? 2026-11-21

- Published the user-authorized current snapshot to `vishwajeet-singh-bhati/Android-nids` via their authenticated terminal account; clean initial main commit `3dc33a0`.
- Added isolated source allowlist/export templates, portable setup/training/test CLI, readable source layout, complete reproduction/data/setup/model documentation, pinned dependencies and GitHub build/smoke workflow.
- Excluded research data/private captures, historical packet fixtures/unused weights, machine credentials and generated outputs; no ZIP created.
- Verified Android builds, Kotlin contracts, model/label checks, paper/context and aligned train/evaluate/export smokes, plus clean-checkout contracts. Fixed fresh-runner dependencies/SDK setup; both hosted CI jobs passed (run 44821013266). Latest repository commit `e0100ed`. Separate real training and installed v2 models remain unchanged.

## Quality-gated real phone capture and updated-data training - 2026-11-20

- Added separate DatasetLab0.1.0 with independently confirmed SQL/XSS effects and per-socket outcomes; verified all16preflightforms. Added HTTPpasswordspraying as a Websubtype and matched legitimate errors/code-search/varied-size/burst controls.
- Added phone-local768-byte/all-context recording,340swarmup, strict capture/flow/label/native147parity checks and frozen-core replay adapter. Preserved pilot's initial start-alignment rejection; deterministic native-start replay passes56rows/8,232values exactly,24normal/32attacklabels, zero kernel drops.
- Added frozen20-session chronological/held-out-form plan, source/APK hashes, datasheet with CIC/USENIX methodology references, persistent status/log/stop/resume controls, and original-split-preserving augmentation. Allpreviousdiagnostics/pilot excluded from research fitting/test; no model labels or fabricated vectors.
- Added six40-epoch/3-seed fixed-architecture jobs, every checkpoint retained, two concurrent, training-only normalization and declared8xrealphone replay. Validation-only cascade selection followed by separate legacy/new-phone classwise comparison and exports. Training/export/full-evaluation technical smokes pass; no automatic phone model replacement or new accuracy claim.

## Real-phone dataset preparation - 2026-11-20

- Added collection protocol for actual controlled-phone traffic with native147-input parity, verified flow/request labels, matched normal controls, independent campaign splits and complete-pipeline comparison.
- Inventoried11existing v2diagnostic runs with artifact hashes, capture headers and development-only status. No labels inferred from model flags, automatic training merge or reuse as new blind test.
- Documented96-byte/filtered old-capture and missing target-connection-ID limitations before fresh collection. No new traffic/model/data or network-policy changes.

## Beacon retry and explicit inbound block diagnosed - 2026-11-20

- Verified user's temporary Administrator-enabled receiver exception; automatically retried onlyBeacon. Twelve outbound timeouts/0PING-PONG;13nativeBenign segments exactly match34packets, noflags/alerts, unchanged weights/clean capture. Kept inconclusive and separate from original results.
- Identified matching Enforced PublicTCPBlock for exact Python executable; newAllow does not override it. Preserved all existing blocks and made exception helper fail early on this configuration. User's cleanup watchdog removed temporaryAllow at21:35:33; verified absent.
- Saved retry/native audit/network diagnosis, updated combined report/handoff and retained local version history. No app/model/threshold changes or further traffic scheduled.

## Sequential remaining phone tests authorized - 2026-11-20

- Added a user-authorized automated runner for the three remaining bounded profiles and a final normal control. Retains the six verified cases, fixed v2 models/cutoffs, per-case observation and five-minute context isolation.
- Records launch mode, backs up diagnostic traces, checks capture health/model integrity, and requires exact native/packet tuple and flag correlation. Smoke and four independent per-connection packet/start-time/input/threshold audits pass.
- Completed HTTPload71matched flags/3notifications, SlowScan110/3 (29/31closed connections flagged;28/31typedScan), finalnormal8requests0flags. Models unchanged, monitor running, clean capture counters. Allsix new explanations completed via evidence fallback. Combined RESULTS.md retains prior misses and explicitly rejects a general-deployment claim.
- Beacon12outbound timeouts/0exchanges makes that case inconclusive. Prepared narrow Administrator-only receiver rule with automatic cleanup; requested user input, no firewall change applied. Target-proof failure remains separate from healthy native evidence checks; retry pending.

## User resource-exhaustion case missed - 2026-11-20

- Matched16live inputs to162packets; target verified twoheldslots and14resource denials. All16native/standalone diagnosis predictions Benign despite14HTTP5xxindicators; zeroalerts and clean capture.
- Preserved as a failed bounded app-resource case with explicit limits on whole-phone/fullDoS/DDoS inference and503semantics. Models/thresholds remain frozen; no assistant-launched tests.

## User XSS case missed despite observed script marker - 2026-11-20

- Verified isolated script execution and exact one-segment/10-packet native matching: script indicator1, gateBenign/score0, noflags, healthy capture. Offline diagnosis alsoBenign; preserved as a failed controlled case.
- Updated manual case ledger without duplicating the repeated SQL result. Installed models/thresholds/data remain unchanged; no new attack or fitting during review.

## User SQL test missed; flag-correlation reporting corrected - 2026-11-20

- Verified three real SQL/control connections and30packets: both successful dummy injections scoredBenign despite SQL-like feature evidence; offline diagnosis alsoBenign. Two flags/oneactivity arose from separate localhost probes, with unknown process/groundtruth, and do not establish SQL detection.
- Added exact companion-PCAP TCP tuple correlation to manual reports/ledger, separating matched traffic from outside-endpoint/unresolved window events. Regression checks on allfour cases and bounded harness smoke pass; PortScan500matched remains verified. Kept original records and installed models/thresholds/traffic profiles unchanged.

## User-run HTTP guessing failure and feature-coverage audit - 2026-11-20

- Matched32real HTTP guessing inputs to all320packets;31failed/one successful dummy login,0flags, allnativeBenign with healthy capture. Preserved as a missed episode; no notification or trace-skipping excuse.
- Added reproducible read-only CPU replay and all-training classwise auth-feature audit. Found394Benign/0attack views carrying per-flow HTTP failure evidence; diagnosis alsoBenign32/32. Clearly separated diagnostic auth masking, which did not recover alerts, from installed predictions. No model/threshold/label/deployment changes or new traffic.

## User-run v2 scan detected and traced - 2026-11-20

- Matched all507native scan segments to recorded SYNs with exact timestamps/tuples and packet-count sum1,019. Verified500realflags,476Scan/24Unclassified, fourgroupednotifications and cleancapture counters.
- Documented per-connection detection128/128closed ports,126Scan labels, six early Benign closed-port segments, one Benign open connection and one-episode/retry limitations. Preserved all artifacts and fallback-summary status; next actual test stays user-launched.

## User-run v2 benign control verified - 2026-11-20

- Verified8/8 normal HTTP200 requests against80 captured records and eight exact client-port-matched native decisions. All eight predicted Benign; zero flags/activity/visible alerts, clean late/drop/eviction counters.
- Preserved numeric trace privately and aggregate review/source hashes with the cumulative user-test log. This is a limited normal-traffic control, not general false-positive accuracy or attack sensitivity. Next traffic case remains user-launched.

## 0.12.2-aligned-v2-test / code36 - connected-phone start - 2026-11-20

- Connected authorized Pixel6a over wireless ADB, backed up installed APK/history/preferences and installed preserved v2. Original baseline and intermediate code35 snapshots remain available; no app-data/Llama clear or attack launch.
- Native saved-input checks passed, but initial code35 passive run exposed10,034/35,833 late-packet rejections. Fixed live wall-clock flushing with immediate capture and queue-aware event-time/monotonic-idle scheduling; unchanged trained extractor, weights and thresholds. Added delayed/backlogged regression fixture and verified it on PC/phone.
- Corrected code36 passed full five-minute passive capture/inference observation with zero reported late/queue drops and native14-case/204-row feature parity. Recorded scope limits; no population accuracy or battery claim.
- Llama/notification test succeeded using synthetic PortScan evidence. User saw its notification; clarified no actual scan/model detection. Guard rejected the generated draft for missing uncertainty, displayed the evidence-based fallback and removed the test row. Monitoring left active; real test profiles remain user-launched.

## 0.12.1-aligned-v2-test / code35 - offline preparation - 2026-11-20

- Prepared the user-selected preserved v2 binary-gate/diagnosis pipeline with the frozen147-input extractor, exact original weights/normalization/cutoffs,768-byte capture and phone-visible5/30/300s history. No repair fitting/threshold change or phone action.
- Preserved positive binary alerts through uncertain/Benign/failed diagnosis, with explicit unknown type; connected measured v2 evidence and best-effort socket ownership to existing automatic Llama summaries/notifications/history/caching. Kept root-derived local-address discovery and added activity-based tracing without a deliberate session reset.
- Built app/instrumentation and passed core regressions,960 native/policy cases with zero flips and29,988 passive feature values exactly. Sealed APK/model/contract/signing identities and exercised deployment/manual automation smoke without a phone. Retained preliminary0.12.0/code34 and pre-integration rollback tag.
- Added backup/install/native-check/rollback tooling and a concise one-at-a-time manual test guide; updated warm-up/default observation and model provenance. Device validation, installation and user-run attacks remain pending. Known offline v2 weaknesses/readiness limits are unchanged.

## Detailed repair classwise comparison - 2026-11-20

- Added precision/recall/F1/support and percentage-point deltas for all seven classes, binary detection/miss counts by true attack family, overall metrics and exact-source provenance.
- Explained reduced benign false flags versus Bot/Web recall losses and aggregate metric masking. Preserved failed-promotion decision and opened-test/device limits; no fitting, model or deployment changes.

## Repair v3 final comparison and verifier fix - 2026-11-20

- Completed all18 jobs/720 fixed epochs, selection/calibration, all finalists and36 best/final evaluations, both bundles and independent artifact verification; all checkpoints retained.
- Selected repair reduces benign flags729->301 and improves overall binary recall99.6424%->99.7765%, but typed Bot recall92.031%->60.938% and other prespecified regressions fail the improvement contract. Preserved v2 remains the intended fallback; neither choice gains an independent-device accuracy claim.
- Fixed report-only finalizer inventory path resolution for Windows/POSIX separators, preserving workspace containment and original failure evidence. Verified path cases and reran complete artifact checks successfully without changing frozen training sources, data or scores. Results committed locally; phone installation/manual validation remain pending.

## Publication suitability and independent validity audit - 2026-11-19

- Added a primary-source literature assessment distinguishing a potential controlled empirical paper from unsupported context/cascade novelty and real-device accuracy claims.
- Replayed all848,349 historical context decisions exactly; independently refit train-only scalers and reconstructed93,600 history values. Quantified exact110-input/tuple/endpoint/time dependence, diagnostic metadata probes and context disruption. Nonmatching subsets retain high accuracy; no estimate of independent-session accuracy or causal inflation is claimed.
- Independently audited the newer v2/v3 cohort: zero group intersections, train-only normalization refit within1.66e-9,2.6144% exact147-input test matches and no unseen-host attack coverage. Recorded shared-stream history/opened-test limitations separately from target-label leakage.
- Updated professor README only within its historical reproduction/context scope. Preserved original models, datasets, results, app and detached GPU repair; no new fitting, installation or attack traffic.

## Resume after PC shutdown - 2026-11-19

- Recovered164 saved repair epochs and skipped3 completed jobs; verified source/config hashes, CUDA and resumable optimizer/RNG states. Restarted interrupted diagnosis at epoch27 and gate at19, plus independent completion audit.
- Archived pre-shutdown scheduler/audit logs. Warmed unchanged feature arrays read-only to clear initial cold-cache page waits; confirmed advancing steps and active GPU execution. Recorded resume evidence; no data/model/training-setting changes.
## Professor-facing paper/context README - 2026-11-19

- Added `docs/tsanet_paper_and_context/README.md`: paper-specified versus assumed settings, exact preprocessing/split/features, reconstructed architecture/pruning, published versus measured results, motivation/design/controls for context and classwise improvements.
- Limited the standalone document to the original reproduction and context extension. Verified frozen numeric results and local references; no later work included and no training/source changes.
## Authorized repair v3 launch - 2026-11-19

- Preserved current v2 under tag `checkpoint/pre-repair-v3-20261119`, snapshotcommitbec3512 and23 artifact hashes. Kept earlier installed contextapp/model and all v2 results/checkpoints intact; no push.
- Implemented independent18job/720epoch matched loss/sampling repair with training-only difficult-benign pool, unchanged147inputs/labels/cohort/modeldimensions, disjoint calibration/selection groups and joint checkpoint/review-routing selection. Added explicit better/fallback comparison and separate readiness flags, all best/final model evaluations, pairedgroup intervals and calibrated native bundles.
- Passed six-job synthetic training/checkpoint/resume/init/order/selection/calibration/evaluation/fallback/nativepolicy smoke and independent uncertain-routing fixtures. Launched bounded detached real training and an independent completion verifier/report-only local committer; all40epochs/checkpoints retained, noearlystop, max2jobs.
- No repair results or phone accuracy claimed yet. Device absent; no installation/attack. User authorized improved-or-v2 fallback deployment after comparison; final device/source/model/resource/manual checks remain pending.
## Proposed next repair experiments - 2026-11-19

- Added `docs/PHONE_ALIGNED_V3_REPAIR_PLAN.md`: ambiguous Bot supervision/normal-lookalike controls, fixed-input loss/sampling comparisons, review-band routing, joint pipeline selection, separate temporal/Web evidence experiments and independent validation.
- Preserved the lightweight general binary -> richer diagnosis -> Llama design and no-veto policy for emitted binary warnings. Distinguished routing from alerting, weak labels from verified events, proposed improvements from measured results, and offline work from pending phone validation. No new training, calibration, thresholds or deployment started.
## Phone-aligned score-drop diagnosis - 2026-11-19

- Reproduced frozen validation/test decisions and final confusion; traced gate rejection, unknown typing, fine-label/protocol evidence, source/time/group concentration and best/final checkpoint tradeoffs. No model, threshold, training or installed-app changes.
- Confirmed all496 false Bot labels concern empty two-packet reset flows; measured exact flow/context label ambiguity and Bot8.27x/Web18.86x loss weighting. Diagnostic weight reversal trades away recall and is not promoted.
- Attributed418 recoverable typed DDoS losses to gate rejection; localized weak Web typing to XSS21/34 versus HTTPbrute102/104, bounded evidence and sparseSQL support. Documented standalone-versus-cascade selection mismatch, limited positive diversity and historical-cohort confounding.
- Checked normalization within4.77e-7 across platforms and zero connection-group overlap across splits. Preserved reproducible diagnostic scripts, aggregate JSON and `DROP_ANALYSIS.md`; all320 original epoch checkpoints and deployment-fail decision remain intact.

## Classwise historical and matched-cohort comparison - 2026-11-19

- Added exact previous context-pruned30 versus current selected-pipeline precision/recall/F1/support and overall metrics, with frozen-source hashes and percentage-point deltas. Separated different-cohort historical scores from the width-32 reference on the same new cohort.
- Recorded Bot/Web precision gains and Bot/DDoS/Web recall losses against the new reference, binary detection versus typing differences, sparse SQL support and untested new phone performance. No model, threshold, fitting or installed-app changes.

## Phone-aligned v2 completion and deployment decision - 2026-11-19

- Completed all8 jobs /320 fixed epochs, final evaluation and selected mobile exports at09:19:56 IST. Retained every epoch plus best-training/validation/last/final states; independent completion report verifies hashes, history coverage, confusion totals and unchanged baseline artifacts.
- Validation-selected gate_s0 + diagnosis64_s1 gives binary precision99.5415%, recall99.6424%, benign FPR0.077545% (729/940,095). Typed Bot precision54.29% fails85% target; preserved matched-reference Bot/DDoS/Web recall regressions. Offline deployment decision remains fail, no new installation or live attack.
- Both selected ExecuTorch exports pass960 cases /zero decision flips on the PC native runtime. Gate18,913 parameters82,820bytes; diagnosis173,721 parameters949,788bytes. Final Pixel verification and ordinary-use/manual tests remain pending. Published complete classwise results, decision, export manifests and checkpoint integrity evidence; historical baseline and rollback tag unchanged.

## Phone-aligned retraining v2 preparation - 2026-11-19

- Preserved installed0.11.3/code33 source and model/APK hashes in local commit6806be1 and annotated tag `checkpoint/pre-alignment-20261119` before alignment changes.
- Added a shared147-value Kotlin raw-packet/flow/history contract, actual packet flag counts, phone-visible causal context, deterministic expiry, zero-duration handling and bounded numeric HTTP evidence; legacy feature behavior remains the default. Added classic-PCAP/PCAPNG extraction, unknown/conflicting-label rejection and an independent Android contract checker.
- Passed legacy/new core, conflicting-label and real-container checks; passive predecessor Android/desktop parity matched29,988 values. Final source-hash/native weights reattestation remains pending the unavailable Pixel.
- Rebuilt five raw CICIDS days and Android benign controls, auditing/excluding one whole corrupt PARROT file and one whole truncated AAGM file with retained reasons/hashes. Added grouped splits, train-only scaling, coverage guards and diagnostic-phone-data exclusion.
- Added detached eight-job/40-epoch training, every-epoch/best/last/final checkpoint retention, no early stop, bounded concurrency/retry, validation-only selection with recall/FPR/classwise gates, full candidate evaluation and mobile exports. Synthetic end-to-end automation/export smoke passed; preparation/training progresses in background. No retrained metric, installation or new live attack is claimed.

## HTTP login diagnosis, cumulative logging and repair options - 2026-11-19

- Verified fast HTTP guessing (31 failed/one successful login,32 valid recorded flows) with no NIDS flags; retained both saved fast runs. Added a cumulative log refreshed by each manual case/Check and read-only login/training-contract audits.
- Measured binary training SYN/RST/ACK fields across1,979,480 rows versus phone SYN2/ACK9; corrected HTTP/Web Attack versus FTP/SSH Brute Force scope and documented minute-history blindness to the fast burst.
- Prepared a user-launched five-second timing variant and no-traffic Preview, preserving weights and failures. Proposed shared raw-capture extraction/retraining, optional separate behavior rules and supported app evidence. No new attack, training or model installation executed by assistant.

## Repeated manual scan: confirmed missed detection - 2026-11-19

- Verified the user's warmed-up repeat reached the phone: 513 SYN packets and 512 reset replies, 129 ports, no companion capture drops; zero NIDS positives/activity/notifications through the longer wait.
- Replayed only recorded packets through unchanged Kotlin feature code: 513 valid segments, 512 scanned-port segments carrying SYN/RST=1 and backward bytes0, confirming the training/live representation gap. No malformed/invalid/late/evicted replay records; no native per-flow-logit claim.
- Saved repeat audit and explicit failed-test conclusion. No new attacks, model/threshold changes, installation or history clear. Another unchanged scan is unnecessary.

## First manual scan diagnosis - 2026-11-19

- Audited the user's no-alert scan: one connection / 128 timeouts, zero model-positive events at later check; per-flow attribution unavailable in the original run. Notification/Llama had no positive event to process.
- Measured a training/live representation mismatch from frozen evidence: all 111,163 training scan SYN/RST fields are zero, versus one in 26 earlier native scan segments; all those native segments predicted Benign. Published precise scope and aggregate evidence without fitting or changing thresholds.
- Fixed manual-tool observability: require full history, cover 120-second flow timeout, retain bounded passive test-port PCAP and SYN/RST/tuple summaries. Offline parser/harness and passive-only start/stop checks passed. No attack rerun, app/model change or further history clear.

## Manual attack-test preparation - 2026-11-19

- Replaced the next test workflow with eight user-invoked cases and read-only follow-up checks. No attack scheduler or automatic matrix; no phone attack was run during preparation. Added command guide, bounded runner and loopback/locking/SQLite-handle smoke checks.
- Built/installed Traffic Lab 0.2.0/code3 with isolated real password guesses, in-memory SQL injection, restricted XSS proof, disposable resource exhaustion and fixed outbound exchanges. Archived prior target APK; detector app/model unchanged. Only target startup/binding was verified on the phone; actual tests await the user.
- Backed up and cleared the requested old app logs/history (33 observations, 5 feedback rows, 104 files). Verified empty activity, no old alerts and unchanged model SHA; normal monitoring resumed. Llama and other model files retained.

## Context phone-test completion - 2026-11-19

- Completed all eight bounded incoming profiles: 104 attempts, 116 associated scored flows, no flags in any profile. These results do not demonstrate real attack sensitivity. Native/original model decisions matched on all 280 recorded vectors.
- Finalizer disabled tracing, stopped the mock listener and verified the background monitor at completion. Later progress check found monitoring paused with a clean session end; recorded this separately without overriding the saved pause. Added final reports and current-state evidence; models and thresholds unchanged.

## 0.11.3-context-rc4 - 2026-11-19

- Installed the user-requested experimental context model on the owned Pixel after unchanged-weight export parity (960 inputs, zero flips), core regressions and native self-checks. Detector: 46,841 parameters, 440,220-byte PTE; original benchmark/source models preserved.
- Added phone-visible full-flow statistics and 2/5/15-minute context, foreground monitoring, user-enabled persistence/recovery, capture retries, typed observations, per-flow socket attribution and automatic local Llama notifications. Preserved 33 existing observations and local Llama/model files; backed up APK/history before each update without clearing app data.
- Tightened Llama prompts and fact checks; removed presentation-only boilerplate while retaining original drafts and truthful fallback. Native Llama/notification check passed with an accepted generated summary. Retained rc1/code30, rc2/code31 and rc3/code32 candidate evidence/APKs.
- Added a bounded mock test app and detached incoming traffic-profile/validation/finalization controllers. Fixed test-process lifecycle by starting the normal app after instrumentation, and fresh-intent/reusable-listener startup. Final screen-off/background and traffic reports are under `validation/reports/tsanet_android`; traffic profiles are not real attack-recall measurements.

## Dataset provenance comparison - 2026-11-18

- Verified pre-handoff AndMal raw counts and original local WSL manifests/splits: 2,126 captures, 827,225 capped packet windows, separate family-holdout and group-random cohorts. Documented differences from CICIDS/PARROT/AAGM/Pixel data and capture versus flow label meanings.
- Added `docs/DATASET_COMPARISON.md` and aggregate provenance. Clarified that the current context model uses CICIDS only and laboratory-wide endpoint histories can exceed a phone's visibility; matching the phone's observable history remains an evaluation requirement. No model/data changes.

## TSANet connection-context experiment - 2026-11-18

- Added a conservative causal history extractor with 78 endpoint statistics across 2/5/15 minutes, training-only unlabeled history bank, interval-safe completion ordering, exact frozen-row alignment and train-only normalization.
- Added matched-capacity context/disabled models (46,841 parameters), 10+5 fixed epochs per arm, durable checkpoint/resume, frozen comparison/export/reporting and hidden local launcher. Original paper files and decision/loss settings remain unchanged.
- Completed all 30 epochs and frozen evaluation. Pruned-30 context accuracy 99.9850%, macro F1 98.6028%, attack recall 99.9491%, benign FPR 0.00558% (38 false positives), versus original 97.3240% / 77.1588% / 95.2472% / 2.16379% (14,744 false positives). Same-capacity disabled control and full classwise results are published.
- Passed six temporal/isolation/model/pruning/resume checks, synthetic automation and independent full-result audit: preserved cohorts/source hashes, all epochs, scaler refit verification, confusion recomputation and 512 additional export decisions per model with zero flips. Added descriptive paired time-block intervals and exact input-ambiguity comparisons. These are one-seed development-benchmark results, not phone generalization; no installation.

## TSANet classwise diagnostic follow-up - 2026-11-18

- Published all-class precision/recall/F1 for all three frozen variants, sample counts and confusion breakdowns in `validation/reports/tsanet_paper/CLASSWISE_ANALYSIS.md`.
- Confirmed input ambiguity by directly comparing all 32 stored float32 values: 207 missed Bot, 872 missed Brute Force and 2,146 missed Port Scan flows in the 30% variant match Benign training inputs. Separated evidence from possible imbalance/context/feature explanations. Models, splits and thresholds were unchanged.

## TSANet paper-based reference implementation - 2026-11-18

- Completed all 20 fixed epochs and frozen evaluation: test accuracy 97.03% baseline, 97.32% pruned 30%, 97.33% pruned 40%, versus paper 97.35% / 98.30%. Published full classwise, binary/FPR, metric-averaging, feature-overlap and export/timing results without test-based tuning.
- The 30% pruned model gives 95.25% attack recall and 2.16379% benign false positives; Bot/Web recall remains weak. All models are reference baselines, not deployed winners. Every epoch remains saved; three TorchScript exports passed 64-input zero-flip checks.

- Reviewed the supplied six-page TSANet Android IDS paper and its architecture/result figures. Recorded paper-specified settings and unreported details; the user chose a 70/30 train/test split and requested a baseline before improvements.
- Implemented a 42,761-parameter CNN/spatial-attention plus LSTM/temporal-attention reconstruction with seven-class output. Added full publisher-flow CSV cleaning, source count verification, stratified saved indices, train-only scaling and feature-overlap reporting.
- Full data: 1,979,480 train / 848,349 test with all seven classes, including 89,618 training DDoS examples. Completed 10 baseline epochs and independent 30%/40% pruning fine-tunes of 5 epochs each, retaining all checkpoints and freezing models before test scoring.
- Passed architecture/CUDA/pruning, synthetic CSV/split/cleaning, train-only normalization, exact resume and TorchScript smoke checks. Added automatic classwise/paper-comparison and novel-feature-subset reports. No phone model or APK was installed; the unknown mobile feature-imputation experiment is not claimed reproduced.

## V6 completion and failed-result audit - 2026-11-18

- Verified all 12 jobs completed 40 epochs and retained 480 epoch checkpoints; frozen evaluation and selected PTE exports passed numerical parity.
- Recorded the preselected cascade's failed detection result (0/2,083 held-out positives) and all-pair diagnostic alternatives. The strongest held-out alternative reaches 95.92% recall with 0.03217% benign flags, but has weak Bot transfer and mostly unknown types; it is not a newly selected or deployable winner.
- Identified missing training-class coverage (zero DDoS, 99 scan, 10 web rows) and absent minimum-recall selection eligibility. Preserved frozen results and started a read-only Friday exclusion audit before any repair/retraining.
- No V6 model was installed. Published aggregate results and clarified incomplete Android runtime/native/ordinary-use validation.

## Cascade V6 implementation and background launch - 2026-11-17

- Implemented a general lightweight binary gate followed by a larger temporal diagnosis model, with benign rejection, supported-category/unknown output, and structured evidence for local Llama.
- Added causal 72-value endpoint context and masked 64x12 recent metadata, directional traffic and TCP outcome features. Broadened raw preprocessing to all CIC weekdays plus weak Android controls, with grouped splits, embargoes and explicit development sources.
- Launched detached extraction followed by 12 full 40-epoch jobs, frozen cascade comparison and research export. Every epoch/best/last checkpoint is retained, without early stopping or automatic installation.
- Passed synthetic train/evaluate/PTE export smoke, exact interrupted/resumed weights, bounded real-source preprocessing, and Android feature parity (1,211 snapshots, zero error) plus RC4 feature regressions. Added/compiled optional Llama facts adapter; new live Android stage gating/ownership/native-generation checks remain pending models.
- Verified the previous weekday alignment audit is complete. Full V6 accuracy results are pending; no production promotion is claimed.

## Model architecture documentation and offline dry run - 2026-11-17

- Documented both RC4 detectors and all eight V5 task/variant configurations from capture and feature construction through normalization, neural layers, fixed thresholds, confirmation, and grouped app observations.
- Added a reproducible in-memory metadata example run through all 24 frozen V5 checkpoints and both RC4 checkpoints. Saved exact tensors, normalization constants, intermediate layer traces, scores, thresholds, hashes, and first-warning/confirmation results.
- Checked the RC4 and two preferred V5 CPU ExecuTorch exports against their checkpoint outputs on the example. These illustrative runs do not measure attack accuracy or change the failed V5 promotion decision. No app version, model weight, threshold, or phone installation changed.

## 0.9.3-mentor-rc4 (versionCode 14) ? 2026-11-14

- Automatic local Llama explanations through a persistent queue; grouped notifications appear before generation completes.
- Seven-day SQLite activity and feedback history with active/dismissed filters, pagination and JSON export. User labels remain unverified and do not trigger retraining.
- Best-effort connected-socket app/UID association and traffic direction, including explicit unknown ownership and incoming receiver caveats.
- Reuse isolated Llama weights for two minutes of idle time, resetting prompt context for each request. Release idle cache after dismissal leaves no pending work.
- Fix stale feedback revisions, worker completion readiness, empty-metadata JSON export and explanation failure/dismissal placeholders. Stabilize pagination order for equal timestamps.
- Add device validation for retention/export, queue recovery, real socket attribution, cold/warm reuse, cancellation and eviction. Runtime fixtures are synthetic and are not detection-accuracy evidence.

Validation outcome and deployment hash: see `validation/reports/mentor_rc4_validation.json` (validated and installed on 2026-11-14).

## 0.9.2-mentor-rc3 (versionCode 13)

- Isolate native Llama inference in the `:llama` process to avoid the observed monitor/runtime contention.
- Preserve measured cold inference and concurrent-capture evidence in `validation/reports/mentor_resource_profile.json`.
- Manual explanation preview; superseded by RC4 automatic flow after validation.

## Research audit - robust v5 deployment evaluation (2026-11-15)

- Completed a post-freeze, classwise and cross-scope audit of all 24 v5 candidates and four baseline operating points. Added per-seed, time-block, protocol/prefix, Android capture/app, uncertainty and phone-recording replay diagnostics.
- No candidate passed the frozen offline deployment gates. The installed RC4 detector and app assets remain unchanged; candidate exports remain research-only.
- Four fresh bounded Pixel scan/retry recordings captured all 52 intended connection attempts. Candidate inference for those recordings was offline replay; the separate temporary APK test is documented below.
- Recorded failure analysis, data limitations, and the next data/label repair priorities in `validation/reports/robust_v5_audit/`.

## Temporary V5 on-device validation (2026-11-15; versionCodes 21 and 22)

- Built trace-enabled, test-only APKs for `shortflow_specialist_s1` and `behavior_general_s2`. Diagnostic mode logs timestamped short-flow warnings and model hashes while suppressing incident history, notifications, and automatic Llama explanations.
- Fixed candidate JSON packaging for Android: UTF-8 without BOM, app-schema tensor names, and the required `absolute_tolerance` self-check value. Preserved superseded APKs and their hashes in `validation/reports/robust_v5_phone/CANDIDATE_BUILD_HISTORY.md`.
- Ran both candidates on the owned Pixel, one at a time. Each received 104 SYN-only attempts to ports absent from the Pixel TCP listen table, at no more than 20 attempts/second. Every attempt was visible in the app's parsed trace; no payload, exploit, malware, external target, or denial-of-service traffic was generated.
- V5 short-flow warnings by profile: 5/8 slow scan, 10/12 moderate scan, 24/24 rapid scan, 3/8 slow retries, 0/12 moderate retries, 0/40 bounded burst. Paired RC4 short-flow control: 0/8, 3/12, 15/24, 0/8, 0/12, 33/40. V5 behavior: 69 positive and 65 confirmed endpoint-second windows during/after probes; RC4 behavior control: 113/110. Both 12-second quiet controls had zero short-flow warnings and zero positive behavior windows; this is not enough to estimate alerts/day.
- Restored RC4 versionCode 14 and verified both model hashes plus normal capture. Candidate offline gates remain failed; no V5 candidate was promoted.
- Summary: `validation/reports/robust_v5_phone/ON_DEVICE_MATRIX.md`; detailed metrics: `on_device_matrix.json`; raw phone traces remain ignored under `validation/private/phone_candidate_matrix_20261115/`.
