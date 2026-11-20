# V2 controlled phone results — 20 November 2026

**Conclusion: scan detection and notifications work, but v2 is not ready as a general intrusion detector.** Confirmed HTTP login guessing, SQL injection and XSS examples were missed. Bounded HTTP load was flagged with weak type identification. Beacon could not be evaluated because its connections to the PC timed out.

## Fixed pipeline and procedure

- Pixel 6a; NIDS 0.12.2-aligned-v2-test / code36. Preserved v2 gate_s0 → diagnosis64_s1 → local explanation/notification.
- 147 numeric inputs: 32 flow plus 115 connection-history/protocol inputs. History windows: 5/30/300 seconds. Gate cutoff: 0.7858333333333334; diagnosis cutoff: 0.6. Positive gates with uncertain/Benign diagnosis remain Unclassified alerts.
- Six verified user-run cases retained. User then authorized automatic remaining tests: HTTPFlood → SlowScan → Beacon → Benign. Detached run: 20:11:50–20:37:20 IST, including fresh history warm-up, 130-second observation per case and 305-second isolation after the last test decision/traffic.
- No synthetic alert injection, retraining, threshold tuning or model replacement. Existing activity history/Llama files retained. The prior diagnostic trace was backed up before resetting that bounded diagnostic file and restarting the monitor.

## Combined results

Flag counts below are native flow segments, **not independent attacks or accuracy/recall percentages**. Notification counts are visible related activity notifications at each saved check.

| Profile | Delivered/verified behavior | Matched model flags | Types among flagged segments | Related notifications | Assessment |
|---|---|---:|---|---:|---|
| Normal HTTP, before/after | 8 + 8 normal HTTP200 requests | 0 | — | 0 | Both small controls quiet |
| PortScan, earlier verified | 129 ports; 128 closed | 500 | 476 Port Scan; 24 Unclassified | 4 | Detected; all 128 closed-port connections flagged at least once; 126 correctly typed at least once |
| HTTP PasswordGuessing | 31 failed dummy logins + 1 valid login | 0 | All 32 segments Benign | 0 | Confirmed guessing episode missed |
| SQLInjection | 2 confirmed dummy SQL injections + 1 normal query | 0 | All 3 segments Benign | 0 for SQL traffic | Both injections missed; 2 concurrent localhost flags belong to other traffic |
| XSS | 1 confirmed isolated script execution | 0 | Benign | 0 | Confirmed example missed |
| ConnectionExhaustion | 2 held dummy slots; 14 verified resource denials | 0 | All 16 segments Benign | 0 | Bounded app-resource case missed; not a whole-phone DoS experiment |
| HTTPFlood, automated | 128 requests; all HTTP200 | 71 | 1 DoS; 70 Unclassified | 3 | Load pattern flagged; actual denial of service was not established |
| SlowScan, automated | 32 ports; 31 closed | 110 | 105 Port Scan; 5 Unclassified | 3 | Detected; 29/31 closed-port connections flagged, 28/31 correctly typed; open connection unflagged |
| Beacon, automated + permitted retry | Trigger accepted in both runs; each run's 12 outbound attempts timed out; 0 PING/PONG exchanges | 0 | Attempted connections Benign | 0 | **Inconclusive: connectivity failure. Excluded from detection scoring.** |

The automatic cases produced 128/124/13/8 native segments respectively. Those counts include retransmission-related scan segments and, for Beacon, the trigger connection plus 12 failed outbound connections. Ten visible notifications across the two scan cases and HTTP load are grouped activity cards, not ten independent attacks.

## Evidence quality and explanation behavior

- All four new cases passed independent saved-artifact checks: exact per-connection packet counts, segment starts matching packet timestamps, finite 32+115 input arrays and consistency with the frozen gate threshold. Captured packet counts were 1,279 / 252 / 34 / 84.
- Monitor stayed running with zero late/drop/eviction/reorder/invalid-rate counters at case checks. Installed gate and diagnosis hashes were verified before and after automation. Models stayed unchanged.
- All six new HTTP-load/SlowScan activity explanations completed, using **evidence-based fallback**. Llama drafts were not accepted; these are not claimed as accepted Llama-generated summaries. Earlier PortScan's four summaries used the same fallback path.
- Earlier missed web cases had their relevant auth-failure, SQL-like or script-like input indicators present. Frozen standalone diagnosis also predicted Benign in those earlier replays. This is broader than a missing notification or input-shape problem.
- Earlier full training-view audit found auth-failure inputs present in 394 Benign views and zero attack-class views. This establishes a positive-supervision gap, not the sole explanation of every miss.

## Beacon blocker and retry

Each attempt emitted24SYNpackets across12phone connections toPC TCP43990; noPCreplies orPING/PONGevents were recorded. The receiver was bound to the expected address. The user enabled the prepared Administrator-only rule at21:30; its exact phone/PC/program/port scope and presence in ActiveStore were verified before the retry. The retry ran21:32:29–21:35:31IST and still timed out12/12.

Read-only ActiveStore inspection then identified an **Enforced Public-profile TCP Block rule for the exact Python313 executable**, all local ports/addresses, all remote addresses and all users. This matches the receiver and takes precedence over the newAllowrule. A separate managed `codex_sandbox_offline_block_inbound` rule exists with a specific local-user filter; its applicability to this process was not established, and it was not modified. No packet-level WFP drop log was collected, so the observation does not identify an individual drop event.

The retry's13native segments account for all34captured packets exactly, with matching start timestamps, finite147inputs and frozen threshold checks. All13wereBenign;0notifications. This remains an inconclusive connectivity case, not a real Bot detection result. Models stayed unchanged and monitoring remained healthy/running.

The user's elevated watchdog removed the temporary allow rule at21:35:33IST; absence was verified. Existing block rules were preserved. `Allow-ControlledBeacon.ps1` now fails early when this matching PythonTCPblock is present, avoiding another ineffective exception. A valid Beacon evaluation requires an administrator-approved receiver policy; no further attempts or changes to the existing blocks were made.

## Limits and next decision

These are a small diagnostic campaign with correlated requests/retries, not independent samples of all attack classes. Sixteen quiet normal HTTP requests do not establish a low real-world false-positive rate. Bounded load and dummy-resource denial do not establish full DoS/DDoS recall; fixed PING/PONG would not establish real Bot detection. HTTP guessing belongs to the original Web Attack family, not its FTP/SSH Brute Force family. Those original protocol attacks and full distributed attacks remain untested here.

Keep v2 as an experimental checkpoint. Future improvement needs verified positive web/authentication sessions and realistic failed-login/normal-burst controls under the same phone extractor, then independent host/session/campaign evaluation. Lowering cutoffs to force these examples to alert would not resolve diagnosis errors or demonstrate low false positives.

## Source and evidence boundaries

The [test guide](../docs/PHONE_TESTING.md) maps each profile to its bounded behavior.
The [runner](../validation/controlled_phone_test.py) and [correlation code](../validation/manual_test_correlation.py) are included.
Original raw packets, socket/target events, per-flow native traces and device histories remain private and are not published.
These aggregate counts cannot replace an independent re-audit of those recordings.
Model hashes and policy are recorded in the [model card](../models/current/MODEL_CARD.md) and shipped manifests.
