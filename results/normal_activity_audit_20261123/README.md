# Saved network-alert audit

Reviewed 23-24 November 2026. Installed app: **Rakshak 0.17.0 / code43**. Network weights, thresholds and alert policy remain unchanged. The Wi-Fi pairing fault was repaired during deployment. The user's accidental WhatsApp **Expected** feedback was corrected to **Not sure**, preserving the original observation and all feedback history.

Evidence: [findings.json](findings.json), [model/regression comparison](comparison.json), [feedback correction](feedback_correction.json). Personal phone snapshots, addresses, SQLite backups and complete model inputs remain under ignored `runs/`.

## The WhatsApp event

| Recorded fact | Value |
|---|---|
| Activity time | 23 November, 20:01:17 IST |
| Socket association | WhatsApp, UID10301; connected-socket snapshot about1.17s old |
| Direction / destination | Outgoing TCP, port443 |
| Observed fragment | Two outgoing packets, no incoming packets or application bytes; zero SYN, one RST, two ACK flags |
| Actual duration | About311 microseconds; the saved display duration rounded this to0.000s |
| Binary detector | Score0.781050, above its frozen0.540833 cutoff |
| Diagnostic model | Highest-scoring class Benign, score0.999994 |
| Resulting alert | Unclassified, because diagnosis does not veto the binary gate |
| Current feedback / ground truth | Not sure / unverified |

The destination is in a block registered to **Meta Platforms Ireland Limited**, checked against the [RIPE registry](https://rdap.db.ripe.net/ip/57.144.253.33). Registration identifies the network owner; it does not establish the purpose or safety of this connection.

This is an ending/reset fragment, not a complete recorded connection: there is no SYN in these two packets. It does not establish that WhatsApp was opened or that a message was sent at the alert time. Background networking or an earlier session ending are possible explanations. The exact trigger, parent connection and application operation cannot be recovered from the stored fragment. Socket ownership is a best-effort association, not proof of intent.

The binary model receives32 flow measurements plus115 connection-history/protocol measurements. App names and UID are added to the alert afterward. The five-minute source history here included58 connections and seven remote ports across observed traffic; it is not a WhatsApp-only history. The measured vector crossed the binary cutoff. The diagnostic model favored Benign, so no specific attack family was established. Llama explains that result; it does not decide whether the connection was malicious. Scores are not calibrated probabilities that an attack happened.

**A benign binary result does not emit a new intrusion alert in the current mode.** Checked583 saved binary-negative native segments:zero alert emissions. The installed native negative-gate test also passes. In the WhatsApp record, `gate_flagged` is true; Benign is the second model's result. This is model disagreement, not a binary-negative alert. [Machine-readable check](negative_gate_check.json). Existing warning updates, foreground monitoring notices and independent SMS/link warnings are separate. The experimental SSH/FTP episode policy was off in these records.

**The Expected selection was withdrawn by the user.** It cannot be used as a verified benign label or credited as a confirmed false positive. At22:44:50 IST the phone feedback was corrected to Not sure, with six feedback records and all27 original observation IDs retained. No training example was created from the withdrawn label.

The app subsequently records a history-clear action at23:52:51 IST. At the final24 November check, its live database contains one newer SMS/link safety record and no feedback rows. The archived27 network records and corrected feedback remain available locally for this audit. The phone's newer history was left intact. See [final state](final_state.json).

## Other recent entries

Ten snapshot activities are from23 November;17 older entries align with the earlier controlled-lab endpoint/time patterns.

| Recent group | Activities | What can be established |
|---|---:|---|
| Work-PC wireless ADB retries | 6, containing7 grouped flags | Endpoints and diagnostic timestamps match our authorized setup attempts. The Pixel rejected the PC certificate. Fresh pairing fixed that operational problem. These are not evidence of a malicious app. |
| Configured DNS server, TCP853 | 1 | Two SYN/reset packets shortly after Wi-Fi reconnection, with no application bytes. The peer is a configured resolver. Consistent with a TLS resolver probe; the precise producer is unverified. The model's Bot label does not prove bot malware. |
| Unidentified LAN peer | 2 | Two short SYN/reset connections. Source identity and intent are unresolved. |
| WhatsApp-associated fragment | 1 | Facts above; current ground truth is unverified. |

No attack or account compromise is confirmed by the WhatsApp record. This is also insufficient evidence to declare all these activities benign. The older laboratory entries must not be counted as ordinary-use false positives.

## Input/runtime check

Replayed all27 saved147-input vectors through the frozen exports. Binary decisions agree with the phone for all27; maximum gate-score difference is `0.000001848`. Maximum diagnostic-score difference is `0.000002577`.

The vectors are being consumed and scored in the expected model format. This replay does **not** independently verify the original packet extraction for the WhatsApp episode: a matching raw PCAP for that event is unavailable. The sub-millisecond display rounding is not the detector's input; its raw flow feature retains the microsecond value. No inference-runtime or input-shape failure was found in these records.

## Testing possible alert fixes

Two fixed candidate filters were evaluated offline. Both apply only to at most two packets ending with RST, with no SYN or application bytes. The narrower variant additionally requires diagnosis to favor Benign at the existing0.8 cutoff. Neither uses app names or endpoint exemptions.

| Legacy test, 1,098,929 rows | TP | FN | FP | TN |
|---|---:|---:|---:|---:|
| Current pipeline | 158,724 | 110 | 965 | 939,130 |
| Hold all such short endings | 122,462 | 36,372 | 953 | 939,142 |
| Also require confident Benign diagnosis | 158,724 | 110 | 964 | 939,131 |

For the legacy comparison, the candidate-eligible subset (81,502 rows) was rescored with hash-verified frozen exports and its changes applied to the existing full-cohort baseline. Other decisions are unchanged by construction. This is not a fresh full-cohort inference pass or a new independent test.

The broad filter suppresses **36,262 positive-labeled segments**:35,504 DoS,742 Brute Force and16 DDoS. It is rejected. These are dataset-label results, not a claim that every individual reset packet constitutes an attack.

The narrower filter removes one legacy false flag without losing a legacy positive. Both candidates leave the saved phone test unchanged (TP62/64, FP10/120) and the304-row protocol development cohort unchanged (TP79/268, FP13/36). They would hold the WhatsApp entry, but it is unverified; suppressing it cannot be counted as a real-phone false-positive improvement. These cohorts have already been examined, and novel reset-only attacks are not independently covered. No new default policy is justified by this audit.

Simply requiring both models to agree is also unsuitable: the earlier [routing study](../dual_model_routing/README.md) reduces protocol detections from79 to10. Raising the binary cutoff alone cannot resolve the ADB cases, some of whose scores saturate at1.0.

## Decision and next repair work

Completed actions: repair wireless pairing, verify deployment/data preservation, correct mistaken feedback, reproduce the saved model decisions, examine ownership/destination context, and test the candidate filters. No blanket app/port exemption, threshold change, retraining or alert suppression was deployed.

The added real-phone training cohort contains848 unique **HTTP lab flows**, repeated eight times in training. It provides no mobile-specific WhatsApp, DNS-validation or wireless-debugging examples. Large legacy datasets do not remove this coverage gap. This is a plausible source of ordinary-phone generalization errors, not proof that this particular WhatsApp event is benign.

A defensible model repair needs independently labeled ordinary-app/background/reconnect sessions and representative attack sessions. Keep uncertain examples out of hard benign labels. Split whole sessions/devices before fitting, keep a fresh evaluation cohort, and select calibration/fusion using validation false-alarm and recall constraints. Recheck each attack class and alerts per benign hour. Do not infer a repair from this single unverified event or tune until an already-opened test set looks good.

At the last recorded post-deployment heartbeat: **186,855 packets,4,098 model checks,zero new network-model flags,zero queue drops and zero late packets over about3.49h**. The foreground monitor is running. This single-device observation has no independent per-flow labels; it does not establish a general false-positive rate, everyday zero warnings or complete attack detection.

## Reproduce

The full comparison requires the original private caches/captures and frozen exports, as in the earlier routing audit. The observations argument accepts a JSON list of saved observation bodies or the app's progress export. The optional correction file maps observation IDs to updated labels, keeping the original snapshot intact. Add `--replay-only` to check saved alerts without evaluating the other cohorts; this still requires the frozen exports.

```powershell
wsl.exe -d Ubuntu --cd <PROJECT_ROOT> --exec <PROJECT_ROOT>/.venvs/edge-export/bin/python validation/audit_normal_activity.py --observations '<private observations JSON>' --feedback-corrections '<private correction JSON>' --private-output runs/normal_activity_audit_20261123 --report results/normal_activity_audit_20261123/comparison.json
```

The mixed dataset cache appends phone rows. Legacy comparisons use its manifest's `old_rows` prefix, with phone rows evaluated separately. This avoids comparing mixed-cohort counts with the legacy baseline. User feedback is reported as feedback, never asserted to be verified traffic ground truth. The script performs no fitting, phone changes or attack traffic.
