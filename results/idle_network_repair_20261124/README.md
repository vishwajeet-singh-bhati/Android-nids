# Idle-phone network alert review —24 November2026

SMS improvement was explicitly put on hold by the user. This change concerns network explanations and grouping; no learned model or binary threshold was changed.

## What happened

The user reported alerts while the Pixel was idle after its factory reset. Four saved activity groups represented five model flags. They were incoming TCP attempts from two LAN peers to phone port7680. Each saved representative flow had one packet in each direction, one SYN, one RST, one ACK, no FIN and zero application bytes. The binary gate was positive; diagnosis chose Bot for three groups and Unclassified for one. No receiving app owner was established.

This is evidence of rejected incoming attempts, not established bot activity on the phone. Port7680 is used by [Windows Delivery Optimization](https://learn.microsoft.com/en-us/windows/deployment/do/delivery-optimization-workflow), but a port number does not identify software or prove safety. The original packets were not archived; a subsequent150-second passive capture saw no matching packets. The peer identities, raw vectors and private snapshots remain under ignored `runs/`.

## Suppression candidates: tested and rejected

Fixed candidates were evaluated on2,288,325 saved regression rows:1,188,724 legacy validation;1,098,929 legacy test;184 phone validation;184 phone test;304 protocol development. These are previously inspected data, not a new holdout. The legacy cache lacks endpoint-role metadata, so treating eligible flows in all directions as incoming gives a conservative upper bound on suppression loss.

The broad candidate withheld any two-packet, payload-free SYN/RST/ACK handshake. The narrower candidates required quiet peer context (no sweep over three prior target ports; fewer than15 prior peer flows in5s; fewer than31 in30s; fewer than seven recent peers) and, optionally, a Bot/Unclassified diagnosis. No IP, app or port was exempted.

| Legacy test result | Baseline | Narrow suppression candidate | Released code49 |
|---|---:|---:|---:|
| TP |158,724|158,512|158,724|
| FN |110|322|110|
| FP |965|625|965|
| TN |939,130|939,470|939,130|

The narrow candidate removed340 false positives but also210 Bot-labelled and two Port-Scan-labelled detections. Bot typed recall fell from86.09% to53.28%; its binary-detected count fell from630/640 to420/640. It was rejected. The broad candidate lost47,798 positive-labelled detections. Both phone cohorts and the saved protocol cohort had unchanged counts under these candidates, which was insufficient to justify promotion.

## Released: measured facts and grouping, no suppression

- Code49 /0.17.6-connection-notes describes a qualifying record as **Incoming connection was rejected**. The plain note says no completed connection or message content was seen; it does not identify an app as responsible or certify the peer as safe.
- Original binary result, diagnostic class, scores and vector remain intact. The original model hypothesis remains in technical details. No positive binary decision is hidden.
- Repeat qualifying probes from the same peer to the same phone service group across up to five minutes between updates, instead of splitting by model subtype/minute. Different peers and phone services retain different keys. Sweeps/concentrated volume retain the ordinary presentation path. This is duplicate grouping, not a claimed reduction in classifier false-positive rate.
- Old stored Llama text is rejected when its presentation version is stale. Deterministic facts lead the note; Llama remains restricted to checked guidance. Existing history and detector controls are preserved.
- All38 bundled assets are byte-identical to code47, including network/SMS/URL weights and thresholds. Released classifier metrics above are unchanged by construction, supported by unchanged assets/scorer and native self-checks; they are not a new trained result.

The core boundary checks, isolated Android presentation/storage contract, installed native network check, installed hybrid contract and safety contract passed. Four original activity rows were preserved byte-for-byte before relaunch. Cross-minute same-peer grouping and stale-explanation rejection are exercised in a sandbox. Live history review and deployment details are recorded alongside this file.

## Reproduce

The full private datasets are not bundled. With the existing local cache and saved observation list:

```powershell
wsl.exe -d Ubuntu -- /mnt/d/NIDS-development/.venvs/edge-export/bin/python /mnt/d/NIDS-development/validation/audit_closed_connection_policy.py --observations /path/to/private_observations.json --output /path/to/candidate_audit.json
```

For source-only checks, use JDK21 and the documented Android SDK, then from `android` run:

```powershell
.\gradlew.bat :core:rejectedHandshakeEvidenceCheck :core:alignedV2PolicyCheck :core:alignedCheck :contractcheck:assembleDebug :app:assembleDebug :app:assembleDebugAndroidTest
```

On an explicitly selected owned test device, the installed test APK supports `-e mode network_history_review -e refresh_explanations true`. This revisits existing records using current facts/guidance; it does not send traffic or create attack labels.

## Remaining limitation

The learned detector still has false positives and missed protocol cases. This release fixes an unsupported Bot description and duplicate grouping; it does not establish that all idle traffic is benign, solve the classifier's false-positive rate or improve attack recall. Better model decisions require separately labelled normal/device and attack cohorts with an agreed validation protocol. No new training or live attack campaign was run here.

An intermediate code48 build corrected note bodies but a live notification dump revealed cached old titles. Final code49 derives notification and screen titles from the same current facts; legacy stored titles cannot override them. The expanded regression contract protects this case. Existing four activities were retained.
