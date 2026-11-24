# Code41 authentication episode preview

Built `0.15.0-auth-episodes-preview` (code41). **Device → Network coverage → SSH and FTP episode alerts (experimental)** enables the policy. The switch defaults to off. The installed monitoring app was checked and is still Code40. The Code41 APK is available under `artifacts/releases/nids-0.15.0-auth-episodes-preview.apk`.

The policy counts distinct completed inbound SSH or FTP connections that show a SYN and a protocol cue. It groups by peer, phone address and receiving port. Four distinct observations in 30 seconds produce one alert for that episode. Traffic with a confidently named non-authentication class keeps its original alert. Capture loss clears episode state and reverts to the original policy while coverage is impaired. The factual note describes observed connections and their port, and retains the caveat that the traffic does not establish failed logins.

| Saved cases | Code40 flagged connections | Code41 preview matches | Code41 preview alert events |
|---|---:|---:|---:|
| Normal SSH/FTP | 11/16 | 0/16 | 0 |
| All four normal protocol sessions | 13/36 | 2/36 | 2 |
| FTP guessing | 29/32 | 29/32 | 1 |
| SSH guessing | 32/32 | 29/32 | 1 |
| Restricted Bot emulator | 0/12 | 0/12 | 0 |
| DoS load | 18/96 | 18/96 | 18 |
| DDoS load | 0/96 | 0/96 | 0 |

Both guessing cases were detected at the episode level. FTP first alert was 3.08 s with either policy. SSH first alert moved from 0.41 s to 1.70 s from the first captured attack connection. Matches after the first warning are counted for diagnosis in the replay, while the app emits one event for the authentication episode. Code40 connection flags were already subject to separate notification grouping, so its flag totals do not represent notifications. The two remaining normal flags were HTTP probes. The HTTP episode classifier and pressure specialist remain research because false alarms, delay and multi-client coverage have not passed validation.

The measured comparison replayed nine already examined traces through the same Kotlin policy used in the APK and matched 395 labeled connections to the saved packet and target evidence. It does not establish everyday performance. Both weights in the APK match Code40 byte for byte. The Android and instrumentation builds and the Kotlin policy smoke passed. The independent Android contract APK passed the revised alert wording check on the Pixel. No live attack traffic was generated. [Replay and APK hashes](comparison.json) · [Android note contract](android_note_contract.json)

To repeat the saved-evidence comparison, build `:app:assembleDebug` with Java 21, then run `python validation/compare_applied_auth_policy.py --java java` from the project root. The script writes native replay input under ignored `runs/applied_auth_policy/` and publishes only aggregate results here.
