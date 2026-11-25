# Expected network feedback, 25 November 2026

Code50 (0.17.7) adds an opt-in, local alert rule. Marking an eligible network activity Expected mutes the same peer address and local address/port for the remainder of that activity's seven-day history. The peer's ephemeral port may change. The rule requires a positive Bot or Unclassified model result on an incoming payload-free two-packet TCP reset, healthy capture, quiet context, and at most one distinct local port in the five-minute context. A different peer or service, a completed connection, a Port Scan diagnosis, higher port diversity, or unhealthy capture bypasses the rule. Prior dismissals do not activate the rule. Undoing the dismissal or clearing history removes it. The original activity and feedback stay local. Muted repeats are scored but are skipped before writing an activity or posting a warning.

Code51 (0.17.8) renders the dismissed activity with a compact confirmation and one Undo action. The note field and the three feedback buttons collapse as soon as feedback is saved.

## Verification

The isolated Pixel Android contract passed offline fixtures for an exact repeat, a changed ephemeral source port, different peer/service, changed connection outcome, capture degradation, Port Scan diagnosis, increased port diversity and undo. The contract also checks that a changed event sharing the original grouping key is recorded as a fresh active activity. All 38 bundled assets matched code49 byte for byte in the code50 APK.

## Saved labelled regression

No mute is active before explicit feedback, so model scores and output decisions retain the baseline. The table compares baseline output to a stress case that withholds every structurally eligible flag, regardless of peer, direction or whether any user marked it expected. The legacy cache lacks the metadata to measure true personalized alert recall. Metrics count emitted alerts in the stress case.

| Cohort | Baseline TP / FN / FP / TN | Stress case TP / FN / FP / TN |
| --- | --- | --- |
| Phone validation | 64 / 0 / 11 / 109 | 64 / 0 / 11 / 109 |
| Phone test | 62 / 2 / 10 / 110 | 62 / 2 / 10 / 110 |
| Legacy test | 158,724 / 110 / 965 / 939,130 | 158,513 / 321 / 625 / 939,470 |

The stress case hides 340 false alerts and 211 labelled detections. Legacy alert recall goes from 99.93% to 99.80%. This is a conservative test of blanket eligibility, not a forecast for a user-selected rule. A malicious connection that looks identical to a muted repeat can also be hidden. No real network fixture was marked Expected during deployment.

Code51 was installed in place on the verified Pixel. The monitor preferences and history database hashes matched across the upgrade. The foreground monitor resumed. Code51 APK SHA-256 is ED59293E149EEAE609D351EF8F9ECB0EBDA18A181C3D33EB7A423E64B79ECCC6. Rollback APKs for codes49 and50 remain local. The compact feedback view was built and deployed without marking any genuine history entry Expected for a visual test.
