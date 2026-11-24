# Automatic incoming SMS links - 24 November 2026

Installed Rakshak **0.17.1-auto-links / code44** on the Pixel 6a with an upgrade preserving app data. APK: `artifacts/releases/rakshak-0.17.1.apk`. Model weights and cutoffs unchanged; previous code43 APK retained.

New carrier SMS already enters the protected SMS receiver when incoming checks/permission are enabled. This update checks extracted links first and can warn before MobileBERT, preserving the link verdict in every subsequent preliminary/final update. The phishing detector works when the SMS classifier is disabled. Without links it performs no URL inference. Existing ten-distinct-link limit and unchecked statuses remain explicit. Automatic checks use Android SMS delivery events and do not require permanent polling. Other messaging apps require sharing/pasting their messages.

A warning says the link was flagged as possibly leading to a fake website and advises using the official app or known address instead of opening it. Llama may rephrase approved advice after the initial warning; it does not clear the finding. Manual URL checks remain available.

Validation: Android app/test builds passed. Pixel passed ten combination cases, eleven link-tidying cases and integration contracts; four Tier-1 fixture sets of 34 rows; 14/14 neural token/class matches; 230 authored SMS scenarios with no neural failures. Known maximum neural logit drift 0.449647 still fails strict 0.05 numerical parity; unchanged from code43. Service assertions additionally verify URL-only message warnings, no-link handling, and three actual notification/Llama events (SMS request, standalone URL, embedded URL). Settings and network-monitor state restored; test rows removed without clearing user history. SMS/link/incoming switches and permissions enabled on final inspection.

These are local authored fixtures, not a new carrier-delivered SMS or independent accuracy study. A real incoming carrier SMS is the remaining delivery-level check. No attack traffic or website visits were generated.

Results: [validation.json](validation.json). Reproduce using `python validation/validate_rakshak.py --serial <serial> --install --modes rakshak_contract rakshak_sms --include-service`. The service test temporarily pauses and restores capture and creates/removes marked test observations.
