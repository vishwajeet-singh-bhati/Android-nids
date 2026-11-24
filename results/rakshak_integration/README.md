# Rakshak integration validation - 23 November 2026

Source/build: **0.17.0-rakshak / code43**, package `nids.app`. [App/setup guide](../../docs/rakshak/README.md). Supplied SMS/link models are integrated with the existing network pipeline. No detector was retrained; network weights and thresholds are unchanged.

**Pixel deployment completed over Wi-Fi.** Fresh pairing repaired the certificate rejection. Code43 installed with matching APK hash; all27 prior activities/five feedback records and existing Llama retained. The actual ARM suite and two local Llama notifications complete. Strict SMS logit tolerance fails (0.449647 versus0.05), with14/14 class matches and the same230 scenario decisions as emulator. Network/SMS/link switches, incoming SMS and notification permission are enabled. See [Pixel validation](pixel_validation.json) and [deployment preservation/health](pixel_deployment.json). Real carrier SMS delivery and a fresh live attack campaign have not been run.

## Results

Environment: work-PC Android emulator, **API37, x86_64**, production Kotlin/ExecuTorch code and separately copied checksum-verified local Llama. These results do not establish Pixel ARM64 timing or carrier-delivery reliability.

| Check | Result | Interpretation |
|---|---|---|
| Handoff integrity | 192/192 file SHA256 and byte counts match | Supplied files intact |
| URL port | 2,077/2,077 decision/source matches; 2,066 scored cases | Agreement with supplied reference at its frozen time |
| URL numerical parity | Max probability error `3.027e-7`, CNN logit `5.722e-6`, n-gram `2.766e-7`, scaled features zero | Within declared tolerances |
| SMS Tier1 | Four files, 34 normalization/evidence/linear-model/policy checks each, all pass | Supplied Kotlin behavior preserved |
| SMS neural | 14/14 normalization, token and class matches; max logit difference zero here | Export works on this runtime |
| SMS scenarios | 230 processed, 180 routed to MobileBERT, zero runtime failures | Functional regression; weaknesses below |
| Fusion/tidying | 10 exact combination and 11 link-tidying cases pass | URL warnings never erase SMS evidence |
| Actual service and Llama | High-risk SMS and URL fixtures each notify, complete explanations and accept checked Llama advice with capture paused | New alert types use the shared production path |
| Missing Llama | Same two fixtures notify with factual/default advice | Warning remains available without generation |
| Incoming SMS | Ordinary OTP: ham/low, deeper check unnecessary. OTP-disclosure request: smishing/high, deeper check completed. Disabled delivery: ignored | Actual emulator SMS receiver/permission/routing path |
| Existing network | 21 native self-checks, zero decision changes; 14 note/store fixtures pass | Frozen network behavior retained |
| Controls/UI/history | Switches persist; all-disabled check explicit; share requires review; notification re-entry opens detail; confirmed clear leaves zero activities | Interface/lifecycle checks |
| Privacy/recovery | Raw OTP absent from saved evidence/results; stale callbacks rejected; interrupted preliminary warning recovered as partial | No completion/safety claim for lost work |

Machine-readable records: [Android checks](android_validation.json), [fallback](fallback_service.json), [SMS/UI](ui_sms.json), [history/UI](ui_history.json), [release and asset hashes](release.json). Instrumentation wall times are not phone inference benchmarks. Earlier code42 Pixel Llama timings remain historical.

The handoff records ARM/Python MobileBERT logit drift of about 0.45, exceeding a strict 0.05 numerical tolerance despite matching its 14 argmax classes. This integration does not claim that drift repaired. The suite records strict numerical tolerance separately from class agreement; rerun on Pixel before claiming ARM parity.

## Remaining SMS weaknesses

Final risk on the handoff's **synthetic** scenarios; a warning means suspicious or high. This is not an independent everyday-message test set.

| Supplied label | Inputs | High | Suspicious | Low |
|---|---:|---:|---:|---:|
| Ham | 90 | 0 | 10 | 80 |
| Spam | 40 | 4 | 4 | 32 |
| Smishing | 84 | 38 | 28 | 18 |
| Uncertain | 16 | 4 | 8 | 4 |

Here 66/84 smishing inputs warn, 18 remain low, and 10/90 ham inputs warn. Spam is not automatically treated as fraud; uncertain labels have no single binary target. Reference parity and the few delivery/Llama fixtures cannot establish general precision/recall, everyday zero false positives or production readiness.

## Decisions and corrections

- Reuse frozen SMS models/Kotlin policy. Port URL normalization, IDNA/public suffix handling, encoding/features, n-gram scoring, calibration and list/rule decisions into the same APK.
- Hash-check runtime assets; expire saved list entries and mark lists stale after 48 hours. Strong list hits/shorteners do not require neural loading. Model errors stay visibly unverified. No URL fetching or redirect following.
- Check enabled links even after a routine-SMS fast path; cap inputs, distinct links and the service queue. Keep raw bodies/senders/OTPs and URL paths/queries out of history and prompts.
- Show deterministic facts/advice immediately. Llama only rephrases approved short guidance. Reject unsafe actions, invented names/numbers and loss of the OTP privacy instruction. Default advice remains on rejection/failure.
- Preserve one preliminary/final event, settings-change cancellation and clear-history cutoff. Recover interrupted work as partial after reopening. Preserve shared drafts through initial UI redraw and fix notification tab selection after adding Check.
- Reference token arrays omit zero padding. Tests compare their prefix plus the required zero tail of the Android tensor. Early test-harness assertions were corrected without modifying the URL model to fit them. UI automation waits for launch and decodes UTF-8 explicitly.

## Reproduce / finish on Pixel

Build app and test APK using the [guide](../../docs/rakshak/README.md), then use an explicitly selected device:

```powershell
python .\validation\validate_rakshak.py --serial '<adb-serial>' --install
python .\validation\validate_rakshak.py --serial '<adb-serial>' --modes rakshak_service
```

The service fixture test pauses/restores capture, creates marked TEST notifications and deletes only its fixture rows. No attacks or carrier SMS are sent. Emulator delivery can be reproduced after enabling incoming SMS with `adb -s <emulator-serial> emu sms send 5551234567 "<test message>"`. On a real phone use consented SMS from another phone or paste/share.

Completed on Pixel: upgrade/hash verification, ARM suite, SMS permission, network foreground monitoring, both real Llama fixture notifications and data preservation. Remaining: real carrier SMS delivery and a controlled live network regression. Fresh independent SMS/URL holdouts, everyday false-alarm assessment and threat-list refresh are separate evaluation work. Existing network false positives and missed classes remain unresolved by this integration.
