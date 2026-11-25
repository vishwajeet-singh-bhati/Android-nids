# Rakshak current app guide

Current source: **0.18.0-passive-notices / code53**. This public checkout is a reproducible development snapshot; [submission gates](../../SUBMISSION_CHECKPOINTS.md) remain separate.

## Use the app

Home controls network monitoring. Check accepts pasted/shared text. Activity shows seven-day warnings and confirmed clearing. Settings independently controls network, SMS, URL and automatic incoming SMS.

For new carrier SMS, enable **Automatically check incoming SMS and links**, grant RECEIVE_SMS and notification permissions, and keep the URL detector enabled. Extracted links are checked automatically before optional deeper SMS analysis. Messages without links do no URL inference. The SMS classifier may be disabled while URL checking remains active. RCS/WhatsApp/inbox/browser-wide interception is not implemented; paste/share supports other text.

An immediate What happened / What you can do note precedes optional local Llama guidance. Raw SMS bodies, senders, OTPs and full URLs are excluded from history/prompts. Low-risk results stay quiet. UNCERTAIN inside an otherwise low-risk message does not itself raise an alert; standalone URL uncertainty requests review. Llama does not decide risk or invent a causal app.

## Build, install and verify

Use Java21, Android SDK34 and platform-tools on PATH. Set ANDROID_HOME/JAVA_HOME for your machine.

    ./android/gradlew -p android :app:assembleDebug :app:assembleDebugAndroidTest
    adb devices -l
    python validation/validate_rakshak.py --serial YOUR_SERIAL --install

Use gradlew.bat on Windows. Root/tcpdump is needed for the network branch, as described in [Android setup](../ANDROID_SETUP.md); SMS/URL checks work without root. Build/signing hashes differ by environment.

The public database starts **empty and stale** to avoid redistributing feed content. Learned URL inference is present. [Local feed preparation](../../components/phishing_url/README.md) can populate it before a local build. This differs from the dated populated snapshot used in historical Pixel list-assisted measurements. The app does not refresh it automatically.

The public URL smoke fixture has27 authored cases; the private2,048-URL benchmark and two real feed examples are excluded. Historical2,077-case parity and current benchmark results retain their original scope. [Architecture](architecture/README.md) gives exact layers, inputs and policies.

## Llama and service checks

The optional1.06GiB Llama weights are separately installed using the licensed model manifest and [setup guide](../ANDROID_SETUP.md). They are not in the APK/repository. Immediate facts/default advice work without them.

    python validation/validate_rakshak.py --serial YOUR_SERIAL --modes rakshak_service

The service check creates/removes three marked test events, verifies notifications/history privacy, temporarily pauses/restores capture and uses real Llama if installed or verifies fallback otherwise. It sends no SMS or website requests and does not clear existing user history.

## Read the evidence

- [SMS component and full source](../../components/sms/README.md)
- [URL component](../../components/phishing_url/README.md)
- [Integration](../../components/integration/README.md)
- [Pixel integration history](../../results/rakshak_integration/README.md)
- [SMS routing correction](../../results/sms_alert_review_20261124/README.md)
- [URL/email correction and old-history distinction](../../results/sms_followup_20261124/README.md)
- [2,048-URL benchmark and unknown labels](../../results/url_benchmark_20261124/README.md)
- [Complete report](../project_report/README.md)

Native/reference/synthetic checks do not establish universal scam coverage or production readiness. The report distinguishes archived classifier results, reused benchmarks, actual carrier observations and remaining false positives/misses.

Code47 adds the original [logo](../branding/README.md); measured model results retain their original code46 identities. Pixel code47 installed and home/logo visually checked24 November; history and controls preserved.

Code49 corrects rejected-handshake descriptions/grouping and stale notification titles. Detector weights and binary decisions are unchanged; SMS improvements are on hold. See the [network comparison](../../results/idle_network_repair_20261124/README.md).


Code51 adds compact, reversible Expected feedback; model scores are unchanged. Use the [A-to-Z guide](../../REPRODUCE.md) for the complete current setup and measured limitations.
