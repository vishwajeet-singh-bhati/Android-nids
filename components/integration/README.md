# SMS, URL and network integration

The three detectors have independent switches. Network capture uses its existing147-input binary-gate/diagnosis pipeline. Incoming carrier SMS requires user consent and RECEIVE_SMS; no inbox/RCS/WhatsApp reader is present. Paste/share remains available for other text.

New SMS -> extract links -> URL checks first -> immediate phishing warning if needed -> optional SMS cascade -> combine evidence -> shared history/notification -> local Llama guidance. No URL means no URL inference. SMS classification can be disabled while URL checks remain enabled. Bare links skip semantic classification of `url_present` and retain the independent URL verdict. Link verdicts can raise SMS risk but never erase its findings.

The combination is deterministic policy, not a third trained neural model. UNCERTAIN inside a low-risk SMS records uncertainty without raising risk; a standalone uncertain URL check requests review. Explicitly report this distinction when measuring notifications.

The initial **What happened / What you can do** note is factual and available before Llama. The shared Llama3.2-1B SpinQuant INT4 model, loaded through ExecuTorch in a separate process, rephrases approved advice with an8-20-word target and48-token cap. Checked default advice is kept on failure or unsupported wording. It cannot change detector risk or invent a causal app. Its large weights are downloaded separately using the existing model manifest.

Seven-day history and confirmed clearing apply to all warning types. Raw bodies, senders, OTPs and full private URLs are excluded from history and Llama prompts. The APK has no INTERNET permission. New carrier SMS is event-driven; no permanent polling is required. Notification appearance also depends on Android permissions/channel settings.

## Source map

- `android/app/src/main/kotlin/nids/app/RakshakSmsReceiver.kt`: new SMS delivery.
- `SafetyPipeline.kt`, `MessageLinkPolicy.kt`: extraction, routing and combination.
- `SafetyAnalysisService.kt`: serialized local work and preliminary/final warning updates.
- `SafetyNote.kt`, `LocalExplainer.kt`: plain facts, checked guidance and local model calls.
- `LearnedNetworkActivity.kt`: interface and independent controls.
- `android/app/src/androidTest/kotlin/nids/app/`: native contracts, service fixtures and sequential URL benchmark.
- `validation/validate_rakshak.py`: current native checks. `benchmark_phone_urls.py` and `label_url_benchmark.py`: URL scoring and evidence labeling.

Use the [app guide](../../docs/rakshak/README.md), [component index](../README.md) and [full report](../../docs/project_report/README.md). Synthetic fixtures, actual SMS delivery, real website validity and general attack detection are separate claims.
