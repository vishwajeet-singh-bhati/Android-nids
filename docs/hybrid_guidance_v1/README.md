# Hybrid explanations — app 0.14.0/code38

Current follow-up release: **0.14.1-bounded-guidance/code39**. It retains this pipeline and adds a validated callback stop guard because the installed Android1.5.1 config overload omits`maxNewTokens`. Detailed PR review, native upper-bound checks and current installed timings: [ForgeSight review](../../results/forgesight_pr_review/README.md). Automatic boot prewarm was tested and left disabled; runtime reuse remains enabled. Code38 remains a rollback point.

This release implements the user's requested deployment of immediate factual notes followed by short local Llama guidance. The explicit deployment request supersedes the earlier instruction to preserve the installed code37 app. The trained detector, normalization, gate/type cutoffs and installed 1B Llama weights remain unchanged. No new attack test or training campaign starts automatically.

## What the user sees

1. As soon as an activity is recorded, the notification and activity page show the suspected pattern, verified app association/role when available, other endpoint/phone port, measured packets/duration, recent connection context, coverage warnings and a manual check.
2. The existing isolated ExecuTorch Llama worker rephrases only the short check. The factual sentences and warning stay outside its prompt. The combined note has more detail than the generated sentence alone.
3. A checked guidance sentence replaces the default guidance. Unsupported names, numbers, causes, refusals, instructions or unsafe password advice are rejected; the useful default note stays visible on rejection, cancellation or runtime failure.
4. New evidence immediately replaces the factual note. A response for an older revision is rejected and the latest evidence is queued. Dismissal prevents an in-flight response from restoring an alert. Seven-day history and user feedback are retained.

App names come from Android socket UID/package/display-label evidence, never Llama guesses. Connected-socket matches take priority over weaker receiving-port matches. Fresh, unambiguous TCP listeners/UDP bound sockets can identify an associated receiving port, explicitly without claiming that the particular connection reached the app. Conflicting ownership stays unresolved. A receiving app is not blamed as the originator.

If no app can be linked, the note explains why and shows the known activity/endpoints. Probes to closed ports may have no receiving app. A process, Android Service component or remote attacking program is not identified by this release. Naming those without evidence would be misleading. App attribution is best-effort, not a guarantee that every connection is mapped correctly.

## Model and performance scope

- Gate: same 82,820-byte PTE, SHA256 `733187848e41b5d28c58af4df0a779646c9388d8c010d0e217d9fd9ad47a2b2e`.
- Diagnosis: same 949,788-byte PTE, SHA256 `e91e6fe319f459b54c657ac1964c66f2c848bbd2e0b202f07aef03377bce752e`.
- Llama3.2-1B SpinQuant INT4 EO8: same1,135,951,488-byte model and tokenizer. Fresh context per activity,512-token sequence budget,48 requested new tokens, temperature0; existing120-second idle warm cache and process isolation retained.
- The independently benchmarked hoisted detector and E8/smaller-model experiments are not included. Detection successes, misses and false positives are not repaired by this explanation release.

Live-worker timing, notification checks, ownership checks and installed identities are recorded in [the deployment report](../../results/hybrid_guidance_v1/README.md). Previous component measurements are historical and are not substituted for this release's production-worker results.

## Validation and reproduction

The separate `nids.contractcheck` helper compiles exact copies of the production renderer/fact/store/ownership sources, with recorded source hashes. It exercises14 category/app notes, ambiguity/receiving-port handling, missing evidence, strict guidance rejection, immediate notes, stale revisions and dismissal in its own store. Run it before replacing the monitoring app:

```powershell
cd <PROJECT_ROOT>\android
$env:JAVA_HOME='<USER_HOME>\.jdks\openjdk-21.0.2'
$env:GRADLE_USER_HOME='<USER_HOME>\.gradle'
.\gradlew.bat --offline --no-daemon :contractcheck:assembleDebug
$hybridAdb='D:\AndroidStudioData\platform-tools\adb.exe'
& $hybridAdb install -r .\contractcheck\build\outputs\apk\debug\contractcheck-debug.apk
& $hybridAdb shell am instrument -w -e mode hybrid_contract nids.contractcheck/.ContractInstrumentation

# After the isolated checks pass:
.\gradlew.bat --offline --no-daemon :app:assembleDebug :app:assembleDebugAndroidTest
& $hybridAdb install -r .\app\build\outputs\apk\debug\app-debug.apk
& $hybridAdb install -r .\app\build\outputs\apk\androidTest\debug\app-debug-androidTest.apk
& $hybridAdb shell am instrument -w -e mode hybrid_contract nids.app.test/nids.app.ValidationInstrumentation
& $hybridAdb shell am instrument -w -e mode aligned_v2_native nids.app.test/nids.app.ValidationInstrumentation
& $hybridAdb shell am instrument -w -e mode hybrid_runtime nids.app.test/nids.app.ValidationInstrumentation
& $hybridAdb shell am start -n nids.app/.LearnedNetworkActivity --ez start_monitor true
```

Use one connected owned Pixel or add `-s <device>` to ADB commands. Adjust SDK/JDK paths on another PC. Offline Gradle assumes the dependencies are cached; otherwise omit `--offline`. A fresh phone still needs the documented root/capture setup and Llama files; an APK update retains them. Never clear app data to update this release.

The runtime check uses declared evidence fixtures and the real Llama IPC worker while monitoring runs. One transient notification is labelled `TEST: explanation preview, no real incident`, checked before Llama begins and then removed. No synthetic activity is added to the user's history, and no attack is generated. Socket attribution validation uses a separate owned lab app and a benign connection/listener; that does not estimate attack-detection accuracy.

Instrumentation/app replacement can restart monitoring. Leave it enabled until its300-second history is ready before manually running controlled attack tests. Existing manual test/spacing rules remain in force. No automatic next profile is scheduled.

The original code37 APK, preferences and private history snapshots are retained under ignored `runs/hybrid_guidance_v1_deploy/rollback`. For rollback on this work PC, stop monitoring, use `adb install -r -d` with `nids-code37-original.apk`, then start monitoring. The history schema is unchanged; restoring history files is not required for a normal rollback and must never overwrite newer user feedback casually.

No GitHub push or ZIP is part of this deployment. Source changes, validation aggregates, release identity and changelog are maintained locally.
