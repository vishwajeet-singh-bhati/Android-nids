> Current source is Rakshak code53. Start with the [A-to-Z reproduction guide](../REPRODUCE.md). This page retains the stage-specific network methodology; historical measurements retain their original build identities.

# Android build and phone setup

## Requirements

- Android 8 / API 26 or newer; tested device was an ARM64 Pixel 6a. Live traffic capture requires an already-rooted owned test phone. This guide does not unlock bootloaders or root devices.
- Java 21, Android SDK platform 34/build tools and platform-tools/ADB. Android Studio can install these. Gradle 9.6.0 is supplied through the wrapper; AGP 8.7.3 / Kotlin 2.0.21 are pinned in source.
- Windows Python 3.12/3.13 or Linux Python 3.12. Model training dependencies are not necessary just to build the Android source, except the Python command runner itself.
- For full local Llama, allow roughly 2 GiB additional memory and 1.1 GiB file storage. Devices with less available memory may use fallback explanations.

## 1. Locate your SDK and check the device

PowerShell:

```powershell
$env:ANDROID_HOME='C:\path\to\Android\Sdk'
$env:JAVA_HOME='C:\path\to\jdk-21'
$env:Path="$env:ANDROID_HOME\platform-tools;$env:JAVA_HOME\bin;$env:Path"
adb devices
$env:NIDS_DEVICE_SERIAL='YOUR_AUTHORIZED_DEVICE_SERIAL'
python reproduce.py doctor --phone --serial $env:NIDS_DEVICE_SERIAL
```

Linux uses `export ANDROID_HOME=...`, `export JAVA_HOME=...`, `export NIDS_DEVICE_SERIAL=...`. Set `NIDS_ADB` or `NIDS_JAVA` only when tool discovery needs an explicit executable. USB debugging must be enabled and authorized by the phone owner. The setup checker invokes `su -c id`; approve root only for your own test device.

## 2. Build

```powershell
python reproduce.py build-android --sdk $env:ANDROID_HOME
```

This bootstraps the checksum-verified frozen feature extractor, runs Kotlin contract checks and builds the current app, instrumentation, TrafficLab, DatasetLab and contract checker. It writes an ignored `android/local.properties` for your SDK. The first build needs Internet access for Gradle/Maven dependencies. `--offline` works only after those dependencies are cached.

The main APK is `android/app/build/outputs/apk/debug/app-debug.apk`. Packet-derived golden fixtures and unused legacy weights are excluded. Some shared research support classes remain for compilation; the launcher/current live pipeline is `LearnedNetworkActivity` â†’ `TsanetCaptureService` â†’ `AlignedV2Scorer`.

## 3. Install the capture dependency and apps

Obtain a compatible ARM64 Android tcpdump from a trusted provider or build it from the [upstream tcpdump/libpcap sources](https://www.tcpdump.org/). The Android binary must support `--immediate-mode`, `-i any`, `-U`, and snaplen 768. Record its source/version/checksum. No unverified capture executable is bundled.

```powershell
python reproduce.py install-phone --serial $env:NIDS_DEVICE_SERIAL --tcpdump C:\path\to\trusted\tcpdump --start
```

If compatible tcpdump already exists at `/data/local/tmp/tcpdump`, omit `--tcpdump`. The command installs only the current debug apps, checks root/capture compatibility and starts monitoring. It never changes firewall rules. Allow notification permission. Leave monitoring running for 340 seconds before a controlled test so the complete history window is available.

## 4. Optional local Llama

```powershell
pip install huggingface-hub
python reproduce.py download-llama --accept-license
python reproduce.py install-phone --serial $env:NIDS_DEVICE_SERIAL --llama external_models\llama --start
```

Read `models/LLAMA_LICENSE.txt` and `models/LLAMA_USE_POLICY.md` first. The manifest pins the upstream repository revision and exact file hashes required by `LocalExplainer`. If upstream access requires approval/authentication, complete that with the provider; never commit access tokens. The 1.06 GiB model is not included in this repository.

Without these files, monitoring and evidence fallback remain available; no accepted Llama-generated text is claimed. Generation runs in an isolated process, reuses weights for about 2 minutes idle and resets prompt context per activity.

## Checks and limits

- NIDS shows a foreground monitoring notification. Pausing it stops capture; tests do not override Pause.
- Root/SELinux/tcpdump support can differ by device. A successful APK installation alone does not establish working live capture.
- Closed-port probes can have unknown app ownership because the OS responds without an application socket. Attribution is best effort.
- The detector warns; it does not block traffic or prove compromise. Validate with [controlled tests](PHONE_TESTING.md), not synthetic self-check alerts.
- New devices/networks require fresh normal-use and attack evaluation. Published Pixel metrics are not a compatibility/accuracy guarantee for every phone.


## Current release clarification

Current source is code53 with the augmented-v1 detector and opt-in Expected feedback. Network model weights/thresholds are unchanged from the augmented baseline; historical code36 is a reference. Read [current pipeline](CURRENT_PIPELINE.md), [final report](final_submission_report/README.md), [completed training](../results/phone_capture_training_v1/RESULTS.md) and [protocol testing](PROTOCOL_TESTING.md). All six training jobs completed; readiness remains false. The old v2 reference is kept only for comparison. New cases must be kept separate from already examined development cohorts.
