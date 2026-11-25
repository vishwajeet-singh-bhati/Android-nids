# Rakshak: clone-to-phone reproduction guide

Submission preparation, 25 November 2026. Current source: **0.18.0-passive-notices / code53**.
Use this guide from a fresh clone. No author's drive layout, phone identity,
SSH key or running service is required. Commands below use **Windows PowerShell
5.1** unless a block explicitly says Linux/WSL. Run commands from the repository
root except where `Set-Location`/`cd` changes it.

## 1. Choose what to reproduce

| Goal | Requirements | What you can verify |
|---|---|---|
| Build/install and exercise SMS + URL | One Android phone, PC, SDK/JDK; no root | Actual bundled inference and app behavior |
| Network detection | Already-rooted ARM64 test phone, compatible tcpdump, controller PC, private Wi-Fi | Real traffic capture, features, decisions and alerts |
| FTP/SSH/Bot/DoS/DDoS lab | Network setup plus two owned Windows SSH PCs | Bounded protocol cases, independent target effects and multi-source overlap |
| Original paper/context training | Linux/WSL, research Python environment, matching external CSV archive | Reconstructed method, splits, training and aggregate comparison |
| Aligned/augmented training | Original raw corpora; new phone recordings for augmentation | Same processing/training procedure; your own cohort |

**Clone-and-run does not imply identical historical accuracy.** Models, source,
configuration and aggregate reports are included. Research datasets, personal
messages, original private phone captures, downloaded threat feeds, private keys
and the optional 1.06 GiB Llama model are excluded. Exact historical retraining
needs the original permitted data and split identities. New phone traffic and
current threat feeds create different measurements. Debug signing also changes
the APK checksum; compare model hashes separately.

Expected milestones: build succeeds; fixture checks pass; capture heartbeat is
healthy; a normal control is measured; then suspicious cases are measured.
**A valid test may miss an activity or produce a false alert.** Do not modify
thresholds until every test alerts, or call a fixture notification attack recall.

## 2. Install PC prerequisites and clone

Install Git, 64-bit Python 3.12, JDK21, and Android Studio with Android SDK34,
build-tools34.0.0, platform-tools and command-line tools. Use your own SDK/JDK
locations. Initial dependency/model downloads need Internet; local phone model
inference does not require Internet. SSH and test packets still require LAN access.

```powershell
git clone https://github.com/vishwajeet-singh-bhati/rakshak.git
Set-Location rakshak
git rev-parse HEAD
git status --short

$env:JAVA_HOME='C:\path\to\jdk-21'
$env:ANDROID_HOME="$env:LOCALAPPDATA\Android\Sdk"
$env:Path="$env:JAVA_HOME\bin;$env:ANDROID_HOME\platform-tools;$env:Path"
java -version
adb version
py -3.12 --version

py -3.12 -m venv .venv
$py=Join-Path (Get-Location) '.venv\Scripts\python.exe'
& $py -m pip install --upgrade pip
& $py reproduce.py doctor
```

Using `$py` avoids requiring a PowerShell activation-policy change. Reassign it
after opening a new terminal. If SDK packages are missing, use Android Studio
SDK Manager or the following installed command-line tool, accepting its licenses:

```powershell
& "$env:ANDROID_HOME\cmdline-tools\latest\bin\sdkmanager.bat" --licenses
& "$env:ANDROID_HOME\cmdline-tools\latest\bin\sdkmanager.bat" 'platform-tools' 'platforms;android-34' 'build-tools;34.0.0'
```

Do not use Linux training commands inside PowerShell or run the test `.ps1`
files with Bash. The Android build does not need the heavy training packages.

## 3. Build the app, tests and isolated lab apps

```powershell
& $py reproduce.py build-android --sdk $env:ANDROID_HOME
```

The wrapper bootstraps the checksum-verified reference feature extractor, runs
the shared feature/policy/clock checks, and builds app, instrumentation,
TrafficLab, DatasetLab, contract checker and protocol modules. It writes ignored
`android/local.properties`. First build downloads Gradle/Maven dependencies;
add `--offline` only after a successful cached build.

Main output: `android/app/build/outputs/apk/debug/app-debug.apk`.
The deployed network PTEs, SMS coefficients/MobileBERT and URL CNN/n-gram assets
are bundled; no retraining is needed to test their inference. The public URL
database is deliberately **empty/stale**. Historical populated-list scores are
not the expected output of this default build.

## 4. Connect and prepare your phone

Use an owned test phone; the measured reference device was a rooted ARM64 Pixel
6a. Android API26+ is the source minimum, not a guarantee of every device's
capture/runtime compatibility. Network capture needs root; SMS/URL checking does
not. This repository does not root, wipe or unlock bootloaders.

1. Enable Developer options and USB debugging. Connect by USB and accept the
   computer's debugging key on the unlocked phone. Prefer USB during long runs.
2. Select the exact serial from the command below. Keep the phone on the same
   reachable private Wi-Fi as the controller for network tests.
3. For network monitoring, grant Shell and Rakshak root access in your installed
   root manager when asked. Check both capture readiness and app root permission.

```powershell
adb devices -l
$env:NIDS_DEVICE_SERIAL='REPLACE_WITH_SERIAL_FROM_ADB'
adb -s $env:NIDS_DEVICE_SERIAL shell getprop ro.product.model
adb -s $env:NIDS_DEVICE_SERIAL shell getprop ro.product.cpu.abi
adb -s $env:NIDS_DEVICE_SERIAL shell su -c id
```

Root check must return `uid=0` for the network path. Optional wireless ADB:

```powershell
# Use current values from Developer options > Wireless debugging.
adb pair PHONE_IP:PAIRING_PORT
# Enter the on-screen pairing code interactively, not in a public file.
adb connect PHONE_IP:CONNECTION_PORT
adb devices -l
```

Pairing and connection ports differ and can change. Set `NIDS_DEVICE_SERIAL`
to the actual connected transport. Do not select an unrelated second phone.

### Network installation

Obtain/build a trusted Android **ARM64 tcpdump**, supporting `--immediate-mode`,
`-i any`, `-U` and snaplen768. The upstream project is
[tcpdump/libpcap](https://www.tcpdump.org/). A desktop Windows/Linux executable
will not work on Android. This binary is an explicit external prerequisite;
there is no bundled or automatic unverified binary download. Record its source,
version and checksum alongside your experiment.

```powershell
$tcpdump='C:\path\to\trusted-android-arm64\tcpdump'
Get-FileHash -Algorithm SHA256 -LiteralPath $tcpdump
& $py reproduce.py install-phone --serial $env:NIDS_DEVICE_SERIAL --tcpdump $tcpdump --start
& $py reproduce.py doctor --phone --serial $env:NIDS_DEVICE_SERIAL
adb -s $env:NIDS_DEVICE_SERIAL shell pm grant nids.app android.permission.POST_NOTIFICATIONS
adb -s $env:NIDS_DEVICE_SERIAL shell pm grant nids.trafficlab android.permission.POST_NOTIFICATIONS
```

This installs the app, TrafficLab and DatasetLab. ProtocolLab is installed later
by Prepare. If the compatible tcpdump already exists at `/data/local/tmp/tcpdump`,
omit `--tcpdump`. Open Rakshak, allow its root prompt and enable network
monitoring. Confirm a foreground monitoring notification and healthy heartbeat.
Installation success alone does not prove capture works.

### SMS/URL-only installation without root

Skip the network installer/root check and use:

```powershell
adb -s $env:NIDS_DEVICE_SERIAL install -r android/app/build/outputs/apk/debug/app-debug.apk
adb -s $env:NIDS_DEVICE_SERIAL shell pm grant nids.app android.permission.POST_NOTIFICATIONS
adb -s $env:NIDS_DEVICE_SERIAL shell am start -n nids.app/.LearnedNetworkActivity
```

## 5. Optional local Llama explanations

Read [model license](models/LLAMA_LICENSE.txt) and
[acceptable-use policy](models/LLAMA_USE_POLICY.md). If you accept them:

```powershell
& $py -m pip install huggingface-hub
& $py reproduce.py download-llama --accept-license
& $py reproduce.py install-phone --serial $env:NIDS_DEVICE_SERIAL --llama external_models\llama --start
```

The second command pins the repository revision/files in
`models/llama_download.json` and checks SHA256. Obtain upstream account/access
approval if required; never commit tokens. The installer shown here is the rooted
network setup. SMS/URL-only users can use factual fallback without these files.

The app first shows an immediate factual **What happened / What you can do**
note, then optionally adds checked local guidance. Llama cannot change a risk
decision or invent an app owner. Reused model weights improve warm latency;
each activity gets fresh prompt context. Allow roughly1.1GiB disk plus device
memory headroom. Missing/failed/rejected generation uses an evidence-based
fallback; do not claim that text was accepted Llama output.

## 6. Run software checks before live traffic

After installing research dependencies in step11, run the dataset-free Python
checks. The following Android fixtures need no research datasets:

```powershell
& $py validation/validate_rakshak.py --serial $env:NIDS_DEVICE_SERIAL --install --modes rakshak_contract rakshak_urls hybrid_contract aligned_v2_native
```

Run SMS numerical checks separately because the historical strict neural-logit
tolerance is a **known failure**, despite class agreement:

```powershell
& $py validation/validate_rakshak.py --serial $env:NIDS_DEVICE_SERIAL --modes rakshak_sms
```

Inspect each result rather than promising this command must pass every strict
criterion. Never loosen tolerances to hide drift. Logs/summary are saved under
`runs/rakshak_validation`. Optional marked service/Llama fixtures, run separately
from live campaigns:

```powershell
& $py validation/validate_rakshak.py --serial $env:NIDS_DEVICE_SERIAL --modes rakshak_service
```

This temporarily pauses/restores capture and creates/removes clearly marked
fixture activities. It is an integration check, not an attack or accuracy test.

## 7. Exercise SMS and phishing links

In Settings, enable the SMS and URL switches and **Automatically check incoming
SMS and links**. Grant SMS and notification permission when prompted. These are
independent switches: URLs from an incoming carrier SMS can be checked while
the SMS classifier is disabled. No extracted link means no URL inference.

For a deterministic interface smoke check, paste/share authored test text into
Check. Use a harmless normal message first, then a clearly authored suspicious
message. To test the automatic receiver, send a **real carrier SMS** from your
own second device/SIM to this phone. RCS, WhatsApp, old inbox contents and browser
navigation are not automatically monitored. Disable RCS for that test or verify
the delivery was SMS. Mark test messages as authored, not independent labels.

For a locally supplied URL list, one address per line, run:

```powershell
& $py validation/benchmark_phone_urls.py --input C:\path\to\urls.txt --serial $env:NIDS_DEVICE_SERIAL --output runs\my_url_benchmark
# Optional: independent labels CSV with columns line,label; line is 1-based,
# label is phishing or benign. Never label using the detector's own verdict.
& $py validation/benchmark_phone_urls.py --input C:\path\to\urls.txt --serial $env:NIDS_DEVICE_SERIAL --output runs\my_url_benchmark --labels C:\path\to\labels.csv --rescore
```

No URL is visited. Label-free files produce decisions/timing, not accuracy or
precision/recall. Read [URL evidence](results/url_benchmark_20261124/README.md)
for the historical2,048-row label/overlap limitations.

Optional local threat lists, before building your own APK:

```powershell
& $py -m pip install idna tldextract
& $py tools/setup_runtime_feeds.py --assets android/app/src/main/assets/url --phishtank C:\path\to\permitted-online-valid.json
# Or use --download-phishtank instead of --phishtank PATH.
# Restore the no-feed public configuration before sharing source:
& $py tools/setup_runtime_feeds.py --assets android/app/src/main/assets/url --empty
```

Keep permission/source/date/hash of the feed. A changing list changes coverage;
historical218/218 list hits are not independent classifier accuracy. No online
Safe Browsing or automatic browser interception is enabled by this setup.

## 8. Single-controller network lab

Use the installed disposable lab apps; no real vulnerable accounts, shell,
personal database or malware is used. Keep the unlocked phone charging, Wi-Fi
addresses stable and controller awake. Prevent automatic screen locking during
the session, then restore your screen settings. Other VPNs/client isolation or
unreachable subnets can invalidate the path even if the Wi-Fi name is identical.

For ordinary use, keep **Alert on on-device connections (experimental)** off.
Localhost exchanges stay inside the phone and are outside the default external
intrusion assessment; this does not declare every local exchange safe. Read the
[ordinary-use scope correction](results/signin_scope_review_20261125/README.md).

Record detector switches, authentication-episode/local-traffic settings and any
Expected feedback before comparing runs. The opt-in Expected rule can mute
a narrowly matching repeated rejected connection; Undo removes the rule. Do not
mark test traffic Expected, clear feedback or change thresholds mid-comparison.
Clearing activity history also removes associated feedback; export what you need
before intentionally using Clear history. A clean test phone is preferable.

The Windows wrapper invokes `python`; make this terminal use the venv:

```powershell
$env:Path="$(Split-Path -Parent $py);$env:Path"
python --version
.\validation\Run-ControlledPhoneTest.ps1 -Profile Smoke
.\validation\Run-ControlledPhoneTest.ps1 -Profile PortScan -Preview
Start-Sleep -Seconds 305
.\validation\Run-ControlledPhoneTest.ps1 -Profile Benign
```

The normal control sends **eight HTTP requests**, not zero traffic. Expected
normal-control behavior is no alert, but save a false alert if it occurs. Wait
305 seconds with monitoring running between independent controlled cases:

```powershell
Start-Sleep -Seconds 305
.\validation\Run-ControlledPhoneTest.ps1 -Profile PortScan
Start-Sleep -Seconds 305
.\validation\Run-ControlledPhoneTest.ps1 -Profile PasswordGuessing
Start-Sleep -Seconds 305
.\validation\Run-ControlledPhoneTest.ps1 -Profile SQLInjection
Start-Sleep -Seconds 305
.\validation\Run-ControlledPhoneTest.ps1 -Profile XSS
Start-Sleep -Seconds 305
.\validation\Run-ControlledPhoneTest.ps1 -Profile ConnectionExhaustion
Start-Sleep -Seconds 305
.\validation\Run-ControlledPhoneTest.ps1 -Profile HTTPFlood
```

Each command performs one live case, observes130 seconds and stops its own
target. No next profile is scheduled by that command. Check errors and files
before continuing; do not paste an unchecked loop that ignores failed commands.

| Profile | Generated activity and independent evidence |
|---|---|
| Benign |8 ordinary HTTP requests, status200 |
| PortScan |1 lab port +128 verified closed ports;129 TCP tuples; retries/segments are not129 independent attacks |
| PasswordGuessing |32 dummy HTTP logins;31 rejected,1 valid. Web/password behavior, not FTP/SSH authentication |
| SQLInjection |1 control search +2 injections against the toy in-memory database; returned-row proof |
| XSS |1 isolated JavaScript proof in the dummy app; execution event |
| ConnectionExhaustion |16 requests,8 workers, two-slot dummy resource; denials limited to that resource |
| HTTPFlood |128 requests, at most8 workers; bounded load, not proof of volumetric DoS |

Optional varieties, outside this13-profile submission sequence: `SlowScan`
(one lab+31 closed ports) and `Beacon` (12 fixed exchanges to TCP43990).
Beacon needs an approved reachable PC receiver/firewall path. Use protocol
BotBehavior below for the documented managed receiver setup.

## 9. Two additional PCs: complete protocol/DDoS setup

Total equipment: **one controller + two owned Windows source PCs + test phone**.
All three PCs must reach the phone over the private lab LAN; BotBehavior also
needs phone-to-PC1 reachability. Windows source accounts need administrator
capability for the narrow temporary receiver rule/cleanup watchdog. Do not
disable a firewall or bypass organization-managed PowerShell policy.

### 9.1 On each source PC, Administrator PowerShell

```powershell
$sshCapability=Get-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
if($sshCapability.State -ne 'Installed') {
    Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
}
Start-Service sshd
Get-Service sshd
Get-NetTCPConnection -LocalPort 22 -State Listen
hostname
whoami
ipconfig
```

Write down each current Wi-Fi IPv4 address, hostname and actual local login.
The PCs may have different subnets if routing permits; verify each path rather
than assuming identical SSID means reachability.

### 9.2 On the controller, create your own key

```powershell
$labSsh=Join-Path $env:USERPROFILE '.ssh\rakshak-lab'
New-Item -ItemType Directory -Force -Path $labSsh | Out-Null
ssh-keygen -t ed25519 -f (Join-Path $labSsh 'id_ed25519') -C 'rakshak-owned-lab'
```

Use your normal key/passphrase management. The runner uses BatchMode: unlock a
protected key through an SSH agent before testing. A password prompt cannot be
answered by a background test. Copy **only** `id_ed25519.pub` and
`tools/Install-LabSshKey.ps1` to each source PC. Keep the private key on your PC.

On each source, Administrator PowerShell, adapting its public-key path:

```powershell
.\Install-LabSshKey.ps1 -PublicKeyFile C:\path\to\id_ed25519.pub -Login $env:USERNAME -ControllerIp 'CONTROLLER_PRIVATE_IPV4'
```

The helper appends the key, backs up an existing authorized-key file, applies
the OpenSSH Windows ACL and adds a source-scoped TCP22 allow rule. It starts no
test traffic. It does not enable blank-password SSH or replace other keys.

### 9.3 Pin identities and verify from the controller

On each source, obtain the host-key fingerprint locally:

```powershell
ssh-keygen -lf C:\ProgramData\ssh\ssh_host_ed25519_key.pub
```

On the controller, replace every placeholder with the recorded values:

```powershell
$pc1='PC1_PRIVATE_IPV4'
$pc2='PC2_PRIVATE_IPV4'
$login1='PC1_LOGIN'
$login2='PC2_LOGIN'
$known=Join-Path $labSsh 'known_hosts'
Test-NetConnection $pc1 -Port 22
Test-NetConnection $pc2 -Port 22
ssh -i "$labSsh\id_ed25519" -o "UserKnownHostsFile=$known" -o StrictHostKeyChecking=ask -l $login1 $pc1 hostname
ssh -i "$labSsh\id_ed25519" -o "UserKnownHostsFile=$known" -o StrictHostKeyChecking=ask -l $login2 $pc2 hostname
```

Compare each displayed fingerprint with its source-PC value **before** accepting.
Do not use `StrictHostKeyChecking=no`. Test again with `-o BatchMode=yes` and
`-o StrictHostKeyChecking=yes`; both must succeed without a password prompt.

Create the private configuration using the exact expected hostnames:

```powershell
New-Item -ItemType Directory -Force runs\protocol_phone_tests | Out-Null
$sshConfig=@{
    identity_file=(Join-Path $labSsh 'id_ed25519')
    known_hosts_file=$known
    hosts=@(
        @{name='PC1';host=$pc1;expected_hostname='PC1_HOSTNAME';login=$login1;identity_verified=$true},
        @{name='PC2';host=$pc2;expected_hostname='PC2_HOSTNAME';login=$login2;identity_verified=$true}
    )
}
$sshConfig | ConvertTo-Json -Depth 5 | Set-Content -Encoding UTF8 runs\protocol_phone_tests\ssh_config.json
.\validation\Run-ProtocolPhoneTest.ps1 -Profile Smoke
.\validation\Run-ProtocolPhoneTest.ps1 -Profile DDoS -Preview
.\validation\Run-ProtocolPhoneTest.ps1 -Profile Prepare
.\validation\Run-ProtocolPhoneTest.ps1 -Profile Status
```

Prepare verifies pinned SSH identities, administrator capability and policy,
installs the inert ProtocolLab, uploads hashed helpers/contract to
`C:/ProgramData/NidsProtocolLab`, and validates Android protocol support.
It starts no listener or attack. If IPs/helpers/APK change, rerun Prepare.
ProtocolLab binds its callback socket to the Wi-Fi network matching the contract;
it does not change the phone's general cellular routing.

### 9.4 Execute protocol cases sequentially

```powershell
Start-Sleep -Seconds 305
.\validation\Run-ProtocolPhoneTest.ps1 -Profile Benign
.\validation\Run-ProtocolPhoneTest.ps1 -Profile FTPBruteForce
.\validation\Run-ProtocolPhoneTest.ps1 -Profile SSHBruteForce
.\validation\Run-ProtocolPhoneTest.ps1 -Profile BotBehavior
.\validation\Run-ProtocolPhoneTest.ps1 -Profile DoS
.\validation\Run-ProtocolPhoneTest.ps1 -Profile DDoS
```

No extra sleep **between protocol commands** is needed: each resets diagnostics,
warms a fresh305-second history, then observes130 seconds. Wait for each command
to finish. This plus step8 is the13-profile sequence; allow roughly100–110minutes
excluding equipment/setup failures. Do not run another test/collector in parallel.

| Profile | Real bounded behavior / verified effect |
|---|---|
| Benign |1 failed +1 valid FTP and SSH login each,5 HTTP probes; all three PCs reachable |
| FTPBruteForce |32 wrong dummy logins over FTP, server records32 failures |
| SSHBruteForce |32 wrong dummy logins using real encrypted SSH; no shell/exec/SFTP/forwarding |
| BotBehavior |12 fixed PING/STATUS exchanges with an owned PC receiver; emulator, not malware |
| DoS |96 requests, at most6 workers, dummy resource denial + probe failure/recovery |
| DDoS |3 physical sources ×32 requests/≤2 workers; distinct source IPs and overlap required |

Phone ports: TrafficLab43190, protocol HTTP43194/FTP43195/SSH43196;
Bot receiver PC1 TCP43991. The Bot receiver creates a narrow temporary
phone-IP/program/port rule and independent120-second cleanup. Each target has
a15-minute limit; profile cleanup stops it. Capacity loss remains inside the
dummy service, not the phone, router or outside hosts.

If cleaning up SSH after evaluation, remove only this helper's rule if no longer
needed (`Remove-NetFirewallRule -Name Rakshak-Lab-SSH` on that source), and remove
the exact public-key line you added. Preserve other keys and the source's
previous SSH/firewall configuration.

## 10. Read results and compute defensible metrics

| Output | Location |
|---|---|
| Controlled case | `runs/manual_phone_tests/<timestamp>_<profile>/` |
| Controlled report | `check.json`, `run.json`, `traffic.pcap`, `target_events.json`, capture stderr |
| Protocol case | `runs/protocol_phone_tests/cases/<case>/` |
| Protocol report | `review.json`, `effects.json`, `native.jsonl`, `capture.pcap`, `target_events.json`, capture quality |
| Aggregate/manual chronology | generated `results/manual_phone_tests/` and `results/protocol_phone_tests/` |
| Android fixture results | `runs/rakshak_validation/<run>/summary.json` and per-mode logs |

```powershell
Get-Content runs\manual_phone_tests\latest.json
Get-Content runs\protocol_phone_tests\status.json
# Replace CASE_DIRECTORY with the newly created path, not an old example:
Get-Content 'CASE_DIRECTORY\check.json'
# For protocol cases:
Get-Content 'CASE_DIRECTORY\review.json'
```

Separate **raw binary flags**, post-policy emitted warnings, diagnosed attack
types, activity groups and visible notification snapshots. Authentication
episodes can change emitted warnings while the raw score is preserved. A
filtered Expected repeat is not a raw benign decision. A late absent notification
does not prove it was never posted. Unrelated background flags are not detections
of the case you just ran. Source/target event proof and capture health precede
scoring; an SSH timeout or incomplete capture is **inconclusive**, not FN/TN.

Choose and state a unit: an independently labelled flow/session or repeated
test case. TP=positive unit flagged, FN=positive unit missed, FP=normal unit
flagged, TN=normal unit quiet. Precision=TP/(TP+FP), recall=TP/(TP+FN),
F1=2TP/(2TP+FP+FN), FPR=FP/(FP+TN), accuracy=(TP+TN)/all labelled units.
Report undefined denominators, uncertain/unlabelled units and failed attempts
separately. Binary detection and correct-type classification need separate
confusions. One PortScan producing500 segments is one scenario, not500 attacks.
This13-case run alone cannot establish general classwise precision/recall.

Archived measured numbers and denominators are indexed in [results](results/README.md).
The25November live campaign was still incomplete when this guide was prepared;
it is not represented as a finished benchmark or a guarantee of all-class alerts.

## 11. Reproduce training and offline evaluation

Keep training separate from the phone demonstration. Train/evaluate in Linux or
WSL with Python3.12; do not install the different SMS and network export stacks
into the same environment. CUDA was used for network training; CPU is slower.
Use publisher terms and original file hashes, not silently substituted datasets.

### 11.1 Network environment and dataset-free checks (Linux/WSL)

```bash
cd /path/to/rakshak
python3.12 -m venv .venv-research
source .venv-research/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pytest tests -q
python -m unittest validation.test_url_benchmark_metrics
python reproduce.py paper --smoke
python reproduce.py context --smoke
```

Smoke uses generated software fixtures; its metrics are not research results.
Pinned environment details are in [reproduction methods](docs/REPRODUCING_RESULTS.md).
For CPU-only paper/context runs set `export NIDS_TRAIN_DEVICE=cpu`.

### 11.2 Paper and added-context benchmark

Obtain the publisher CICIDS2017 **GeneratedLabelledFlows.zip** and retain it at:

```text
data/external/CICIDS2017/GeneratedLabelledFlows.zip
```

Verify its hash/members against `results/tsanet_paper/data_report.json`.
Do not replace it with an ML-only CSV archive lacking identifiers/timestamps.

```bash
python reproduce.py paper
python reproduce.py context
```

Paper: stratified70/30, seed42,10 baseline epochs, independent30%/40% pruning
branches with5 fine-tuning epochs. Context comparison: same rows/split and10+5
budget for both arms,78 extra connection-history features, final frozen
checkpoints. Outputs: `runs/tsanet_paper_70_30` and `runs/tsanet_context_v1`.
Read [paper assumptions](docs/PAPER_AND_CONTEXT.md) for unspecified author details
we reconstructed; this is not an assertion of an author-supplied exact split.
Historical context results share campaigns and are not unseen-device evidence.

### 11.3 Phone-aligned model

Acquire the five original CICIDS2017 PCAPs plus PARROT2025 and benign CIC-AAGM2017
captures in the exact [dataset layout](docs/DATASETS.md). This is a different
benchmark from the70/30 CSV paper run. Missing raw sources are not synthesized.

```bash
python reproduce.py aligned prepare
python reproduce.py aligned train
python -m pip install -r requirements-export.txt
python reproduce.py aligned export
```

The fixed extractor produces32 flow+115 context/protocol inputs. Group split
is70/15/15; normalization fits training only. Eight fixed40-epoch jobs retain
epochs; selection is by validation before test reporting. The original aligned
model is a reference; the current shipped network weights are the later
real-phone-augmented model. Export does not automatically promote/redeploy it.

### 11.4 New phone data and augmented training

Build/install on the actual Windows controller first. After activating the
Windows Python environment, choose either native Linux training or configured
WSL training. Example Windows collection with your WSL environment:

```powershell
$env:NIDS_TRAIN_BACKEND='wsl'
$env:NIDS_WSL_DISTRO='Ubuntu'
$env:NIDS_WSL_PYTHON='/home/YOUR_USER/path/to/.venv-research/bin/python'
& $py reproduce.py phone pilot --serial $env:NIDS_DEVICE_SERIAL
& $py reproduce.py phone collect --serial $env:NIDS_DEVICE_SERIAL
```

The pilot must pass independent effects and all147 native/offline feature checks.
Collection uses20 preassigned sessions (14train/3validation/3test), new attack
forms/rates and matched normal controls. Only train-phone rows get the declared
8-fold replay; validation/test are not resampled. Six fixed40-epoch/three-seed
jobs retain checkpoints. See [datasheet](experiments/phone_capture_v1/DATASHEET.md)
and [training procedure](docs/REPRODUCING_RESULTS.md). Do not run live evaluation
in parallel with collection. Your recordings produce your own scores; exact
historical augmented results cannot be regenerated without the private corpus.

### 11.5 SMS source, training and quantization

Use another environment from `components/sms/python`:

```powershell
Set-Location components\sms\python
py -3.12 -m venv .venv-sms
$smsPy=Join-Path (Get-Location) '.venv-sms\Scripts\python.exe'
& $smsPy -m pip install -r requirements.txt
& $smsPy -m pip install -e .
& $smsPy -m sms_detection.cli info --model-dir ..\models
& $smsPy -m sms_detection.cli predict 'Your OTP is 123456. Do not share it.' --model-dir ..\models
# Review the source licenses/URLs in the downloader before acquisition:
& $smsPy scripts/download_data.py --help
& $smsPy scripts/download_data.py
# Then prepare the downloaded, permitted sources:
& $smsPy scripts/prepare_data.py
& $smsPy -m sms_detection.models.train_baseline
```

Do this on an experimental copy; baseline training writes model/report outputs.
The downloader records URLs, license notes, byte counts and SHA256 in
`data/raw/source_manifest.json`. It covers UCI SMS Spam Collection, LSDST2022,
NCSU campaign messages and the documented Hinglish/Indian controls. Some
upstream snapshots/APIs may require manual publisher access or have changed;
compare the recorded hashes/splits instead of assuming today's download is the
original corpus. Do not skip a source and then claim the original denominator.
For the neural experiment, create a separate environment compatible with
`experiments/mobilebert/requirements.txt` and its documented CPU versions:

```powershell
# Original neural experiment used Python3.14; install that interpreter separately.
py -3.14 -m venv .venv-mobilebert
$mobilePy=Join-Path (Get-Location) '.venv-mobilebert\Scripts\python.exe'
& $mobilePy -m pip install -r experiments/mobilebert/requirements.txt
& $mobilePy -m pip install -e .
& $mobilePy experiments/mobilebert/train_mobilebert.py --run-name mobilebert22_lr5e5_bs16_e4 --num-layers 22 --epochs 4 --lr 0.00005 --batch-size 16 --seed 42
& $mobilePy experiments/mobilebert/evaluate_mobilebert.py --split val
# After freezing model selection, evaluate test once:
& $mobilePy experiments/mobilebert/evaluate_mobilebert.py --split test
Set-Location ..\..\..
```

The original split counts are4055/869/869. Match the recorded hashes before
claiming exact reproduction. Read [SMS provenance](components/sms/provenance/ARCHIVED_EVALUATION.json)
and [MobileBERT procedure](components/sms/python/experiments/mobilebert/README.md)
for22-layer stability variant, best epoch3 and PTQ/QAT export commands/dependencies.
The supplied original test is already opened; a rerun is regression evaluation,
not a fresh holdout. Python reference policy differs from later Android routing.
Re-exporting a model does not automatically replace the app's selected assets.

### 11.6 URL source and training

Use another environment from `components/phishing_url/python`. Install a
compatible PyTorch separately and `requirements.txt`, then inspect the available
source CLIs before running full dataset acquisition:

```bash
cd components/phishing_url/python
python -m pip install -r requirements.txt
python -m src.data.download_datasets --help
python -m src.data.build_dataset --raw data/raw --out data/processed
python -m src.data.split_dataset --samples data/processed/samples.csv --out data/processed/splits
python -m src.training.train_cnn --mode full_url --model hybrid --device auto
python -m src.training.ensemble --cnn-run artifacts/runs/full_url_hybrid
python -m src.deploy.mobile_export --help
```

The build commands need matching permitted input snapshots, not empty data/raw.
Original full training/split provenance is incomplete in the handoff, so these
are available procedure commands, not a promise of exact historical retraining.
The frozen Android model can still be inspected/tested without those sources.
URL/mobile export has additional ExecuTorch dependencies: follow the component
README rather than mixing it with the network exporter. Select/calibrate on
validation before using final test labels; do not derive labels from predictions.

## 12. Troubleshooting and reviewer evidence package

| Symptom | Check / action |
|---|---|
| `java`/SDK missing | Set JAVA_HOME/ANDROID_HOME and install SDK34/build-tools34; rerun doctor |
| Training says source/config changed | Preserve old results; choose a new `--directory runs/YOUR_NEW_RUN` instead of overwriting the frozen run |
| `python` wrapper uses wrong environment | Prepend the selected venv Scripts directory to PATH |
| Script blocked | Inspect your permitted script policy; obtain administrator approval for managed restrictions, do not bypass it |
| APK signature mismatch | Same application ID with a different debug key; preserve required data before consciously uninstalling the old test build |
| No ADB/unauthorized/offline | Unlock, accept USB prompt, prefer USB; wireless pairing does not replace connect; refresh the actual port/serial |
| No root/tcpdump | Verify Shell/app grants, ABI, executable permission and immediate-mode support; SMS/URL can still run |
| History `7/300` | Leave capture running305s; no attack started, no detector miss |
| Raw capture ended/drops | Check stderr, space, packet cap and process health; invalid case, repair and rerun separately |
| Protocol SSH timeout | Verify current source IP/hostname, awake state, sshd, host key, login/agent and scoped TCP22 rule **before** five-minute warm-up |
| Callback failure | Check Wi-Fi contract/bind, phone→PC1 path and TCP43991 rule; update Prepare after IP changes |
| Benign gets flagged | Preserve evidence/model scores; record FP only with established benign labels; do not whitelist whole apps/ports or silently mark Expected |
| Raw flag but no notification | Inspect emission policy, user feedback, grouping, permissions and snapshot timing separately |
| No Llama text | Check model hashes/path/memory; distinguish safe fallback from accepted generation |
| No incoming SMS check | Verify actual carrier SMS, RECEIVE_SMS, auto-check/SMS/URL switches; RCS/chat/inbox is outside receiver scope |
| URL benchmark has no metrics | Supply independent labels; unknown labels are not benign |

Allow at least2GiB free on phone and controller for protocol capture, plus the
optional model's storage. Never clear another device's data to make space.
Restoring the phone or resetting root is not a routine installation step.

For review, supply the public commit SHA, app version, model/contract hashes,
environment versions, dataset manifests and permissions, aggregate reports,
case validity/effect evidence, known failures, [report PDF/source](docs/project_report/README.md)
and [two-minute demo guide](docs/DEMO_VIDEO_SCRIPT.md). Preserve full logs/captures
privately with consent; do not upload personal packets/messages/keys. Read
[submission checkpoints](SUBMISSION_CHECKPOINTS.md) before freezing claims.
No demo upload, mentor approval or final form submission is performed by these
commands.
