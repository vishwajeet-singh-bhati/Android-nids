# Network intrusion testing procedure

This is the executable procedure for the thirteen live cases listed in [tests/NIDS_tests.sh](../tests/NIDS_tests.sh). It covers the single-PC HTTP/scan lab and the FTP/SSH/bot/resource-denial lab with two additional PCs. These commands generate new bounded traffic; they do not replay saved captures or inject classifier scores.

The `.sh` filename is historical: its contents are **PowerShell**, not Bash. The recommended procedure below is manual: complete setup, then run each command individually, inspect its result, and continue. An optional [PowerShell runner](../tests/NIDS_tests.ps1) reads the same sheet and stops on the first error. Neither route clears activity history automatically.

## 1. Equipment and software

- An owned ARM64 Android test phone, already rooted for network capture. Grant Shell and Rakshak root access. Rooting/resetting the phone is not part of this procedure.
- A Windows controller with Python 3.12, Java 21, Android SDK 34/platform-tools, PowerShell 5.1 and the repository dependencies.
- For the complete protocol suite: two additional owned Windows PCs, powered on and reachable using pinned-key SSH. They must reach the phone; BotBehavior also requires phone-to-PC1 reachability. Same Wi-Fi name alone does not guarantee routing.
- USB ADB is preferable for a long test. Wireless ADB also works but can disconnect. Select the intended phone explicitly; do not let another discovered device become the target.
- At least 2 GiB free on phone and controller. Keep the phone unlocked and charging and all PCs awake. Use only the selected private lab endpoints and disposable targets.

See [Android setup](ANDROID_SETUP.md) and [REPRODUCE.md, sections 1–6](../REPRODUCE.md) for detailed dependency, root/tcpdump and installation checks. No cloud inference or phone Internet connection is required for already-installed models. Development downloads require a connection on the controller.

## 2. Clone, build and install

From PowerShell, replace SDK/device placeholders with your own values:

```powershell
git clone https://github.com/vishwajeet-singh-bhati/rakshak.git
cd rakshak
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
$env:ANDROID_HOME='C:\path\to\Android\Sdk'
# Set JAVA_HOME to your installed Java 21 directory if it is not already set.
python reproduce.py build-android --sdk $env:ANDROID_HOME
adb devices -l
$env:NIDS_DEVICE_SERIAL='YOUR_AUTHORIZED_SERIAL'
adb -s $env:NIDS_DEVICE_SERIAL shell getprop ro.product.model
adb -s $env:NIDS_DEVICE_SERIAL shell su -c id
```

The root check must return `uid=0`. Accept USB authorization only for this PC on the intended unlocked phone. For wireless ADB, pair using the phone's current pairing screen, then connect using its separate connection port; select the connected transport shown by `adb devices -l`. Ports can change.

Obtain a trusted **Android ARM64 tcpdump**, supporting `--immediate-mode`, `-i any`, `-U` and snaplen 768. A Windows/Linux desktop tcpdump executable is unsuitable. Record its source/version/hash; the repository does not download an unverified capture binary. Install it together with the app and inert HTTP lab:

```powershell
$tcpdump='C:\path\to\trusted-android-arm64\tcpdump'
Get-FileHash -Algorithm SHA256 -LiteralPath $tcpdump
python reproduce.py install-phone --serial $env:NIDS_DEVICE_SERIAL --tcpdump $tcpdump --start
adb -s $env:NIDS_DEVICE_SERIAL shell su -c '/data/local/tmp/tcpdump --version'
```

If compatible tcpdump is already installed, omit `--tcpdump` and its path. The installer does not root a phone. Grant Rakshak root separately in the root manager. Llama weights are optional and installed separately; factual warnings remain available without them.

In Rakshak, enable network monitoring and notification permission. Leave the experimental on-device/loopback alerts and authentication-episode rules off for the default learned-model comparison. Do not mark test traffic Expected or alter thresholds/scope mid-run. Record any different setting in the result cohort. Allow at least 300 seconds for history to become ready.

## 3. Prepare the two source PCs before the full run

Name the PCs Controller, PC1 and PC2 in your notes. Record their current Wi-Fi IPv4 addresses and PC1/PC2 Windows hostnames and logins. Do not copy the author's old IP addresses.

**On PC1 and PC2**, open Administrator PowerShell and run:

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

**On the controller**, create your own SSH key and copy only its `.pub` file plus `tools/Install-LabSshKey.ps1` to each source:

```powershell
$labSsh=Join-Path $env:USERPROFILE '.ssh\rakshak-lab'
New-Item -ItemType Directory -Force -Path $labSsh | Out-Null
ssh-keygen -t ed25519 -f (Join-Path $labSsh 'id_ed25519') -C 'rakshak-owned-lab'
```

Keep the private key on the controller. For a passphrase-protected key, load it into your normal SSH agent before testing: the harness uses BatchMode and cannot answer a password prompt. Do not store passwords/passphrases in scripts.

**On each source**, Administrator PowerShell, use the copied paths and the controller's actual private address:

```powershell
.\Install-LabSshKey.ps1 -PublicKeyFile C:\path\to\id_ed25519.pub -Login $env:USERNAME -ControllerIp 'CONTROLLER_PRIVATE_IPV4'
ssh-keygen -lf C:\ProgramData\ssh\ssh_host_ed25519_key.pub
```

The helper backs up existing keys, appends the selected public key, sets Windows OpenSSH ACLs and creates a controller-scoped SSH allow rule. It does not enable blank-password login or replace other keys. Record each locally displayed host-key fingerprint.

**Back on the controller**, replace placeholders below. Compare each displayed SSH fingerprint with the value recorded directly on that source before accepting it:

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
ssh -i "$labSsh\id_ed25519" -o "UserKnownHostsFile=$known" -o StrictHostKeyChecking=yes -o BatchMode=yes -l $login1 $pc1 hostname
ssh -i "$labSsh\id_ed25519" -o "UserKnownHostsFile=$known" -o StrictHostKeyChecking=yes -o BatchMode=yes -l $login2 $pc2 hostname
```

Both final commands must succeed without prompting. Create the private configuration using the actual expected Windows hostnames:

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
```

The resulting file stays private:

```text
runs/protocol_phone_tests/ssh_config.json
```

Actual credentials, keys and addresses are not shipped. Temporary receiver rules are restricted to this lab; do not disable firewalls or bypass managed policy. Additional explanations are in [PROTOCOL_TESTING.md](PROTOCOL_TESTING.md) and [REPRODUCE.md, section 9](../REPRODUCE.md).

After checking the configuration:

```powershell
.\validation\Run-ProtocolPhoneTest.ps1 -Profile Prepare
.\validation\Run-ProtocolPhoneTest.ps1 -Profile Status
.\tests\NIDS_tests.ps1 -PreflightOnly
```

Prepare installs the inert protocol target and copies the bounded helpers. It does not run an attack. Preflight verifies the selected phone, root/capture tool, running monitor/history, installed model hashes, storage, saved preparation, current phone/controller addresses and both pinned SSH hostnames. It sends no test requests and starts no listener. Actual target paths are checked again during each case; later Wi-Fi/ADB changes can still interrupt a run. If any address, APK, helper or source changes, prepare again.

For only the seven controlled cases, the extra PCs are unnecessary:

```powershell
.\tests\NIDS_tests.ps1 -Suite Controlled -PreflightOnly
```

## 4. Run the tests manually, one command at a time

Stay in the repository root with the Python environment active and `NIDS_DEVICE_SERIAL` set. Wait for **each command to return to the PowerShell prompt**, read its output and inspect the phone before entering the next command. If a command fails, stop and fix that issue; do not continue the sequence or call it a missed attack.

For tests 1–7, run the listed wait before each case. This rebuilds/isolates connection history; it sends no attack. The case itself then observes for 130 seconds. Tests 8–13 each contain their own 305-second warm-up, so no extra sleep between them is required.

### Test 1 — normal HTTP control

```powershell
Start-Sleep -Seconds 305
.\validation\Run-ControlledPhoneTest.ps1 -Profile Benign
```

Expect eight ordinary HTTP requests and no matched warning. Save any false warning; normal means ordinary requests, not zero network traffic.

### Test 2 — TCP connect port scan

```powershell
Start-Sleep -Seconds 305
.\validation\Run-ControlledPhoneTest.ps1 -Profile PortScan
```

The script tries one lab port and 128 verified-closed ports. Compare matched flags and the estimated family with captured connections. Retransmissions can produce many segments from one connection.

### Test 3 — HTTP password guessing

```powershell
Start-Sleep -Seconds 305
.\validation\Run-ControlledPhoneTest.ps1 -Profile PasswordGuessing
```

Check for 31 failed and one valid dummy login. This profile is web authentication, not FTP/SSH brute force. The valid login is a separate control.

### Test 4 — isolated SQL injection

```powershell
Start-Sleep -Seconds 305
.\validation\Run-ControlledPhoneTest.ps1 -Profile SQLInjection
```

The target executes one normal search and two injections in its disposable database. Confirm target effects before calling the requests positive examples.

### Test 5 — isolated XSS

```powershell
Start-Sleep -Seconds 305
.\validation\Run-ControlledPhoneTest.ps1 -Profile XSS
```

Check for the target's script-execution event. A verified effect with no matched model flag is a miss, even if unrelated phone notifications are visible.

### Test 6 — bounded connection/resource exhaustion

```powershell
Start-Sleep -Seconds 305
.\validation\Run-ControlledPhoneTest.ps1 -Profile ConnectionExhaustion
```

Sixteen requests compete for the dummy service's two resource slots. Resource denial is restricted to the lab service; this is not Slowloris or whole-phone exhaustion.

### Test 7 — bounded HTTP burst

```powershell
Start-Sleep -Seconds 305
.\validation\Run-ControlledPhoneTest.ps1 -Profile HTTPFlood
```

Check that 128 requests were delivered. The historical profile name does not establish a realistic flood or availability loss by itself.

### Test 8 — normal FTP/SSH control

```powershell
Start-Sleep -Seconds 305
.\validation\Run-ProtocolPhoneTest.ps1 -Profile Benign
```

The wait above is the last controlled-to-protocol isolation step in the command sheet. This case tests ordinary successful/failed FTP/SSH logins and normal HTTP probes. A single wrong password is normal control activity. Both remote PCs must be available.

### Test 9 — FTP password guessing

```powershell
.\validation\Run-ProtocolPhoneTest.ps1 -Profile FTPBruteForce
```

Check 32 dummy wrong-password attempts and compare them with the normal FTP control, not just the number of notifications.

### Test 10 — SSH password guessing

```powershell
.\validation\Run-ProtocolPhoneTest.ps1 -Profile SSHBruteForce
```

Check 32 rejected SSH attempts. The target offers no shell, file access or forwarding. Compare false flags on normal SSH as well as attack flags.

### Test 11 — restricted bot-behaviour emulator

```powershell
.\validation\Run-ProtocolPhoneTest.ps1 -Profile BotBehavior
```

Confirm 12 exchanges reached the owned PC receiver. Failed receiver connectivity is inconclusive, not evidence that the model missed a completed exchange. No real malware is installed.

### Test 12 — single-source dummy-service denial

```powershell
.\validation\Run-ProtocolPhoneTest.ps1 -Profile DoS
```

Verify resource/probe denial and subsequent recovery. Report load-request flags separately from normal availability probes.

### Test 13 — three-source dummy-service denial

```powershell
.\validation\Run-ProtocolPhoneTest.ps1 -Profile DDoS
```

Require three distinct phone-visible source IPs, overlapping activity and dummy-service impact. This is a bounded application-resource case, not a volumetric network attack.

Afterward, optionally run another protocol Benign control to check normal behaviour after the attack cases. It is a fourteenth case and must be labelled separately. The complete thirteen-case manual command sheet is [NIDS_tests.sh](../tests/NIDS_tests.sh).

## 5. Optional plan preview and sequential runner

These commands only list the plan; no phone, SSH, wait or test action occurs:

```powershell
.\tests\NIDS_tests.ps1 -Preview
.\tests\NIDS_tests.ps1 -Suite Controlled -Preview
.\tests\NIDS_tests.ps1 -Suite Protocol -Preview
```

To run new traffic, choose **one** command:

```powershell
.\tests\NIDS_tests.ps1                    # all 13 cases, roughly 100–120 minutes
# Or select one part:
.\tests\NIDS_tests.ps1 -Suite Controlled # 7 cases, one controller
.\tests\NIDS_tests.ps1 -Suite Protocol   # 6 cases, controller + 2 SSH PCs
```

Do not paste all three launch commands together. The runner fails before the first case if prerequisites are missing, then waits for each case to finish. An error stops the sequence; preserve the incomplete attempt, fix setup and choose the remaining manual commands. There is no automatic retry or clearing of failed evidence.

Alternatively open [NIDS_tests.sh](../tests/NIDS_tests.sh) and execute its PowerShell lines individually from the repository root. The eight `Start-Sleep -Seconds 305` lines isolate recent context between controlled cases. Each protocol case warms its own fresh 300-second history; it needs no additional sleep between protocol commands. Monitoring must stay on during all waits. Do not run another test/collection at the same time.

## 6. Case reference

| Order | Case | Generated activity / independent truth | Expected behaviour |
|---|---|---|---|
| 1 | Controlled Benign | 8 ordinary HTTP requests | No matched alert expected; retain any false positive. |
| 2 | PortScan | 1 lab port plus 128 verified-closed ports | A scan warning/family estimate is expected, not guaranteed. Count connections separately from retries/segments. |
| 3 | PasswordGuessing | 32 dummy HTTP logins: normally 31 failures, 1 valid control | Correlate flags to each request; this is not FTP/SSH guessing. |
| 4 | SQLInjection | 1 normal search and 2 isolated database injections | Require target evidence of the effect; never label using the prediction. |
| 5 | XSS | One script executed in the isolated lab target | Require execution event. A completed target effect can still be missed. |
| 6 | ConnectionExhaustion | 16 requests against a two-slot dummy resource | Resource holds/denials; not whole-phone exhaustion or Slowloris. |
| 7 | HTTPFlood | 128 bounded HTTP requests | Measure delivered requests; load alone does not prove availability loss. |
| 8 | Protocol Benign | Ordinary wrong/correct FTP/SSH logins and HTTP probes | No matched alerts expected; a single wrong password is a normal control. |
| 9 | FTPBruteForce | 32 dummy wrong-password FTP attempts | Record binary flags and correct-family counts separately. |
| 10 | SSHBruteForce | 32 dummy wrong-password SSH attempts | Actual SSH authentication; no shell or file access is enabled. |
| 11 | BotBehavior | 12 restricted outbound exchanges | Behaviour emulator, not malware infection. |
| 12 | DoS | 96 requests, at most 6 workers, dummy resource | Confirm bounded service denial and recovery; separate probes from load. |
| 13 | DDoS | 3 owned PCs, 32 requests each | Verify three phone-visible sources, overlap and dummy-service effects; not volumetric DDoS. |

An optional final normal protocol control can be run manually with `Run-ProtocolPhoneTest.ps1 -Profile Benign`; it is an additional case, not part of the thirteen-case sheet. `SlowScan` and `Beacon` are optional controlled profiles documented in the component guide.

## 7. Save and interpret results

- Controlled runs: `runs/manual_phone_tests/<run_id>/`, including `run.json`, `check.json`, packet evidence and target events. Combined local chronology: `results/manual_phone_tests/TEST_LOG.md`.
- Protocol runs: `runs/protocol_phone_tests/cases/<run_id>/`, including `run.json`, `review.json`, `effects.json`, `capture.pcap`, native traces and target/source events.
- Preflight: `runs/network_test_suite/preflight.json`.

Archive private originals. Publish only reviewed aggregate counts/hashes; exclude addresses, packet payloads, account details and other private data. An aborted path/capture/startup case is **inconclusive**, not a false negative. A healthy case with independently verified attack effect and no matched flag is a miss. Background-window alerts are not detections of test traffic.

Report four separate quantities: matched binary flags; family correctness; policy/activity groups; and visible notifications. A single scan can create many segments and grouped flags. The 32-password test includes a valid-login control. Compute TP/FP/FN/TN only for independently labelled, matching units; do not call a notification count accuracy. Compare protocol guessing with normal FTP/SSH controls, and keep model hashes and settings/cohorts separate.

The recorded [seven-case current snapshot](final_submission_report/EVIDENCE.json), [older protocol results](../results/protocol_phone_tests/RESULTS.md) and [final report](final_submission_report/README.md) include false positives and missed behaviours. Repeating commands is a new cohort and need not reproduce every historical count.

## 8. Common failures

| Error | Action |
|---|---|
| No device / unauthorized / offline | Check the selected serial in `adb devices -l`; reconnect/authorize only the owned phone. USB reduces wireless dropouts. |
| No private Wi-Fi address on local WLAN | Enable Wi-Fi and verify controller routing/client isolation. ADB connectivity alone does not provide a phone Wi-Fi test target. |
| History not ready | Leave monitoring on for at least 300 seconds after a restart. |
| SSH timeout or changed hostname/key | Check each source's current address, wake state, OpenSSH and approved scoped firewall rule; verify changed keys independently before updating. |
| Phone/controller address changed | Repeat protocol Prepare before starting another case. |
| Target did not become ready | Unlock the phone, keep it awake and check installed lab apps. Keep the failed attempt separate. |
| Capture ended / low space | Review capture stderr and available storage; do not score incomplete evidence as a model miss. |
| Normal control flagged | Keep and investigate it as an error case; do not delete it to improve the score. |
