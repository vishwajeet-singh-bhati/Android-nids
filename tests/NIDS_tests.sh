# PowerShell command sheet. Historical .sh filename; this is NOT a Bash script.
# Run these lines individually in PowerShell from the repository root, or use:
# .\tests\NIDS_tests.ps1 -Preview
# .\tests\NIDS_tests.ps1 -PreflightOnly
# .\tests\NIDS_tests.ps1
# Setup, labels, output files and troubleshooting: docs/NETWORK_TEST_PROCEDURE.md
# Keep monitoring on, phone unlocked/charging, and all configured PCs awake.

Start-Sleep -Seconds 305
.\validation\Run-ControlledPhoneTest.ps1 -Profile Benign # 8 ordinary HTTP requests; no alert expected
Start-Sleep -Seconds 305
.\validation\Run-ControlledPhoneTest.ps1 -Profile PortScan
Start-Sleep -Seconds 305
.\validation\Run-ControlledPhoneTest.ps1 -Profile PasswordGuessing # 32 dummy HTTP logins, including 1 valid control
Start-Sleep -Seconds 305
.\validation\Run-ControlledPhoneTest.ps1 -Profile SQLInjection # 1 control and 2 isolated injections
Start-Sleep -Seconds 305
.\validation\Run-ControlledPhoneTest.ps1 -Profile XSS # isolated script execution in the lab target
Start-Sleep -Seconds 305
.\validation\Run-ControlledPhoneTest.ps1 -Profile ConnectionExhaustion # bounded dummy-resource exhaustion
Start-Sleep -Seconds 305
.\validation\Run-ControlledPhoneTest.ps1 -Profile HTTPFlood # 128-request burst; not proof of a volumetric DoS
Start-Sleep -Seconds 305
.\validation\Run-ProtocolPhoneTest.ps1 -Profile Benign # ordinary FTP/SSH logins and HTTP probes
.\validation\Run-ProtocolPhoneTest.ps1 -Profile FTPBruteForce
.\validation\Run-ProtocolPhoneTest.ps1 -Profile SSHBruteForce
.\validation\Run-ProtocolPhoneTest.ps1 -Profile BotBehavior # restricted emulator, not malware
.\validation\Run-ProtocolPhoneTest.ps1 -Profile DoS # bounded denial in the dummy service
.\validation\Run-ProtocolPhoneTest.ps1 -Profile DDoS # same dummy service, 3 owned source PCs
