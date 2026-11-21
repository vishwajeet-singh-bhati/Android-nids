# Manual protocol and multi-source tests

Use an owned rooted test phone and three owned Windows PCs (controller plus two SSH sources) with a reachable private LAN path. The protocol target is disposable and separate from NIDS. Do not expose it publicly. Build using the Android guide; no test launches during a build or preview.

OpenSSH on the two source PCs must already accept your public key; pin their host keys in your own known-hosts file and verify fingerprints through a trusted channel. No credentials/private keys/actual host identities are published. Put this configuration into ignored`runs/protocol_phone_tests/ssh_config.json`, replacing all examples:

```json
{
  "identity_file": "C:/Users/YOU/.ssh/owned_lab_key",
  "known_hosts_file": "C:/Users/YOU/.ssh/known_hosts",
  "hosts": [
    {"name":"PC1","host":"10.0.0.20","expected_hostname":"YOUR-PC1","login":"YOUR_LOGIN","identity_verified":true},
    {"name":"PC2","host":"10.0.0.21","expected_hostname":"YOUR-PC2","login":"YOUR_LOGIN","identity_verified":true}
  ]
}
```

These are configuration placeholders, not credentials or verified addresses. `identity_verified` records your explicit selection; Prepare still verifies actual hostnames with strict pinned-key SSH, administrator capability and script-policy compatibility. It refuses mismatches. Choose`NIDS_DEVICE_SERIAL`explicitly; optional`NIDS_SSH`,`NIDS_POWERSHELL`,`NIDS_JAVA`,`NIDS_ADB`override tool discovery. Controllers require Windows PowerShell 5.1; use WSL for research training, not Windows remote-source orchestration.

```powershell
$env:NIDS_DEVICE_SERIAL='YOUR_ADB_SERIAL'
New-Item -ItemType Directory -Force runs/protocol_phone_tests | Out-Null
# Save your private configuration above, then inspect a zero-action preview:
.\validation\Run-ProtocolPhoneTest.ps1 -Profile DDoS -Preview
.\validation\Run-ProtocolPhoneTest.ps1 -Profile Prepare
.\validation\Run-ProtocolPhoneTest.ps1 -Profile Status
```

Prepare installs the inert lab, copies bounded helpers to the two explicitly configured PCs and checks platform availability without listeners/test traffic. It does not create a receiver rule until the manual BotBehavior profile. Source-admin access is needed for the scoped temporary receiver rule and cleanup watchdog; managed blocks are not bypassed.

Run **one** case at a time, inspect it, then choose the next command manually:

```powershell
.\validation\Run-ProtocolPhoneTest.ps1 -Profile Benign
.\validation\Run-ProtocolPhoneTest.ps1 -Profile FTPBruteForce
.\validation\Run-ProtocolPhoneTest.ps1 -Profile SSHBruteForce
.\validation\Run-ProtocolPhoneTest.ps1 -Profile BotBehavior
.\validation\Run-ProtocolPhoneTest.ps1 -Profile DoS
.\validation\Run-ProtocolPhoneTest.ps1 -Profile DDoS
.\validation\Run-ProtocolPhoneTest.ps1 -Profile Benign
```

Each case restarts/warms NIDS for 305 seconds and observes 130 seconds afterward; no additional manual sleep is needed for this runner. Logs distinguish warm-up from traffic. History is retained. Full phone-local capture includes background context, snaplen 768 and 2 million-packet cap; at least 2 GiB free on phone/controller is required. Early capture/path failures are incomplete attempts, not detector misses. No next case is scheduled.

| Profile | Actual bounded behaviour | Expected family / ground truth |
|---|---|---|
|Benign|One wrong and one valid dummy FTP/SSH login; five normal HTTP probes|No flag expected; single mistakes are controls |
|FTPBruteForce|32 wrong dummy passwords, actualFTP dialogue|BruteForce; server rejects each login |
|SSHBruteForce|32 wrong dummy passwords, real encrypted SSH authentication|BruteForce; no shell/exec/SFTP/forwarding |
|BotBehavior|12 outbound PING/STATUS exchanges to owned receiver|Restricted Bot-behaviour emulator, not real malware |
|DoS|96 requests/≤6 workers against 2 dummy resource slots|Confirm service denials and normal-probe recovery |
|DDoS|3 physical sources×32 requests/≤2 workers each|Verify distinct sources/overlap and dummy-service impact |

HTTP/scan tests and their separate 305-second inter-case isolation rule are in [PHONE_TESTING.md](PHONE_TESTING.md). Do not conflate HTTP password guessing(Web) with FTP/SSH BruteForce. A tiny bounded load is not a general volumetric DDoS benchmark. Completed counts and misses are in [reviewed results](../results/protocol_phone_tests/RESULTS.md).

Private case outputs include PCAP, target/source events, native 147-value traces, health and notification snapshots under`runs/protocol_phone_tests/cases`. The runner checks exact tuples/packet counts/timestamps. `review_protocol_results.py` audits the frozen original sequence only when those recordings are supplied; it does not silently replace it with later retries. No private recording is shipped.
