# Attack test audit: what each phone test really proves

Reviewed 25 November 2026 against the harness code (`validation/controlled_phone_test.py`,
`validation/protocol_phone_test.py`, `android/trafficlab`, `android/protocolcore`,
`validation/protocol_lab/*.ps1`), the feature contract, the alert policy and the saved
results in `results/`. Purpose: make sure no project claim says the model detected an attack
when the evidence does not support it.

## 1. Short answer

| Attack test | Is the generated traffic a real example of that attack? | Did the model detect it *in a way that means something*? | Safe to claim? |
|---|---|---|---|
| **Port scan** (129 ports, TCP connect) | Yes: a genuine small TCP connect scan from one LAN PC | Flagged, and most segments were labelled *Port Scan*. **But** single unanswered inbound connections are also flagged (see 3.5). | **Yes, with wording below.** Run the two verification cases to strengthen it. |
| **Slow scan** (32 ports, 1 port/s) | Yes, but only "slow" relative to the fast scan (real stealth scans wait 10s or more) | Flagged, mostly *Port Scan* | Yes, as "a 1-port-per-second scan" |
| **FTP brute force** (32 wrong passwords) | Yes: real FTP protocol, 1 connection per attempt (like FTP-Patator, much smaller) | **No.** Normal FTP logins were flagged at the same rate (3/4). | **No.** |
| **SSH brute force** (32 wrong passwords) | Yes: real encrypted SSH (Apache MINA), 1 connection per attempt | **No.** 4/4 normal SSH logins (including correct-password logins) were flagged. | **No.** |
| **HTTP password guessing / SQLi / XSS** | Yes, against a deliberately vulnerable lab app, over **plain HTTP** | Flagged, but the model was **trained on traffic from the same lab and phone** (before that training it detected 0/64). The detection uses regex-style HTTP header cues. | Only as "detects the lab's cleartext web attacks it was trained on". Not as general web-attack detection. |
| **DoS** (96 requests, 6 workers, 1 PC) | Weak: about 5 requests/s against a dummy service with **2 slots**, so denial is guaranteed by design. Not like Hulk/GoldenEye/Slowloris. | **No.** Only the 18 requests that waited 1 s were flagged; none of the 78 refused requests were. | **No.** Report as missed. |
| **DDoS** (3 PCs × 32 requests) | Weak: same toy service; real multi-source overlap is verified, but the volume is tiny | Missed (0/96) | Report as **missed** |
| **Bot / beacon** (12 PING/PONG every 3 s) | Emulator of C2 timing only, not malware | Missed (0/12) | Report as **missed** |
| **HTTP flood** (128 GETs in ~2.6 s) | No: about 50 requests/s is a burst, not a flood | n/a | Do not call it DoS |
| **Connection exhaustion** (16 requests holding a 2-slot resource for 5 s) | Toy resource exhaustion, not Slowloris (which holds *incomplete* requests) | n/a | Do not call it Slowloris/DoS |

## 2. What the model can actually see

The network model gets 147 numbers per connection. 32 describe the connection (packet/byte counts,
timing, TCP flags). 115 describe recent history over 5, 30 and 300 s: distinct ports and peers, SYN/RST
fractions, and HTTP request counts. It also gets **a few cues from the first plaintext HTTP header**:
`flow_sql_like_requests`, `flow_script_like_requests`, `flow_login_like_requests`,
`flow_http_auth_failures`, plus flags such as `flow_ssh_banner_seen` and `flow_ftp_banner_or_credentials_seen`
(`android/app/src/main/assets/aligned_v2_contract.json`).

Consequences:
- **Web attacks are only visible over plain HTTP.** Almost all real phone traffic is HTTPS, where these cues are always zero.
- **SQLi/XSS "detection" relies largely on regex-like header cues**, i.e. close to a signature rule, not learned behaviour.
- **The model knows a connection is SSH/FTP.** In CIC-IDS2017 almost every SSH/FTP connection to the victim was a
  Patator brute-force attack. The model learned the shortcut "SSH/FTP ⇒ attack", which explains why it flags
  every normal login (offline Brute Force precision 0.9996, yet 7/8 normal logins flagged on the phone).

## 3. Problems found in the tests and reports

1. **Segments are not attacks.** The 129-port scan produced 512 decision segments (about 4 per port). "510/512 flagged"
   counts each port about four times. Use **connections** (129) or **scenarios** (1 scan) as the unit.
2. **Brute-force results have no discriminating power.** Attack attempts were flagged 61/64 and normal logins 7/8.
   The 21 Nov report already notes this; any summary line "SSH 32/32, FTP 29/32 detected" without that comparison is misleading.
3. **Rule, not model.** With the experimental *SSH and FTP episode alerts* switch on,
   `AuthenticationEpisodePolicy` relabels SSH/FTP traffic as **Brute Force** when 4 or more connections arrive from one peer
   within 30 s, even if the model said Benign. Any "Brute Force" label produced with that switch on is a
   counting rule. It is off by default; check `auth_episode_enabled` in the monitor log for each run.
4. **Same-lab training.** The Web Attack class was trained on 20 sessions from `nids.datasetlab`: the same phone, PC and
   Wi-Fi, with cleartext HTTP password guessing, spraying, SQLi and XSS. The 62/64 held-out result and any later
   SQLi/XSS/PasswordGuessing detections from `controlled_phone_test.py` are **in-distribution**.
5. **Unanswered inbound connections are flagged on their own.** On 25 Nov a single 2-packet incoming
   connection from a LAN PC to port 7680 (Windows Delivery Optimization, normally benign) scored 0.89 (`results/passive_notice_review_20261125`).
   So the gate fires on unsolicited connection attempts, not only on scans. The *Port Scan* **label**
   (not the alert) is the scan-specific part.
6. **DoS/DDoS effect is guaranteed by the target.** `LabServer` allows 2 concurrent `/resource` requests, each held 1 s.
   Any 3 overlapping requests cause "denial". The test proves the harness works, not that a DoS happened in any
   realistic sense. The flagged DoS connections were exactly the slow, served ones (18/18), and none of the refused ones (0/78).
7. **Tiny samples.** XSS = 1 request, SQLi = 2 injection requests, one port scan, one run per profile. These are
   demonstrations, not accuracy estimates.
8. **Report bug (fixed in this commit).** `results/augmented_v1_phone_trial` labelled the PortScan run
   "Inconclusive: beacon exchanges did not complete". The code was wrong; the scan *was* flagged. Corrected to
   "Controlled scan detected (label corrected)".

What the harness does well (keep saying this): every case has an independent packet capture and
target-side event log, flags are matched to the exact test connections, background flags are excluded, model hashes are
pinned, and failed runs are kept separate.

## 4. Claims you can safely make

> "In controlled tests on our own Pixel 6a, Rakshak flagged a TCP connect scan of 129 ports from a LAN PC and
> labelled most of it as Port Scan. It also flagged a slower 1-port-per-second scan. After adding phone data from our
> lab, it detected 62 of 64 held-out cleartext web-attack segments from the same lab setup.
> It did **not** reliably detect SSH/FTP brute force, because normal logins were flagged at the same rate,
> and it missed our low-rate DoS, three-source DDoS and bot-beacon emulations."

Do **not** say: "detects DDoS/DoS/bot attacks", "detects SSH/FTP brute force", "detects SQL injection/XSS" (without
"cleartext, same lab"), "510 attacks detected", or any accuracy % for live attacks.

## 5. Verification runs (about 40 minutes, on the work PC)

These test whether the remaining positive claims are real or a shortcut. Start Rakshak monitoring and wait 5 minutes,
then run **one command at a time**:

```powershell
git pull
python reproduce.py build-android --sdk $env:ANDROID_HOME   # only if the apps changed
$env:NIDS_DEVICE_SERIAL='YOUR_SERIAL'

# A. Negative control for port scan: ONE closed port, 3 tries, 20 s apart (normal app retry)
.\validation\Run-ControlledPhoneTest.ps1 -Profile ClosedPortControl
Start-Sleep -Seconds 305
# B. Same port scan with a real tool (install nmap from nmap.org first)
.\validation\Run-ControlledPhoneTest.ps1 -Profile NmapScan
Start-Sleep -Seconds 305
# C. Negative control for password guessing: same rate, ordinary pages, no login
.\validation\Run-ControlledPhoneTest.ps1 -Profile NormalBurst
Start-Sleep -Seconds 305
# D. Repeat the scan once more so it is not a single run
.\validation\Run-ControlledPhoneTest.ps1 -Profile PortScan

# Then summarise ALL saved runs (old and new) per connection. No phone needed.
python validation\summarize_attack_claims.py
```

Optional: `-Profile NmapScan -NmapType syn` (Administrator PowerShell + Npcap) tests a SYN scan, which is nmap's default.

How to read the results:

| Result | Meaning |
|---|---|
| ClosedPortControl **not** flagged, PortScan + NmapScan flagged | Scan detection is genuine. Claim it confidently. |
| ClosedPortControl flagged but labelled Unclassified, scans labelled Port Scan | The alert is not scan-specific, but the Port Scan label is. Claim "labels scans as Port Scan". |
| ClosedPortControl flagged as Port Scan | The model flags any unanswered connection. Weaken the claim to "flags unsolicited inbound connections". |
| NmapScan missed | Detection does not transfer beyond our script. Do not claim general scan detection. |
| NormalBurst flagged | The Web Attack decision is rate-based. Do not claim password-guessing detection. |

Send back `results/attack_claims_review/SUMMARY.md` and `summary.json`, either by committing them on a branch or by pasting them.
They contain counts and run IDs only, with no IP addresses or payloads. The claims in the README and report will then be updated to match.
