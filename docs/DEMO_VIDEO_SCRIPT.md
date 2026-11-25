# Rakshak: two-minute demonstration

**Order:** tech stack → pipeline → app tour → PC PortScan → normal traffic → results/weak cases → four SMS examples → limitations.

Target120seconds,1920×1080,16:9,MP4. Read only **Narration** aloud. Record real clips separately and edit them together; warm-up and test observation take minutes and must be labelled when omitted. This document does not run tests, send messages, record/upload a video or submit the form.

## Timed script and screen actions

| Time | Narration | Show on screen |
|---|---|---|
|0–12s|“Rakshak uses Android and Kotlin, PyTorch-trained models, ExecuTorch inference, and a quantized local Llama. It combines network, scam-message and phishing-link checks.”|Logo1s, then **Kotlin/Android · Python/PyTorch · ExecuTorch · Llama3.2 1B INT4**. Small caption: rooted capture for network monitoring.|
|12–22s|“Connections, message text and extracted links reach their respective detectors. Suspicious findings produce immediate factual warnings, followed by optional local Llama guidance.”|Diagram: flow statistics → binary gate → possible category; SMS → message detector; extracted URL → URL detector; all → facts and guidance.|
|22–40s|“Home controls monitoring. Check accepts pasted messages or links. Activity keeps seven-day records, explanations and Clear history. Settings controls each detector separately and enables automatic incoming-message checks.”|Home3s, Check3s, Activity5s, Settings7s. Point to Start/Pause, explanations, feedback/Undo, Clear history, three detector switches and incoming-SMS switch. Advanced information can be captioned. Do not clear evaluation history.|
|40–55s|“From the PC, I run a bounded port scan against our test phone. Rakshak flags scan-like activity and explains what happened and what the user should do.”|Exact PortScan command → real report → matching phone alert and explanation. Caption across cuts: **Waiting omitted; real recorded test**. Use a genuinely detected case.|
|55–64s|“Next comes normal traffic. Here, eight normal test flows are classified as benign, with no flags on those flows.”|Benign command and actual8-flow result. Caption: **Test flows:0/8 flagged; background warnings assessed separately**.|
|64–79s|“Our lab results show strong scan and SQL-injection detection, partial password-guessing detection, and missed XSS and connection-exhaustion cases. Traffic differences and limited context are possible reasons.”|One results card, using the verified snapshot below or its finalized replacement. Mark misses red and partial detection amber. Footer: **Bounded lab cases; not general accuracy**.|
|79–110s|“Now I send four test messages: a normal message, a scam asking for an OTP, promotional spam with a suspicious test link, and a normal message with a legitimate link. Incoming SMS is checked automatically; extracted links also reach the URL detector. The actual warning or safe result appears on the phone.”|Four clips: normal7s; scam8s; spam/test link8s; normal/legitimate link8s. Show sender/receiver and actual app output. Caption invented content **Authored demo**. Never force a verdict.|
|110–120s|“Rakshak warns; it does not block connections. False alarms and missed attacks remain possible. Source, results and reproduction instructions are available on GitHub.”|Final card: repository URL, report path, **Warnings, not blocking · Best-effort attribution · Limited validation**.|

Rehearse against the timestamps. Use captions for secondary details instead of increasing speaking speed until the demo is hard to follow.

## Commands for the PortScan and normal-traffic clips

Record these **after the automated campaign finishes**, with monitoring enabled, the phone unlocked and the selected owned phone/PC reachable. Do not run manual demo cases alongside evaluation.

```powershell
Set-Location D:\NIDS-development
Start-Sleep -Seconds 305
.\validation\Run-ControlledPhoneTest.ps1 -Profile PortScan

Start-Sleep -Seconds 305
.\validation\Run-ControlledPhoneTest.ps1 -Profile Benign
```

Reviewers use their own clone path and [REPRODUCE.md](../REPRODUCE.md) first. Each command also observes130seconds after traffic. Show command submission → report → corresponding app activity, with **waiting omitted** on the cut. Do not imply the full sequence takes24seconds. The existing harness still uses ADB; the proposed standalone no-debugging workflow is not implemented yet.

If a demonstration case misses or a normal flow flags, retain that outcome. Never inject a model alert, fake terminal output, or substitute an unrelated background notification. Opening the phone's warning should show **What happened** and **What you can do**. Attribute advice to Llama only if generation actually ran and was accepted; otherwise identify the factual fallback.

## Results card: currently verified snapshot

As of25November2026,21:20IST, **6/13 code53 cases were completed**:

| Profile | Matched segments flagged / observed | Interpretation |
|---|---:|---|
| Normal HTTP |0/8|Test flows remained benign |
| PortScan |505/510|503 typed Port Scan;2 Unclassified |
| HTTP password guessing |16/32|5 typed Web Attack;11 Unclassified; partial detection |
| SQL injection |2/3|Both injection flows flagged; the control was benign |
| XSS |0/1|Missed despite target execution proof |
| Connection exhaustion |0/16|Missed despite dummy-resource denials |

HTTPFlood, protocol Benign, FTP, SSH, BotBehavior, DoS and DDoS were pending at that snapshot. **Do not mark them passed or missed before their reports finish.** Before final submission, replace this card with finalized aggregate results from the folder in `runs/network_campaign_latest.txt`. Keep the same15-second slot; a compact detected/partial/missed matrix can accommodate all completed profiles.

These are segments/flows from bounded cases, not505 independent attacks or general precision/recall. The benign window also had3 unrelated background flags and2 visible activity groups: say **no flags on the test flows**, not “the phone had no alerts.” Notification counts are not attack counts.

The first five cases used experimental local alerts; ConnectionExhaustion and subsequent resumed cases use normal external-only scope. Models/thresholds are unchanged, but do not pool background false-alert rates across those settings. Captions may list **dataset-to-phone traffic differences** and **limited application context** as possible reasons for weak cases; these are hypotheses, not proven root causes for every miss.

## Four authored message examples

Use your own second phone/SIM and actual **carrier SMS**, not RCS/WhatsApp. Enable incoming SMS and both SMS/URL detectors. No real passwords, account numbers or OTPs.

| Clip | Example text | Inspect |
|---|---|---|
| Normal text |Hi, our meeting is at4pm. Please bring your notebook.|Actual normal/no-warning result. Report an unexpected warning honestly.|
| Scam |Your account will be blocked today. Reply with your OTP and PIN immediately to keep it active.|SMS risk and advice; the request is invented.|
| Promotion with phishing-style test URL |Congratulations! Claim your cash prize now: http://accounts.google.com.security-check.example/claim|Automatic URL extraction plus SMS/URL results. `.example` is a non-public authored test address, not verified real phishing.|
| Normal text and legitimate link |Here is the video we discussed: https://www.youtube.com/|Automatic link checking and actual outcome; do not claim every link on a popular domain is safe.|

Rehearse these inputs before recording: their predictions are **not guaranteed**. Show UNCERTAIN or a miss if that is the outcome. If replacing a string with another previously verified authored demonstration input, retain its exact text/result with the footage. Four chosen examples are interface demonstrations, not an independent accuracy benchmark. Do not visit the suspicious address or create a credential-collection page.

The narration says “actual warning or safe result” so it does not promise success before the examples run. If using Check/paste instead of incoming delivery, caption **Manual input; not an SMS-receiver demonstration**.

## Functions to explain visually during the app tour

- **Home:** status and Start/Pause; pause confirmation affects monitoring only, not Internet access.
- **Check:** manual paste/share for supported messages and links.
- **Activity:** grouped warnings, explanation, seven-day history, review/Expected feedback, Undo and Clear history confirmation. Show clearing without deleting needed results. Never mark genuine suspicious traffic Expected just for a clean demo.
- **Settings:** independent detectors and automatic incoming SMS. Briefly caption model/resource information and research controls; explaining every advanced option aloud will exceed two minutes. Keep experimental on-device alerts **off for normal use**.

## Recording checklist

1. Collect real network/message footage first and retain matching reports and app/model versions. Earlier code51 cases are a separate cohort.
2. Use a1080p16:9 canvas with readable terminal/phone panels; preserve the portrait phone's aspect ratio. Hide personal notifications, accounts, keys, pairing codes and private network identifiers.
3. Record narration separately. Remove waiting, not failures, and label cuts, authored inputs and recorded excerpts. Do not navigate the phone during an automated evaluation.
4. Limitations card: false positives/misses, root needed for network capture, no automatic RCS/WhatsApp/old-inbox coverage, URL text analysis rather than page inspection, best-effort app ownership, and possible Llama fallback.
5. Export approximately120seconds,1920×1080,16:9,MP4. After user/faculty review, upload publicly and verify signed-out playback. Save the link in [submission checkpoints](../SUBMISSION_CHECKPOINTS.md). No upload or form submission is performed by this guide.
