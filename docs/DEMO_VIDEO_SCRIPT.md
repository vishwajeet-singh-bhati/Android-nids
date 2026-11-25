# Rakshak: 2-minute demo video guide

Target: **about 2:00 · 1920×1080 · 16:9 · MP4 · Public** on YouTube or Google Drive.

## Before you record (about 15 minutes)

1. Install the current APK on the demo phone. Turn on **Automatically check incoming SMS and links** and grant the permissions.
2. Turn on **Do Not Disturb** (with Rakshak allowed) and hide personal notifications, contacts and account names.
3. Rehearse the three test inputs below in **Check a message or link** and note the verdict each one actually gets. **Show only real app output.** If an input doesn't give the result you expected, pick another one. Don't fake a screen.
4. If the rooted phone already has network activity in the history (for example, the port-scan test), open it once so you know where it is. If you don't have it, use the slide fallback in scene 4.
5. Prepare two simple slides (16:9): the architecture figure from the report (section 3) and a results card (table below).

Suggested test inputs (invented, with no real people or brands):

| Purpose | Paste this |
|---|---|
| Scam SMS (OTP request) | `Your OTP is 482913. Share it with our delivery agent to reschedule your parcel.` |
| Normal SMS (should stay quiet) | `Never share your OTP with anyone. Our bank staff will not ask for it.` |
| Link check | A phishing-style URL you tested beforehand, then a normal site such as `https://www.wikipedia.org` |

To show the **automatic** SMS path, send the scam text from a second phone as a normal carrier SMS (not RCS/WhatsApp) and record the notification appearing.

## Script and shot list

| Time | Say | Show |
|---|---|---|
| 0:00–0:12 | "Hi, we are Vishwajeet, Sumit and Lakshya from IIITDM Kurnool. This is **Rakshak**, an Android app that detects scam SMS, phishing links and network attacks, entirely on the phone." | Logo/title card with team names, then the app home screen |
| 0:12–0:27 | "Rakshak runs three AI detectors locally. Nothing goes to the cloud: the app doesn't even have internet permission. Each detector can be switched on or off." | Detection controls screen, pointing at the three switches |
| 0:27–0:42 | "Here's the architecture. Messages go through fast rules and a small model first, and an INT8 MobileBERT only when needed. Links use a character CNN plus an n-gram model. Network traffic becomes 147 features for a gate model and an attack-family model." | Architecture slide |
| 0:42–1:05 | "Let's receive a scam SMS asking to share an OTP. Rakshak warns immediately and explains what happened and what to do. A normal OTP message stays quiet." | Real notification and the "What happened / What you can do" screen, then the normal message result |
| 1:05–1:20 | "Links are checked automatically. This look-alike link is flagged, and a normal site is not. The app never opens the link." | Check screen: phishing verdict, then likely-safe verdict |
| 1:20–1:35 | "On a rooted test phone, Rakshak also watches network connections. Here, a port scan from our lab PC was detected and grouped into a few clear alerts." | Saved activity in History (fallback: protocol-test results slide) |
| 1:35–1:52 | "Results: 97% accuracy for SMS, 0.976 ROC-AUC for links, and about 1 to 4 milliseconds per check on a Pixel 6a. Quantization made MobileBERT 59% smaller. It does not yet detect brute force, DoS or bots reliably, and we document that openly." | Results card slide |
| 1:52–2:00 | "The code, models and full report are on GitHub. Thank you!" | Closing card: GitHub URL and team names, held for 5 seconds |

Results card text:

```
SMS scams     97.1% accuracy · 89.8% scam recall (INT8 MobileBERT)
Phishing URLs 0.976 ROC-AUC · 3.9 ms per link on Pixel 6a
Network       controlled port scan flagged as Port Scan · 1.18 ms per check
Optimisation  INT8: 87.5 → 35.5 MiB · cascade routing · 5.4× faster LLM advice
Privacy       100% on-device · no INTERNET permission
```

## Recording and editing (Windows)

- **Phone screen:** use Android's built-in **Screen record** (Quick Settings), or from the PC: `adb shell screenrecord --time-limit 170 /sdcard/demo.mp4`, then `adb pull /sdcard/demo.mp4`.
- **Edit:** Clipchamp (built into Windows 11) or any editor. Create a **16:9 1920×1080** project, place the portrait phone video in the centre (don't stretch it), add the slides, then record the narration in a quiet room.
- **Export:** 1080p MP4. Check that the length is close to 2:00 and that the text is readable.

## Upload

1. **YouTube:** Create → Upload → set Visibility to **Public** (not Unlisted or Private). For **Google Drive:** Share → General access → **Anyone with the link** (Viewer).
2. Open the link in a private/incognito window to confirm it plays without signing in.
3. Paste the link into the submission form, and replace the placeholder line in the top table of `README.md` with it.
