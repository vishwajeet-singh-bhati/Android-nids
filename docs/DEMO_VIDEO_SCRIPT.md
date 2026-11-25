# Two-minute Rakshak submission demo

Target: **120 seconds,1920x1080,16:9,MP4**. This is a script/recording plan, not
an uploaded video. Record after the current live evaluation ends; do not
interrupt a campaign, stage a false alert, or run tests concurrently for footage.
The narration below is approximately240 words; rehearse once at a natural pace.
Use the actual app screens and your own saved, valid results.

## Timed narration and screen plan

| Time | Say this | Show this |
|---|---|---|
|0–12s|“This is Rakshak, an Android research prototype that brings network intrusion warnings, scam-message checks and phishing-link detection into one app.”|Title/logo for3s, then real app Home. Small caption: “Research prototype · on-device analysis.”|
|12–27s|“The three detectors can be switched independently. Processing happens on the phone. Network monitoring needs a rooted test device; message and link checks can work without root.”|Settings: point to three switches and incoming-SMS option. Show current app version; avoid personal accounts or identifiers.|
|27–43s|“For network activity, Rakshak summarizes connections and their recent history. A small model checks for suspicious behavior. A second model suggests a possible category when the evidence supports one.”|Simple connection → binary check → possible category diagram; then foreground monitoring indicator. Do not show raw packet payloads or claim the model reads encrypted passwords.|
|43–60s|“Here is a controlled port scan against our test phone. The app groups repeated detections into activities. In this normal control, eight requests produced no warnings. These are limited lab observations, not universal accuracy claims.”|Previously recorded/saved valid PortScan activity and matching test report, then Benign0/8 result. Label it “one bounded PortScan case; repeated flags grouped.” Use real footage only if the matching case actually alerted.|
|60–77s|“Incoming carrier messages can be checked automatically. When a message contains a link, the URL detector checks the address too. Messages without links skip that detector. Pasted or shared text can also be checked.”|SMS/URL flow diagram and Check screen. Use invented examples and label “authored demo message.” For receiver footage show a real carrier-SMS test, not RCS/chat.|
|77–94s|“A warning first explains what happened and what to do in simple language. Local Llama can then add checked guidance. If generation fails, a factual fallback remains. App names appear only when ownership can be established.”|Open a genuine activity; zoom to “What happened” and “What you can do.” Show actual generated/fallback source accurately; never relabel fallback as Llama output.|
|94–108s|“The project includes model training, preprocessing and phone test tools. Our tests record packets and independent target outcomes, so an unrelated background warning is not counted as a successful detection.”|GitHub repository folders, REPRODUCE.md, one sanitized report/evidence screenshot. Show current commit briefly; no raw captures, keys, messages or lab passwords.|
|108–120s|“False positives, missed cases and limited datasets remain. The repository and report document these limits, the measured results and the steps needed to repeat the experiments.”|Final card: repository URL, report path, “Known limits documented.” Keep link visible for at least5s.|

## Prepare before recording

1. Read [reproduction guide](../REPRODUCE.md), then freeze the app/model/source
   version used in the video. Use the version actually shown; do not mix an old
   report with a new app and imply one measured experiment.
2. Choose one valid normal control and one valid suspicious case. Keep the
   matching report, app activity and time window together. If a case misses,
   report the miss; use another genuinely detected case for the UI demonstration.
   The25November provisional evidence is Benign0/8 flags and one PortScan with
   504 matched segment flags grouped into6 visible notifications. Those are
   **not**504 independent attacks or general precision/recall. Refresh this
   caption from the final verified campaign before submission.
3. Optional SMS/link footage: use your own invented non-personal text and show
   the actual returned verdict. A suspicious-looking reserved `.example` URL is
   an interface test, not labelled real-world phishing. Never open a phishing
   page or collect credentials just for a demo.
4. Use the UI's actual Activity history; avoid clearing it during a campaign.
   Hide personal notifications and sender/account details. Do not claim
   unsupported RCS/WhatsApp/browser monitoring or automatic attack blocking.
5. Make a slide for the three detector paths and a small results/limitations
   card. These can be static; record the actual app for the UI portions.

## Record and edit

- Use a1080p16:9 landscape PC canvas. Put the portrait phone recording in the
  center, with short captions at the sides; do not stretch the portrait image.
  Use a camera or a trusted screen recorder. USB mirroring is optional; obtain
  it separately and do not navigate the phone during a running evaluation.
- Capture the app segments and diagrams first, then record the narration in a
  quiet room. Edit to the timestamps above with any editor you already use.
  Cut footage rather than speeding speech until it is difficult to understand.
- A full network test takes minutes because of history warm-up/observation.
  Show a short excerpt and label skipped waiting; do not suggest it finishes
  in a few seconds. If displaying saved footage, identify the recorded case.
- Export MP4,1920x1080,16:9, approximately120s, with clear speech. Avoid loud
  music, tiny code text, fast transitions and terminal dumps.

Optional Android-native recording, **after** evaluation and with personal
content hidden:

```powershell
adb -s $env:NIDS_DEVICE_SERIAL shell screenrecord --time-limit 120 /sdcard/rakshak-demo.mp4
# While it records, perform only the planned UI demonstration.
adb -s $env:NIDS_DEVICE_SERIAL pull /sdcard/rakshak-demo.mp4 .\rakshak-demo.mp4
```

This records the display only; record narration separately. The phone's output
may be portrait and needs the landscape canvas in editing. Keep the local MP4
out of Git; this is not an instruction to upload it now.

## Final viewing checklist

- Duration close to2minutes;1080p16:9MP4; readable text and audible narration.
- All three pipelines and the common warning/explanation flow are visible.
- Actual version/result identities match; normal and suspicious cases have
  evidence; authored fixtures and fallback text are labelled honestly.
- No claim of100% protection, all-class coverage, universal no-false-positives,
  complete message interception or automatic blocking.
- Public repository/report links are correct; no personal data/keys/passwords.
- After user/faculty review, upload to YouTube or Google Drive with **Public**
  access and test the link signed out. Record the final URL in
  [submission checkpoints](../SUBMISSION_CHECKPOINTS.md). This document does not
  submit/upload anything; only the first final challenge submission counts.
