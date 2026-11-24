# Plain alerts and interface — 0.16.0 / code42

Installed and hash-verified on the Pixel 6a on 22 November 2026. The release APK is `artifacts/releases/nids-0.16.0-plain-alerts.apk`.

## User experience

- Light background, dark text and blue controls. Monitor shows monitoring status and the latest activity. Activity lists recent entries first. Settings contains privacy information and an optional Advanced settings panel.
- Clear history is available in Activity and Settings. Its confirmation explains that saved activities, feedback and related notifications will be removed. Clearing uses a database transaction, cancels related notifications and generation, rejects late explanation callbacks and ignores detector evidence queued before the clearing timestamp. New activity can appear afterward.
- Alerts start with What happened and end with What you can do. App ownership uses short factual wording when an app is identified. Missing ownership is explained plainly. Measurements and connection addresses are under Technical details.
- A structured factual note and default advice appear immediately. Llama rewrites the advice using everyday words. Content checks retain default advice when a generated sentence fails validation. Existing saved notes render in the new format when their old explanation version differs.

Example of a Web alert with no verified owner:

> **What happened**
>
> A web connection looked unusual and may need your attention. We could not identify the app for this connection.
>
> This may be normal activity. An attack has not been confirmed.
>
> **What you can do**
>
> Review recent web activity and avoid entering passwords into unexpected prompts.

## Validation

Fourteen content fixtures passed across seven categories and known/missing app ownership. Isolated store checks verified clearing, rejection of stale detector evidence, rejection of late Llama responses and protection against restoring cleared legacy history. The real confirmation dialog, Cancel button, navigation and a historical activity's structured display were checked on the phone. Real user activity was retained during these checks.

Twenty-one native model self-checks passed with zero decision flips. Eight real production Llama requests completed; six generated guidance sentences passed checks and two used the default advice. Warm median request time was 3.599 seconds across seven requests. A labelled transient fixture notification was verified before Llama in 14 ms and removed. Recorded capture queue drops were zero. These timings describe fixture execution. They do not measure end-to-end detection latency or attack accuracy. [Release summary](summary.json), [content and history checks](content_fixtures.json), [Llama runtime](runtime.json), [native checks](native.json).

Builds used the work PC's existing offline Gradle cache. Private build logs, verification scripts and screen captures are under `runs/ui_refresh_20261122`. Source and APK version history are local.

## Problem statement reference

The supplied video is Arm Education's Bharat AI-SoC Challenge 2026–27 PS3 mentoring session. Its title and description were retrieved. The caption request returned no content, so no claim is made to have reviewed the full spoken session. The official brief calls for local cybersecurity detection, plain-language explanations and remediation guidance, using Llama through ExecuTorch on Arm hardware. It also lists phishing URLs and scam communications, which require their own detection and evaluation work beyond this network-interface release. [Mentoring video](https://www.youtube.com/watch?v=ujr8Nsx5WPo), [official PS3 brief](https://arm-education.github.io/Arm-Developer-Labs/Bharat_AI_SoC_2026_27.html).
