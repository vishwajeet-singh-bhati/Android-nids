# Rakshak detection components

The current Android app combines three separately evaluated detectors. The original network work stays under `experiments/` and `models/current/`; these folders document the added message/link work without mixing its results with network detection.

| Component | Source and setup | Android implementation |
|---|---|---|
| SMS scam detection | [SMS component](sms/README.md) | `android/app/src/main/kotlin/com/bharat/smsguard/` |
| Phishing URL detection | [URL component](phishing_url/README.md) | `LinkDetector.kt`, `LinkNormalizer.kt` |
| Combined routing, notifications and Llama | [Integration](integration/README.md) | `SafetyPipeline.kt`, `MessageLinkPolicy.kt`, `SafetyAnalysisService.kt` |

[Full architecture](../docs/rakshak/architecture/README.md) and [current app guide](../docs/rakshak/README.md) describe inputs, layers, exact rules and limitations. All observed numbers retain their original cohort and unit. SMS fixtures, URL-list hits and network attack segments are different kinds of evidence.
