# Synthetic SMS follow-up - 24 November 2026

Code46 / 0.17.3-link-extraction corrects URL/email overlap in SMS preprocessing. Weights, thresholds and threat feeds are unchanged.

## Actual incoming evidence before this update

The new standalone celebration SMS arrived at **03:26:20 IST**, with latest result LOW / fast_path_simple_celebration / no deeper scan. It produced no new history alert. The two visible celebration warnings were older observations at02:46:06 and02:47:00, preserved through upgrades. A saved warning is not a fresh notification. Original history remains intact.

The user's first and third synthetic examples generated URL PHISHING findings (0.9942975391 and0.9856403305). The second example generated a misleading SMS warning: EMAIL_PRESENT, zero extracted links. Its explicit HTTPS URL contains userinfo before an @. Email masking ran first and destroyed the address before URL extraction. Thus the initial three warnings represented **two URL-model positives and one SMS warning**, not three confirmed URL-model detections.

## Fix

Protect explicit HTTP/HTTPS/FTP URL spans while identifying/masking email addresses. Email-like text in URL userinfo or query parameters stays inside its URL and reaches the URL detector intact. Ordinary standalone email addresses still become email_present and do not turn into URLs. Existing unrelated preprocessing and the code45 link-only/celebration routing stay unchanged.

## Phone replay after the fix

| Input case | URL score | URL verdict | Combined warning |
| --- | ---: | --- | --- |
| Synthetic bank verification | 0.9942975391 | PHISHING | Yes |
| Synthetic userinfo/@ | 0.9919364575 | PHISHING | Yes |
| Synthetic payment | 0.9856403305 | PHISHING | Yes |
| Synthetic delivery | 0.5537486282 | UNCERTAIN | No |
| Neutral library example | 0.1763477741 | UNCERTAIN | No |
| Neutral weather example | 0.0646751158 | LIKELY_SAFE | No |
| Normal music link | 0.1513457164 | UNCERTAIN | No |
| Standalone celebration | Not applicable | No link | No |
| Previously reported risky live link | 0.0027492583 | LIKELY_SAFE | No |

These are nine exact private replays of user-delivered messages through the Pixel pipeline. All eight links are now extracted. Synthetic .invalid addresses have no live phishing content, so3/4 model-positive patterns is not a phishing recall/accuracy estimate. The previously reported live URL's ground truth remains unverified and its URL verdict is unchanged. No destination was opened and no new SMS sent.

## Validation and privacy

Android app/test builds pass. Native SMS tests retain all230 previous scenario outcomes and14/14 reference classes; the known strict numeric drift is still reported. Three new extraction cases cover userinfo, query email and ordinary standalone email. Existing protected routing controls pass. Real service notification/Llama checks run separately and their final result is included in validation.json. Marked fixture events are removed, original user history is preserved, and the original switches/capture state restored. Raw inbox text, sender identities and full private URLs stay under ignored runs; temporary private device replay inputs are removed after checking.

See [validation.json](validation.json). Earlier diagnosis: [SMS review](../sms_alert_review_20261124/README.md).

Final service check passed all three notification/Llama events after replacing the immediate notification snapshot with a bounded five-second visibility wait. The original immediate-snapshot failure remains recorded in `initial_service_attempt`; the passing retry is separate. All eight original safety observation IDs and enabled incoming/SMS/URL controls were verified after cleanup.
