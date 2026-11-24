# User SMS alert review - 24 November 2026

Code45 / 0.17.2-message-routing is the correction to code44. Model weights, URL thresholds and saved threat feeds are unchanged. Original observations remain preserved; no inbox messages or user history were deleted. Recent six SMS bodies were read only from the short user-authorized test window on the rooted phone and retained privately under ignored runs. Raw bodies, senders and full links are excluded from this report. Temporary private replay inputs were removed from the phone.

## Findings

Both new links reached the phishing detector and completed inference. The music link scored 0.1513457164, giving UNCERTAIN; the other, user-reported phishing link scored 0.0027492583, giving LIKELY_SAFE. The feeds were stale. Neither was a URL-model PHISHING result. These results reproduced exactly when replayed; no evidence of an extraction or tensor-format failure was found for these two links. The live destination was not opened or independently authenticated; the second link's phishing ground truth awaits confirmation.

Both URL-only SMS messages normalized to `url_present`. The linear stage had smishing score 0.4896759 and the neural stage 0.9272169 for both. SMS lacked actual message prose to distinguish their URLs, so generic placeholder classification generated both warnings. This was inappropriate routing for a link-only message.

The two standalone celebration messages (`You won` and punctuation variant) had linear smishing score 0.4314044. A prize cue supported the Tier-1 high-risk policy. MobileBERT then gave ham scores 0.9989617/0.9959153, but high-risk preservation retained the alert. The problem was policy context, not Llama inventing a warning.

## Corrections and comparison

- Bare extracted links, with no remaining alphanumeric prose/contact data, use a `link_only` SMS fast path. The independent URL detector still decides link risk and can raise a phishing warning. This does not whitelist any domain or change URL scores.
- A narrow set of standalone celebration phrases stays low if there is no link/contact or other strong cue. Adding further instructions, a URL, payment or OTP request defeats this fast path. This is a small contextual correction, not a general prize-scam solution.
- Expose `sms_routing_reason` in final evidence for diagnosis.

| User test | Code44 warning | Code45 replay |
| --- | --- | --- |
| Standalone celebration | High | Low; no new warning |
| Celebration with punctuation | High | Low; no new warning |
| Normal music link | Suspicious from SMS | Low; URL remains UNCERTAIN |
| User-reported phishing link | Suspicious from SMS | Low; URL remains LIKELY_SAFE |

The last row is an unresolved coverage concern. The generic SMS warning on that link is removed along with the generic warning on the normal link. If the supplied phishing label is correct, this means the combined warning is lost for that case. The routing correction must not be claimed as an overall accuracy/recall improvement or as a repaired phishing detector. No domain blacklist was added from an unverified user label. Verified phishing examples and independent benign controls are needed for a URL model/data repair.

## Validation

App/test builds pass. Pixel contract checks and all 230 pre-existing authored SMS scenario outcomes are unchanged; 14/14 neural classes match the reference, with the previously documented strict numeric drift still failing. Five new routine/link-routing checks pass, plus three dangerous-extension controls that cannot take the fast paths. Six exact recent message bodies were replayed privately through the real phone pipeline; public results retain only aggregate/host-free comparison. SMS/standalone URL/embedded URL service notification and Llama tests pass. These are development regressions, not independent accuracy estimates.

See [validation.json](validation.json). The separate final service check verifies a known model-positive *bare URL inside a message* still has high combined risk and a real notification; its evidence is recorded alongside this report. Permission/settings and capture state are restored after fixtures, and all marked fixture observations are removed. Previous user warnings remain in history for review.
