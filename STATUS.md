# Current Rakshak status -24 November2026

## Reproducibility repair and manual test guide - 26 November 2026

Fixed the isolated notification-contract compilation failure without changing the production app or detector models. Hosted Android/Python checks passed on main `0d10f96` and PR2 `59de1b8`; details: [CI repair record](reproducibility/CI_REPAIR_20261126.json). Added the complete [manual network testing procedure](docs/NETWORK_TEST_PROCEDURE.md), the historical PowerShell command sheet and an optional strict sequential runner. Local checks: full Android build, 21 pytest checks, 4 metric tests and all three preview plans. No phone attack, installation, model change or historical-result replacement was performed.

## Concise final report prepared - 25 November 2026

The [19-page final project report](docs/final_submission_report/README.md) now includes the three team members, IIITDM Kurnool and Dr. Rohit Kumar Das. Cover page 1, index page 2, content page 3; numerical/pagination checks and visual review passed. It separates code-53 seven-case phone results, older protocol failures, archived SMS test scores and the URL known-positive subset. Current campaign ended at 21:38:49 IST with 7/13 completed; locked-phone target startup failed before case 8. It is not running, and that interruption is inconclusive. Models/app/phone unchanged by report work. Mentor approval, video publication and final form submission remain pending.

Current source/app: **0.18.0-passive-notices / code53**. The prior network-only code40 source remains in Git history. Network weights and thresholds are unchanged. SMS/URL models and the source recovered from the full SMS archive are included.

The original Pixel used a populated dated offline feed. This public build has an empty/stale database; populate it locally from permitted sources if desired. All three learned pipelines are present. The selected SMS training checkpoint, PTQ/QAT scripts and checked split hashes are included; datasets and raw/private content are excluded.

Publication is a development snapshot. Improvements, user candidate selection, faculty review, public video and the once-only form remain distinct gates. See [checkpoints](SUBMISSION_CHECKPOINTS.md).

Known limits: network false positives/protocol misses; limited SMS language/real-message evaluation; strict native numerical drift; URL unknown labels and reference reuse; feed freshness; no automatic inbox/RCS/chat/browser interception; best-effort network app attribution; no proof of compromise from a flag. Llama advice does not repair detection.

Read the [components](components/README.md), [improvement plan](docs/MODEL_IMPROVEMENT_PLAN.md), [report](docs/project_report/README.md) and [changelog](CHANGELOG.md).

Branding update: code47 adds the original [Rakshak logo](docs/branding/README.md). Historical model/device measurements remain from their explicitly stated builds, including code46. Pixel code47 installed and checksum verified24 November;20 activities and settings preserved.

Network-note update24 November: code49 describes qualifying rejected incoming handshakes factually and groups repeats by peer/service. Raw model decisions are unchanged. A suppression candidate lost212 positive-labelled legacy-test detections and was rejected. SMS improvements are on hold. See [comparison](results/idle_network_repair_20261124/README.md).


## Code51 reproduction update —25 November2026

Code50 adds opt-in narrowly matched Expected-repeat feedback; code51 collapses
the feedback form and offers Undo. Neither changes model assets or raw scores.
See [feedback evidence](results/expected_repeat_feedback_20261125/README.md).
The current live13-profile campaign is incomplete; no final all-class result is
claimed. The [reproduction guide](REPRODUCE.md) documents setup, controls and
validity checks; the [demo script](docs/DEMO_VIDEO_SCRIPT.md) remains preparation,
not an uploaded video or mentor approval.


## Passive notice correction ?25 November2026

Code53 confirms manual monitoring pauses and records stop sources. Historical entries are no longer reposted on app launch; reset notes explicitly say Rakshak observed the connection rather than blocked it. Models/thresholds are unchanged. See [review and exact validation limits](results/passive_notice_review_20261125/README.md). The live campaign is incomplete and the manual cancellation check awaits an unlocked phone.


## Normal-use scope correction ?25 November2026

Two19:47?19:48 warnings were localhost exchanges, not recorded Google connections. The experimental local-alert setting was on. Restored default external-only alert scope without model changes;137 network records preserved,11 loopback rows separated, external evidence unchanged. See [review](results/signin_scope_review_20261125/README.md). The interrupted live campaign resumed with an explicit scope-phase annotation; it is not yet a completed benchmark.
