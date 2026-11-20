# Why the phone-aligned v2 scores dropped

Investigation of frozen checkpoints and actual validation/test error records. No retraining, model/threshold replacement, phone access, live attack or promotion. Counterfactual predictions are post-evaluation diagnostics, not new blind results. Reproduce with validation/diagnose_phone_alignment_v2.py (local WSL training Python), then validation/audit_phone_alignment_v2_patterns.py.

## What is directly measured

The historical context model and current pipeline do not share test rows, extraction, history visibility, sources, split, loss, optimizer or decision policy. The old CSV benchmark therefore cannot identify the causal cost of any one change. The width-32 aligned reference shares the new cohort, but is also a different architecture/decision policy.

All40 epochs completed for every job; all320 checkpoints remain. The diagnostic reproduced the published complete test confusion matrix exactly. Shared train/validation/test connection groups:0 for all three pairwise comparisons. Cached normalization agrees on more than10,000 sampled rows per split within maximum4.77e-7 absolute error under Windows versus training Linux NumPy; no material normalization mismatch was found. Earlier export checks matched960 cases/model with zero decision flips. Final phone source/model verification is still pending.

## 1. Bot inputs overlap ordinary failed connections

All496 benign test views assigned the Bot label are the same broad traffic shape: one packet each direction, zero payload bytes, SYN=1/RST=1/ACK=1, duration about0.318-1.530 milliseconds. These records have no HTTP, TLS, application payload or authentication evidence. There are408/640 true-Bot test views with the same broad reset pattern. A failed connection alone does not establish Bot activity.

Exact comparisons of all32 flow values:322/496 false Bot views have both Benign and Bot training counterparts. Among3,130 training Bot views,1,792 share all32 flow values with at least one Benign training view. Added context usually distinguishes full inputs, but full147-value contradictions remain:36 training Bot views also exactly match Benign training inputs. Nine true-Bot test views exactly match a Benign training input. Hash matches were followed by full float equality; no collisions were accepted.

All496 false Bot labels occur in Friday traffic,113 connection groups and6 watched endpoints;338 are associated with one endpoint. Test Bot labels occur roughly64-237 minutes after the first Friday test row, while false Bot labels occur241-435 minutes after it. This demonstrates phase/source concentration and similar later connection shapes. It does not prove that the publisher labels are incorrect or that all later connections were genuinely harmless. CSV tuple/time intervals are tentative labels, not application-level ground truth.

Interpretation: flow-only ambiguity is confirmed; limited discriminating context/application evidence is a plausible major contributor. Publisher phase/label quality needs independent audit before any relabeling. Do not interpret identical inputs as proof of duplicate complete captures or malware.

## 2. Rare-class weighting shifts the decision toward Bot/Web

Effective training loss weights relative to Benign: Bot8.27x, Brute Force4.35x, DDoS1.61x, Web18.86x. Training includes4,214,044 Benign versus3,130 Bot and602 Web views. Weights were intended to improve rare-class recall; they can increase false Bot assignments where inputs overlap. The broad reset pattern also appears in53,750 Benign and221,054 Port Scan training views, so weighting alone is not a full explanation.

A diagnostic division of diagnosis probabilities by the training loss weights changes test Bot precision54.29% ->87.11%, but recall92.03% ->52.81%. Validation shows the same tradeoff: precision52.22% ->80.41%, recall90.34% ->48.47%. This is evidence of a precision/recall tradeoff; it is not an unweighted retraining experiment, calibrated model, or acceptable fix. The binary gate is unchanged, so this operation does not remove its729 false alerts.

False Bot labels already have diagnosis confidence0.786-0.956 (median0.863). Raising the generic0.6 typing cutoff slightly will not remove them.

## 3. The binary gate is the main DDoS recall bottleneck

| True class | Support | Rejected by gate | Flagged unknown type | Flagged wrong named type | Correct final type |
|---|---:|---:|---:|---:|---:|
| Bot | 640 | 50 | 1 | 0 | 589 |
| Brute Force | 2,442 | 8 | 0 | 0 | 2,434 |
| DDoS | 17,840 | 474 | 22 | 0 | 17,344 |
| DoS | 90,084 | 30 | 6 | 0 | 90,048 |
| Port Scan | 47,688 | 1 | 1 | 0 | 47,686 |
| Web Attack | 140 | 5 | 10 | 1 | 124 |

Of17,840 DDoS views,474 are rejected before diagnosis and22 are left unknown. The diagnosis model alone assigns the correct type to17,772/17,840 (99.62%); only17,344 receive it in the final pipeline (97.22%). Specifically418 gate-rejected DDoS views would have been correctly typed by diagnosis, and10 flagged/correct-argmax views fall below the0.6 confidence cutoff. A strict gate threshold0.785833 contributes to the end-to-end loss. Lowering it indiscriminately risks increasing benign false alerts.

The missed DDoS subset has median8 forward/6 backward packets,20 forward payload bytes,11,595 backward bytes and7.51-second duration. It is not represented by a universally extreme packet count in every individual connection. The small147->96->48->1 gate may need better temporal relationships/distillation or an uncertainty path, not just a different number of epochs. This architectural explanation requires a controlled comparison.

None of the current DDoS test snapshots has a history flow-count at the50,000 cap; capacity saturation is not directly shown as the explanation for these misses. Earlier cap evictions remain documented, and this snapshot check does not reconstruct every historical eviction effect.

## 4. Web failures concentrate in XSS and missing protocol evidence

| Web subtype | Training views | Test views | Gate rejected | Correct Web type |
|---|---:|---:|---:|---:|
| Web Attack Brute Force | 454 | 104 | 0 | 102 |
| Web Attack XSS | 136 | 34 | 5 | 21 |
| Web Attack Sql Injection | 12 | 2 | 0 | 1 |

The current broad Web recall88.57% hides98.08% correct-family recall for HTTP brute-force views versus61.76% for XSS. SQL has onlytwo views from one held-out connection group and cannot support a reliability claim.

Only2/34 XSS views contain the script-like numeric indicator;20/34 have payload gap/truncation observations and14/34 have no parsed HTTP request. The parser intentionally observes only a bounded first HTTP header block in each direction,512 payload bytes/packet, and ignores body lines and later HTTP messages. This limits semantic evidence; it does not prove the exact location of every missing XSS string without raw-packet inspection. All104 HTTP brute-force test views have zero observed401/403 auth-failure counters, so that new counter supplies no direct failure signal for these lab examples. HTTPS cannot supply these cleartext indicators.

For the selected diagnosis model, all124 correct Web argmax decisions survive the gate/cutoff. Thus the5 rejected Web cases are also already wrong in standalone diagnosis: bypassing the gate alone would not restore Web typing.

## 5. Standalone checkpoint selection differs from cascade quality

Diagnosis checkpoints were ranked by standalone validation macro F1 and eligibility, not final gate-plus-diagnosis outcomes. With the same selected gate and cutoffs, the smaller aligned32 final checkpoint yields validation pipeline macro F193.7639%, versus93.6994% for the selected wider diagnosis. This small diagnostic difference demonstrates that independently ranking components does not maximize the composed pipeline; it does not justify selecting a replacement on the opened test set. All of these variants still have poor Bot precision.

With the same gate, using diagnosis64_s1 final instead of selected epoch23 changes test Web recall88.57% ->95.71%, but precision95.38% ->86.45% and F191.85% ->90.85%. Bot typing is unchanged. There is no uniformly better later checkpoint.

All larger diagnosis models show lower training loss by epoch40 while validation macro F1 falls after earlier selected checkpoints; for diagnosis64_s1 it is93.7243% at selected epoch23 versus92.8587% at epoch40. This is consistent with overfitting/objective tradeoffs and shows why more epochs or capacity is not a guaranteed solution. No precious checkpoint was lost to early stopping.

## 6. Changed history visibility and limited positive diversity

Historical context used network-wide endpoint history over120/300/900 seconds. Current history uses only traffic visible to one watched host over5/30/300 seconds. The old remote-endpoint bank could summarize conversations that a phone would never observe; removing that information is necessary for deployment but may reduce benchmark separability. How much each history change contributes requires matched ablations. Random-row historical tests also share attack sessions/patterns across partitions; neither benchmark establishes independent-session phone generalization.

Current training has860 Bot groups from Friday and242 Web groups from Thursday. Test support640 Bot views represents184 groups;140 Web views represents51 groups. Both endpoint views and multiple segments do not equal independent devices/attack sessions. Millions of ordinary-flow samples do not replace diverse, independently verified positive episodes.

## Recommended next experiments

1. Audit the Bot/Benign reset examples against independent packet/session/application ground truth. Retain ambiguous examples as ambiguous; do not relabel them merely because the classifier disagrees. Add diverse normal failed-connection/scan/retry controls and verified Bot sessions.
2. Freeze one shared input cohort, group split, architecture,40-epoch budget and initialization; compare unweighted versus moderated class-weighted loss as a controlled ablation. Evaluate hard benign examples and every class, not aggregate accuracy alone.
3. Select and calibrate the complete pipeline on validation with explicit Bot precision, per-class recall and source-FPR gates. Diagnose uncertain gate decisions with a richer model, or distill the richer decision into the small gate, instead of globally lowering the alert threshold.
4. Improve bounded multi-message/protocol coverage for supported cleartext Web evidence and add varied XSS/SQL/control sessions. Keep encrypted application limits explicit. Validate each subtype independently with enough independent groups.
5. Compare history windows/visibility under the same experiment; keep training and phone extraction identical. Do not restore invisible network-wide history just to recover CSV benchmark scores.
6. Use a separate declared campaign and fresh phone/manual evaluation after changes. This final test is now opened; do not repeatedly tune it and call subsequent results blind.

Full aggregate measurements: drop_diagnostics.json and drop_pattern_audit.json. Private cached predictions remain under runs/phone_alignment_v2/drop_diagnostics. Installed app, frozen campaign, checkpoint choices and deployment decision remain unchanged.
