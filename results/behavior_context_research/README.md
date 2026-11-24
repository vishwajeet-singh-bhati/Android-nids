# Behavior context experiments — 22 November 2026

The strongest result is for authentication episodes. On the recorded phone cases, repetition helped distinguish ordinary SSH/FTP logins from sustained guessing. The same rule delayed the first warning and lost early SSH flags. The results support further work on episode features. Code40 is still the phone release.

## Authentication replay

The candidate counts completed inbound TCP connections with an observed SSH or FTP cue for each remote peer and local service. It uses native decision order and a rolling 30-second window. The research rule requires four distinct connections, allows an episode to flag even if its earlier connections passed the gate, and preserves typed alerts for other families. The rule measures protocol-like repetition. SSH authentication outcomes are encrypted and come from the existing lab labels during evaluation only.

| Saved development cases | Code40 flagged | Episode candidate flagged | Code40 → candidate family matches |
|---|---:|---:|---:|
| Four normal protocol cases | 13/36 | 2/36 | — |
| FTP guessing | 29/32 | 29/32 | 0 → 29 |
| SSH guessing | 32/32 | 29/32 | 6 → 29 |

The two remaining normal flags were HTTP probes. Both guessing episodes reached the candidate rule, at about 3.1 seconds for FTP and 1.7 seconds for SSH from the first recorded connection start to the native decision used by replay. The three lost SSH detections occurred before repetition was established. This is one recorded guessing episode per protocol, four normal protocol sessions, and one preselected research rule. Slow guessing, multiple attempts inside one encrypted connection, legitimate reconnect bursts and multiple source peers require separate evidence. The candidate also leaves a lone authentication connection quiet when it might still matter for other reasons. The displayed family matches use the controlled labels. A live explanation could only claim repeated connection behavior.

## Active service pressure

The Kotlin replay uses the same packet decoder as the phone and samples inbound TCP service pressure on each new SYN. It reports tracked pending and apparently established connections, observed source counts, and arrivals over the preceding five seconds. It deduplicates retransmitted SYNs for tracked connections and removes observed closures or idle entries. These counters approximate socket concurrency from packets and do not measure server queue occupancy, resource consumption, or whether a request was denied.

| Recorded traffic | Peak prior established | Peak starts in 5 s | Peak distinct starting sources in 5 s |
|---|---:|---:|---:|
| 288 legitimate HTTP burst connections across six sessions | 3 | 60 | 1 |
| 96 DoS load requests | 5 | 104 | 1 |
| 96 DDoS load requests | 4 | 104 | 3 |
| DDoS availability probes observed during the same test | 4 | 104 | 3 |

Starts include all observed arrivals to the service, so they can exceed the number of load requests. The legitimate bursts came from one source. The data supplies no matched legitimate multi-client busy service, and ordinary probes can share the same pressure context as load requests. The prototype extracts features at packet time and makes no pressure alert decision. The Bot emulator's 11 inter-exchange gaps were 3.041–3.227 seconds. There is no matched periodic benign cohort to assess whether this distinguishes malware-like behavior from normal sync.

The cited DDoS paper supports evaluating destination aggregates, but its evidence concerns different datasets and a different feature design. The cited brute-force paper concerns Web hosting and uses per-connection payload-size histograms, so its results cannot validate this Android SSH episode rule. [Destination-window study](https://www.mdpi.com/2073-431x/15/6/399) · [Flow-based Web authentication study](https://link.springer.com/article/10.1007/s10922-017-9421-4) · [Security ML evaluation pitfalls](https://www.usenix.org/conference/usenixsecurity22/presentation/arp)

## Audit of existing features

Scanned all 4,963,458 augmented training rows for the 216 classification errors across the saved protocol cases and already opened recorded-phone HTTP test. Reported ten nearest benign and ten nearest attack rows per error in the private audit, together with distance by feature group, labels, dataset and connection-group identity. Exact raw matching found zero opposite-label duplicates for these errors. This does not exclude overlap at realistic distances or guarantee that the inputs are sufficient. The metric weights standardized coordinates equally and the training cache contains repeated rows.

The median nearest distances for missed DDoS requests were 6.36 to benign and 11.70 to attack rows. The same direction held for missed DoS and Bot exchanges. For the 10 recorded-phone HTTP false positives the distances were 15.09 to benign and 10.42 to attack. These results suggest distribution overlap or mismatch under this metric. Neither proximity nor replacing one feature group with its training mean establishes the cause of a model failure. Among uniquely recorded phone training negatives, code40 already flags 41/56 ordinary incorrect logins and 11/56 normal search/code requests. That grounds the hard-negative experiment below.

The same-protocol comparison paired each of eight normal SSH connections with its nearest recorded SSH guess, and did the same for eight FTP controls. There were zero exact opposite-label full vectors. Median standardized flow-feature RMS differences were 0.106 for SSH and 0.052 for FTP, while 30-second history differences were 0.621 and 0.664. Protocol-feature differences had median zero in both comparisons. This supports the relevance of repetition in these recordings and rejects the stronger claim that the existing 147 inputs contain no distinguishing information at all.

## HTTP specialist experiment

The two logistic models use the 848 unique recorded phone training segments, without the cache's eightfold repetition. They give equal weight to sessions within a class. The second additionally triples the weights of verified normal training examples code40 flagged before normalizing class weights. Scaling and fitting use training only. Each cutoff is selected on validation with a 2% false-positive cap. The cohort has 14 training, three validation and three test sessions with no session overlap. The final split had already been inspected for code40 during earlier work, so these results are retrospective.

| Existing phone test split | Normal flags / 120 | Attacks flagged / 64 | SQL and XSS flagged / 24 |
|---|---:|---:|---:|
| Code40 | 10 | 62 | 23 |
| Session-balanced logistic, selected on validation | 2 | 36 | 23 |
| With additional hard-negative weighting | 3 | 38 | 23 |

Both candidates fell below 85% attack recall. Their losses concentrated in HTTP guessing and spraying. The experiment does not validate a replacement gate, or establish that harder negatives never help. It strengthens the case for evaluating HTTP authentication episodes separately from single-request Web evidence. An independent episode cohort with verified successful logins, ordinary mistakes, reconnect bursts and varied recorded attack episodes is needed before choosing a live rule. Domain adaptation, new routing, an unknown/OOD state, multi-task training and distillation need separate evidence. They do not recover unavailable authentication outcomes.

## Reproduce locally

Use Java 21 and the existing frozen extractor JARs for Kotlin, Windows Python for the capture replay, and the WSL project Python environment with PyTorch and scikit-learn for fitting and feature audit. The commands read saved captures or feature arrays and create outputs under `runs/behavior_context_research` and this directory. Original recordings, per-connection identities, detailed neighbor records and fitted research weights remain local.

```powershell
cd android
.\gradlew.bat --offline :datasettools:jar
java -cp 'datasettools/build/libs/datasettools.jar;../runs/phone_alignment_v2/extractor/core.jar;../runs/phone_alignment_v2/extractor/kotlin-stdlib.jar' nids.dataset.PressureReplay --self-check
cd ..
python validation/replay_behavior_context.py --java java
wsl.exe -d Ubuntu --cd <PROJECT_ROOT> --exec <PROJECT_ROOT>/.venvs/edge-export/bin/python validation/audit_behavior_features.py
wsl.exe -d Ubuntu --cd <PROJECT_ROOT> --exec <PROJECT_ROOT>/.venvs/edge-export/bin/python validation/compare_phone_http_specialist.py
```

The lifecycle check exercises retransmission, parallel sources, service separation, closure and expiry. Read the machine-readable results for each comparison. [Episode and pressure replay](replay.json) · [Feature audit](feature_audit.json) · [HTTP experiment](http_specialist.json)
