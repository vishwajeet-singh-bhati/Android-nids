# Completed manual protocol tests - 21 November 2026

Seven completed manual cases; the earlier HTTP-controller and capture-limit failures remain separate incomplete attempts. Frozen NIDS models and cutoffs were unchanged. No additional phone traffic, training or retuning during this review.

| Case | Primary connections flagged | Correct family assigned | Visible notification groups* |
|---|---:|---:|---:|
| Benign | 3/9 | Normal control | 2 |
| FTPBruteForce | 29/32 | 0 | 1 |
| SSHBruteForce | 32/32 | 6 | 3 |
| BotBehavior | 0/12 | 0 | 0 |
| DoS | 18/96 | 0 | 2 |
| DDoS | 0/96 | 0 | 1 |
| Benign | 4/9 | Normal control | 2 |

Primary counts use 96 load requests per DoS/DDoS case, 12 emulator exchanges, and 32 login attempts per guessing case. Availability probes and the emulator trigger are excluded from those primary denominators. Each matched connection has one native segment in these particular cases.

*Notification counts are visible groups in each saved snapshot, not individual model decisions or proof of every notification ever posted.

The DoS console total was 19/139: 18/96 load requests and 1/43 probes flagged. The DDoS console total was 1/143: 0/96 load requests and 1/47 probes flagged. Neither case received a DoS/DDoS family diagnosis. The single DDoS flag must not be reported as detection of a load request.

Independent target evidence confirms resource denial and recovery: DoS denied 36 availability probes and 78 resource requests; DDoS denied 38 probes and 76 requests. DDoS used three distinct phone-visible source IPs with overlapping intervals. This is application-resource denial, not a volumetric network flood.

Normal controls falsely flagged 3/9 and 4/9 connections (7/18 total). All four successful FTP/SSH control logins were flagged; ordinary wrong-password controls contributed three flags; all ten normal HTTP probes stayed quiet. This tiny protocol-specific sample is not an everyday false-positive-rate estimate.

FTP flagged 29/32 attempts, all Unclassified. SSH flagged 32/32, but only 6/32 received Brute Force; 26 were Unclassified. All 12 restricted emulator exchanges stayed Benign, which does not establish general real-malware recall.

Matched activity explanations completed through evidence-based fallback; no generated draft was accepted. Do not describe these displayed summaries as accepted Llama generations.

The pipeline needs improvement before normal-use deployment: benign authentication false positives, missed distributed load/emulator behavior and weak family classification remain. These completed checks establish the test plumbing and expose model limitations.

PC-only re-audit passed: 377 matched connections/native segments, 4270 packets, exact per-connection packet counts/start timestamps, finite 147-feature inputs, frozen binary decisions, PCAP hashes and target-event matching. Raw/private captures and endpoint records remain under ignored runs; aggregates are versioned.

Re-run this saved-evidence review (no phone required): `python validation/review_protocol_results.py`. Detailed role partitions and evidence hashes: [COMPLETED_REVIEW.json](COMPLETED_REVIEW.json).
