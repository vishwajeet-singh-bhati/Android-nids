# Cascade V6 completed results - 18 November 2026

**All 12 jobs completed 40 epochs (480 checkpoints); the experiment failed its detection targets. No V6 model was deployed.**

The preselected pair is `gate_w64_s0` + `diagnosis_w192_s1`. Its held-out gate recall was 57.85%, but final cascade recall was 0/2,083; it flagged 2/245,549 benign windows. Development Bot recall was 0/1,019. The second-stage cutoff rejected all labeled positives.

Other frozen pairs are reported as post-hoc diagnostics, not newly selected winners. No weights, thresholds, labels or selection were changed.

| Pair | Scope | Detected / labeled positive windows | Recall | Benign flags / benign windows | Benign flag % |
|---|---|---:|---:|---:|---:|
| gate_w64_s0 + diagnosis_w192_s1 | holdout | 0/2,083 | 0.00% | 2/245,549 | 0.00081% |
| gate_w64_s0 + diagnosis_w192_s1 | development | 0/1,019 | 0.00% | 0/192,583 | 0.00000% |
| gate_w96_s2 + diagnosis_w256_s1 | holdout | 1,998/2,083 | 95.92% | 79/245,549 | 0.03217% |
| gate_w96_s2 + diagnosis_w256_s1 | development | 427/1,019 | 41.90% | 63/192,583 | 0.03271% |
| gate_w64_s1 + diagnosis_w256_s2 | holdout | 1,911/2,083 | 91.74% | 77/245,549 | 0.03136% |
| gate_w64_s1 + diagnosis_w256_s2 | development | 624/1,019 | 61.24% | 89/192,583 | 0.04621% |

The strongest observed held-out pair detects DoS 1,930/1,993, credential-associated 14/15 and infiltration-associated 54/75. Its Bot development recall is 427/1,019 (41.9%). About 94.6% of its flagged held-out windows have unknown diagnostic type; it does not meet the requested general detector plus reliable diagnosis goal.

## Data coverage failure

| Training class | Rows | Temporal/app/capture groups |
|---|---:|---:|
| benign | 1,483,947 | 303 |
| port_scan | 99 | 3 |
| ddos | 0 | 0 |
| dos | 195 | 4 |
| credential_attack | 2,017 | 7 |
| web_attack | 10 | 2 |
| bot_activity | 1,485 | 9 |
| infiltration | 780 | 5 |
| heartbleed | 1,674 | 2 |
| mixed_suspicious | 0 | 0 |

The preflight checked numerical validity, parsing and group separation but did not stop training when required attack coverage was missing. That implementation gap must be corrected before another full run. The source contains attack-labeled records, but the extracted window/split coverage is inadequate. A read-only Friday exclusion audit was started to determine where positive examples were removed. Do not assign an exact exclusion cause before that audit completes.

## Scope and implementation checks

- 1,490,207 training rows; 300,398 selection; 260,299 calibration; 247,632 held-out; 193,602 explored development.
- Units are correlated active endpoint-seconds, not independent attack sessions or real phone incidents.
- Held-out positives: 1,993 DoS, 15 credential-associated, 75 infiltration-associated. No held-out scan/DDoS/web/Bot/Heartbleed examples exist.
- Development positives are 1,019 Bot-associated windows; Android controls are previously explored weak negatives.
- Both selected model exports passed numerical parity with zero decision flips. This establishes implementation parity, not detection quality.
- Android feature parity: 1,211 snapshots, zero error; RC4 regressions and optional Llama-adapter compilation passed.
- The new Android stage-gated runtime, native explanations on V6 evidence and representative ordinary-use validation remain unfinished.
- All held-out results are now opened diagnostic material. Any revised pipeline needs a newly reserved evaluation protocol; do not retune this run and call it a new blind success.

Full fixed metrics: `runs/cascade_v6/evaluation.json`; original freeze: `frozen_cascade.json`; public structured summary: `completed_summary.json`.
