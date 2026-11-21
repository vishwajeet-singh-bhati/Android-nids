# Deployment decision and classwise findings - 15 November 2026

**Do not promote a v5 model to production yet.** No candidate met all frozen offline gates. The phone replays provide additional reasons to improve the task/data/decision design rather than choose a model using headline recall.

Preferred candidates below were fixed from validation before final-test access. Student seed2 rows are explicitly post-hoc diagnostics, not newly selected deployment winners.

## Classwise detection (frozen scores)

| Candidate | Class | Raw detected / labeled | Raw recall | Consecutive confirmation recall |
|---|---|---:|---:|---:|
| shortflow_specialist_s1 | Bot | 172/226 | 76.1% | - |
| shortflow_specialist_s1 | PortScan | 9042/9064 | 99.8% | - |
| shortflow_specialist_s1 | DDoS | 11321/11405 | 99.3% | - |
| behavior_general_s2 | PortScan | 68/70 | 97.1% | 41.4% |
| behavior_general_s2 | DDoS | 375/414 | 90.6% | 90.1% |
| shortflow_student_s2 | Bot | 176/226 | 77.9% | - |
| shortflow_student_s2 | PortScan | 8971/9064 | 99.0% | - |
| shortflow_student_s2 | DDoS | 5295/11405 | 46.4% | - |
| behavior_student_s2 | PortScan | 69/70 | 98.6% | 42.9% |
| behavior_student_s2 | DDoS | 367/414 | 88.6% | 87.4% |
| shortflow_deployed_frozen | Bot | 139/226 | 61.5% | - |
| shortflow_deployed_frozen | PortScan | 9023/9064 | 99.5% | - |
| shortflow_deployed_frozen | DDoS | 10772/11405 | 94.4% | - |
| behavior_deployed_frozen | PortScan | 70/70 | 100.0% | 42.9% |
| behavior_deployed_frozen | DDoS | 392/414 | 94.7% | 94.2% |

## False flags on final source/development sets

| Model | CIC benign units flagged | PARROT captures | AAGM captures |
|---|---:|---:|---:|
| shortflow_specialist_s1 | 1138/58144 | 6/64 | 1/39 |
| behavior_general_s2 | 17/73755 | 0/64 | 1/39 |
| shortflow_student_s2 | 114/58144 | 0/64 | 0/39 |
| behavior_student_s2 | 14/73755 | 0/64 | 0/39 |
| shortflow_deployed_frozen | 854/58144 | 0/64 | 4/39 |
| behavior_deployed_frozen | 95/73755 | 0/64 | 1/39 |

A zero capture-flag count is not zero real-world risk: 0/64 has a descriptive Wilson upper bound of approximately 5.7%; app/capture correlation and source shift further limit interpretation. Do not pool endpoint buckets, flows and sessions into a single accuracy number.

## Phone recording checks

| Model | Scope | Scan profiles detected | Retry controls flagged | Ordinary-use clips flagged |
|---|---|---:|---:|---:|
| shortflow_specialist_s1 | recorded_development | 2/9 | 1/6 | 1/2 |
| shortflow_specialist_s1 | fresh_frozen_profiles | 1/2 | 0/2 | 0/0 |
| behavior_general_s2 | recorded_development | 2/9 | 6/6 | 0/2 |
| behavior_general_s2 | fresh_frozen_profiles | 1/2 | 1/2 | 0/0 |
| shortflow_student_s2 | recorded_development | 0/9 | 1/6 | 1/2 |
| shortflow_student_s2 | fresh_frozen_profiles | 0/2 | 0/2 | 0/0 |
| behavior_student_s2 | recorded_development | 1/9 | 6/6 | 0/2 |
| behavior_student_s2 | fresh_frozen_profiles | 0/2 | 0/2 | 0/0 |
| shortflow_deployed_frozen | recorded_development | 2/9 | 0/6 | 1/2 |
| shortflow_deployed_frozen | fresh_frozen_profiles | 0/2 | 0/2 | 0/0 |
| behavior_deployed_frozen | recorded_development | 5/9 | 6/6 | 0/2 |
| behavior_deployed_frozen | fresh_frozen_profiles | 2/2 | 2/2 | 0/0 |

Only count/reception-verified profiles enter scan/retry denominators. Retry controls are intentionally generated connection attempts, not broad ordinary-app ground truth. Recorded scans/retries are development diagnostics. Fresh cases use unchanged frozen models and thresholds; new candidates run in offline replay, not inside the production phone app. UDP rate stress is not labeled as a verified DDoS attack.

## Robustness and interpretation

- Class support is narrow: the final CIC DDoS examples occupy one time block; behavior PortScan spans two blocks. Many packets/buckets do not equal many independent attacks.
- Per-class recall asks whether activity is flagged. Specialist head confusion matrices separately check whether the intended head identifies the class. A binary model does not predict an attack type.
- Class-versus-benign AP/AUC in audit.json excludes other attack classes. Original class AP used a binary score versus all other labels, so it was not an attack-type classification metric. Frozen model ranking/results were preserved.
- Confirmation causes a large scan-recall loss. An exploratory 2-of-3-second diagnostic is recorded, but must not be adopted because it looks better on this now-opened test.
- Three-seed ranges and all40 epoch checkpoint dynamics are in diagnostic_summary.json. A best checkpoint is retained independently of last epoch.
- Prefix, protocol and time-block results; class Wilson/cluster-bootstrap intervals; source drift/tail captures; head confusion; hypothetical prevalence sensitivity; and PC inference costs are in audit.json.
- PC timing establishes only a rough capacity cost. No new-candidate Android battery, latency or long-duration false-alert-rate claim is made.

## Recommended next research change

Separate low-rate multi-port probing from legitimate single-service retries and high-rate traffic using matched controls and richer connection outcomes. Current aggregate history and desktop labels are not enough to establish those distinctions reliably. Add handshake/response/completion and retransmission context, preserve longer causal sequences, and collect varied ordinary-use sessions. Keep raw and confirmed policies separately evaluated.

Use correctly scoped labels for each specialist; do not label every packet in a malware capture as an attack or a controlled UDP burst as DDoS truth. Revisit publisher timing/flow joins and acquire new independent sessions/days/devices. Reserve a new untouched evaluation before tuning with these diagnostic failures.

Changing only model size, increasing a threshold, or requiring more consecutive positives has already shown a detection/false-alert tradeoff. There is room for improvement, but no result here justifies a production promotion.

Full tables: AUDIT.md, classwise.csv, audit.json, diagnostic_summary.json. Production RC4 models remain unchanged.
