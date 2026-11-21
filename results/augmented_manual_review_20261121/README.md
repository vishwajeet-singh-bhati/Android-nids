# Augmented v1: review of eight user-run phone tests

Review only: no new test traffic, installation, fitting or threshold changes. App 0.13.0/code37; gate0.5408333333333333, type cutoff0.8.

**Conclusion:** Web behavior detection improved over the preserved v2 model on these exact inputs, but detection and typing remain incomplete. Resource-denial probes were missed; bounded load response varied. The pipeline is not validated for general deployment.

## Actual phone results

| Start (IST) | Profile | Test support | Flagged segments | Actual model labels | Activity / visible notification groups | Five-minute separation |
|---|---|---|---:|---|---|---|
| 11:39:35 | PasswordGuessing | 31 failed guesses +1 valid login | 20 | Web Attack:8, Unclassified:12, Benign:12 | 2/0 | Yes |
| 11:42:13 | SQLInjection | 2 confirmed injections +1 normal query | 1 | Benign:2, Web Attack:1 | 1/1 | No; mixed prior-test history |
| 11:44:37 | XSS | 1 confirmed isolated script execution | 0 | Benign:1 | 0/0 | No; mixed prior-test history |
| 11:47:17 | ConnectionExhaustion | 16 requests;14 dummy-resource denials | 0 | Benign:16 | 0/0 | No; mixed prior-test history |
| 11:49:45 | HTTPFlood | 128 HTTP200 requests; no demonstrated outage | 0 | Benign:128 | 0/0 | No; mixed prior-test history |
| 11:59:02 | HTTPFlood | 128 HTTP200 requests; no demonstrated outage | 3 | Benign:125, DoS:3 | 2/2 | Yes |
| 12:07:51 | ConnectionExhaustion | 16 requests;14 dummy-resource denials | 0 | Benign:16 | 0/0 | Yes |
| 12:19:09 | XSS | 1 confirmed isolated script execution | 1 | Unclassified:1 | 1/1 | Yes |

## What each result means

- **HTTP password guessing:**20/31 failed guesses flagged;11 missed. Only8 guesses received the Web Attack label;12 flags stayed Unclassified. The valid-login control was Benign. There were two saved activities but zero visible notifications at that snapshot; this does not prove that notifications were never posted.
- **SQL injection:** the UNION form was correctly flagged as Web Attack; the confirmed tautology form was missed. The normal query was quiet. Both injections had the numeric SQL indicator set. Prior password-guessing history was still present, so this is a mixed-history case.
- **XSS:** the first confirmed execution was missed. The isolated retry was flagged, but Unclassified: gate0.721505 exceeds0.540833; Web confidence0.695394 is below the fixed0.8 naming cutoff. Both requests had script-like indicator1. Correct execution confirmation and a binary alert do not establish correct Web typing.
- **Connection exhaustion:** both16-request runs remained Benign, including all14 dummy-resource denials in each. This is a miss for this bounded application-resource scenario, not a measured whole-phone/network DoS recall result.
- **HTTP load:** first run0/128 flags; isolated retry3/128, all three typed DoS. Every request returned HTTP200 and no outage was demonstrated. These are load-response observations; neither0 nor128 flags would alone establish correctness.

## Audit and reproducibility checks

- Matched all325 native segments to325 captured client connections and3,248 packet records. Per-connection packet counts and segment-start timestamps agree exactly; all147 inputs finite and frozen thresholds consistent.
- Recorded capture-health counters show no late packets, queue drops, forced reorder, flow/history evictions or invalid-rate flows in these runs. These counters alone do not measure every possible kernel/link loss.
- CPU replay of the frozen augmented exports reproduces all325 phone binary/type decisions exactly. Maximum gate probability difference: 2.384185791e-07.
- Numeric authentication failures, SQL/script indicators and resource-denial HTTP5xx are present where expected. Remaining misses in these cases are classification decisions; no input-shape or notification-routing failure explains those unflagged cases.

## Five-minute history and repeatability

| Run | Seconds since preceding test traffic ended | Interpretation |
|---|---:|---|
| 20261121_113935_PasswordGuessing | 2350.19 | Separated from previous test |
| 20261121_114213_SQLInjection | 150.57 | Previous test can remain in300s history |
| 20261121_114437_XSS | 140.36 | Previous test can remain in300s history |
| 20261121_114717_ConnectionExhaustion | 158.34 | Previous test can remain in300s history |
| 20261121_114945_HTTPFlood | 141.78 | Previous test can remain in300s history |
| 20261121_115902_HTTPFlood | 554.12 | Separated from previous test |
| 20261121_120751_ConnectionExhaustion | 525.01 | Separated from previous test |
| 20261121_121909_XSS | 672.53 | Separated from previous test |

The initial SQL, XSS, resource and load runs started only about140–158seconds after the previous traffic ended. Their history-age counter means the monitor has been running long enough; it does not establish separation between test profiles. The later load/resource/XSS retries had554/525/673seconds of separation.

SQL and the first XSS input actually contain the earlier authentication-failure history. The two XSS inputs have different flow/history statistics. Context is a plausible contributor to their different outputs; this observational comparison does not isolate a causal effect of context alone.

## Paired frozen-v2 comparison on the same325 inputs

Only the augmented model ran live in these cases. The v2 numbers below are counterfactual CPU replay of its unchanged exports, not a second phone installation or a fresh independent benchmark.

| Case | Preserved v2 flags | Augmented live flags | v2 Web labels | Augmented Web labels |
|---|---:|---:|---:|---:|
| 20261121_113935_PasswordGuessing | 0 | 20 | 0 | 8 |
| 20261121_114213_SQLInjection | 0 | 1 | 0 | 1 |
| 20261121_114437_XSS | 0 | 0 | 0 | 0 |
| 20261121_114717_ConnectionExhaustion | 2 | 0 | 0 | 0 |
| 20261121_114945_HTTPFlood | 106 | 0 | 0 | 0 |
| 20261121_115902_HTTPFlood | 71 | 3 | 0 | 0 |
| 20261121_120751_ConnectionExhaustion | 0 | 0 | 0 | 0 |
| 20261121_121909_XSS | 0 | 1 | 0 | 0 |

V2 flagged0 of the35 verified Web requests; the augmented candidate flagged22 and correctly named9 Web. Two explicit normal request controls were unflagged. Those small, related cases do not establish a population recall or benign false-positive rate.

V2 also flagged more bounded-load traffic (106/128 and71/128 versus0/128 and3/128). Because no outage was demonstrated, that difference is not proof that either model has better DoS detection. V2 flagged two resource-holder flows in the first mixed-history resource case; the separated resource retry remained unflagged with both models.

## Remaining weaknesses and next decision

- **Binary detection:**13 of35 confirmed Web request examples were missed. Password-guessing scores also fell to Benign on later failures despite increasing observed failure history. Recognition remains sensitive to the observed feature pattern; no monotonic attack-evidence guarantee exists.
- **Diagnosis:**13 flagged Web examples remained Unclassified. Top diagnosis predictions among them: {'Web Attack': 2, 'Benign': 11}. A lower type cutoff cannot fix a diagnosis that strongly prefers Benign and has not been changed during this review.
- **Data coverage:** new real-phone positive training covered Web subtypes, not Bot, FTP/SSH brute force or genuine DoS/DDoS. Benign bursts and server errors were deliberately included as normal controls. These tests do not isolate whether new normalization, sampling, labels or model weights account for each changed prediction.
- **Llama/display:** all six saved activity explanations completed, using evidence-based fallback display text. No generated draft was accepted. Local explanation execution works in these snapshots; accepting useful generated notes remains a separate weakness.
- **Normal traffic:** the final standalone Benign control is not present in the supplied runs. The earlier8-request quiet baseline and these two embedded controls are too small to establish low real-world false positives.
- **Untested families:** real Bot malware, FTP/SSH-Patator and distributed DDoS remain unverified. Both extra PCs have SSH access, but no multi-source traffic was launched or phone-target connectivity validated.

Suggested next steps for user-controlled testing: final standalone Benign control; a clean-history SQL repeat retaining both known payload forms; then separately prepare the missing protocol/multi-source lab setups with independent target measurements. Keep current weights/cutoffs frozen while completing this diagnostic matrix.

## Artifacts

- audit.json: per-case native counts, model outputs, numeric evidence, controls, timing and artifact hashes.
- paired_frozen_replay.json: every paired frozen prediction and native parity check.
- summary.json: concise aggregate counts and explicit scope limits.
- Private original PCAPs, requests, numeric inputs and raw phone snapshots remain under runs/manual_phone_tests and validation/private; they are excluded from publication.
- Reproduction scripts: validation/review_augmented_manual_cases.py, replay_augmented_manual_models.py and summarize_augmented_manual_cases.py. Exact replay requires the excluded private captures/input snapshots and preserved local exports.
