# Phone-aligned v2 results

Grouped raw-flow benchmark with causal unlabeled stream context. Opened manual phone captures are excluded from fitting and are development diagnostics. Laboratory scores do not establish phone attack accuracy.

| Candidate | Attack precision | Attack recall | Benign FPR | Macro F1 (typed) |
|---|---:|---:|---:|---:|
| gate_s0:best | 0.995415 | 0.996424 | 0.000775 | gate only |
| gate_s0:final | 0.995456 | 0.998615 | 0.000770 | gate only |
| diagnosis64_s0:best | 0.993961 | 0.998886 | 0.001025 | 0.9355353326297726 |
| diagnosis64_s0:final | 0.994479 | 0.999062 | 0.000937 | 0.9235165625713683 |
| gate_s1:best | 0.994844 | 0.998634 | 0.000874 | gate only |
| gate_s1:final | 0.994228 | 0.998760 | 0.000980 | gate only |
| diagnosis64_s1:best | 0.983339 | 0.999931 | 0.002862 | 0.9348535560079209 |
| diagnosis64_s1:final | 0.995377 | 0.997778 | 0.000783 | 0.9353408764387037 |
| gate_s2:best | 0.994935 | 0.997941 | 0.000858 | gate only |
| gate_s2:final | 0.990461 | 0.999509 | 0.001626 | gate only |
| diagnosis64_s2:best | 0.991922 | 0.999603 | 0.001375 | 0.935849272579647 |
| diagnosis64_s2:final | 0.994140 | 0.998615 | 0.000995 | 0.8673801281156684 |
| aligned32_s0:best | 0.990358 | 0.999698 | 0.001645 | 0.9330036414736104 |
| aligned32_s0:final | 0.994964 | 0.998892 | 0.000854 | 0.9254891186815202 |
| wire_only32_s0:best | 0.798644 | 0.995417 | 0.042402 | 0.8776967313441383 |
| wire_only32_s0:final | 0.797650 | 0.995026 | 0.042648 | 0.8742131625936579 |

## Selected pipeline classwise results

| Class | Precision | Recall | F1 | Support | Binary gate recall |
|---|---:|---:|---:|---:|---:|
| Benign | 0.999396 | 0.999225 | 0.999310 | 940095 | n/a |
| Bot | 0.542857 | 0.920312 | 0.682899 | 640 | 0.921875 |
| Brute Force | 0.999589 | 0.996724 | 0.998155 | 2442 | 0.9967239967239967 |
| DDoS | 0.996266 | 0.972197 | 0.984085 | 17840 | 0.9734304932735426 |
| DoS | 0.999323 | 0.999600 | 0.999462 | 90084 | 0.9996669774876782 |
| Port Scan | 0.999706 | 0.999958 | 0.999832 | 47688 | 0.9999790303640329 |
| Web Attack | 0.953846 | 0.885714 | 0.918519 | 140 | 0.9642857142857143 |

Offline targets passed: False. Deployment remains pending fresh native/ordinary-use/manual phone validation.

Diagnosis unknowns retain their binary alert. Exact application attack confirmation is not inferred from traffic shape alone. Fine-label/source metrics and every confusion count are in evaluation.json. Historical CSV benchmark results are a different cohort and are not directly comparable.
