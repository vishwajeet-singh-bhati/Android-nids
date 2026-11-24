# Both-model routing comparison — 23 November 2026

The deployed cascade runs the binary gate first. It runs diagnosis for gate-positive inputs, and diagnosis cannot veto or rescue a binary decision. Executing diagnosis on every input needs an accompanying decision rule to change detection.

This experiment evaluates six predefined rules using the frozen gate_s0_final and diagnosis_s1_best exports. The gate threshold is 0.5408333333333333 and the existing diagnosis confidence threshold is 0.8. There is no fitting or threshold search. Both networks receive the same 32 flow and 115 context/protocol inputs.

## Recorded-phone test split

This previously examined split contains 64 Web Attack and 120 normal segments from the same phone/lab app.

| Rule | TP | FN | FP | TN | Precision | Recall |
|---|---:|---:|---:|---:|---:|---:|
| Current gate | 62 | 2 | 10 | 110 | 86.11% | 96.88% |
| Diagnosis on every input, highest-scoring class | 64 | 0 | 9 | 111 | 87.67% | 100% |
| Either model flags | 64 | 0 | 11 | 109 | 85.33% | 100% |
| Both models flag | 62 | 2 | 8 | 112 | 88.57% | 96.88% |
| Gate or confident diagnosis | 64 | 0 | 10 | 110 | 86.49% | 100% |
| Gate and confident diagnosis | 61 | 3 | 8 | 112 | 88.41% | 95.31% |

## Saved protocol development cases

Nine cases provide 268 primary positive connections and 36 normal protocol connections. Availability probes during load and the emulator trigger are excluded. The attack connections come from one FTP, SSH, Bot, DoS and DDoS episode each. These counts cannot establish independent attack-family coverage.

| Rule | TP | FN | FP | TN | Recall |
|---|---:|---:|---:|---:|---:|
| Current gate | 79 | 189 | 13 | 23 | 29.48% |
| Diagnosis on every input, highest-scoring class | 27 | 241 | 0 | 36 | 10.07% |
| Either model flags | 96 | 172 | 13 | 23 | 35.82% |
| Both models flag | 10 | 258 | 0 | 36 | 3.73% |
| Gate or confident diagnosis | 95 | 173 | 13 | 23 | 35.45% |
| Gate and confident diagnosis | 6 | 262 | 0 | 36 | 2.24% |

The either-model rule adds eight DoS and nine DDoS flags. Requiring agreement removes all 29 FTP flags and leaves seven SSH flags. None of the six rules detects the twelve Bot emulator exchanges. These are binary detections; an additional flag may still have an incorrect attack-family diagnosis.

## Interpretation

Running both models supplies complementary scores for some recordings. OR routing increases recall and can add false positives. AND routing can suppress real attacks where diagnosis has learned the wrong pattern. Merely adding model stages supplies no guarantee of better detection. Extra inference cost needs a new on-device benchmark before changing the mobile route.

A useful next experiment is a small fusion classifier over the gate score, diagnosis scores and validated connection-history measurements. Its training inputs need out-of-fold model scores with splits grouped by session and device. Thresholds should be selected using validation false-alarm and recall requirements, followed by independent evaluation. Authentication and service-pressure context need appropriate benign controls, especially normal reconnects, background synchronisation and healthy busy services. The existing HTTP specialist experiment also demonstrates that reducing false alarms can lose substantial attack recall.

The phone validation results are included in [comparison.json](comparison.json). The legacy split's original standalone gate/diagnosis metrics remain in the augmented training report. These cohorts are already examined development evidence. This experiment supplies neither a new independent holdout nor grounds for a deployment claim.

Reproduce locally with the original private captures and feature caches available:

```powershell
wsl.exe -d Ubuntu --cd <PROJECT_ROOT> --exec <PROJECT_ROOT>/.venvs/edge-export/bin/python validation/compare_dual_model_routing.py
```

The replay audits saved protocol capture hashes, packet accounting and native inputs through the existing auditor. Gate outputs must match native scores within 0.00002. Phone test confusion counts must match the original gate and standalone diagnosis results exactly. Model export hashes are recorded. The experiment performs offline inference and writes aggregate reports.
