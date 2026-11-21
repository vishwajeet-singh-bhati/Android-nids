# Real-phone augmented data v1 results

Same phone/app, chronological sessions with held-out request forms; small per-subtype support. Rates are recorded segments, not independent campaigns or general mobile accuracy. No auto-deployment.

No phone model was replaced. Deployment eligibility in this pilot: False.

| Cohort | Version | Binary precision | Binary recall | Benign FPR | Typed macro F1 |
|---|---|---:|---:|---:|---:|
| legacy | Frozen v2 | 0.995415 | 0.996424 | 0.000775 | 0.940323 |
| legacy | Augmented v1 | 0.993957 | 0.999307 | 0.001026 | 0.941080 |
| phone | Frozen v2 | 0.000000 | 0.000000 | 0.000000 | 0.394737 |
| phone | Augmented v1 | 0.861111 | 0.968750 | 0.083333 | 0.932785 |

## legacy classwise

| Class | Support | v2 P/R/F1 | Augmented P/R/F1 |
|---|---:|---|---|
| Benign | 940095 | 0.9994/0.9992/0.9993 | 0.9999/0.9990/0.9994 |
| Bot | 640 | 0.5429/0.9203/0.6829 | 0.5645/0.8609/0.6819 |
| Brute Force | 2442 | 0.9996/0.9967/0.9982 | 0.9996/0.9971/0.9984 |
| DDoS | 17840 | 0.9963/0.9722/0.9841 | 0.9918/0.9929/0.9924 |
| DoS | 90084 | 0.9993/0.9996/0.9995 | 0.9993/0.9999/0.9996 |
| Port Scan | 47688 | 0.9997/1.0000/0.9998 | 0.9997/0.9999/0.9998 |
| Web Attack | 140 | 0.9538/0.8857/0.9185 | 0.8973/0.9357/0.9161 |

## phone classwise

| Class | Support | v2 P/R/F1 | Augmented P/R/F1 |
|---|---:|---|---|
| Benign | 120 | 0.6522/1.0000/0.7895 | 0.9821/0.9167/0.9483 |
| Web Attack | 64 | 0.0000/0.0000/0.0000 | 0.8841/0.9531/0.9173 |

Classwise values, subtypes, counts, all best/final candidates and confusion matrices: evaluation.json. No test-driven checkpoint/threshold change follows this report.
