# Results index

Published aggregate measurements are retained here; generated runs write under ignored `runs/`, `data/` and `validation/reports/`.

| Report | Interpretation |
|---|---|
| [Paper reconstruction](tsanet_paper/RESULTS.md) | User-chosen 70/30 split and documented assumptions; not exact author-code replication |
| [Context comparison](tsanet_context/COMPARISON.md) | Same historical cohort/epoch comparison; related-row/session limitations apply |
| [Phone-aligned classwise comparison](phone_alignment_v2/CLASSWISE_COMPARISON.md) | New raw-capture contract and cohort; not directly comparable to the CSV score |
| [Controlled phone cases](PHONE_TESTS.md) | Scans detected; confirmed web examples missed; connectivity-blocked Beacon excluded |
| [New real-phone collection](phone_capture_v1/collection_summary.json) | Independent target labels/input parity, not new model accuracy |
| [Current training status](../STATUS.md) | Updated-data results are included only after completion |

No dataset or real phone packet capture is included. Do not interpret class counts, flow retries or smoke metrics as independent attack episodes. Raw private phone-cohort results cannot be exactly regenerated from source alone; see [reproduction limits](../docs/REPRODUCING_RESULTS.md).
