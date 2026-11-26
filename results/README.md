# Results index

Published aggregate measurements are retained here; generated runs write under ignored `runs/`, `data/` and `results/`.

| Report | Interpretation |
|---|---|
| [Paper reconstruction](tsanet_paper/RESULTS.md) | User-chosen 70/30 split and documented assumptions; not exact author-code replication |
| [Context comparison](tsanet_context/COMPARISON.md) | Same historical cohort/epoch comparison; related-row/session limitations apply |
| [Phone-aligned classwise comparison](phone_alignment_v2/CLASSWISE_COMPARISON.md) | New raw-capture contract and cohort; not directly comparable to the CSV score |
| [Controlled phone cases](PHONE_TESTS.md) | Scans detected; confirmed web examples missed; connectivity-blocked Beacon excluded |
| [New real-phone collection](phone_capture_v1/collection_summary.json) | Independent target labels/input parity, not new model accuracy |
| [Completed augmentation](phone_capture_training_v1/RESULTS.md) | Frozen classwise before/after comparison; failed readiness |
| [Actual augmented phone trials](augmented_v1_phone_trial/SUMMARY.md) | Development scan/Web cases, with exact denominator caveats |
| [Protocol and multi-source tests](protocol_phone_tests/RESULTS.md) | Verified effects; normal false positives and missed families |
| [Inference measurements](performance_v1/README.md) | Component/production distinction; rejected optimizations retained |
| [Deployed Llama guidance](forgesight_pr_review/README.md) | Persistent runtime, bounded generation and measured IPC |
| [Current false-positive audit](false_positive_audit_20261121/README.md) | Loopback scope correction; external SSH remains unfixed |
| [Final report](../docs/final_submission_report/README.md) | Methodology, results, hardware utilization, optimisation and limitations |

No dataset or real phone packet capture is included. Do not interpret class counts, flow retries or smoke metrics as independent attack episodes. Raw private phone-cohort results cannot be exactly regenerated from source alone; see [reproduction limits](../docs/REPRODUCING_RESULTS.md).
