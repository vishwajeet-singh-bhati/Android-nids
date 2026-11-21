# Inference measurements and reproduction

The app already uses ExecuTorch. Current production chooses verified facts immediately and the existing 1 B Llama for one short checked guidance sentence. Detector graph/E 8/smaller-model alternatives remain experiments.

| Experiment | Result | Boundary |
|---|---|---|
| Paired detector original/hoistedFP 32 |1.583→1.182 ms median,25.3% reduction; zero tested decision changes |Not promoted into code 40 |
| Direct full-note/guidance-only component |21.053→3.888 s warm |Capture paused,4 threads; not production-worker end-to-end |
| Code 39 actual isolated IPC |14.047 s cold(n 1),3.690 s warm median(n 7),7/8 drafts accepted |Monitor active; numeric fixtures, not attack detection |
| One-token boot warmup |13.092 s prepare+request vs 12.794 s cold total |Moves cost earlier; disabled |
| E 8 reconstructed approximations |278 binary decisions and 655/577 diagnosis decisions changed |Rejected; no packed Android backend or QAT claim |
|135 M explanation model |Faster, unreliable advice |Rejected |

Accessible CPU/RAM/PSS/RSS, battery, thermal and GPU counters are recorded in [performance evidence](../results/performance_v1/README.md). Unavailable counters are not zeros. CPU inference has no separately measured model VRAM allocation. Device battery/temperature are whole-device observations; timing excludes flow expiration/history and is not packet-to-alert latency. Model 1,135,951,488 bytes plus 2,183,982-byte tokenizer; component resident PSS roughly 1.2 GiB.

Build the instrumentation APK, configure your owned device serial using the Android setup guide, and keep the monitor enabled:

```powershell
python validation/run_performance_bench.py --suite detector --session YOUR_UNIQUE_SESSION --install-test-apk
python validation/run_performance_bench.py --suite llama --session YOUR_OTHER_UNIQUE_SESSION
```

These commands run numeric/evidence fixtures, not network attacks. Some comparison modes temporarily pause capture, install test assets, or need prepared candidates; read their source and [performance report](../results/performance_v1/README.md). Candidate preparation uses matching training checkpoints/caches excluded from GitHub. The E 8 study additionally requires the user's separately owned local E 8 implementation with its reviewed hash; third-party unpublished scripts are not bundled. Historical raw benchmark recordings remain private; aggregate evidence and all project benchmark source are provided.

[Hybrid deployment](../results/hybrid_guidance_v1/README.md) and [PR review/native budget validation](../results/forgesight_pr_review/README.md) preserve cold/warm distinctions, rejected outputs and model identities.
