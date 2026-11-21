# ForgeSight PR review and Pixel validation — 21 November 2026

Reviewed the public PR metadata and every changed production module/test diff. Exact revisions and diff hashes are in [sources.json](sources.json); raw responses remain under ignored runs. No external code was executed or copied into the Android production app.

## Decisions

| Source | Technique | Android decision |
|---|---|---|
| [ForgeSight PR5](https://github.com/honey-cake7/ForgeSight/pull/5) | Keep a verified Llama runtime alive; reset generation state for each request; avoid repeated process/import/hash/load work | Already implemented by our isolated Android worker. Retain it, with the existing120-second idle release. |
| [ForgeSight PR17](https://github.com/honey-cake7/ForgeSight/pull/17) | Complete a bounded one-token generation before declaring a persistent worker ready | Tested successfully on the Pixel, including unchanged same-input guidance. Do not enable speculative startup warming by default: it moves the wait earlier without establishing lower total time. |
| Issue exposed during the comparison | Android config overload omits the requested new-token limit | Add an explicit native stop guard in0.14.1/code39; keep the factual note/default advice when a draft reaches the limit. |

PR5 targets a Jetson/Linux Python pipeline with substantial per-request subprocess/import overhead. Its architecture is useful, but repeating that change in our already persistent Java/JNI worker adds no comparable optimization. Request context is reset; this is weight/runtime reuse, not reuse of another incident's conversation or cached response. The PR17 description itself distinguishes moving model load to worker boot from a measured improvement in total runtime; it did not claim a completed Jetson speed benchmark for that change.

## Warm-up comparison on our phone

Three alternating-order pairs, same frozen1B INT4 model, same guidance inputs, requested four-thread component pool, monitoring paused for the comparison. Cold means released/reverified/reloaded, without flushing the OS page cache. It is not a production IPC/live-capture timing experiment.

| Median over three cases | Time |
|---|---:|
| Cold first explanation request |12.693s |
| One-token preparation before READY |10.202s |
| First explanation after READY |3.048s |
| Full cold path, including instrumentation overhead |12.794s |
| Preparation + first request, including overhead |13.092s |

Per-case totals: PortScan14.437→14.250s; Unclassified12.690→13.092s; BruteForce12.794→12.635s. These small mixed differences do not establish a total-time improvement. All three same-input guidance strings matched exactly after warm-up; native warm-up counters were exactly one token, and warm-up output was discarded. [Detailed results](warmup_comparison.json).

A prepared model gives a shorter *subsequent* request by paying the load earlier. It still has to be prepared, remains memory-resident while ready, and may be evicted/released before a later alert. Our first useful factual note already appears without waiting for Llama. Consequently, this release retains on-demand loading and idle-cache reuse rather than creating additional speculative generations during ordinary monitoring. This does not claim that anticipatory loading could never benefit another workload.

## Android token-limit issue and fix

The initial one-token test produced17 native generated tokens and was correctly rejected. Inspection of the actual cached ExecuTorch Android1.5.1 AAR showed that `LlmModule.generate(String,LlmGenerationConfig,LlmCallback)` forwards sequence length, echo, temperature and BOS/EOS settings, but does not forward `maxNewTokens`. The setter's presence alone therefore does not establish an enforced limit. [Pinned binary evidence](android_api_evidence.json).

The production fix caps forwarded text callbacks and calls the runtime's `stop()` at the limit. Framing notifications make this a conservative ceiling rather than an exact token counter; native stats are checked independently. Terminal text arriving after stopping is not forwarded again. A stopped draft is not presented as complete guidance; the immediate detailed factual note and checked default advice remain available. The bounds below are verified for our installed model/runtime, not asserted for every tokenizer/backend.

Stopping from a callback is supported by the [official Android runner documentation](https://docs.pytorch.org/executorch/stable/llm/run-on-android.html). No model re-export, retraining or runtime-library upgrade is required. The existing fresh-context reset, isolated worker, watchdogs, output validation and model hashes remain in place.

Failed diagnostic attempts are preserved: the ignored one-token configuration, callback/exact-fill assertions that confused framing notifications with native token counts, and a test comparison that expected guidance-only text from a field containing a full note. The corrected checks use the required upper bound and compare identical full-output fields before/after generation.

## Final validated release: 0.14.1/code39

Installed/hash-verified on the Pixel; monitoring restored. Main detector weights/cutoffs and Llama/tokenizer hashes are unchanged. All87unexpired original observation IDs remain, and SQLite integrity passes. No unexpired feedback rows existed in the original snapshot. [Installed identity/history check](final_deployment.json).

| Native callback ceiling | Native generated tokens | Result |
|---:|---:|---|
|1 |1 |Within bound |
|3 |2 |Within bound |
|48 |47 |Within bound |

The production callback was exercised against the real native model. Guidance on the same input matched before and after these truncated numeric generations. [Native probe evidence](native_budget_checks.json).

Repeated live IPC validation with monitoring active passed all8requests across7categories: cold full-client14.047s(n1), warm median**3.690s**, range3.221–4.021s(n7). Seven generated guidance sentences accepted; the Web draft drifted in meaning, so the complete factual note and checked default advice were retained. Every native count remained within its48-token budget; capture queue drops were zero. A labelled transient TEST notification was posted/queried before Llama in9ms and then removed. These are evidence fixtures, not attack tests or detector-accuracy estimates. [Release summary](release_summary.json), [full runtime evidence](hybrid_runtime_code39.json).

Runtime reuse and immediate factual notes remain the latency design. The new guard bounds abnormal generation; it is not claimed to accelerate guidance that already ends naturally. Speculative boot prewarm stays disabled. Source/history are local;0.14.0/code38 and code37 rollback APKs remain available.

## Reproduction

With the matching app/test APKs built and the owned Pixel connected, from`<PROJECT_ROOT>`:

```powershell
$reviewPython='<USER_HOME>\AppData\Local\Programs\Python\Python313\python.exe'
# Unique session names preserve previous evidence; run one phone job at a time.
& $reviewPython validation\run_performance_bench.py --suite llama_boot_warmup --session warmup_review_new --install-test-apk --resource-period 1
& $reviewPython validation\run_performance_bench.py --suite llama_token_budget --session native_budget_new --resource-period 1
& $reviewPython validation\review_forgesight_performance.py
# The ordinary hybrid_runtime instrumentation mode checks the actual IPC worker.
```

Build/install commands and the release's factual-note/ownership/notification checks are in the [hybrid deployment guide](../../docs/hybrid_guidance_v1/README.md). The offline reviewer recomputes comparisons and validates budgets/factual prefixes/history from the included captured reports; it passes ([offline_audit.json](offline_audit.json)). Component tests pause and restore monitoring; allow the300-second connection history to rebuild before subsequent manual attack tests. No automatic attack suite, GitHub push or ZIP is part of this review.
