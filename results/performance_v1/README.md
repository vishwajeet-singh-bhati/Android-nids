# Phone inference comparison — 21 November 2026

The best explanation candidate tested is **the existing Llama 3.2 1B INT4 model with verified factual sentences and a short, separate guidance prompt**. Show the factual note immediately; do not make the user wait for a generated rewrite. Keep the current binary gate, diagnosis policy and detector decisions.

These are **test-only candidates**, not a deployed update. Production remains NIDS `0.13.0-augmented-v1-trial`, code37. Automatic approval review rejected a main-app performance update because the handoff requires preserving that version. Only the instrumentation APK was updated. Production APK, detector models, Llama model, normalization, thresholds and history were preserved. The original monitor was restored after the tests; final counters showed no queue drops, late packets, evictions or reorder failures. Its 300-second history rebuilds after the necessary process restart.

## What was measured

Pixel 6a / Google Tensor / Android17 / eight online CPU cores; accessible RAM `5,723,472 KiB` (5.46GiB). ExecuTorch Android1.5.1, CPU XNNPACK. No performance governor or thermal overrides. The device had other work and variable temperature; these are development measurements, not a controlled laboratory energy benchmark.

- Detector: actual `AlignedV2Scorer.score` plus separate gate/diagnosis forwards; 21 frozen numeric fixtures, 80 repetitions per block. Final comparison alternates baseline/candidate order over three blocks each: **5,040 calls per variant**, same process, requested one thread, both models resident.
- Current explanation: **actual production LlamaClient/worker IPC**, checksums, loading, generation and output validation, with monitoring active. Three cold and three warm requests on PortScan, Unclassified and BruteForce fixtures. No incident rows or notifications inserted.
- Explanation alternatives: same evidence and runtime in a **direct component test**, monitoring paused, process-wide CPU pool requested four threads. Cold/warm order alternated for the paired comparison. Three cold/three warm timings; five extra quality requests cover Bot, DDoS, DoS, Web and a known receiving app with both capture/history incomplete. Eleven requests represent **eight distinct evidence combinations**, not eleven independent examples.
- Private numeric/evidence fixtures only. **No attack traffic, retraining, threshold tuning or new accuracy evaluation.** Packet collection, flow expiry/history waiting and Android notification delivery are outside these inference timings. A model scoring time is not event-to-notification latency.

Cold means released, reverified and reloaded; the OS file cache was not flushed. Warm means weights reused, with a fresh generation context. Different activities do not share a conversation/KV context.

## Detector results

| Final paired experiment | Current | Hoisted FP32 candidate |
|---|---:|---:|
| Median of three block medians | 1.583ms | **1.182ms** |
| Three block medians | 1.413 / 1.583 / 1.585ms | 1.165 / 1.182 / 1.259ms |
| Block p95 range | 1.617–1.756ms | 1.317–1.377ms |
| Median process CPU time per 1,680 calls | 2,192ms | **1,755ms** |
| Decision changes in phone timing blocks | 0 | 0 |
| Gate PTE bytes | 82,820 | 82,820 (identical) |
| Diagnosis PTE bytes | 949,788 | **921,116** |

Median latency decreased **25.3%**, process CPU work per block about20%. The candidate computes each LSTM's input projection once across all32 positions and retains only the final output where the model uses only that output. Weights, feature order, normalization and cutoffs stay the same. This is a graph optimization, not a new trained model.

Parity checks: 1,125 validation diagnostic rows, zero binary/family changes; **2,351 saved phone inputs**, zero family changes and maximum diagnosis-logit change0.0 between current and candidate exports on that replay. All current CPU decisions also matched saved native decisions. These checks preserve existing successes **and existing misses/false alarms**; they do not establish a new recall/FPR estimate. See [candidate_exports.json](candidate_exports.json) and [saved_phone_parity.json](saved_phone_parity.json).

Earlier unpaired measurements were slower: current exact cascade median2.490ms/p953.269ms; optimized1.159ms/p951.272ms. The latter had only two valid resource samples. **Use the final paired25.3% comparison**, not the larger apparent improvement from those separate runs.

Increasing requested detector threads did not consistently help: diagnosis medians at1/2/4 threads were2.355/2.076/2.246ms, p952.906/3.548/3.942ms. Keep one thread for this small graph pending a larger controlled study.

## Current production Llama request

Model: `Llama-3.2-1B-Instruct-SpinQuant_INT4_EO8.pte`, **1,135,951,488bytes** (1.058GiB), plus2,183,982-byte tokenizer. The existing app already uses ExecuTorch; switching to ExecuTorch is not a new optimization here.

| Actual production worker, monitor active | Cold, n=3 | Warm, n=3 |
|---|---:|---:|
| Full explanation request median | **54.605s** | **38.254s** |
| Range | 44.672–61.551s | 30.086–39.638s |
| First callback median, including load/verification | 21.531s | 7.100s |
| Model checksum median | 5.351s | 0 |
| Model load median | 8.836s | 0 |
| Worker CPU time median | 131.191 CPU-seconds | 116.548 CPU-seconds |
| Generated draft accepted | 0/3 | 0/3 |

All six completed without runtime errors. Their generated drafts failed the existing quality checks; the evidence-based fallback was returned. Measured monitor queue drops were zero in these six trials. A later cumulative drop counter was observed between experiments; it is retained in private snapshots and cannot be causally attributed to these requests.

The warm worker decoded about3.72tokens/s (median), with172 prompt tokens and115 generated tokens. Warming removes checksums/loading; it does not remove the remaining text-generation cost. The current120-second warm-worker policy remains unchanged.

## Explanation alternatives and quality

**Do not compare the table below directly to the production38.254s as an end-to-end speedup.** These component runs pause capture, execute in the instrumentation target process and request a four-thread pool. Production uses its isolated worker, active capture and a different thermal/load state.

| Component approach | Warm median (n=3) | Cold median (n=3) | Existing acceptance screen | Additional evidence/presentation screen |
|---|---:|---:|---:|---:|
| Current full-note prompt, paired reference | 21.053s | 31.221s | 0/6 | 0/6 |
| Shorter full-note prompt + opening sentence | 5.714s | 14.960s | 0/6 | 0/6 |
| Fixed facts + assistant-prefilled continuation | 6.315s | 18.084s | 0/11 | 0/11 |
| **Fixed facts + separate Llama guidance prompt** | **3.888s** | **14.580s** | **11/11** | **11/11** |
| **Plain wording + separate Llama guidance prompt** | **3.247s** | **13.769s** | **11/11** | **11/11** |
| SmolLM2-135M, full-note rewrite | 2.104s | 4.146s | 7/11 | **5/11** |
| SmolLM2-135M, fixed facts + guidance | 1.485s | 3.594s | 3/11 | **0/11** |

The direct paired comparison is **21.053s →3.888s, 81.5% less waiting /5.42× faster**. CPU work fell from median93.379 to18.377CPU-seconds. Prompt tokens fell172→72; generated tokens115→16. Much of the gain comes from asking the model to do less work, not from a faster quantization kernel. The later plainer variant had a3.247s median but ran in a separate session; do not treat its additional difference as a controlled improvement over3.888s. Its cold range was12.645–29.212s, so cold-start variability remains significant.

The failed prompt variants omitted packet/app facts, contradicted the estimate or refused routine guidance. SmolLM2 sometimes repeated itself or omitted the suspected Bot/Web pattern despite passing the original validator. Its three accepted guidance outputs echoed the prompt heading. The additional screen exposes those failures instead of reporting the smaller model as a winner. One repeating full-note request took22.733s warm; native stats reported511 generated tokens despite the requested96-token budget. That export/runtime generation-bound behavior needs resolving before use. No smaller-model promotion.

The guidance-only variants deliberately keep category names, app identity and traffic evidence **out of the LLM prompt**. The app renders those facts, and the model only rephrases supplied manual guidance. This is a **hybrid explanation**, not a wholly Llama-written investigation or independent attack diagnosis. Seven category cases include Unclassified; no malicious payload, successful login attack or actual harm is inferred.

The additional screen checks suspected pattern, packet count, ownership/receiver role, uncertainty, both incomplete-data warnings, note length and prompt/refusal leakage. Raw and displayed text are retained in [comparison.json](comparison.json). Text was inspected for meaning; there is **no blinded human study, readability user study or general hallucination-rate claim**. The Web guidance expands to a generic check for suspicious sign-ins; that is advice, not observed login evidence. A production integration should keep the deterministic guidance whenever generated advice drifts in meaning.

## Fastest useful user experience

An evidence-only plain note took **0.010701ms median,0.018677ms p95**, over16,000 assemblies/eight fixture combinations. This measures string assembly and fact lookup only; it excludes detection, I/O and notification delivery. It uses no language model and adds no Llama memory requirement.

Recommended flow:

1. Score the147 inputs and preserve the gate/diagnosis result.
2. Immediately display a plain evidence note: suspected pattern as an estimate, measured evidence, known app role or unknown ownership, uncertainty and one manual check.
3. Optionally request the short Llama guidance sentence using the existing warm isolated worker. Replace only the guidance after validation; retain the immediate note on failure. Do not delay the first useful notification for generation.
4. Retain the worker isolation and fresh per-activity context. Reusing a verified guidance sentence by category/model/prompt/language version may avoid future generation, but **guidance-result caching was not benchmarked or implemented**. Never cache app identity, counts or evidence from another incident.

Example from the plain hybrid fixture, not an actual detected incident:

> Possible check for open connections (model estimate). This does not confirm an attack. Observed:37 network packets (small pieces of data). nids.protocollab received this traffic. Some traffic was missed and recent history is incomplete. Check whether you expected a device search or connection test; review unfamiliar app activity.

App attribution remains best-effort. A receiving app must not be blamed as the source. In the UI, a verified installed-app display name can supplement its package identifier; no name should be invented when attribution is unavailable.

## RAM, CPU, GPU, temperature and power

Raw2s/1s sampling includes process CPU ticks, PSS/RSS/swap, thread count, CPU frequencies, device memory, Mali counters, battery current/voltage/charge/temperature/capacity. Aggregates and per-trial measurements are in [measurements.json](measurements.json); failed telemetry is explicitly marked.

| Scope | Observed result | Interpretation |
|---|---|---|
| Original monitoring-only interval | app median resident PSS51.9MiB; root capture4.6MiB | Four samples under that background workload; not a universal idle footprint |
| Production Llama worker | sampled peak resident PSS1.338GiB; peak sampled RSS1.403GiB | Worker only; additional app/capture memory remains |
| Production Llama worker lifetime RSS high-water mark | up to1.436GiB | Process-lifetime peak, not an exact per-request delta |
| Production Llama warm CPU | about303–306% median within individual warm phases | About3 busy cores, or38% of the capacity of eight cores; CPU% may exceed100% |
| Matched direct baseline/guidance warm memory | approximately1.18GiB resident PSS /1.24GiB RSS | Same1B weights; shorter generation does not materially shrink model RAM |
| Plain hybrid warm component memory | about1.12–1.18GiB resident PSS | Includes test process; no production memory saving established |
| Smaller model |173,005,952-byte PTE; warm process PSS roughly0.92GiB | Process previously ran1B models and retains allocators/KV/test state; not isolated smaller-model memory |
| Production Llama battery temperature |39.4–41.9°C | Component comparison was cooler,35.2–36.6°C; another reason not to compare its absolute time with production |
| Production-session device battery-power estimate |2.916–7.205W | Whole device, including screen/radios/other apps; not Llama-only energy |
| GPU | Shared device GPU allocations, frequency and raw utilization recorded | Models ran on CPU XNNPACK. No dedicated model VRAM; UI/other apps affect counters |
| Work-PC GPU | RTX2000Ada,16GB | Inventory only; not used for phone inference |

After reclaiming the instrumentation process, the original monitor's sampled resident PSS was81.7–84.7MiB and RSS172.4–175.6MiB. Its UI/background state differs from the earlier interval; do not call that a model-induced regression. Queue depth/drops were zero at the final heartbeat.

`Debug.MemoryInfo.totalPss` includes proportional swap; `/proc/<pid>/smaps_rollup` PSS is resident. They must not be mixed. See [Android Debug implementation](https://android.googlesource.com/platform/frameworks/base/+/HEAD/core/java/android/os/Debug.java). Sampled maxima can miss brief spikes; CPU values include other work in that process. GPU counters and instantaneous battery estimates cannot establish per-model energy or GPU speedups. No controlled joules/request result is claimed.

## E8 source review and experiment

Read all five supplied files in `D:\infrence`; hashes are in [source_review.json](source_review.json). The C++ pipeline is a BERT encoder/classifier, not a causal Llama generator. Its useful ideas are reusable scratch, ARM NEON, shared projection/LUT work, true padding removal and separate single-request/throughput measurements. The eight-worker version processes independent samples; it does not make one Llama generation eight times faster. The detector's32 ordered features cannot be trimmed as token padding. Llama already prefills its actual prompt length.

The Python E8 code uses a256×8 codebook: four8-bit indices and one32-bit scale per32 weights, nominally2bits/weight before padding/metadata/codebook. Its training path reconstructs FP32 weights. Reviewed E8 post-training reconstructions were evaluated on the same1,125 validation diagnostic rows, with frozen normalization and thresholds:

| Reconstruction | Binary decision changes | Family decision changes | Decision |
|---|---:|---:|---|
| Block-max E8 |278/1,125 |655/1,125 | Reject |
| Row-sigma E8 |278/1,125 |577/1,125 | Reject |
| Hoisted FP32 |0/1,125 |0/1,125 | Keep as performance candidate |

This is **not E8 quantization-aware retraining** and does not prove a properly trained E8 model cannot work. These exports reconstruct FP32 and are **not a packed2-bit Android kernel**; no fabricated E8 compression/latency claim is made. The supplied packed BERT kernels cannot be inserted into the stock ExecuTorch Llama runner without a model-specific exporter/operator/backend and numerical validation. No custom E8 Llama export was run.

`EO8` in the current SpinQuant filename refers to embedding/output precision and is different from lattice `E8`; see the [upstream model card](https://huggingface.co/meta-llama/Llama-3.2-1B-Instruct-SpinQuant_INT4_EO8). Existing supported CPU quantization is described in [ExecuTorch XNNPACK documentation](https://docs.pytorch.org/executorch/stable/backends/xnnpack/xnnpack-quantization.html). Smaller-model source, pinned revision, license, sizes and hashes: [small_model_provenance.json](small_model_provenance.json).

## Reproduction and evidence

Run on this work PC from`<PROJECT_ROOT>`, with one authorized Pixel connected. Do not run phone instrumentation jobs concurrently. Private checkpoints, numeric traces, dataset caches, downloaded weights and original raw telemetry remain under ignored`runs/`/`data/`; the repository contains source and aggregate results, not those private inputs. Exact offline replay needs the excluded snapshots; new numeric self-check benchmarks use the app's included fixtures.

```powershell
# Build only instrumentation; do not install/rebuild the production main APK.
$env:JAVA_HOME='<USER_HOME>\.jdks\openjdk-21.0.2'
$env:GRADLE_USER_HOME='<USER_HOME>\.gradle'
cd <PROJECT_ROOT>\android
.\gradlew.bat --offline --no-daemon :app:assembleDebugAndroidTest
cd <PROJECT_ROOT>
$perfPython='<USER_HOME>\AppData\Local\Programs\Python\Python313\python.exe'

# PC-only cleanup/readiness regression; no phone activity.
& $perfPython validation\smoke_performance_controller.py

# Use NEW session names; previous evidence is never overwritten.
& $perfPython validation\run_performance_bench.py --suite detector --session detector_new --install-test-apk
& $perfPython validation\run_performance_bench.py --suite llama --session production_worker_new
& $perfPython validation\run_performance_bench.py --suite llama_compare --profile guidance_only48 --session guidance_new

# Optional pinned smaller model download, then all additional explanation options.
& $perfPython validation\prepare_small_explainer.py
& $perfPython validation\run_performance_bench.py --suite explanation_options --session options_new --resource-period 1

# Requires the frozen local checkpoints/validation cache and reviewed E8 scripts.
wsl -d Ubuntu --cd <PROJECT_ROOT> --exec <PROJECT_ROOT>/.venvs/edge-export/bin/python validation/prepare_inference_candidates.py --e8-source /mnt/d/infrence
wsl -d Ubuntu --cd <PROJECT_ROOT> --exec <PROJECT_ROOT>/.venvs/edge-export/bin/python validation/check_inference_parity.py
& $perfPython validation\run_performance_bench.py --suite detector_pair --session paired_new --resource-period 1

# Read progress/logs from another terminal; no attack is started.
Get-Content .\runs\performance_v1\status.json
Get-Content .\runs\performance_v1\options_new\instrumentation.log -Tail 30 -Wait

# Offline aggregation. report_performance.py describes this frozen experiment's
# named sessions; adapt names deliberately for a new campaign.
& $perfPython validation\summarize_performance.py
& $perfPython validation\report_performance.py
```

Controller minimum: three valid external resource samples; failed/aborted runs remain visible. Failure cleanup cancels Android instrumentation, preserves evidence and restarts the monitor. Main-app identity is attested before/after each run. Offline failure/readiness smoke passes ([controller_smoke.json](controller_smoke.json)); Android instrumentation assembly and all completed suites passed runtime checks. Runtime completion does **not** imply generated-text quality acceptance.

The aborted one-thread-confounded Llama comparison, first detector run with failed telemetry, insufficiently sampled standalone optimized detector, and initial paired-detector readiness failure are excluded from selected claims. All still appear in the evidence ledger. Final production identity and restored monitor: [final_attestation.json](final_attestation.json).

No GitHub push, ZIP, main-app deployment or model promotion was performed. The next deployment comparison must integrate the candidate in the isolated production worker, repeat cold/warm requests with live monitoring and verify immediate notification timing, evidence revision handling, quality rejection and capture health before claiming an end-to-end speedup.


## Publication context

This is a dated experiment record. Its original workstation commands may require excluded private recordings, checkpoints or rollback snapshots and are not fresh-device setup instructions. For the current portable entry points use [Android setup](../../docs/ANDROID_SETUP.md), [protocol testing](../../docs/PROTOCOL_TESTING.md), [inference measurements](../../docs/INFERENCE_PERFORMANCE.md) and [current status](../../STATUS.md). Current source is code40; historical version-preservation decisions are not current build restrictions.
