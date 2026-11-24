# Rakshak: faculty/reviewer briefing

Current draft:0.17.3/code46,24 November2026. Repository: https://github.com/vishwajeet-singh-bhati/rakshak . This is an experimental local Android security assistant, not a production-protection claim.

## Problem and implementation

Network intrusion uses rooted TCP/UDP capture,147 flow/history measurements, a binary gate and diagnostic model. SMS uses normalized text/evidence, word TF-IDF logistic regression and selective MobileBERT-22 PTQ. URLs use address characters,27 numeric features, a CNN, character n-gram classifier, learned combiner and local rules/lists. URL links in incoming SMS are automatically extracted and checked. Shared facts-first notifications, checked local Llama advice, independent controls and seven-day clearable history connect the branches.

## Evidence reviewers should inspect

| Scope | Result | What it does not establish |
|---|---|---|
| Archived869-row SMS PTQ export test |97.12% accuracy; smishing P78.57%, R89.80%,44/49 positives | Current Android warning accuracy or fresh unseen evaluation |
| Physical Pixel SMS checks |14 neural class matches;230 authored scenarios | Strict numerical parity (logit drift0.449647 fails0.05), language-wide scam coverage |
|2,048 URLs on Pixel |325 phishing,1,581 likely safe,142 uncertain;0 failures | Full precision/accuracy:1,830 labels remain unknown and all inputs repeat export references |
|218 externally supported positives | Raw model172 phishing,30 uncertain,16 likely safe | General recall/precision on an independent two-class population |
|Those218 with saved lists |218 list hits | Independent learned-model accuracy or default empty-public-database coverage |
|Network development test |62/64 positive segments,10/120 negative segments flagged | Production readiness or reliable detection of all trained classes on phone |

The SMS full archive contains train/validation/test4055/869/869 and external27885 rows. CSV hashes matched the archived configuration and declared group intersections were zero. Test scores were already opened/reused upstream. No raw datasets/private messages are published. No URL was opened by benchmark inference.

## Hardware and optimization

Measured device: Pixel6a, ARM64. Current URL detector mean4.215ms, median3.940ms, p95 5.307ms; first cold row703.793ms;2048-row native execution9.417s. These exclude SMS delivery, notification and Llama. SMS PTE37,250,700bytes; URL CNN381,444bytes plus n-gram6,391,214bytes. Model size is not RAM usage.

ExecuTorch/PTQ, conditional routing, cached model loads and immediate factual notes with bounded Llama guidance reduce unnecessary work. The report retains earlier CPU/RAM/PSS/thermal/accessible GPU-counter measurements and rejected E8/smaller-model options at their original dates. No dedicated NPU or GPU acceleration benefit is claimed.

## Review packet

Read [report PDF/source](project_report/README.md), [components](../components/README.md), [full architecture](rakshak/architecture/README.md), [setup](ANDROID_SETUP.md), [improvement plan](MODEL_IMPROVEMENT_PLAN.md) and [submission gates](../SUBMISSION_CHECKPOINTS.md). Build/source checks are separate from accuracy studies. The public URL database is empty to avoid redistributing feeds; local setup code is provided and model weights are unchanged.

Model improvement and user selection precede faculty approval and final submission. Two-minute public video and once-only form submission remain pending. Deadline supplied by the organizer email:25 November2026,23:59IST. No form was submitted by this preparation work.
