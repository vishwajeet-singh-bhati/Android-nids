# Rakshak project report

**Historical development report.** For the concise current submission report with team/institute/mentor details, use the [19-page final report](../final_submission_report/README.md). The 91-page document below remains an earlier development record.

Current91-page **submission draft** through24 November2026 / code49 (historical measurement builds retained):

- [Compiled PDF](Rakshak_Project_Report.pdf)
- [Self-contained Overleaf source](Rakshak_Project_Report.tex)
- [Added-model evidence](ADDON_MODELS_EVIDENCE.json)
- [Compilation record](VALIDATION.json)

Part I preserves the network paper-to-phone history. Part II separately explains current Rakshak, SMS data/training/FP32/PTQ/QAT, URL architecture, automatic message links, shared Llama/privacy, real fixes, the2,048-URL benchmark and its missing-label/reference-reuse limits. Hardware/runtime/optimization evidence and remaining model-improvement/submission gates are explicit. Archived scores are distinguished from newly executed phone checks.

Upload only Rakshak_Project_Report.tex to Overleaf and select pdfLaTeX. No external figures/bibliography/data are needed. Regenerate both using python tools/report/build_report.py. Local validation used Tectonic; Overleaf itself was not accessed.

The PDF is a development draft pending candidate selection and faculty review; no final submission is implied. See the root submission checkpoints. The source/evidence are retained for audit, and no raw datasets/messages/captures or project ZIP are included.

## Historical report coverage


The self-contained source is [Rakshak_Project_Report.tex](Rakshak_Project_Report.tex).

Upload that one file to a blank Overleaf project, set it as the main document, select **pdfLaTeX**, and compile. Recompile if the contents page needs updating. No image uploads, bibliography file, dataset, shell escape or ZIP is required.

The report covers:

- Network and machine-learning basics, the exact problem and evaluation terminology.
- Dataset provenance/counts, preprocessing, splits and paper-reproduction assumptions.
- TSANet, pruning, matched connection-context controls and their classwise results.
- Initial Android deployment, the input-meaning mismatch, shared Kotlin extraction and the current binary-gate/diagnosis cascade.
- The rejected repair experiment, device parity checks, capture, attribution, seven-day history, Llama and warm caching.
- Actual controlled phone tests, corrected SQL attribution, verified misses and the inconclusive Beacon case.
- Twenty accepted real-phone collection sessions, labels/QC, completed six-job augmentation training and full classwise before/after comparisons.
- Experimental augmented-model deployment, actual FTP/SSH/emulator/three-source resource tests, matched packet/native accounting and the observed misses/false positives.
- Detector/E8/smaller-model timing experiments, rejected options, deployed immediate factual notes and measured local Llama guidance, app attribution and runtime caching.
- Code40's loopback scope correction, preserved history, six frozen-checkpoint regressions, the later normal SSH failure and the remaining detector repair.
- Reproducibility, result-validity limitations, GitHub/CI history and a historical RC4/v5/v6 appendix.
- A complete explicitly constructed software-input fixture plus CPU-executed frozen-model walkthroughs and candidate tables.

[REPORT_EVIDENCE.json](REPORT_EVIDENCE.json) contains aggregate numeric sources/hashes and the executed examples. It is not needed by Overleaf. Real-cohort examples use a few selected feature values from already-opened older data; full dataset rows, raw captures and private endpoint identities are excluded. The complete invented fixture is solely a software explanation, never training data or an accuracy result. New held-out phone-model scores were not inspected for this report.

The original network portion was a dated development record through **0.14.2-network-scope / code40**. The augmented-v1 detector was installed for an explicitly requested experimental trial after failing readiness checks; trial deployment does not turn that failed decision into production validation. All earlier measurements retain their original pipeline, cohort and denominators. Normal SSH false positives and missed protocol behaviours remain documented. The later 22:59 normal protocol case still falsely flagged both SSH connections.

The earlier version compiled a 73-page PDF with no overflowing boxes or unresolved references. The [validation record](VALIDATION.json) pins the source/evidence hashes. Overleaf itself was not accessed. The compiled preview remains a local generated artifact; this directory publishes the self-contained source and evidence notes.

Regenerate the LaTeX from the shipped aggregate evidence using `python tools/report/build_report.py` at the repository root. It does not train or contact the phone. The evidence collectors additionally require the original private/local artifacts; they are distinct from the portable report builder. No raw phone recordings or ZIP are created by report generation.

Branding addendum24 November: source0.17.4/code47 adds the original [Rakshak logo](../branding/README.md). It changes launcher/header appearance only. The compiled report preserves its code46 measurement history; no new model scores or deployment results are implied.

Current network-note build: **0.17.6/code49**. Rejected incoming handshakes get factual wording and stable duplicate grouping; learned decisions are unchanged. Suppression was rejected after losing212 positive-labelled legacy-test detections. SMS improvements remain on hold. See [network audit](../../results/idle_network_repair_20261124/README.md).


## Submission setup supplement —25 November2026

The existing PDF/source retain their dated code49 measurements. The code51 source/setup supplement is [REPRODUCE.md](../../REPRODUCE.md), with [Expected-feedback evidence](../../results/expected_repeat_feedback_20261125/README.md) and the [demo script](../DEMO_VIDEO_SCRIPT.md). The ongoing13-profile campaign is not yet a completed report result. Freeze and reconcile final results before mentor/final submission review.
