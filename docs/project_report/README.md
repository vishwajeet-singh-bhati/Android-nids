# Complete Android NIDS development report

The self-contained source is [Android_NIDS_Project_Report.tex](Android_NIDS_Project_Report.tex).

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

This is a dated development record through **0.14.2-network-scope / code40**. The augmented-v1 detector was installed for an explicitly requested experimental trial after failing readiness checks; trial deployment does not turn that failed decision into production validation. All earlier measurements retain their original pipeline, cohort and denominators. Normal SSH false positives and missed protocol behaviours remain documented. The later 22:59 normal protocol case still falsely flagged both SSH connections.

Local validation compiled a 73-page PDF with no overflowing boxes or unresolved references. The [validation record](VALIDATION.json) pins the source/evidence hashes. Overleaf itself was not accessed. The compiled preview remains a local generated artifact; this directory publishes the self-contained source and evidence notes.

Regenerate the LaTeX from the shipped aggregate evidence using `python tools/report/build_report.py` at the repository root. It does not train or contact the phone. The evidence collectors additionally require the original private/local artifacts; they are distinct from the portable report builder. No raw phone recordings or ZIP are created by report generation.
