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
- Twenty accepted real-phone collection sessions, labels/QC, augmentation and the unfinished updated-data training experiment.
- Reproducibility, result-validity limitations, GitHub/CI history, the proposed extra-PC tests and a historical RC4/v5/v6 appendix.
- A complete explicitly constructed software-input fixture plus CPU-executed frozen-model walkthroughs and candidate tables.

[REPORT_EVIDENCE.json](REPORT_EVIDENCE.json) contains aggregate numeric sources/hashes and the executed examples. It is not needed by Overleaf. Real-cohort examples use a few selected feature values from already-opened older data; full dataset rows, raw captures and private endpoint identities are excluded. The complete invented fixture is solely a software explanation, never training data or an accuracy result. New held-out phone-model scores were not inspected for this report.

This is a dated development record. Read its evidence cutoff before treating training progress or pending work as current status. Preserved v2 remains the installed detector at that cutoff; no new model promotion is implied.

Local validation compiled a 63-page PDF with no overflowing boxes or unresolved references. The [validation record](VALIDATION.json) pins the source/evidence hashes. Overleaf itself was not accessed. The compiled preview remains a local generated artifact; this directory publishes the self-contained source and evidence notes.
