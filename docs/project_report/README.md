# Rakshak full technical report

This folder contains the **complete 91-page technical record** of the project. For evaluation, start with the concise
[Final Project Report](../Rakshak_Final_Report.pdf), which covers methodology, results, hardware utilization and optimization.

- [Compiled PDF](Rakshak_Project_Report.pdf)
- [Self-contained LaTeX source](Rakshak_Project_Report.tex): upload this single file to Overleaf and compile with pdfLaTeX. No figures, bibliography or data files are needed.
- [Report evidence (aggregate numbers and hashes)](REPORT_EVIDENCE.json), [added-model evidence](ADDON_MODELS_EVIDENCE.json), [compilation record](VALIDATION.json)

## Contents

**Part I: Network intrusion detection, paper to device.** Network and ML basics; CIC-IDS2017 provenance and preprocessing; the TSANet reconstruction and pruning; connection-context features; the initial Android deployment and the input-mismatch finding; the phone-aligned 147-feature gate/diagnosis cascade; the rejected repair v3; capture, attribution, history and local Llama; controlled phone and protocol tests; the 20-session real-phone dataset extension; inference optimisation (graph hoisting, E8 and smaller-model studies); false-positive investigations; reproducibility.

**Part II: SMS, phishing URLs and the integrated app.** SMS data, splits, TF-IDF and MobileBERT-22 training, FP32/PTQ/QAT comparison; the URL architecture and decision policy; SMS + link combination; shared explanations and privacy; the 2,048-URL phone benchmark and its labelling limits.

Measured results, illustrative calculations and proposed future work are labelled separately throughout. The measurement builds are dated in the text (network evidence through version code 49). Later app changes (codes 50–51) add a feedback option and do not change model weights or scores.

Regenerate the LaTeX from the shipped aggregate evidence with `python tools/report/build_report.py` at the repository root. This does not train models or contact a phone.
