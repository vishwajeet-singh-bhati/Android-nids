# Hardening workspace

This directory contains the Phase 1 indicator-hardening work. It is isolated
from the original `experiments/handmade_evaluation/results/` and
`artifacts/model/` outputs.

## Contents

- `evaluate_ptq_handmade.py`: evaluates the frozen PTQ ExecuTorch artifacts on
  the 100-message handmade set. Local only; no SMS body is sent externally.
- `export_kotlin_parity.py`, `export_flags_parity.py`,
  `export_model_parity.py`, `export_policy_parity.py`: generate local TSV
  oracles for the Kotlin desktop-JVM parity runners.
- `export_indian_parity.py`: exports the external Indian control set for all
  three Kotlin parity layers; raw fixtures stay in the approved local temp
  workspace.
- `model/`: portable re-export used for parity verification.
- `model_retrain/`: isolated retrain output; production artifacts were not
  overwritten.
- `reports_retrain/`, `docs_retrain/`: isolated retrain reports and docs.
- `results/`: metrics, provenance, parity, text-free predictions, and the
  decision-ready `hardening_report.md`.

## Status

- Handmade TF-IDF coverage: **89/100**.
- Handmade MobileBERT FP32 coverage: **93/100**.
- Handmade PTQ `.pte` coverage: **92/100**.
- Validation/test policy metrics: unchanged from baseline.
- Unit tests: **66 passed**.
- Production model artifacts and thresholds: unchanged.
- Kotlin desktop-JVM Tier-1 parity: **334/334 local cases and 34/34 synthetic
  cases** for evidence, the full 31-flag vector, the portable model, and
  end-to-end policy.
- External Indian control parity: **2,014/2,014** for flags, model, and policy.
  The set is previously observed, has no smishing labels, and is not a blind
  test. See `results/indian_control/` for the aggregate evaluation and
  `results/kotlin_indian_control_parity.json` for parity details.
- Android app build and device measurements: **not started**.
- A fresh blind Indian precision estimate: **not measured**.

Read `results/hardening_report.md` before promoting anything to the Android
build.
