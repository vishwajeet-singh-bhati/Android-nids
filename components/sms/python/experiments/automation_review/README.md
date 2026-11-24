# Automated SMS validation

The baseline is the saved v0.4.1 routing policy in `baseline/CascadePolicy.kt`. The candidate is v0.5.0. Both use the same portable Tier-1 model and frozen MobileBERT PTE. No model training or score threshold fitting is performed here.

`build_suite.py` creates the authored challenge and APK asset; `audit_suite.py` exports CSV and checks reuse; `run_desktop.py` compares baseline/candidate using the actual Kotlin detection/fusion core and frozen Windows ExecuTorch PTE. It deduplicates neural forwards across modes using normalized input hashes. Raw existing corpus texts and intermediates remain under ignored `data/indian/automation_v1/`; published comparison reports contain IDs, categories and scores/results without message bodies.

From the `sms-detection` directory:

```powershell
.venv\Scripts\python.exe experiments/automation_review/build_batch.py
.venv\Scripts\python.exe experiments/automation_review/audit_suite.py
.venv\Scripts\python.exe experiments/automation_review/run_desktop.py
```

The desktop runner requires `tier1-kotlin/build/baseline-batch.jar` and `candidate-batch.jar`, the installed JDK, existing processed datasets and `experiments/mobilebert/.venv`. The Python worker uses local weights/tokenizer only. Desktop and Android runtimes currently differ (1.6.0 vs 1.5.1); these results are not phone validation.

After reconnecting the Pixel through ADB:

```powershell
.venv\Scripts\python.exe experiments/automation_review/run_pixel_benchmark.py --install
```

This saves prior live-evaluation logs when available, installs the built debug APK with app data retained, runs the 230 cases on the phone and retrieves its report. It force-stops/reopens the app to start the batch; run after any real-SMS queue finishes. Use `--serial` if multiple devices are connected. A failed/partial run is never reported as a pass.

Alternatively, open the updated app and tap **Run automatic tests** once. Keep the app in the foreground; it keeps the screen awake during the batch. No individual SMS sends are needed. Synthetic batch cases do not change live SMS receipt counts, write fake real-SMS audit events, or post hundreds of warnings. Real incoming SMS are still processed separately.

Reports remain under app-private `files/benchmarks/<id>/`; each case is flushed to JSONL before proceeding. `files/last_benchmark.json` holds the last completed summary, including Tier-1/Tier-2 usage, failures, per-stage times and sampled PSS. JSONL partials remain if interrupted. Sampled PSS is not continuous peak RAM. No battery claim is made.

The batch tests detector execution, not carrier delivery, multipart SMS broadcasts, notification visibility, process survival or background restrictions. Those require a small controlled real-SMS integration check on the reconnected phone. A sender-side failure or an RCS message cannot be counted as a received SMS test.

See `DATA_CARD.md` and `RESEARCH.md` before interpreting reported accuracy. Do not train on this challenge and then continue calling it a holdout.

`failure_review.csv` contains only the new authored synthetic cases with missed
scams or unnecessary final warnings, with blank independent-review fields.
It contains no real private SMS. `readiness.json` in the report directory marks
phone validation and release readiness explicitly. Neural caching assumes the
frozen tokenizer and runtime; invalidate the private cache stamp if either changes.
