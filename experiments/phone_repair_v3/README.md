# Repair campaign v3

Authorized independent repair of phone-aligned v2. See `PROTOCOL.md` for exact controls, thresholds and the better/fallback decision. Preserved version: tag `checkpoint/pre-repair-v3-20261119`; snapshot commit `bec3512`. Earlier installed phone app/model is also preserved. No remote workspace or push.

Run these from PowerShell in `<PROJECT_ROOT>`:

```powershell
# Overall phase and actual per-job epochs/steps
.\experiments\phone_repair_v3\Run-Repair.ps1 -Action Status

# Recent scheduler events, or follow them
.\experiments\phone_repair_v3\Run-Repair.ps1 -Action Logs
.\experiments\phone_repair_v3\Run-Repair.ps1 -Action Logs -Follow

# Actual training logs (substitute another job name)
Get-Content .\runs\phone_repair_v3\unweighted_gate_s0.log -Tail 30 -Wait
Get-Content .\runs\phone_repair_v3\unweighted_diagnosis_s0.log -Tail 30 -Wait
Get-Content .\runs\phone_repair_v3\moderate_diagnosis_s0.log -Tail 30 -Wait

# Post-training selection/comparison/export logs
Get-Content .\runs\phone_repair_v3\joint_selection.log -Tail 30
Get-Content .\runs\phone_repair_v3\final_comparison.log -Tail 30
Get-Content .\runs\phone_repair_v3\mobile_export.log -Tail 30
Get-Content .\runs\phone_repair_v3\scheduler_error.log -Tail 30
Get-Content .\runs\phone_repair_v3\finalizer.log -Tail 30
```

Ctrl+C stops log viewing. Detached training continues. The PC must stay on and awake.18 jobs /40 epochs each, max2 concurrently; every epoch/optimizer/RNG state and validation logits are retained in `runs/phone_repair_v3/jobs/`. Early stopping is disabled; there is one bounded retry per failed training process. Restarting the completed or active job preserves its saved checkpoints.

```powershell
# Start/resume only if needed; an active host is detected
.\experiments\phone_repair_v3\Run-Repair.ps1 -Action Start
```

Data preparation reuses the unchanged v2 input files; it hashes the full cohort and creates disjoint calibration/selection indices and a training-only difficult-benign pool. No manual phone cases or new labels enter training. All Python code and input hashes are frozen; do not edit campaign source during execution. The old v2 files are read-only inputs to this campaign.

Three arms (unweighted, moderate weights, difficult-benign sampling) each have three seeds and both models. Gate and diagnosis architectures, same seed initialization,147 input meanings, data partition, optimizer and40-epoch/update budgets match across arms. Sampling intentionally changes row exposure; effective class counts are saved each epoch. The existing v2 weighted pipeline and unchanged-weights/new-routing control are reported separately.

Outputs appear under `validation/reports/phone_repair_v3/`: `COMPARISON.md`, `evaluation.json`, `selection.json`, `mobile_export.json`, `completion_verification.json` and `COMPLETION_STATUS.md`. Until they exist there are no final repair scores. Final evaluation includes all treatment/seed pipeline finalists and every saved best/final model, classwise/fine-label/source counts and paired group differences.

The selected repair is used only if it meets the predeclared improvement comparison on validation selection and the identical opened v2 test cohort. Otherwise the preserved v2 is the requested intended fallback. Strict readiness failures remain visible regardless of that choice. The comparison is development evidence; independent phone accuracy remains pending.

Native bundles are separate: `runs/phone_repair_v3/exports/repair` and `exports/preserved_v2`; `deployment_bundle.json` identifies the intended one. No phone installation or live attack is automated. The Pixel is currently unavailable. Final source/model/runtime/resource checks and fresh user-launched attacks remain necessary before declaring the final phone pipeline validated.

The Start command also ensures the detached finalizer is running. Its audit can additionally be launched directly if needed:

```powershell
$audit = Start-Process -FilePath C:\Windows\System32\wsl.exe -ArgumentList @('-d','Ubuntu','--','<PROJECT_ROOT>/.venvs/traffic-pretrain/bin/python','<PROJECT_ROOT>/validation/finalize_phone_repair_v3.py') -WorkingDirectory <PROJECT_ROOT> -WindowStyle Hidden -RedirectStandardOutput <PROJECT_ROOT>\runs\phone_repair_v3\finalizer.log -RedirectStandardError <PROJECT_ROOT>\runs\phone_repair_v3\finalizer_error.log -PassThru
```

It verifies saved artifacts after completion and commits only named owned reports locally, leaving other staged/user files outside that commit. It cannot deploy, send traffic or repair a new training error on its own. `finalizer_status.json` reports whether verification/history completed or failed.
