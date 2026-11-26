# Controlled phone testing

For setup followed by **each of the thirteen live commands run individually**, use the [step-by-step network testing guide](NETWORK_TEST_PROCEDURE.md). The historical `tests/NIDS_tests.sh` is a PowerShell command sheet; `tests/NIDS_tests.ps1 -Preview` checks its plan without accessing devices.

Use only an owned, explicitly selected test phone on the same private LAN as the PC. The harness derives the target from authorized ADB and checks its private route; it has no arbitrary external target argument. TrafficLab uses dummy accounts, a disposable in-memory database, isolated script execution and a bounded test resource. It exposes no shell or phone files.

Build/install first, enable monitoring and wait 340 seconds. Set `NIDS_DEVICE_SERIAL` (PowerShell `$env:...` or Linux `export ...`) and install Python dependencies. Run one command at a time:

```bash
python reproduce.py phone test --profile Benign
python reproduce.py phone test --profile PortScan
python reproduce.py phone test --profile SlowScan
python reproduce.py phone test --profile PasswordGuessing
python reproduce.py phone test --profile SQLInjection
python reproduce.py phone test --profile XSS
python reproduce.py phone test --profile ConnectionExhaustion
python reproduce.py phone test --profile HTTPFlood
python reproduce.py phone test --profile Beacon
```

Add `--preview` to print a case without accessing the phone or sending traffic. Each actual command runs one bounded case, observes for 130 seconds and stops the disposable target. Allow at least 305 seconds after the last test decision before another independent case; the observation period alone may not clear 300-second history. Leave NIDS running. Do not run manual tests concurrently with the dataset campaign.

| Profile | Actual behavior and limit |
|---|---|
| Benign | 8 normal HTTP requests |
| PortScan | One lab port plus 128 verified closed ports; retransmissions can produce multiple model segments |
| SlowScan | One lab port plus 31 verified closed ports at a slower rate |
| PasswordGuessing | 32 dummy HTTP-account guesses, normally 31 failed / one valid; this is Web Attack, not FTP/SSH-Patator |
| SQLInjection | One control and two actual injections into the disposable database; target effect logged |
| XSS | One isolated script-execution proof; target effect logged |
| ConnectionExhaustion | 16 requests against a two-slot dummy resource; limited application denial, not whole-phone exhaustion |
| HTTPFlood | 128 bounded requests/at most 8 workers; delivered load alone does not prove DoS/DDoS |
| Beacon | 12 fixed PING/PONG attempts to PC TCP 43990; behavior probe, not actual Bot infection |

Logs/checks/PCAPs stay under ignored `runs/manual_phone_tests`. Generated chronology is under `results/manual_phone_tests`. Match full TCP tuples against packets/native traces; unrelated flags in the same time window are not test detections. Notifications group flags into activities; multiple segments/retries are not independent attacks. A notification absent from a late snapshot may have been dismissed earlier.

The original manual-test companion captures are 96-byte/filtered packet evidence. The newer dataset collector uses 768-byte/all-context recording with strict native parity and socket-level target events. Use DatasetLab/`phone collect` for training data; do not treat old manual PCAPs as complete feature replays.

If Beacon records connection timeouts/no PING/PONG, mark it inconclusive. Check listener reachability and your administrator-approved firewall policy. An explicit inbound Block can override an Allow. The harness does not disable firewalls or managed restrictions. Encrypted application semantics remain outside the current cleartext indicators.

The new DatasetLab also records password spraying across dummy accounts, varied SQL/XSS forms, legitimate bursts and normal error/code-text controls. Those dataset actions and labels are implemented in `experiments/phone_capture_v1/collect.py` and `quality.py`; they do not depend on detector scores.


## Current release clarification

Current source is code53 with the augmented-v1 detector and opt-in Expected feedback. Network model weights/thresholds are unchanged from the augmented baseline; historical code36 is a reference. Read [current pipeline](CURRENT_PIPELINE.md), [final report](final_submission_report/README.md), [completed training](../results/phone_capture_training_v1/RESULTS.md) and [protocol testing](PROTOCOL_TESTING.md). All six training jobs completed; readiness remains false. The old v2 reference is kept only for comparison. New cases must be kept separate from already examined development cohorts.
