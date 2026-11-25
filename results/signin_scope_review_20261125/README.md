# Ordinary-use alert review and normal monitoring scope —25 November2026

The user reported an alert while signing into Google around19:00–20:00IST.
The verified test Pixel's history contains two network activity groups at
19:47:05 and19:48:00. Both observed loopback exchanges to localhost port7810:
two packets, TCP reset, zero application payload. No app owner was established.
These are not recorded external Google connections. Sign-in causation and the
owning local service cannot be established from these records.

| Time IST | Binary score | Diagnostic top class/score | Displayed assessment |
|---|---:|---|---|
|19:47:05|0.577934|Benign /0.901999|Unclassified warning |
|19:48:00|0.651260|Benign /0.849226|Unclassified warning |

The binary threshold is0.5408333. The diagnosis model does not veto the binary
gate, so these positive gates became generic warnings. Scores are model outputs,
not calibrated probabilities. This is not evidence of an attack on the account.

## Cause and correction

`include_device_local_alerts` was true: the explicitly experimental option for
app-internal traffic was enabled in the test configuration. The normal/default
scope evaluates external connections and counts device-local exchanges separately.
Applying an external intrusion classifier to local IPC caused these inappropriate
external-intrusion warnings. Local traffic is not thereby proven universally safe.

Restored this one option to false at21:09IST. Existing app53, model files,
thresholds, SMS/URL controls and authentication-episode configuration were not
replaced. External-network monitoring remains enabled and foreground.

All137 existing network records and their original model evidence were preserved.
Eleven loopback records were moved to the device-local/out-of-scope history
category; external records were unchanged. No raw inbox/SMS query, Google-login
contents, credentials, Google-domain whitelist or new training labels were used.

## Validation and limits

- The installed hybrid contract passed its actual external147-feature parity
  checks with/without interleaved loopback traffic.
- Native gate/diagnosis/policy/delivery-clock checks passed; no model change.
- Before/after stored evidence dictionaries matched for every existing network
  record; external history rows matched in full. History was retained.
- Changed only the experimental device-local alert preference; monitor enabled
  and foreground status verified after restart.
- These checks establish the scope correction and preserved contracts, not a
  new classwise accuracy/recall estimate or a diagnosis of the local service.
- External ordinary-use false positives remain possible. Do not suppress all
  Google/bank/app traffic or label unknown external events benign by assumption.

## Live campaign status

The controlled test campaign stopped at18:36IST on a wireless ADB dropout before
this reported hour, so it was not generating attacks at19:47–19:48. Five cases
were completed; interrupted ConnectionExhaustion remained inconclusive.

After identity/health and both SSH PCs were reverified, the campaign resumed from
case6 with an explicit scope-phase annotation. The first five cases retain their
experimental-local setting tag; subsequent cases use external-only mode.
Background-warning counts cannot be pooled across these settings. The external
feature contract is unchanged; no new completed all-class result is claimed.

Private evidence remains local. No messages, database snapshots, network endpoint
identities, keys or raw captures are included in this aggregate report.
