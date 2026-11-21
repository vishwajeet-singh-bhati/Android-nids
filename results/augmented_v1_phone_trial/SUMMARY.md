# Augmented v1 live phone results

State: **manual_remaining**.

Frozen app 0.13.0/code37; gate threshold 0.5408333333333333, type cutoff 0.8. No retraining or tuning during these tests.

| Case | Test/effect | Native segments | Binary flags | Predicted types | Visible notification groups | Interpretation |
|---|---|---:|---:|---|---:|---|
| Benign | http_request: 8 | 8 | 0 | Benign: 8 | 0 | Normal control quiet |
| PortScan | 129 port attempts; 129 captured tuples | 512 | 510 | Benign: 2, Bot: 5, Port Scan: 437, Unclassified: 68 | 7 | Controlled scan detected |
| SlowScan | 32 port attempts; 32 captured tuples | 124 | 122 | Benign: 2, Bot: 2, Port Scan: 86, Unclassified: 34 | 4 | Controlled scan detected |

## Request-level checks

| Case | Independently verified attack requests | Binary detected | Correct Web label | Normal controls | Normal controls flagged |
|---|---:|---:|---:|---:|---:|
| Benign | 0 | 0 | 0 | 8 | 0 |

## Scan connections

- PortScan: 128/129 captured connections flagged; 122 had at least one Port Scan label. The deliberate open-port connection is included in the denominator.
- SlowScan: 31/32 captured connections flagged; 23 had at least one Port Scan label. The deliberate open-port connection is included in the denominator.

## Interpretation and limits

- Model segments, connection attempts, activity groups and independent attack episodes have different denominators. Several segments can belong to one scan connection.
- Notifications are real Android notification records correlated with activity groups. Several flags can merge into one group. The saved snapshot cannot prove that an absent notification was never posted.
- Llama explains flagged evidence separately. Explanation states at case snapshots: {'complete': 11}. Display sources at snapshots: {'evidence_based_fallback': 11}. Later completion may occur; generated draft text is not automatically accepted.
- HTTP password guessing tests Web Attack behavior. It does not reproduce FTP/SSH-Patator. Real Bot malware, multi-source DDoS and protocol-specific FTP/SSH attacks remain untested.
- HTTPFlood is bounded load, not demonstrated full DoS/DDoS. ConnectionExhaustion confirms denial of the isolated two-slot dummy resource, not exhaustion of the phone.
- Beacon is excluded when receiver policy blocks it. Existing firewall blocks were preserved.
- Normal controls here are small controlled samples, including the successful login within the guessing sequence and the normal SQL query. They do not establish everyday mobile false-positive rates.
- Scan segments predicted Bot are incorrect attack-type labels; their binary flags are still associated with the controlled scan. Unknown labels are retained explicitly.
- This is a development test on the same phone/app used during data collection; it is not a fresh independent device/campaign benchmark.
- Every executed case passed exact per-connection packet accounting, segment-start timestamp matching, finite147-input checks, frozen-threshold consistency and live capture-health checks.

## Comparison with prior v2 diagnostics

Prior v2 detected the fast/slow scans, missed the confirmed HTTP guessing/SQL/XSS and isolated-resource cases, and flagged 71/128 bounded HTTP-load segments (mostly unclassified). Those runs are historical diagnostic cases with different packet/retry counts. Use the request/connection-level results above; do not treat segment totals across runs as a matched independent accuracy experiment.

Machine-readable detail: SUMMARY.json and results.json. Private packet/request/native-feature evidence remains local under runs/manual_phone_tests. No raw dataset is published.

## Subsequent manual tests

Eight additional user-run cases/retries have been audited: [read the full review](../augmented_manual_review_20261121/README.md). The table above records the earlier automatic partial campaign. Remaining tests stay manual; no automatic restart occurred.
