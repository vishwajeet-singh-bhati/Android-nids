# Augmented v1 controlled phone trial

State: manual_remaining

Fresh controlled development cases on one owned phone/app. Exact tuple-correlated decisions. Bounded load does not establish full DoS/DDoS; no population accuracy claim.

| Case | Verified target evidence | Matched segments | Flagged segments | Model labels | Visible alert groups | Outcome |
|---|---|---:|---:|---|---:|---|
| Benign | {'http_request': 8} | 8 | 0 | Benign: 8 | 0 | Normal control quiet |
| PortScan | {} | 512 | 510 | Benign: 2, Bot: 5, Port Scan: 437, Unclassified: 68 | 7 | Controlled scan detected (label corrected 25 Nov 2026: the original text came from a report-generator bug) |
| SlowScan | {} | 124 | 122 | Benign: 2, Bot: 2, Port Scan: 86, Unclassified: 34 | 4 | Controlled scan detected |

The HTTP guessing profile is not FTP/SSH brute force. No real bot malware or multi-source DDoS was executed.
Visible notification absence does not prove none was posted; groups may merge several segment decisions.
Unrelated background flags are excluded from matched test totals. Existing history/Llama files are retained.
