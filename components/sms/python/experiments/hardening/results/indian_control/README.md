# External Indian control benchmark

This directory records the current detector's result on the external
`data/indian/india_spam_sms.csv` benchmark. It is a **previously observed
control set**, not a blind held-out test.

- Input rows: 2,014.
- Leakage-filtered evaluated rows: 1,994 (20 rows overlapped train/validation).
- Labels after filtering: 1,295 ham, 699 spam, 0 smishing.
- Source: `kaggle_india_spam_sms`; language: `en/hi-Latn`; sender metadata is
  unavailable.
- No smishing labels exist, so smishing precision and recall are not
  estimable. The binary spam/ham view is the interpretable result.
- Ham false-positive rate: 13.82% (405/1,295).
- Policy any-non-ham precision: 78.84%.
- Policy exact-spam precision: 70.81%.
- New hardening flags fired only on spam: `TELECOM_LURE` 26, `TASK_SCAM` 1.
  Ham false positives and any-non-ham flagging were unchanged; 21 additional
  spam rows were labelled smishing, reducing exact-spam precision and recall.
- The set was not used to tune the rules or thresholds. Do not tune on it now.

`indian_eval.json` and `indian_eval.md` are aggregate reports; they contain no
raw SMS bodies. Raw parity fixtures are generated only in the approved local
temp workspace by `experiments/hardening/export_indian_parity.py` and are not
committed.

Kotlin parity at all three layers: `2,014/2,014`; see
`../kotlin_indian_control_parity.json`.
