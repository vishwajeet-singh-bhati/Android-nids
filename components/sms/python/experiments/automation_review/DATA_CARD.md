# Indian SMS scenario challenge v1

Created 12 November 2026 for automated regression testing, not model training.

The suite has **230 messages from 115 authored scenarios**: 90 ham, 40 ordinary promotional spam, 84 smishing, and 16 uncertain. Each scenario has an original and an uppercase/spacing variant. Languages: 176 English, 32 Hinglish, 22 Hindi. Variants are related samples, so 230 must not be presented as 230 independent observations.

`challenge.json` is the canonical dataset; `challenge.csv` is the spreadsheet copy. The same cases are bundled in the Android APK. Each row has an ID, semantic scenario group, label, language, category, variant, source and rationale. All embedded web addresses use reserved `.invalid` hosts. No actual private SMS was copied into this new suite.

Labels describe the authored scenario. `ham` means ordinary personal/service content; `spam` means a promotion without established fraud; `smishing` means an intended fraudulent solicitation; `uncertain` means text alone cannot establish authenticity. Some genuine messages also request payments or contain links. These hard negatives matter. An uncertain row is excluded from exact-label accuracy and scam precision/recall, while its review rate is reported separately.

The scenarios cover greetings, personal payments, OTP notices, transactional notices, delivery, security advice, promotions, KYC threats, utility disconnection, UPI refund deception, courier fees, job/task fees, fake investment returns, impersonation and APK/remote-access lures. The advisories linked in `RESEARCH.md` informed the categories; the messages are original synthetic examples, not quotations from those sources or a newly collected Indian inbox corpus.

The author also changed the routing rules and supplied the expected labels. This is **not a blind, independently adjudicated, representative or prevalence-weighted evaluation**. No numeric threshold or model weight was fitted on it, and routing policy was frozen before the first result comparison. Existing legacy test, handmade and Indian datasets are previously inspected controls, not fresh holdouts.

`audit_suite.py` checks normalized exact text, template skeletons, and query-to-reference trigram Jaccard >=0.8 against local train/validation/test/external, handmade and Indian source controls. Results are in `artifacts/reports/automation_review/suite_audit.json`. It flags overlaps without deleting them; simple phrases and reuse remain part of this regression suite. The audit does not establish semantic independence or detect every paraphrase.

Keep all variants of a scenario together if this is later used as development data. A future final benchmark needs new, consented/anonymized Indian messages, two independent labels with disagreements resolved, scam/ordinary-spam separation, language coverage, and campaign/source/time grouping before any retraining or threshold selection.

Frozen rows SHA-256: `14679818ccbc1b9e4705cabaf1baf4c12d6f979630497f19a8cd79a19b0aa175` (UTF-8 JSON rows with sorted keys; not the entire file hash).
