# Rakshak submission checkpoints

Working plan:24 November2026. Deadline supplied in the organizer email: **25 November2026,11:59pm IST (Asia/Calcutta)**. Only the first submission is considered. This is a preparation record; nothing has been submitted and no mentor approval is assumed.

## Current phase and gates

| Phase | State | Completion evidence / next action |
|---|---|---|
| Preserve current experimental baseline | Done | Installed app0.17.3/code46; versioned network/SMS/URL model identities and validation reports retained. |
| Recover all available SMS source | Done | Full archive located in user Downloads. Trainer, PTQ/QAT export, selected checkpoint, split metadata and matching deployed PTQ hash verified. Selected checkpoint tensor count, dataset hashes and disjoint declared groups verified; source/provenance included. |
| Update report through SMS/URL work | Draft complete | 89-page PDF and self-contained LaTeX compiled; separate component chapters, archived/new result distinction and limitations included. Final candidate/mentor review still pending. |
| Update and rename public repository | Done: development snapshot | Public `rakshak` source/report pushed; history preserved. Hosted Python and full Android checks passed on `611bd4d`: [CI evidence](https://github.com/vishwajeet-singh-bhati/rakshak/actions/runs/45356650336). Model/faculty/submission gates remain pending. |
| Model improvement experiments | Planned; not yet accepted | Freeze baseline and validation/test roles. Use the experiment plan below; keep candidates separate until measured improvement. |
| Choose submission candidate | Pending user decision | Pin model hashes, app version, code commit, dataset provenance and exact report numbers. No automatic promotion from one attractive metric. |
| Faculty/mentor review | Pending | User will request review after candidate selection. Supply report PDF, repository, claims/limitations and reproduction guide. Record feedback and approval evidence here. |
| Two-minute public demo video | Pending | Use the storyboard below; record1080p16:9MP4, upload to YouTube/Drive, verify public access without signing in. |
| Final submission | NOT STARTED | Require user go-ahead, mentor review, frozen commit, PDF and public repository/video URLs. User checks form once before the only final submit. |

## Required submission artifacts

1. **Public GitHub/GitLab repository.** Requested target: `https://github.com/vishwajeet-singh-bhati/rakshak`. Confirm the final URL, public visibility and remote commit after publication. Include current Android source, available network/SMS/URL training/preprocessing/evaluation/export code, model identities, setup/testing instructions, dependencies/licenses and aggregate evidence. Keep components separately indexed.
2. **Two-minute public demo video.** Final URL is pending. Preferred1920x1080,16:9,MP4. Include actual app behavior and explain that it is a research prototype. Do not imply synthetic URLs prove real-world accuracy.
3. **Project report PDF** (the email also says `.dox`; PDF is the clear supported route). Planned canonical output: `docs/project_report/Rakshak_Project_Report.pdf`, with self-contained LaTeX source alongside it. Explain methodology, results, hardware utilization, optimization, reproducibility and limitations. This remains a draft until the chosen candidate and mentor review are frozen.
4. **Submission form:** https://forms.gle/3KyscquPFG8rS9ASA . Open/read during preparation only. Do not submit a placeholder or test entry. Check actual fields and upload limits while signed into the intended participant account; preserve answers privately before final submission.

No ZIP is required by the supplied email and none is planned. Raw datasets, personal SMS/inbox contents, packet captures, credentials, private keys, environments and third-party restricted feed snapshots must stay out of the public repository. Large Llama weights use their existing separately licensed download manifest. Public builds initially use an empty threat database with local setup instructions; the report distinguishes that from the measured populated phone build.

## Model improvement plan and acceptance record

Use `docs/MODEL_IMPROVEMENT_PLAN.md` for experiment details. Priorities:

- SMS: compare the exact FP32/PTQ/QAT baselines and end-to-end warning policy on validation data; reduce ham warnings while protecting smishing recall. Preserve group-separated splits. The original test was previously opened, so label it a reused regression test, not a fresh holdout.
- URL: obtain independently supported benign labels and unseen phishing examples. The2,048 supplied URLs duplicate reference inputs;1,830 remain unknown. Do not label by model prediction or tune against the known-positive benchmark and call it unseen evaluation. Compare raw classifier and list-assisted outcomes separately.
- Network: retain the current frozen baseline and documented ordinary-traffic/protocol failures. Candidate routing/context repairs must pass matched normal and attack controls; do not exchange a large recall loss for fewer false alarms.
- Runtime: compare cold/warm latency, CPU/RAM/PSS and output quality on the same hardware. Llama explains findings and cannot repair detector accuracy.

For every proposed change record: hypothesis, source commit, model/config hash, allowed training/validation data, frozen comparison set, before/after confusion counts, per-class precision/recall/F1, warning-level FP/FN, latency/memory, failure cases and promotion/rejection decision. If data or time is insufficient, keep the baseline and describe the limitation.

| Experiment | Baseline | Candidate | Validation / test evidence | Decision |
|---|---|---|---|---|
| Next SMS improvement | code46, matching PTQ model | Pending | Archived comparison available; no new candidate accepted | Pending |
| Next URL improvement | raw172/218 known positives; list218/218 | Pending | Needs independently supported negatives and fresh held-out examples | Pending |
| Next network improvement | augmented-v1 gate/diagnosis | Pending | Existing misses/FP remain documented | Pending |

## Faculty review packet

Provide the repository URL and pinned candidate commit; report PDF and source; one-page project summary; architecture/dry-run guide; datasets/split assumptions and hashes; exact measured results with cohort definitions; hardware/optimization evidence; known failures and unsupported claims; Android build/install/test guide; licenses and what is not bundled. Ask the mentor to review technical claims and reproducibility, and record requested corrections before approval. No email/contact has been sent by this preparation work.

## Demo storyboard (target120seconds)

- 0-15s: problem, Rakshak and the test phone/hardware.
- 15-35s: three detector controls, local processing and permissions.
- 35-65s: one reproducible suspicious test and its immediate factual warning; show separate detector evidence.
- 65-85s: simple Llama guidance and a quiet normal control, without promising all normal activity is safe.
- 85-105s: measured results, their denominators and one honest limitation.
- 105-120s: source/reproduction/report location and closing project identification.

Use test accounts/messages; hide personal notifications and credentials. Show real captured results or clearly mark a replay. Verify the final duration/audio/readability, public link and intended account before pasting the URL into the form. Recording/uploading remains pending user action or explicit authorization.

## Final freeze checklist (perform once candidate is chosen)

- [ ] Candidate source/model/app/report hashes agree; rollback retained.
- [ ] Fresh clone instructions build and tests pass in the documented environment.
- [ ] Report clearly distinguishes archived, newly measured, synthetic and real-world evidence.
- [ ] Claims exclude unavailable full URL precision/accuracy and unverified attack labels.
- [ ] No raw data/credentials/restricted feed snapshot in public files or newly published history.
- [ ] Repository named rakshak, public and readable without sign-in; CI outcome reviewed.
- [ ] Mentor feedback addressed and approval recorded by user.
- [ ] Final PDF visually checked, readable and correctly named.
- [ ] Two-minute video is public and plays without sign-in.
- [ ] Form fields, participant/team information and upload limits checked; links/PDF staged privately.
- [ ] User approves final submission before25November2026,23:59IST.
- [ ] Exactly one submission sent; save confirmation privately with time and final links.

## Handoff for the next session

Read this file, `HANDOFF.md`, `CURRENT_STATUS.md`, the latest publication record and component report before changing source or models. Do not interpret a published development snapshot as final submission approval. Update each phase with actual evidence, dates, commit IDs and remaining steps; keep previous experiment outcomes and the deadline visible.

## Current artifact index

- Report PDF: [Rakshak_Project_Report.pdf](docs/project_report/Rakshak_Project_Report.pdf); Overleaf: [Rakshak_Project_Report.tex](docs/project_report/Rakshak_Project_Report.tex).
- Added-model overview: [components](components/README.md); [model improvement plan](docs/MODEL_IMPROVEMENT_PLAN.md).
- SMS original split/checkpoint/evaluation evidence: [ARCHIVED_EVALUATION.json](components/sms/provenance/ARCHIVED_EVALUATION.json).
- URL measured limits: [benchmark report](results/url_benchmark_20261124/README.md).
- Current repository: https://github.com/vishwajeet-singh-bhati/rakshak . Video URL, faculty approval and submission confirmation remain pending.
- The Google Form could not be inspected through the read-only web tool; its exact fields/file limits still need participant-side review. No form was submitted.
