# Authorized repair v3 - 19 November 2026

User authorized preserving the current pipeline, implementing repair, performing a proper comparison, then using the repaired approach if better or the preserved v2 if not. Rollback tag `checkpoint/pre-repair-v3-20261119` points to01cfea5; checksum snapshot is committed asbec3512 under `validation/reports/phone_repair_v3/rollback_snapshot.json`. The last installed phone app remains the older0.11.3-context-rc4/code33; preserved v2 is an offline147-input binary/diagnosis pipeline, not that110-input installed model.

## Scope of this repair

Reuse the frozen v2 train/validation/test rows, feature extraction,147 inputs, normalization and model dimensions. No raw-capture rebuild, extra labels, invented Bot relabeling, manual-test training data or unknown-to-benign conversion. Label ambiguity remains documented until independent application/session ground truth exists. This first repair measures loss/sampling, calibration, routing and complete-pipeline selection; new Web parsing/temporal inputs and distillation remain separate future changes if evidence supports them.

Three treatments ×three seeds ×gate/diagnosis =18 jobs,40 epochs each,720 total. Gate147->96->48->1 (18,913 parameters); diagnosis retains the current width64 TSANet/context model (173,721). Same initial states, AdamW.001/weightdecay1e-4, batch512, gradient clip5, two CPU threads, fixed update count and no early stopping. All epoch/best-training/best-validation/last/final checkpoints and every epoch's full validation logits are retained. Existing v2 weighted models supply the preserved control; no reusing repaired test results to pick a new old-model winner.

- Unweighted: natural-frequency unweighted loss and full seeded shuffle.
- Moderate: same order/initialization, existing relative class weights capped at3x Benign.
- Difficult-benign sampling: unweighted loss;10% of epoch draws explicitly sampled from training-only Benign reset lookalikes or frozen v2 gate probability>=.5; remaining90% from the seeded full cohort. Same total optimizer updates and unique cohort; effective example/class exposures differ by design and are saved per epoch. Pool has54,695 rows. Do not describe sampling as identical row frequency.

All training loss/metrics are checked for nonfinite values. A failed job receives one resume attempt from its last optimizer/RNG state. Two jobs maximum run concurrently. Hidden local WSL processes persist after the chat turn; the PC must stay running/awake. No automatic attacks, external training, push or installation.

## Calibration and selection

Split the existing validation set by disjoint connection groups, seed9301:547,200 calibration rows and641,524 selection rows. Each contains all seven families. Calibration never fits on training or test rows. Original v2 model weights were selected on the earlier full validation cohort, so the inherited data are development material, not a newly blind benchmark.

Fit a positive shared logit scale and class biases on calibration groups using natural-frequency NLL and small parameter regularization. Gate calibration has one scale/one bias; diagnosis one scale/seven biases. This is scalar temperature/affine bias calibration, not a new raw-feature classifier. Freeze parameters before selection/test.

Per-epoch diagnosis shortlisting uses the composed pipeline with the fixed preserved gate, rather than only standalone macro F1. Retain the top two joint-ranked epochs, best Bot/Web F1 and final; gate shortlist uses top two validation-ranked epochs and final. For each same-arm/seed pair, jointly compare shortlisted checkpoints, calibrations and declared policy grid. Include an additional routing/calibration-only control using unchanged v2 weights. All saved epochs remain available; shortlisting is not a claim that every possible epoch pair or hyperparameter was exhaustively searched.

Routing has a low review threshold and a high alert threshold. High warnings are never vetoed by diagnosis. Middle-band traffic is reviewed and becomes a warning only if diagnosis attack probability passes the declared review cutoff. Diagnosis may output unknown while retaining a high warning. Review is not an alert. Low-score traffic continues monitored history. Review workload is limited to25% of this laboratory cohort; actual phone costs require measurement.

Policy grid: high cutoffs at Benign selection-score quantiles .999/.9995/.9999 and .99; low at high, min(high,.1), or min(high,Benign .99 quantile); review acceptance .5/.9/.99; type confidence .5/.6/.8. Calibration is fit before this grid. Score complete-pipeline precision/recall/confusion/unknowns, binary recall/FPR, source FPR and routing fraction. Choose the best validation pair; freeze all choices before repair test scoring. Model pairing is within each treatment/seed; the full policy selection is shared across all treatments.

## Predeclared better/fallback comparison

Preserved v2 is gate_s0 selected epoch37 + diagnosis64_s1 selected epoch23, original gate threshold0.7858333333/type confidence0.6. Both old and repair are evaluated on exactly the same1,098,929 v2 test views. The baseline confusion must reproduce exactly. Current v2 test and diagnoses are already opened; report this as matched development comparison, not fresh independent generalization.

To call the repair better, require the following on both selection and test:

- Macro F1 increases by at least0.5 percentage points and Bot precision by at least5 points.
- Overall Benign FPR does not increase; every source remains<=0.5%.
- Aggregate binary recall loses no more than0.1 point; each attack family's binary recall loses no more than1 point.
- Each family's typed recall loses no more than2 points and precision no more than1 point.

These are explicit tradeoff tolerances, not a promise of zero regression. Also report the stricter readiness screens: FPR<=0.1%, aggregate attack recall>=95%, each attack's binary recall>=85%, all typed precision>=85%/recall>=80%, and source/routing limits. Improvement and full readiness are separate flags; none is silently converted into a success. If the frozen repair is not better under these checks, the intended deployment bundle is preserved v2 per the user's instruction, with its known Bot limitation disclosed. No post-hoc switching to a different test winner.

Evaluate one validation-selected complete pipeline for each arm/seed plus routing-only control, all18 saved best and final standalone models, class/fine-label/source metrics and paired connection-group bootstrap differences. Both endpoint views/segments share a group; intervals do not establish independent-session confidence. SQL test has only two views and remains unsupported for a strong fine-class reliability claim.

## Export, completion and deployment

Export the selected repair with normalization and calibration embedded, keeping raw input shapes [1,32]/[1,115]. Preserve a separate copy of v2 exports. Native checks compare both models and the complete review/alert/type policy on class-balanced cases, requiring zero decision changes. A separate detached finalizer verifies all720 epoch hashes, saved validation coverage, matching initializations, immutable input/rollback hashes, baseline confusion, all best/final evaluations and native policy output. It writes completion evidence and commits only owned reports locally.

The Pixel is currently absent from ADB. There is no need to wait for it for training; exact Kotlin source/native model verification, app integration, ordinary-use/resource validation and fresh manually user-launched attacks remain pending. User authorized repaired-or-fallback deployment after comparison; do not request redundant model-choice approval. Device availability and successful runtime checks are still required. No phone attack is started automatically.

Automation smoke checks all three treatments, saved epochs, matching initializations/orders, completed-job resume, calibration, joint selection, old-model reproduction, fallback bundles and complete native policy parity. An independent controlled policy test verifies that a review band can recover ten known weak-score attack examples and suppress20 benign lookalikes while preserving high warnings; these synthetic figures are not model detection results.
