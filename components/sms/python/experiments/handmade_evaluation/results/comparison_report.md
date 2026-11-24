# Handmade smishing evaluation

Generated: `2026-11-07T09:47:50.670303+00:00`

Dataset: `<USER_HOME>\Pictures\bharat_ai_2026\sms-detection\experiments\mobilebert\handmade_dataset\smishing_dataset.csv`

Dataset SHA-256: `df8cd4460c5ed50d6c28ba451092fb5942d9d855a6e5eff931480fa0b75697d5`

Source dataset unchanged after run: **True**

## Assumption

All 100 messages are provisionally treated as **smishing**. Because there
are no non-smishing controls, the detection rate is a coverage/recall
measure. Precision, specificity, and false-positive rate are not defined
for this evaluation.

## Models and decision rules

### TF-IDF full detector (primary)

The existing `SmsDetector.from_artifact("artifacts/model")` pipeline is
used unchanged. Its saved risk policy thresholds are applied exactly as
stored in `artifacts/model/metadata.json`:

- high: `0.385`
- suspicious: `0.1009090909090909`
- evidence_free_high: `0.8`

The primary TF-IDF label is the detector's final `ham`/`spam`/`smishing`
label after the risk policy. The classifier-only argmax is recorded as a
diagnostic because MobileBERT-22 has no equivalent policy layer.
`tfidf_rule_label` in `predictions.csv` is the rules-only label;
`tfidf_detector_label` is the final fused detector label.

### MobileBERT-22

The existing fine-tuned 22-layer checkpoint is loaded read-only from
`experiments/mobilebert/checkpoints/mobilebert22_lr5e5_bs16_e4/best`.
Input is `normalize_text(message).model_text`, truncated at 128 tokens.
The reported label is the softmax argmax. No policy thresholds were
applied or created for MobileBERT.

## Overall comparison

| Model | Smishing detected | Detection rate | Missed | Spam pred. | Ham pred. | Mean confidence | Mean p(smishing) |
|---|---|---|---|---|---|---|---|
| TF-IDF full detector | 74 | 74.0% | 26 | 25 | 1 | 0.596 | 0.491 |
| TF-IDF classifier only (diagnostic) | 61 | 61.0% | 39 | 36 | 3 | 0.596 | 0.491 |
| MobileBERT-22 | 93 | 93.0% | 7 | 7 | 0 | 0.967 | 0.920 |

`Mean confidence` is the mean maximum class probability. For TF-IDF it
can belong to a class different from the final policy label when a rule
override occurs; `tfidf_predicted_label_score` in `predictions.csv` is the
score assigned to the final label.

## Detection agreement

- Both detectors predicted smishing: **71**
- Only TF-IDF predicted smishing: **3**
- Only MobileBERT predicted smishing: **22**
- Neither predicted smishing: **4**
- Exact three-class label agreement: **75/100**
- TF-IDF classifier-only vs MobileBERT exact label agreement: **62/100**

| TF-IDF full detector \ MobileBERT-22 | ham | spam | smishing |
|---|---|---|---|
| ham | 0 | 0 | 1 |
| spam | 0 | 4 | 21 |
| smishing | 0 | 3 | 71 |

## Category-wise comparison

| Category | N | TF-IDF detected (rate) | TF-IDF missed (spam/ham) | MobileBERT detected (rate) | MobileBERT missed (spam/ham) | Only TF-IDF | Only MobileBERT | Neither |
|---|---|---|---|---|---|---|---|---|
| Account Security | 8 | 7 (87.5%) | 1 (1/0) | 8 (100.0%) | 0 (0/0) | 0 | 1 | 0 |
| Bank & KYC | 18 | 16 (88.9%) | 2 (2/0) | 18 (100.0%) | 0 (0/0) | 0 | 2 | 0 |
| Charity & Relief | 1 | 1 (100.0%) | 0 (0/0) | 1 (100.0%) | 0 (0/0) | 0 | 0 | 0 |
| E-commerce & Offers | 5 | 3 (60.0%) | 2 (2/0) | 4 (80.0%) | 1 (1/0) | 0 | 1 | 1 |
| Educational | 5 | 4 (80.0%) | 1 (1/0) | 5 (100.0%) | 0 (0/0) | 0 | 1 | 0 |
| Government & Tax | 14 | 11 (78.6%) | 3 (3/0) | 12 (85.7%) | 2 (2/0) | 1 | 2 | 1 |
| Health & Medical | 2 | 1 (50.0%) | 1 (0/1) | 2 (100.0%) | 0 (0/0) | 0 | 1 | 0 |
| Job & Loan | 15 | 6 (40.0%) | 9 (9/0) | 15 (100.0%) | 0 (0/0) | 0 | 9 | 0 |
| Law Enforcement | 6 | 6 (100.0%) | 0 (0/0) | 6 (100.0%) | 0 (0/0) | 0 | 0 | 0 |
| Miscellaneous | 1 | 1 (100.0%) | 0 (0/0) | 1 (100.0%) | 0 (0/0) | 0 | 0 | 0 |
| Mobile Recharge | 2 | 1 (50.0%) | 1 (1/0) | 1 (50.0%) | 1 (1/0) | 0 | 0 | 1 |
| Postal & Delivery | 10 | 6 (60.0%) | 4 (4/0) | 9 (90.0%) | 1 (1/0) | 1 | 4 | 0 |
| Telecom & Utility | 2 | 1 (50.0%) | 1 (1/0) | 0 (0.0%) | 2 (2/0) | 1 | 0 | 1 |
| Travel & Tourism | 1 | 1 (100.0%) | 0 (0/0) | 1 (100.0%) | 0 (0/0) | 0 | 0 | 0 |
| UPI & Payments | 7 | 6 (85.7%) | 1 (1/0) | 7 (100.0%) | 0 (0/0) | 0 | 1 | 0 |
| Utility Bills | 3 | 3 (100.0%) | 0 (0/0) | 3 (100.0%) | 0 (0/0) | 0 | 0 | 0 |

Full per-category details, including classifier-only results and mean
confidences, are in `category_comparison.csv`.

## Tactic-wise comparison

- Unique tactic values: **99**
- Tactic groups where both models detected every message: **70**
- Tactic groups where only TF-IDF detected at least one message: **3**
- Tactic groups where only MobileBERT detected at least one message: **22**
- Tactic groups where neither model detected any message: **4**

Because most tactics have exactly one message, the full tactic table is
descriptive rather than statistical. See `tactic_comparison.csv` for all
100 rows.

### Tactics with at least one TF-IDF miss

- Address verification phishing
- DTH shut-off threat
- Data harvesting
- Debt collection threat
- Fake business renewal
- Fake easy money job offer
- Fake missed delivery
- Fake paid survey data collection
- Fake premium card offer
- Fake premium subscription
- Fake review task scam
- Fake student welfare scheme
- Fake toll/FASTag blacklist
- Fake welfare scheme
- Financial reputation anxiety
- Health anxiety malware delivery
- High-demand gadget scam
- International package scam
- Malware delivery disguised as job
- Ponzi/Pyramid scheme
- Predatory fake loan
- Service interruption threat
- Social media task scam
- Unrealistically cheap data plans
- Unrealistically good loan terms
- Urgent failed delivery

### Tactics with at least one MobileBERT miss

- DTH shut-off threat
- Data harvesting
- Exploiting rural/low-income users
- Fake high-value order cancellation
- High-demand gadget scam
- Malware disguised as 5G update
- Unrealistically cheap data plans

### Tactics missed by both models

- DTH shut-off threat
- Data harvesting
- High-demand gadget scam
- Unrealistically cheap data plans

## Per-message outputs

- `predictions.csv`: every message plus both models' labels, class
  probabilities, confidence scores, TF-IDF risk level, and evidence codes.
- `predictions_text_free.csv`: the same predictions without SMS bodies.
- `summary.json`: machine-readable overall and comparison results.
- `category_comparison.csv`: category aggregates.
- `tactic_comparison.csv`: tactic aggregates.
- `manifest.json`: hashes, environment, thresholds, and output inventory.

## Caveats

- All examples are positive; this cannot estimate false positives or
  precision.
- The TF-IDF primary result includes its existing risk policy, while
  MobileBERT-22 has no policy layer. The classifier-only TF-IDF row is
  provided to expose that difference.
- The dataset is small and tactic labels are mostly unique; category and
  tactic rates should not be over-interpreted.
- No model was retrained, no threshold was changed, and no previous
  experiment result was modified.
- Processing is local only; no SMS text was sent to a cloud service.
