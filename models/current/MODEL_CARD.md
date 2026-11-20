# Current shipped detector

App 0.12.2-aligned-v2-test/code 36; selected preserved v2 `gate_s0` + `diagnosis64_s1`. This identifies the current app's inference bundle, separately from any updated-data candidate still training.

- Input: raw float32 flow `[1,32]`, context `[1,115]`; normalization embedded.
- Output: binary gate logit, then seven diagnosis logits only for flagged traffic.
- Diagnosis label order: Benign, Bot, Brute Force, DDoS, DoS, Port Scan, Web Attack. Unclassified is a policy fallback, not an eighth trained class.
- Parameters: 18,913 gate; 173,721 diagnosis. PTE sizes 82,820 B and 949,788 B.
- Gate cutoff 0.7858333333333334; diagnosis cutoff 0.6. Positive-but-untyped remains Unclassified.
- The exact PTEs/manifests/self-checks are in `android/app/src/main/assets/aligned_v2_*`. CPU reference TorchScript modules here accept the same two raw inputs; use CPU because their traced LSTM state allocation is CPU-bound.
- Frozen extractor and Kotlin runtime are under `extractor/`; source is included under `android/core`. This is reference provenance, not fresh hardware attestation on another phone.

Measured live cases show useful scan detection and important Web Attack misses. The model is experimental, not production validated. It does not decrypt HTTPS, prove compromise or guarantee app attribution. Original-data classwise reports and private-phone evaluation scope are under `results/`. Dataset/label limitations can dominate apparent overall accuracy.

Updated-data candidates must receive separate model hashes, validation-selected policy, final classwise comparisons and native device checks before replacing this bundle. A training run in progress is not a new release or deployment approval.
