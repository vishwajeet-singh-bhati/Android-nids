# Changelog

## Current source submission â€” 21 November 2026

- App: `0.12.2-aligned-v2-test`, version code 36.
- Inference: preserved v2 binary gate and seven-family diagnosis with 147 phone-visible inputs; exact model hashes are in the manifests.
- Includes paper reconstruction, matched context comparison, phone-aligned preprocessing/training, Android source, controlled phone tests and the new real-phone collection/training procedure.
- Fresh-runner fixes: explicitly pin Numba/llvmlite for context extraction and use Ubuntu 24.04's preinstalled Android SDK in CI.
- Adds portable setup commands, pinned dependencies, dataset provenance, model contracts and automated build/smoke checks.
- New phone-data candidate training is separate and unfinished at this snapshot. It has not replaced the shipped inference models.
- Research datasets, private phone recordings, unused legacy weights/packet fixtures, training checkpoints and ZIP archives are excluded.

See [status](STATUS.md), [published results](results/README.md), [paper reconstruction assumptions](docs/PAPER_AND_CONTEXT.md) and the [phone dataset procedure history](experiments/phone_capture_v1/VERSION_HISTORY.md).
