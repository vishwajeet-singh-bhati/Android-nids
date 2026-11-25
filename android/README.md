> Current source is Rakshak code53. Start with the [A-to-Z reproduction guide](../REPRODUCE.md). This page retains the stage-specific network methodology; historical measurements retain their original build identities.

# Android source map

| Module | Role |
|---|---|
| `app` | NIDS foreground monitoring, inference, app attribution, local explanations, notifications and seven-day history |
| `core` | Shared packet parsing, flow segmentation, 147-input extraction and deterministic contract checks |
| `trafficlab` | Disposable targets for individual controlled phone tests |
| `datasetlab` | Independently logged request/effect targets for new dataset collection |
| `datasettools` | Offline replay adapter for matching saved phone captures to native feature traces |
| `contractcheck` | Android feature-contract validation utility |

The current launcher is `LearnedNetworkActivity`. Its monitoring path is `TsanetCaptureService` → `AlignedV2Scorer`; Llama runs through `LlamaWorkerService`. Only the current aligned-v2 detector assets are bundled, together with required license notices. Some shared historical support classes remain in the source; the older packet fixtures and unused model weights are excluded.

Use the root [build/install guide](../docs/ANDROID_SETUP.md). The supported build entry point runs `alignedCheck`, `alignedV2PolicyCheck` and `captureDeliveryClockCheck` before assembling the current modules. Legacy golden tasks require external fixtures and are outside this submission's validation commands.
