# Third-party notices and attribution

The project follows the TSANet paper *A Lightweight Embedded Intelligent Threat Detection System Using TSANet on Android Platforms*, Malode et al., ISED 2025, [DOI 10.1109/ISED67359.2025.11404952](https://ieeexplore.ieee.org/abstract/document/11404952). The copyrighted paper is referenced, not redistributed. Missing author details and reconstruction assumptions are documented.

Datasets must be obtained from their publishers and cited under their terms. They are not bundled. PyTorch, ExecuTorch, Kotlin, Gradle, Android libraries and their dependencies retain their respective licenses. The frozen Kotlin standard-library JAR is redistributed under Apache 2.0; license text is retained with the extractor bundle. Inference model/source provenance is recorded in `reproducibility/SOURCE_SNAPSHOT.json` and model manifests.

Llama 3.2 uses Meta's separate community license/use policy, included under `models/`. Its large weights are downloaded only through the optional setup command after license acknowledgment. This repository does not grant rights beyond upstream terms or assign a new open-source license to the author's project code.

## Added SMS and URL components

The supplied SMS Python source retains its MIT LICENSE. MobileBERT is based on [google/mobilebert-uncased](https://huggingface.co/google/mobilebert-uncased); the selected22-layer checkpoint and project modifications are documented separately. Its upstream Apache2.0 license text is under components/sms/provenance. Dependencies keep their upstream rights; no blanket license is invented for material whose source handoff did not provide one.

Downloaded feeds and raw benchmark/training datasets are not redistributed. OpenPhish terms restrict third-party redistribution, so the public Android database is empty with local preparation code. Large Llama weights and personal messages/captures remain excluded.
