# Phishing URL detector

## Architecture and source

The supplied Python project is under `python/`: URL normalization, character tokenization,27 structural features, data downloads/parsers, cleaning/splits, CNN and n-gram training, calibration, export and inference. Its `models/full_url/` contains the supplied CNN checkpoint, n-gram parameters and version metadata. No training dataset or downloaded threat feed is included.

Android uses the same frozen learned parameters through `LinkNormalizer.kt` and `LinkDetector.kt`. A92,577-parameter character CNN receives `[1,256]` character IDs and `[1,27]` scaled features. A300,000-term character TF-IDF logistic classifier supplies a second logit. A saved logistic combiner yields PHISHING above0.6831367399, LIKELY_SAFE below0.0953727082 and UNCERTAIN otherwise. Lists and guards can change the final verdict. See the [full architecture](../../docs/rakshak/architecture/README.md).

The model analyzes the address text. It does not open websites, inspect HTML, resolve redirects or authenticate a page. An unfamiliar or adult website is not automatically phishing.

## Public build versus the measured phone

The measured work-PC/Pixel build used a dated offline threat snapshot. The public source ships an **empty, valid threat database**, marked stale, rather than redistributing feed content. Model weights/tokenizers are unchanged. Therefore the218/218 saved-list result in the benchmark is not expected from the empty public database. A local feed build changes only the database and its asset hash manifest.

For local academic evaluation, populate your own copy before building:

```bash
pip install idna tldextract
python tools/setup_runtime_feeds.py --assets android/app/src/main/assets/url --download-phishtank
```

Alternatively supply your own permitted feed with `--phishtank path/to/online-valid.json`. Use `--empty` to recreate the distributed no-feed database. The script never visits listed destinations. Do not publish locally downloaded feeds or APKs containing restricted feed content. OpenPhish content is excluded from the public snapshot; its [terms](https://openphish.com/terms.html) restrict redistribution. Local data loading does not enable automatic background updates in Android.

## Reproduction and limits

From `components/phishing_url/python`, use a separate environment, install the requirements and run the module CLIs with `--help`, including `src.data.build_dataset`, `src.data.split_dataset`, `src.training.train_cnn` and `src.deploy.mobile_export`. Exact full retraining requires obtaining permitted original sources and the original split/provenance files; the latter are not all in the handoff. Original README claims about the earlier desktop environment are historical, not new validation of every feature on this checkout. Google Safe Browsing code in the Python reference is not enabled in the Android app.

The public Android reference fixture includes27 authored edge cases, excluding the2,048 benchmark URLs and two real feed examples. Historical2,077-row parity results remain documented; running a smaller public fixture is not reproduction of that entire private benchmark. Your own URL file can be tested with `validation/benchmark_phone_urls.py`.

The reported2,048-URL file duplicated the export reference inputs. Only218 URLs were independently supported as phishing by current PhishTank exact matches;1,830 were unknown and none independently confirmed benign. Raw-model detection172/218 =78.90% is a positive-subset result, not full-file accuracy/precision. The original model training overlap is unknown. Read the benchmark report before using these numbers in a submission.
