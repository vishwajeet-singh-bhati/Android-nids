# External datasets and provenance

No research dataset, real phone recording, normalized matrix or private app history is bundled. Download publisher files yourself under the directory layout below. Keep the original archive bytes; the code records hashes, member names, cleaning counts, split indices and normalization.

## Paper and context experiments

Obtain the publisher's **GeneratedLabelledFlows.zip** for [CIC-IDS2017](https://www.unb.ca/cic/datasets/ids-2017.html). It contains eight labeled CSV members spanning five weekdays, with identifiers/timestamps needed for the historical context reconstruction.

```text
data/external/CICIDS2017/GeneratedLabelledFlows.zip
```

The measured archive SHA256 and exact source member names are in `results/tsanet_paper/data_report.json`. The reconstruction retains 2,827,829 rows after documented exclusions/cleaning, split into 1,979,480 train and 848,349 test rows. A different publisher archive/version can change the result. Do not substitute the ML-only CSV archive if it omits the identifiers/times needed by context processing.

## Phone-aligned raw-capture experiments

These additionally require the five original publisher PCAPs and the Android control corpora:

```text
data/external/CICIDS2017/
  GeneratedLabelledFlows.zip
  Monday-WorkingHours.pcap
  Tuesday-WorkingHours.pcap
  Wednesday-workingHours.pcap
  Thursday-WorkingHours.pcap
  Friday-WorkingHours.pcap
data/external/PARROT2025/pcaps/...publisher captures...
data/external/CIC-AAGM2017/Benign Pcaps/...publisher captures...
```

Match capitalization on Linux. Source inventory/byte sizes and accepted/excluded capture counts are recorded in `results/phone_alignment_v2/data_report.json` and the extraction output. There are no missing-file substitutes. Corrupt Android captures are excluded as complete files with recorded reasons rather than silently salvaging a prefix.

PARROT2025 source provenance was recorded against [Zenodo record 16368932](https://zenodo.org/records/16368932); use the publisher's mitmproxy/network capture component and preserve app grouping. CIC-AAGM2017 is the publisher's [Android Adware and General Malware dataset](https://www.unb.ca/cic/datasets/android-adware.html); this experiment uses its benign capture directory, not whole malware captures labeled benign. Follow publisher terms and citation requirements. Verify exact filenames/inventory before comparing numbers.

Phone-aligned extraction produces 4,956,674 training / 1,188,724 validation / 1,098,929 test views in the recorded corpus. A view is not an independent attack campaign. The raw-flow benchmark uses grouped 70/15/15 splits and training-only normalization; it is distinct from the paper CSV 70/30 benchmark.

## Newly recorded phone data

`phone collect` records your own controlled activity and creates new private files under `runs/phone_capture_v1/sessions`. Each recording keeps raw packets, independent controller/target events, native/offline traces and label/QC records. Unrelated background flows remain unknown, never blanket-labeled Benign.

The author's private twenty-session corpus is excluded. Repeating the procedure generates a new cohort; it cannot promise the same timestamps, feature values or final numbers. The original split memberships remain separate, and only new training-session rows augment the original training partition. See the [datasheet](../experiments/phone_capture_v1/DATASHEET.md) and [reproduction limits](REPRODUCING_RESULTS.md).
