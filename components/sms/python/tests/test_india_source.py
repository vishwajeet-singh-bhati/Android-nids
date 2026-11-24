from pathlib import Path

import pandas as pd

from sms_detection.data.load_sources import load_india_spam

PREPARE_SCRIPT = (
    Path(__file__).resolve().parents[1] / "scripts" / "prepare_india_source.py"
)


def test_load_india_spam_maps_binary_labels_and_drops_missing_text(tmp_path):
    directory = tmp_path / "india_spam_sms"
    directory.mkdir()
    pd.DataFrame(
        {
            "Msg": [
                "Your parcel is ready for collection.",
                "Claim your prize now",
                None,
            ],
            "Label": ["ham", "spam", "ham"],
        }
    ).to_csv(directory / "spam_ham_india.csv", index=False)

    frame = load_india_spam(tmp_path)

    assert len(frame) == 2
    assert frame["label"].tolist() == ["ham", "spam"]
    assert frame["source_label"].tolist() == ["ham", "spam"]
    assert frame["source_dataset"].unique().tolist() == ["india_spam_sms"]
    assert frame["language"].unique().tolist() == ["en/hi-Latn"]
    assert frame["license"].nunique() == 1
    assert frame["text"].str.len().min() > 0


def test_prepare_india_benchmark_removes_exact_duplicates(tmp_path):
    raw = tmp_path / "raw"
    directory = raw / "india_spam_sms"
    directory.mkdir(parents=True)
    pd.DataFrame(
        {
            "Msg": ["Hello there", "Hello there", "Claim your prize"],
            "Label": ["ham", "ham", "spam"],
        }
    ).to_csv(directory / "spam_ham_india.csv", index=False)
    output = tmp_path / "benchmark.csv"

    import importlib.util

    spec = importlib.util.spec_from_file_location("prepare_india_source", PREPARE_SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    stats = module.prepare_benchmark(raw, output)
    prepared = pd.read_csv(output)

    assert stats["input_rows"] == 3
    assert stats["output_rows"] == 2
    assert stats["dropped_exact_duplicate_rows"] == 1
    assert prepared["text"].tolist() == ["Hello there", "Claim your prize"]
    assert prepared["label"].tolist() == ["ham", "spam"]
    assert prepared["source"].unique().tolist() == ["kaggle_india_spam_sms"]

