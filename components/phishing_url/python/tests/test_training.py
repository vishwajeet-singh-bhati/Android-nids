import csv
import json

import numpy as np
import pytest

from src.data.split_dataset import OUT_COLUMNS
from src.preprocessing.url_normalizer import normalize_url
from src.training import baselines
from src.training.data import DataMismatchError, load_features, load_split
from src.training.metrics import (binary_metrics, expected_calibration_error, recall_at_fpr,
                                  slice_metrics)


# ---------------------------------------------------------------- fixtures
def row(i, y, value, input_type):
    n = normalize_url(value, input_type)
    return {"sample_id": f"s{i:05d}", "y": str(y), "label": "phishing" if y else "benign",
            "label_quality": "x", "sources": "test", "model_string": n.model_string,
            "canonical": n.canonical, "host": n.host, "group": n.registered_domain or n.host,
            "first_seen": "", "first_collected_at": "", "tranco_rank": ""}


def write(path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=OUT_COLUMNS)
        w.writeheader()
        w.writerows(rows)


def make_rows(start, count, mode):
    rows = []
    for k in range(count):
        i = start + k
        if mode == "full_url":
            phish = f"https://secure-login-verify{i}.badsite{i}.com/account/update.php?id={i}"
            benign = f"https://www.news{i}.org/world/story-{i}" if k % 2 else f"https://shop{i}.com/"
            rows += [row(2 * i, 1, phish, "full_url"), row(2 * i + 1, 0, benign, "full_url")]
        else:
            rows += [row(2 * i, 1, f"secure-login-verify{i}.badsite{i}.com", "domain"),
                     row(2 * i + 1, 0, f"news{i}.org", "domain")]
    return rows


@pytest.fixture(params=["full_url", "domain"])
def splits(tmp_path, request):
    mode = request.param
    root = tmp_path / "splits"
    for split, (start, count) in {"train": (0, 60), "val": (100, 20), "test": (200, 20)}.items():
        write(root / mode / f"{split}.csv", make_rows(start, count, mode))
    return mode, root


# ---------------------------------------------------------------- metrics
def test_binary_metrics_perfect_and_counts():
    y = np.array([0, 0, 1, 1])
    m = binary_metrics(y, np.array([0.1, 0.2, 0.8, 0.9]))
    assert m["roc_auc"] == 1.0 and m["pr_auc"] == 1.0
    assert m["at_threshold"]["tp"] == 2 and m["at_threshold"]["fp"] == 0
    assert m["recall_at_fpr"]["0.001"]["recall"] == 1.0


def test_binary_metrics_accuracy_and_confusion_matrix():
    y = np.array([0, 0, 0, 1, 1])
    at = binary_metrics(y, np.array([0.1, 0.6, 0.2, 0.9, 0.3]))["at_threshold"]
    assert at["confusion_matrix"] == [[2, 1], [1, 1]]        # [[tn, fp], [fn, tp]]
    assert at["accuracy"] == pytest.approx(3 / 5)


def test_binary_metrics_single_class_has_no_ranking():
    m = binary_metrics(np.array([0, 0]), np.array([0.1, 0.7]))
    assert "roc_auc" not in m and m["at_threshold"]["fpr"] == 0.5 and m["at_threshold"]["recall"] is None


def test_recall_at_fpr_respects_budget():
    y = np.array([0] * 100 + [1] * 10)
    score = np.r_[np.linspace(0, 0.5, 99), [0.95], np.linspace(0.6, 1.0, 10)]
    r = recall_at_fpr(y, score, 0.0)
    assert r["fpr"] == 0.0 and r["recall"] < 1.0
    assert recall_at_fpr(y, score, 0.01)["recall"] == 1.0


def test_ece():
    assert expected_calibration_error(np.array([0, 1]), np.array([0.0, 1.0])) == 0.0
    assert expected_calibration_error(np.array([0, 0]), np.array([0.9, 0.9])) == pytest.approx(0.9)


@pytest.mark.parametrize("y,score", [([0, 2], [0.1, 0.2]), ([0, 1], [0.1, 1.5]), ([0, 1], [0.1])])
def test_metrics_reject_bad_input(y, score):
    with pytest.raises(ValueError):
        binary_metrics(np.array(y), np.array(score))


def test_slice_metrics():
    y = np.array([0, 1, 0, 1])
    s = slice_metrics(y, np.array([0.1, 0.9, 0.2, 0.8]), {"a": np.array([1, 1, 0, 0], bool)})
    assert s["a"]["n"] == 2
    with pytest.raises(ValueError):
        slice_metrics(y, y.astype(float), {"bad": np.array([True])})


# ---------------------------------------------------------------- data
def test_load_split_and_slices(splits):
    mode, root = splits
    d = load_split(mode, "train", root)
    assert len(d) == 120 and d.y.sum() == 60 and len(d.file_sha256) == 64
    sl = d.slices()
    assert sl["all"].all()
    if mode == "full_url":
        assert sl["homepage_only"].sum() == 30          # shop{i}.com/
        assert (sl["homepage_only"] ^ sl["with_path_or_query"]).all()
    else:
        assert sl["with_subdomain"].sum() == 60


def test_load_split_detects_normalizer_drift(tmp_path):
    r = row(1, 0, "https://example.com/a", "full_url")
    r["model_string"] = "example.com/DIFFERENT"
    write(tmp_path / "full_url" / "train.csv", [r])
    with pytest.raises(DataMismatchError):
        load_split("full_url", "train", tmp_path)


def test_load_split_errors(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_split("full_url", "train", tmp_path)
    with pytest.raises(ValueError):
        load_split("nope", "train", tmp_path)
    r = row(1, 0, "https://example.com/a", "full_url") | {"y": "2"}
    write(tmp_path / "full_url" / "val.csv", [r])
    with pytest.raises(ValueError):
        load_split("full_url", "val", tmp_path)


def test_feature_cache_roundtrip(splits, tmp_path):
    mode, root = splits
    d = load_split(mode, "val", root)
    cache = tmp_path / "cache"
    a = load_features(d, cache_dir=cache)
    assert len(list(cache.glob("*.npy"))) == 1
    b = load_features(d, cache_dir=cache)
    np.testing.assert_array_equal(a, b)
    assert a.shape[0] == len(d) and a.dtype == np.float32


# ---------------------------------------------------------------- baselines
def test_run_baselines_end_to_end(splits, tmp_path):
    mode, root = splits
    report = baselines.run_baselines(mode, root, cache_dir=tmp_path / "c", c_grid=(1.0,))
    assert report["evaluated_splits"] == ["val"]          # test untouched by default
    assert set(report["models"]) == {"shortcut_probe", "features_lr", "features_hgb", "char_ngram_lr"}
    ngram = report["models"]["char_ngram_lr"]
    assert ngram["val"]["overall"]["roc_auc"] > 0.9      # trivially separable toy data
    assert "slices" in ngram["val"]
    text = json.dumps(report)
    assert "badsite" not in text and "news1" not in text  # no URLs in reports


def test_cli_with_test(splits, tmp_path, monkeypatch):
    mode, root = splits
    monkeypatch.setattr(baselines, "C_GRID", (1.0,))
    monkeypatch.setattr(baselines, "CACHE_DIR", tmp_path / "c")
    out = tmp_path / "reports"
    assert baselines.main(["--mode", mode, "--splits", str(root), "--out", str(out), "--with-test"]) == 0
    saved = json.loads((out / f"baselines_{mode}.json").read_text(encoding="utf-8"))
    assert saved["evaluated_splits"] == ["val", "test"]
