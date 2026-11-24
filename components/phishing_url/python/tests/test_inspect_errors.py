import json

import pytest

from src.training import inspect_errors
from src.training.calibrate import calibrate_run
from src.training.inspect_errors import inspect_run, site_errors
from src.training.train_cnn import train
from tests.test_char_cnn import small
from tests.test_training import make_rows, row, write


# ---------------------------------------------------------------- counting
def test_site_errors_counts_per_website():
    # safe: a (3 URLs, all flagged), b (2, none), c (5, one flagged); phishing: x (2, one missed), y (1)
    groups = ["a"] * 3 + ["b"] * 2 + ["c"] * 5 + ["x"] * 2 + ["y"]
    y = [0] * 10 + [1] * 3
    p = [0.99] * 3 + [0.1] * 2 + [0.95] + [0.1] * 4 + [0.01, 0.99, 0.99]
    r = site_errors(p, y, groups, t_phishing=0.9, t_safe=0.05, n_boot=500)
    fa = r["false_alarm"]
    assert (fa["urls"], fa["of_urls"], fa["sites"], fa["of_sites"]) == (4, 10, 2, 3)
    assert fa["largest_site_urls"] == 3
    assert fa["rate_without_largest_site"] == pytest.approx(1 / 7)
    lo, hi = fa["site_bootstrap_95"]
    assert 0 <= lo <= fa["rate"] <= hi <= 1
    ms = r["missed"]
    assert (ms["urls"], ms["of_urls"], ms["sites"], ms["of_sites"]) == (1, 3, 1, 2)


def test_site_errors_without_mistakes():
    r = site_errors([0.1, 0.2, 0.99], [0, 0, 1], ["a", "b", "c"], 0.9, 0.05, n_boot=100)
    fa = r["false_alarm"]
    assert fa["urls"] == 0 and fa["site_bootstrap_95"] == [0.0, 0.0]
    assert "rate_without_largest_site" not in fa


# ---------------------------------------------------------------- end to end
@pytest.fixture
def splits_with_query(tmp_path):
    """The tiny splits, plus one safe validation URL whose query holds a secret."""
    root = tmp_path / "splits"
    for split, (start, count) in {"train": (0, 60), "val": (100, 20), "test": (200, 20)}.items():
        rows = make_rows(start, count, "full_url")
        if split == "val":
            rows.append(row(9999, 0, "https://www.shop9999.com/cart?session=SECRET123", "full_url"))
        write(root / "full_url" / f"{split}.csv", rows)
    return root


def test_inspect_run_end_to_end(splits_with_query, tmp_path, capsys, monkeypatch):
    splits, run, reports = splits_with_query, tmp_path / "runs" / "full_url_hybrid", tmp_path / "r"
    train(small(epochs=2, model="hybrid"), splits=splits, run_dir=run, device="cpu",
          cache_dir=None, reports_dir=reports)
    with pytest.raises(FileNotFoundError, match="calibrate first"):
        inspect_run(run, splits=splits, device="cpu", cache_dir=None)
    calibrate_run(run, splits=splits, with_test=True, device="cpu", cache_dir=None,
                  reports_dir=reports)

    r = inspect_run(run, splits=splits, with_test=True, device="cpu", cache_dir=None, top=50,
                    n_boot=100)
    assert r["val"]["errors"]["false_alarm"]["of_urls"] == 21
    assert r["val"]["errors"]["false_alarm"]["of_sites"] == 21
    assert set(r["test"]) == {"errors"}                      # test: aggregates only
    assert "news2" not in json.dumps(r["test"]) and "shop2" not in json.dumps(r["test"])
    examples = [e["example"] for e in r["val"]["top_safe_sites"]]
    assert len(examples) == 21 and "www.shop9999.com/cart" in examples
    assert "SECRET123" not in json.dumps(r)                  # query strings never shown

    monkeypatch.setattr(inspect_errors, "CACHE_DIR", None)   # keep the repo cache clean
    assert inspect_errors.main(["--run", str(run), "--splits", str(splits), "--device", "cpu",
                                "--with-test"]) == 0
    out = capsys.readouterr().out
    assert "[test] false alarms" in out and "SECRET123" not in out
    assert "badsite" not in out                              # phishing URLs never listed


def test_inspect_refuses_stale_calibration(splits_with_query, tmp_path):
    splits, run = splits_with_query, tmp_path / "run"
    train(small(epochs=1), splits=splits, run_dir=run, device="cpu", cache_dir=None,
          reports_dir=tmp_path / "r")
    calibrate_run(run, splits=splits, device="cpu", cache_dir=None, reports_dir=tmp_path / "r")
    cal = json.loads((run / "calibration.json").read_text(encoding="utf-8"))
    cal["checkpoint_sha256"] = "0" * 64
    (run / "calibration.json").write_text(json.dumps(cal), encoding="utf-8")
    with pytest.raises(ValueError, match="changed since calibration"):
        inspect_run(run, splits=splits, device="cpu", cache_dir=None)
