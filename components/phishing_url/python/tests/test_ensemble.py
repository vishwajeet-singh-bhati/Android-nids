import json

import numpy as np
import pytest
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression

from src.models.calibration import OUTCOMES, StackCalibrator
from src.models.ngram_lr import VECTORIZER, NgramLR, fit_with_c_search
from src.training import ensemble
from src.training.data import load_split
from src.training.ensemble import (NGRAM, crossfit, evaluate_candidate, run_ensemble,
                                   site_folds)
from src.training.train_cnn import train
from tests.test_char_cnn import small, tiny  # noqa: F401  (tiny is a fixture)

C_SMALL = (1.0, 10.0)


# ---------------------------------------------------------------- n-gram model
def test_ngram_matches_sklearn_and_survives_save_load(tiny, tmp_path):  # noqa: F811
    tr, va = load_split("full_url", "train", tiny), load_split("full_url", "val", tiny)
    model, search = fit_with_c_search(tr.texts, tr.y, va.texts, va.y, C_SMALL)
    assert set(search) == {"1.0", "10.0"} and model.meta["C"] in C_SMALL

    vec = TfidfVectorizer(**VECTORIZER, dtype=np.float32)
    ref = LogisticRegression(C=model.meta["C"], solver="liblinear", max_iter=1000)
    ref.fit(vec.fit_transform(tr.texts), tr.y)
    np.testing.assert_allclose(model.logits(va.texts), ref.decision_function(vec.transform(va.texts)),
                               rtol=1e-6, atol=1e-6)

    model.save(tmp_path / "m.npz")
    loaded = NgramLR.load(tmp_path / "m.npz")                 # allow_pickle=False inside
    np.testing.assert_array_equal(loaded.logits(va.texts + ["new.example/x"]),
                                  model.logits(va.texts + ["new.example/x"]))
    assert loaded.meta["C"] == model.meta["C"]


def test_ngram_load_rejects_other_settings(tiny, tmp_path):  # noqa: F811
    tr, va = load_split("full_url", "train", tiny), load_split("full_url", "val", tiny)
    model, _ = fit_with_c_search(tr.texts, tr.y, va.texts, va.y, (1.0,))
    model.save(tmp_path / "m.npz")
    with np.load(tmp_path / "m.npz") as z:
        arrays = dict(z)
    meta = json.loads(str(arrays["meta"]))
    meta["vectorizer"]["ngram_range"] = [1, 3]
    arrays["meta"] = np.array(json.dumps(meta))
    np.savez(tmp_path / "bad.npz", **arrays)
    with pytest.raises(ValueError, match="vectorizer settings"):
        NgramLR.load(tmp_path / "bad.npz")


# ---------------------------------------------------------------- cross-fitting
def test_site_folds_keep_websites_together():
    groups = [f"s{i // 3}" for i in range(60)]                 # 20 websites x 3 rows
    folds = site_folds(groups, k=5, seed=0)
    for g in set(groups):
        assert len({f for f, gg in zip(folds, groups) if gg == g}) == 1
    assert sorted(np.bincount(folds)) == [12] * 5
    with pytest.raises(ValueError):
        site_folds(["a", "b"], k=5)


def test_crossfit_scores_every_row_once():
    rng = np.random.default_rng(0)
    y = np.r_[np.zeros(300, int), np.ones(100, int)]
    x = np.column_stack([y * 2.0 + rng.normal(0, 1, 400), y * 1.5 + rng.normal(0, 1, 400)])
    groups = np.array([f"s{i // 2}" for i in range(400)], dtype=object)
    p, out = crossfit(x, y, groups, site_folds(groups, 5), 0.01, 0.05)
    assert np.isfinite(p).all() and ((p > 0) & (p < 1)).all()
    assert set(out) <= set(OUTCOMES)


def _synthetic_logits(y, seed):
    rng = np.random.default_rng(seed)
    return np.column_stack([3.0 * (y - 0.5) + rng.normal(0, 1, len(y)),
                            2.0 * (y - 0.5) + rng.normal(0, 1, len(y))])


# ---------------------------------------------------------------- end to end
def test_run_ensemble_end_to_end(tiny, tmp_path, capsys, monkeypatch):  # noqa: F811
    runs, reports = tmp_path / "runs", tmp_path / "reports"
    train(small(epochs=2, model="hybrid"), splits=tiny, run_dir=runs / "full_url_hybrid",
          device="cpu", cache_dir=None, reports_dir=reports)
    (tiny / "full_url" / "test.csv").unlink()                # proves the test split is never read

    kw = dict(splits=tiny, device="cpu", cache_dir=None, runs_dir=runs, reports_dir=reports,
              c_grid=C_SMALL, folds=4)
    r = run_ensemble(runs / "full_url_hybrid", **kw)
    assert r["members"][NGRAM]["status"] == "trained"
    assert set(r["candidates"]) == {"full_url_hybrid", NGRAM, f"full_url_hybrid+{NGRAM}"}
    for res in r["candidates"].values():
        if "error" not in res:
            cv = res["crossfit_val"]
            assert cv["outcomes"]["unit"] == "website" and cv["outcomes"]["websites"]["safe"] == 20
            StackCalibrator.from_config(res["calibrator"])
    assert "error" not in r["candidates"][NGRAM]

    text = (reports / "ensemble_full_url_hybrid.json").read_text(encoding="utf-8")
    assert "badsite" not in text and "news1" not in text     # no URLs in reports
    assert (runs / "full_url_hybrid_ensemble" / "ensemble.json").exists()
    assert run_ensemble(runs / "full_url_hybrid", **kw)["members"][NGRAM]["status"] == "reused"

    # exercise the combined path with informative stand-in logits
    val = load_split("full_url", "val", tiny)
    combo = evaluate_candidate(["a", "b"], _synthetic_logits(val.y, 1), val,
                               site_folds(val.groups, 4), 0.05, 0.05)
    assert min(combo["calibrator"]["weights"]) > 0
    r["candidates"]["a+b"] = combo
    ensemble.print_report(r)
    out = capsys.readouterr().out
    assert "a+b" in out and "combined: p = sigmoid(" in out and "badsite" not in out

    monkeypatch.setattr(ensemble, "RUNS_DIR", runs)          # CLI writes only into tmp_path
    monkeypatch.setattr(ensemble, "REPORTS_DIR", reports)
    monkeypatch.setattr(ensemble, "CACHE_DIR", None)
    monkeypatch.setattr(ensemble, "C_GRID", C_SMALL)
    assert ensemble.main(["--cnn-run", str(runs / "full_url_hybrid"), "--splits", str(tiny),
                          "--device", "cpu", "--folds", "4"]) == 0
    assert "candidate" in capsys.readouterr().out


def test_run_ensemble_refuses_changed_training_data(tiny, tmp_path):  # noqa: F811
    run = tmp_path / "runs" / "full_url_cnn"
    train(small(epochs=1), splits=tiny, run_dir=run, device="cpu", cache_dir=None,
          reports_dir=tmp_path / "r")
    path = tiny / "full_url" / "train.csv"
    path.write_text(path.read_text(encoding="utf-8") + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="training split changed"):
        run_ensemble(run, splits=tiny, device="cpu", cache_dir=None, runs_dir=tmp_path / "runs",
                     reports_dir=tmp_path / "r", c_grid=C_SMALL)
