import json

import numpy as np
import pytest

from src.models.calibration import (LIKELY_SAFE, PHISHING, UNCERTAIN, Calibrator,
                                    StackCalibrator, classify, sigmoid)
from src.training import calibrate, summarize
from src.training.calibrate import (calibrate_run, choose_thresholds, fit_logistic, fit_platt,
                                    outcome_report, site_weights)
from src.training.train_cnn import train
from tests.test_char_cnn import small, tiny  # noqa: F401  (tiny is a fixture)


# ---------------------------------------------------------------- calibrator
def test_sigmoid_is_stable():
    with np.errstate(over="raise", invalid="raise", divide="raise"):  # underflow to 0 is fine
        out = sigmoid(np.array([-1000.0, 0.0, 1000.0]))
    np.testing.assert_allclose(out, [0.0, 0.5, 1.0])


def test_classify_boundaries():
    out = classify([0.1, 0.2, 0.5, 0.8, 0.9], t_phishing=0.8, t_safe=0.2)
    assert list(out) == [LIKELY_SAFE, UNCERTAIN, UNCERTAIN, UNCERTAIN, PHISHING]


def test_calibrator_roundtrip_and_validation(tmp_path):
    cal = Calibrator(1.5, -0.3, 0.9, 0.1)
    cal.save(tmp_path / "c.json")
    assert Calibrator.load(tmp_path / "c.json") == cal
    np.testing.assert_allclose(cal.probability([0.0]), sigmoid(np.array([-0.3])))
    for bad in [(0.0, 0, 0.9, 0.1), (1, 0, 0.1, 0.9), (1, 0, 1.5, 0.1), (1, float("nan"), 0.9, 0.1)]:
        with pytest.raises(ValueError):
            Calibrator(*bad)
    with pytest.raises(ValueError):
        Calibrator.from_config({"type": "x"})


# ---------------------------------------------------------------- fitting
def test_fit_platt_recovers_parameters():
    rng = np.random.default_rng(0)
    x = rng.normal(0, 2, 40_000)
    y = (rng.random(len(x)) < sigmoid(0.5 * x - 1.0)).astype(int)
    a, b = fit_platt(x, y)
    assert a == pytest.approx(0.5, abs=0.03) and b == pytest.approx(-1.0, abs=0.05)


def test_fit_platt_stays_finite_when_separable():
    a, b = fit_platt(np.array([-3.0, -2.0, 2.0, 3.0]), np.array([0, 0, 1, 1]))
    assert np.isfinite(a) and a > 0


@pytest.mark.parametrize("x,y", [([1.0, 2.0], [1, 1]), ([1.0], [0, 1]), ([np.inf, 1.0], [0, 1])])
def test_fit_platt_rejects_bad_input(x, y):
    with pytest.raises(ValueError):
        fit_platt(np.array(x), np.array(y))


def test_fit_platt_rejects_backwards_model():
    with pytest.raises(ValueError):
        fit_platt(np.array([3.0, 2.0, -2.0, -3.0] * 10), np.array([0, 0, 1, 1] * 10))


# ---------------------------------------------------------------- thresholds
def test_thresholds_respect_budgets():
    rng = np.random.default_rng(1)
    y = np.r_[np.zeros(5000, int), np.ones(1000, int)]
    p = np.clip(np.r_[rng.beta(2, 8, 5000), rng.beta(8, 2, 1000)], 0, 1)
    tp, ts = choose_thresholds(p, y, 0.01, 0.05)
    out = classify(p, tp, ts)
    assert (out[y == 0] == PHISHING).mean() <= 0.01
    assert (out[y == 1] == LIKELY_SAFE).mean() <= 0.05
    assert ts <= tp
    tighter, _ = choose_thresholds(p, y, 0.001, 0.05)
    assert tighter >= tp


def test_thresholds_with_perfect_separation_leave_almost_no_uncertain():
    y = np.array([0] * 100 + [1] * 100)
    p = np.r_[np.linspace(0.0, 0.3, 100), np.linspace(0.7, 1.0, 100)]
    tp, ts = choose_thresholds(p, y, 0.01, 0.05)
    assert ts == tp and (classify(p, tp, ts) == UNCERTAIN).sum() <= 1


def test_outcome_report_projection():
    y = np.array([0] * 100 + [1] * 100)
    p = np.r_[np.full(99, 0.1), [0.95], np.full(90, 0.95), np.full(10, 0.5)]
    r = outcome_report(p, y, t_phishing=0.9, t_safe=0.2)
    assert r["false_alarm_rate"] == 0.01 and r["phishing_caught_rate"] == 0.9
    proj = r["projected_by_phishing_base_rate"]["0.01"]
    assert proj["precision_of_PHISHING"] == pytest.approx(0.009 / (0.009 + 0.0099))


@pytest.mark.parametrize("budgets", [(1.0, 0.05), (0.01, -0.1)])
def test_bad_budgets(budgets):
    with pytest.raises(ValueError):
        choose_thresholds(np.array([0.1, 0.9]), np.array([0, 1]), *budgets)


# ---------------------------------------------------------------- per website
def test_site_weights_count_each_website_once_per_label():
    w = site_weights([0, 0, 0, 1, 1], ["a", "a", "b", "a", "c"])
    np.testing.assert_allclose(w, [0.5, 0.5, 1.0, 1.0, 1.0])


def _lumpy():
    """One safe website with 20 high-scoring pages + 180 safe websites with one page each."""
    rng = np.random.default_rng(3)
    p = np.r_[np.full(20, 0.95), rng.uniform(0.0, 0.5, 180), rng.uniform(0.9, 1.0, 100)]
    y = np.r_[np.zeros(200, int), np.ones(100, int)]
    groups = ["big"] * 20 + [f"s{i}" for i in range(180)] + [f"x{i}" for i in range(100)]
    return p, y, groups


def test_website_budget_treats_a_lumpy_site_as_one_mistake():
    p, y, groups = _lumpy()
    by_url, _ = choose_thresholds(p, y, 0.05, 0.05)                  # 10 URLs allowed: blocks "big"
    by_site, _ = choose_thresholds(p, y, 0.05, 0.05, site_weights(y, groups))   # 9 websites allowed
    assert by_site < 0.95 <= by_url
    r = outcome_report(p, y, by_site, 0.0, groups=groups)
    assert r["unit"] == "website" and r["false_alarm_rate"] <= 0.05
    # "big" (counted once) + 8 one-page websites = 9 of 181 websites, but 28 of 200 URLs
    assert r["websites"]["safe"] == 181 and r["websites"]["safe_with_a_PHISHING_verdict"] == 9
    assert r["rates_by_url"]["benign"][PHISHING] == pytest.approx(28 / 200)


def test_per_url_thresholds_match_the_original_rule():
    rng = np.random.default_rng(4)
    p, y = rng.random(500), (rng.random(500) < 0.3).astype(int)
    benign, phish = np.sort(p[y == 0])[::-1], np.sort(p[y == 1])
    tp_old = float(benign[int(np.floor(0.02 * len(benign)))])
    ts_old = float(phish[int(np.floor(0.05 * len(phish)))])
    assert choose_thresholds(p, y, 0.02, 0.05) == (tp_old, min(ts_old, tp_old))
    assert choose_thresholds(p, y, 0.02, 0.05) == choose_thresholds(p, y, 0.02, 0.05, np.ones(500))
    with pytest.raises(ValueError):
        choose_thresholds(p, y, 0.02, 0.05, np.zeros(500))


def test_fit_logistic_two_inputs():
    rng = np.random.default_rng(5)
    x = rng.normal(0, 1, (40_000, 2))
    y = (rng.random(len(x)) < sigmoid(x @ [1.0, 0.5] - 0.3)).astype(int)
    w, b = fit_logistic(x, y)
    np.testing.assert_allclose(w, [1.0, 0.5], atol=0.05)
    assert b == pytest.approx(-0.3, abs=0.05)
    y_bad = (rng.random(len(x)) < sigmoid(x @ [2.0, -1.0])).astype(int)   # 2nd input points backwards
    with pytest.raises(ValueError, match="not positive"):
        fit_logistic(x, y_bad)


def test_stack_calibrator():
    cal = StackCalibrator(("cnn", "ngram"), (0.6, 0.4), -0.2, 0.9, 0.1)
    assert StackCalibrator.from_config(json.loads(json.dumps(cal.to_config()))) == cal
    np.testing.assert_allclose(cal.probability([[1.0, 2.0]]), sigmoid(np.array([0.6 + 0.8 - 0.2])))
    one = StackCalibrator(("cnn",), (1.5,), -0.3, 0.9, 0.1)
    np.testing.assert_allclose(one.probability([0.5, -1.0]),
                               Calibrator(1.5, -0.3, 0.9, 0.1).probability([0.5, -1.0]))
    with pytest.raises(ValueError):
        cal.probability([[1.0, 2.0, 3.0]])
    for bad in [(("a", "b"), (1.0,)), (("a", "a"), (1.0, 1.0)), (("a", "b"), (1.0, -0.1)),
                ((), ())]:
        with pytest.raises(ValueError):
            StackCalibrator(bad[0], bad[1], 0.0, 0.9, 0.1)
    with pytest.raises(ValueError):
        StackCalibrator.from_config({**cal.to_config(), "type": "platt_three_outcome"})


# ---------------------------------------------------------------- end to end
def test_calibrate_run_end_to_end(tiny, tmp_path, capsys):  # noqa: F811
    runs, reports = tmp_path / "runs", tmp_path / "reports"
    train(small(epochs=2, model="hybrid"), splits=tiny, run_dir=runs / "full_url_hybrid",
          device="cpu", cache_dir=None, reports_dir=reports)
    r = calibrate_run(runs / "full_url_hybrid", splits=tiny, device="cpu", cache_dir=None,
                      reports_dir=reports)
    assert r["evaluated_splits"] == ["val"] and "test" not in r
    assert len(r["threshold_grid_val"]) == 9
    Calibrator.from_config(r["calibrator"])
    r = calibrate_run(runs / "full_url_hybrid", splits=tiny, with_test=True, device="cpu",
                      cache_dir=None, reports_dir=reports)
    assert "test" in r and r["test"]["metrics"]["n"] == 40
    text = (reports / "calibration_full_url_hybrid.json").read_text(encoding="utf-8")
    assert "badsite" not in text and "news1" not in text
    assert json.loads((runs / "full_url_hybrid" / "calibration.json").read_text())["run"] == "full_url_hybrid"
    calibrate.print_report(r)
    assert "[test] PR-AUC" in capsys.readouterr().out
    rows = summarize.summarize("full_url", runs, reports, split="test")
    assert len(rows) == 1 and rows[0][0].endswith("calibrated")
    with pytest.raises(FileExistsError, match="test-split record"):   # the exam result is kept
        calibrate_run(runs / "full_url_hybrid", splits=tiny, device="cpu", cache_dir=None,
                      reports_dir=reports)
    calibrate_run(runs / "full_url_hybrid", splits=tiny, device="cpu", cache_dir=None,
                  reports_dir=reports, force=True)


def test_calibrate_refuses_changed_val(tiny, tmp_path):  # noqa: F811
    run = tmp_path / "run"
    train(small(epochs=1), splits=tiny, run_dir=run, device="cpu", cache_dir=None,
          reports_dir=tmp_path / "r")
    val = tiny / "full_url" / "val.csv"
    val.write_text(val.read_text(encoding="utf-8") + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="validation split changed"):
        calibrate_run(run, splits=tiny, device="cpu", cache_dir=None, reports_dir=tmp_path / "r")


def test_calibrate_missing_run(tmp_path):
    with pytest.raises(FileNotFoundError):
        calibrate_run(tmp_path / "nope")
