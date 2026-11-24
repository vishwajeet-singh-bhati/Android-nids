"""Calibrate a trained CNN run and choose the three-outcome thresholds.

    python -m src.training.calibrate --run artifacts/runs/full_url_hybrid
    python -m src.training.calibrate --run artifacts/runs/full_url_hybrid --with-test

1. Calibration (Platt scaling, Platt's label smoothing): p = sigmoid(a*logit + b),
   fitted on the validation split. Two numbers and monotone, so the ranking
   (PR-AUC, recall at a given FPR) does not change, only the probabilities.
2. Thresholds, also from validation, from two budgets:
     --max-false-alarm  at most this share of SAFE urls may get PHISHING
     --max-missed       at most this share of PHISHING urls may get LIKELY_SAFE
   Everything in between is UNCERTAIN. Both budgets are rates *within* a class,
   so they do not depend on how much phishing the real traffic contains. The
   report also projects what a user sees at 1% / 5% phishing traffic.
   By default (--unit website) every website counts once: the dataset samples
   up to ~20 pages per safe website, and mistakes come in website-sized lumps,
   so a per-URL rate mostly measures how many pages were sampled.
3. --with-test applies the frozen calibration + thresholds to the test split.
   Choose the budgets on validation first; open the test split once.

Writes <run>/calibration.json and reports/calibration_<run>.json (aggregates only).
"""
from __future__ import annotations

import argparse
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
from scipy.optimize import minimize

from src.models.calibration import (LIKELY_SAFE, OUTCOMES, PHISHING, UNCERTAIN, Calibrator,
                                    classify, sigmoid)
from src.models.char_cnn import load_checkpoint

from .data import CACHE_DIR, SPLITS_DIR, file_sha256, load_split
from .metrics import binary_metrics, expected_calibration_error, slice_metrics
from .train_cnn import REPORTS_DIR, predict_logits, resolve_device, to_tensors

BASE_RATES = (0.01, 0.05)
GRID_FALSE_ALARM = (0.0025, 0.005, 0.01)
GRID_MISSED = (0.02, 0.05, 0.10)
UNITS = ("website", "url")


def site_weights(y, groups) -> np.ndarray:
    """1 / (URLs of the same website and label), so every website counts once per label."""
    keys = list(zip(np.asarray(y).tolist(), list(groups)))
    if len(keys) != len(np.asarray(y)):
        raise ValueError("y and groups must have the same length")
    counts = Counter(keys)
    return np.array([1.0 / counts[k] for k in keys])


def fit_logistic(x, y, x0=None) -> tuple[np.ndarray, float]:
    """Fit p = sigmoid(x @ w + b) by maximum likelihood with Platt's smoothed targets.

    x has shape (n, k). k = 1 is Platt scaling; k > 1 combines several models.
    Every weight must come out > 0 (each model must keep its direction).
    """
    x = np.asarray(x, dtype=np.float64)
    y = np.asarray(y)
    if x.ndim != 2 or len(x) != len(y) or y.ndim != 1 or len(x) == 0 or x.shape[1] == 0:
        raise ValueError("x must be (n, k) and y (n,), with n, k > 0")
    if not np.isfinite(x).all():
        raise ValueError("logits must be finite")
    n1, n0 = int((y == 1).sum()), int((y == 0).sum())
    if n1 == 0 or n0 == 0 or n1 + n0 != len(y):
        raise ValueError("calibration needs y in {0,1} with both classes present")
    # Platt (1999): smoothed targets keep the fit finite even if the classes separate.
    t = np.where(y == 1, (n1 + 1) / (n1 + 2), 1 / (n0 + 2))
    k = x.shape[1]

    def nll(params):
        z = x @ params[:k] + params[k]
        g = sigmoid(z) - t
        grad = np.append(x.T @ g / len(z), np.mean(g))
        return float(np.mean(np.logaddexp(0.0, z) - t * z)), grad

    start = np.append(np.full(k, 1.0 / k), 0.0) if x0 is None else np.asarray(x0, dtype=np.float64)
    res = minimize(nll, x0=start, jac=True, method="L-BFGS-B")
    w, b = res.x[:k].astype(np.float64), float(res.x[k])
    if not (np.isfinite(w).all() and np.isfinite(b)):
        raise RuntimeError("calibration fit diverged")
    if (w <= 0).any():
        raise ValueError("a calibration weight is not positive: a model ranks backwards "
                         "or adds nothing")
    return w, b


def fit_platt(logits, y) -> tuple[float, float]:
    """Fit p = sigmoid(a*logit + b) (Platt scaling)."""
    x = np.asarray(logits, dtype=np.float64)
    if x.ndim != 1 or x.shape != np.asarray(y).shape or len(x) == 0:
        raise ValueError("logits and y must be 1-D arrays of the same, non-zero length")
    try:
        w, b = fit_logistic(x[:, None], y, x0=[1.0, 0.0])
    except ValueError as exc:
        if "not positive" in str(exc):
            raise ValueError("calibration slope is not positive: the model ranks backwards") from exc
        raise
    return float(w[0]), b


def _within_budget(w_sorted: np.ndarray, budget: float) -> int:
    """How many leading items fit within budget * total weight."""
    cw = np.cumsum(w_sorted)
    return int(np.searchsorted(cw, budget * cw[-1] * (1 + 1e-9), side="right"))


def choose_thresholds(p, y, max_false_alarm: float, max_missed: float,
                      weights=None) -> tuple[float, float]:
    """(t_phishing, t_safe) meeting both budgets on (p, y); t_safe <= t_phishing.

    weights (e.g. site_weights) make the budgets shares of weight instead of URLs.
    """
    if not (0.0 <= max_false_alarm < 1.0 and 0.0 <= max_missed < 1.0):
        raise ValueError("budgets must be in [0, 1)")
    p = np.asarray(p, dtype=np.float64)
    y = np.asarray(y)
    w = np.ones(len(p)) if weights is None else np.asarray(weights, dtype=np.float64)
    if w.shape != p.shape or not np.isfinite(w).all() or (w <= 0).any():
        raise ValueError("weights must be positive, finite and one per URL")
    b, ph = y == 0, y == 1
    if not b.any() or not ph.any():
        raise ValueError("thresholds need both classes")
    order = np.argsort(-p[b], kind="stable")                  # safe: high -> low
    benign, wb = p[b][order], w[b][order]
    k = _within_budget(wb, max_false_alarm)                   # safe allowed above t_phishing
    t_phishing = float(benign[k]) if k < len(benign) else 0.0
    order = np.argsort(p[ph], kind="stable")                  # phishing: low -> high
    phish, wp = p[ph][order], w[ph][order]
    m = _within_budget(wp, max_missed)                        # phishing allowed below t_safe
    t_safe = float(phish[m]) if m < len(phish) else 1.0
    return t_phishing, min(t_safe, t_phishing)


def outcome_from(out, y, groups=None, base_rates=BASE_RATES) -> dict:
    """Rates of each outcome per class. With groups, every website counts once."""
    out, y = np.asarray(out), np.asarray(y)
    w = np.ones(len(y)) if groups is None else site_weights(y, groups)
    counts, rates, by_url = {}, {}, {}
    for cls, lab in (("benign", 0), ("phishing", 1)):
        mask = y == lab
        n, total = int(mask.sum()), float(w[mask].sum())
        counts[cls] = {o: int((mask & (out == o)).sum()) for o in OUTCOMES}
        by_url[cls] = {o: (c / n if n else None) for o, c in counts[cls].items()}
        rates[cls] = {o: (float(w[mask & (out == o)].sum()) / total if n else None)
                      for o in OUTCOMES}
    fa, caught = rates["benign"][PHISHING], rates["phishing"][PHISHING]
    missed, benign_safe = rates["phishing"][LIKELY_SAFE], rates["benign"][LIKELY_SAFE]
    projected = {}
    for pi in base_rates:
        flagged = pi * caught + (1 - pi) * fa
        called_safe = pi * missed + (1 - pi) * benign_safe
        projected[f"{pi:g}"] = {
            "precision_of_PHISHING": pi * caught / flagged if flagged else None,
            "phishing_among_LIKELY_SAFE": pi * missed / called_safe if called_safe else None,
            "uncertain_share": pi * rates["phishing"][UNCERTAIN] + (1 - pi) * rates["benign"][UNCERTAIN],
        }
    report = {"unit": "url" if groups is None else "website",
              "counts": counts, "rates": rates, "false_alarm_rate": fa,
              "phishing_caught_rate": caught, "missed_rate": missed,
              "uncertain_share_in_this_split": float(w[out == UNCERTAIN].sum() / w.sum()),
              "projected_by_phishing_base_rate": projected}
    if groups is not None:
        g = np.asarray(groups, dtype=object)
        report["rates_by_url"] = by_url
        report["websites"] = {
            "safe": len(set(g[y == 0])), "phishing": len(set(g[y == 1])),
            "safe_with_a_PHISHING_verdict": len(set(g[(y == 0) & (out == PHISHING)])),
            "phishing_with_a_LIKELY_SAFE_verdict": len(set(g[(y == 1) & (out == LIKELY_SAFE)]))}
    return report


def outcome_report(p, y, t_phishing: float, t_safe: float, base_rates=BASE_RATES,
                   groups=None) -> dict:
    report = outcome_from(classify(p, t_phishing, t_safe), y, groups, base_rates)
    return {"thresholds": {"t_phishing": t_phishing, "t_safe": t_safe}, **report}


def threshold_grid(p, y, groups=None) -> list[dict]:
    w = None if groups is None else site_weights(y, groups)
    rows = []
    for fa in GRID_FALSE_ALARM:
        for mm in GRID_MISSED:
            tp, ts = choose_thresholds(p, y, fa, mm, w)
            r = outcome_report(p, y, tp, ts, groups=groups)
            rows.append({"max_false_alarm": fa, "max_missed": mm, "t_phishing": tp, "t_safe": ts,
                         "caught": r["phishing_caught_rate"],
                         **{f"{k}@{pi}": v[k] for pi, v in r["projected_by_phishing_base_rate"].items()
                            for k in ("precision_of_PHISHING", "uncertain_share")}})
    return rows


def _calib_quality(y, raw, cal) -> dict:
    return {name: {"ece": expected_calibration_error(y, p), "brier": float(np.mean((p - y) ** 2))}
            for name, p in (("uncalibrated", raw), ("calibrated", cal))}


def calibrate_run(run_dir: Path, *, splits: Path = SPLITS_DIR, with_test: bool = False,
                  max_false_alarm: float = 0.005, max_missed: float = 0.05, device: str = "auto",
                  cache_dir: Path | None = CACHE_DIR, reports_dir: Path = REPORTS_DIR,
                  unit: str = "website", force: bool = False) -> dict:
    if unit not in UNITS:
        raise ValueError(f"unit must be one of {UNITS}")
    run_dir = Path(run_dir)
    previous = run_dir / "calibration.json"
    if previous.exists() and not force and "test" in json.loads(previous.read_text(encoding="utf-8")):
        raise FileExistsError(f"{previous} holds the test-split record; copy it elsewhere and "
                              "pass --force to replace it")
    ckpt_path = run_dir / "best.pt"
    if not ckpt_path.exists():
        raise FileNotFoundError(f"{ckpt_path} not found: train the run first")
    dev = resolve_device(device)
    model, tokenizer, scaler, meta = load_checkpoint(ckpt_path, map_location=dev)
    model.to(dev)
    mode = meta["mode"]

    val = load_split(mode, "val", splits)
    if val.file_sha256 != meta["data_sha256"]["val"]:
        raise ValueError("the validation split changed since this model was trained")
    val_logits = predict_logits(model, to_tensors(val, tokenizer, scaler, dev, cache_dir))
    a, b = fit_platt(val_logits, val.y)
    val_p = sigmoid(a * val_logits + b)
    val_groups = val.groups if unit == "website" else None
    weights = None if val_groups is None else site_weights(val.y, val_groups)
    t_phishing, t_safe = choose_thresholds(val_p, val.y, max_false_alarm, max_missed, weights)
    cal = Calibrator(a, b, t_phishing, t_safe)

    report = {
        "run": run_dir.name, "mode": mode,
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "checkpoint_sha256": file_sha256(ckpt_path),
        "calibrator": cal.to_config(),
        "unit": unit,
        "budgets": {"max_false_alarm": max_false_alarm, "max_missed": max_missed},
        "fitted_on": {"split": "val", "sha256": val.file_sha256, "rows": len(val),
                      "phishing_rate": float(val.y.mean())},
        "val": {"calibration": _calib_quality(val.y, sigmoid(val_logits), val_p),
                "outcomes": outcome_report(val_p, val.y, t_phishing, t_safe, groups=val_groups)},
        "threshold_grid_val": threshold_grid(val_p, val.y, val_groups),
        "evaluated_splits": ["val"],
        "note": ("Validation numbers are in-sample for calibration and thresholds; "
                 "the test numbers are the honest estimate."),
    }
    if with_test:
        test = load_split(mode, "test", splits)
        logits = predict_logits(model, to_tensors(test, tokenizer, scaler, dev, cache_dir))
        p = cal.probability(logits)
        report["test"] = {"metrics": binary_metrics(test.y, p),
                          "slices": slice_metrics(test.y, p, test.slices()),
                          "calibration": _calib_quality(test.y, sigmoid(logits), p),
                          "outcomes": outcome_report(p, test.y, t_phishing, t_safe,
                                                     groups=test.groups if unit == "website" else None),
                          "sha256": test.file_sha256}
        report["evaluated_splits"].append("test")

    text = json.dumps(report, indent=2) + "\n"
    (run_dir / "calibration.json").write_text(text, encoding="utf-8")
    Path(reports_dir).mkdir(parents=True, exist_ok=True)
    (Path(reports_dir) / f"calibration_{run_dir.name}.json").write_text(text, encoding="utf-8")
    return report


# --------------------------------------------------------------------- printing
def _pct(v) -> str:
    return "-" if v is None else f"{100 * v:.2f}%"


def print_outcomes(split: str, o: dict, indent: str = "  ") -> None:
    unit = o.get("unit", "url")
    noun = "websites" if unit == "website" else "URLs"
    for cls, label in (("benign", "safe"), ("phishing", "phishing")):
        r = o["rates"][cls]
        print(f"{indent}[{split}] {label + ' ' + noun + ':':<18} PHISHING {_pct(r[PHISHING])}  "
              f"UNCERTAIN {_pct(r[UNCERTAIN])}  LIKELY_SAFE {_pct(r[LIKELY_SAFE])}")
    if "websites" in o:
        s = o["websites"]
        print(f"{indent}[{split}] websites with a wrong verdict: {s['safe_with_a_PHISHING_verdict']} of "
              f"{s['safe']} safe got PHISHING, {s['phishing_with_a_LIKELY_SAFE_verdict']} of "
              f"{s['phishing']} phishing got LIKELY_SAFE")
    for pi, v in o["projected_by_phishing_base_rate"].items():
        print(f"{indent}[{split}] if {_pct(float(pi))} of traffic is phishing: a PHISHING verdict is "
              f"right {_pct(v['precision_of_PHISHING'])} of the time, "
              f"{_pct(v['uncertain_share'])} are UNCERTAIN")


def print_report(r: dict) -> None:
    c = r["calibrator"]
    unit = r.get("unit", "url")
    print(f"run {r['run']} ({r['mode']}): p = sigmoid({c['a']:.4f} * logit + {c['b']:+.4f})")
    q = r["val"]["calibration"]
    print(f"  val ECE {q['uncalibrated']['ece']:.4f} -> {q['calibrated']['ece']:.4f}, "
          f"Brier {q['uncalibrated']['brier']:.4f} -> {q['calibrated']['brier']:.4f}")
    print(f"  budgets ({'every website counts once' if unit == 'website' else 'per URL'}): "
          f"false alarm <= {_pct(r['budgets']['max_false_alarm'])}, "
          f"missed <= {_pct(r['budgets']['max_missed'])}  ->  "
          f"PHISHING if p > {c['t_phishing']:.4f}, LIKELY_SAFE if p < {c['t_safe']:.4f}")
    for split in r["evaluated_splits"]:
        print_outcomes(split, r[split]["outcomes"])
        if split == "test":
            m = r["test"]["metrics"]
            print(f"  [test] PR-AUC {m['pr_auc']:.4f}, recall@1%FPR "
                  f"{m['recall_at_fpr']['0.01']['recall']:.4f}, ECE {m['ece']:.4f}")
    print("  threshold options (validation):")
    print("    false-alarm  missed  caught   right@5%  uncertain@5%  right@1%  uncertain@1%")
    for g in r["threshold_grid_val"]:
        print(f"    {_pct(g['max_false_alarm']):>11}  {_pct(g['max_missed']):>6}  {_pct(g['caught']):>6}  "
              f"{_pct(g['precision_of_PHISHING@0.05']):>8}  {_pct(g['uncertain_share@0.05']):>12}  "
              f"{_pct(g['precision_of_PHISHING@0.01']):>8}  {_pct(g['uncertain_share@0.01']):>12}")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--run", type=Path, required=True, help="run directory containing best.pt")
    ap.add_argument("--max-false-alarm", type=float, default=0.005)
    ap.add_argument("--max-missed", type=float, default=0.05)
    ap.add_argument("--unit", choices=UNITS, default="website",
                    help="what a budget counts: websites (each counts once) or single URLs")
    ap.add_argument("--splits", type=Path, default=SPLITS_DIR)
    ap.add_argument("--device", choices=("auto", "cpu", "cuda"), default="auto")
    ap.add_argument("--with-test", action="store_true", help="score the test split (once!)")
    ap.add_argument("--force", action="store_true",
                    help="replace a calibration.json that holds the test-split record")
    args = ap.parse_args(argv)
    report = calibrate_run(args.run, splits=args.splits, with_test=args.with_test,
                           max_false_alarm=args.max_false_alarm, max_missed=args.max_missed,
                           device=args.device, cache_dir=CACHE_DIR, reports_dir=REPORTS_DIR,
                           unit=args.unit, force=args.force)
    print_report(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
