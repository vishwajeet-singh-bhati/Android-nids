"""Combine the char-CNN/hybrid with the character n-gram model, judged on validation.

    python -m src.training.ensemble --cnn-run artifacts/runs/full_url_hybrid

Three candidates are compared:
  <cnn run>                 the CNN/hybrid alone (calibrated)
  char_ngram_lr             the n-gram model alone (the baseline: same settings, same C search)
  <cnn run>+char_ngram_lr   both: p = sigmoid(w1*cnn_logit + w2*ngram_logit + b), w1, w2 > 0

How it stays honest
  * The test split is never read. It was used once for the Phase-2 comparison;
    a new model is judged on validation and confirmed later on fresh data.
  * Validation numbers are cross-fitted over WEBSITES: calibration and
    thresholds are fitted on 4/5 of the validation websites and applied to the
    other 1/5, five times, so no website is judged by thresholds fitted on it.
  * Budgets count every website once (see src.training.calibrate).
  * Caveat: the CNN's best epoch and the n-gram model's C were picked on
    validation, which flatters both members a little.

Outputs
  artifacts/runs/<mode>_ngram/model.npz             n-gram model (no pickle), reused while the data is unchanged
  artifacts/runs/<cnn run>_ensemble/ensemble.json   calibrator + thresholds of every candidate, fitted on all of validation
  reports/ensemble_<cnn run>.json                   the same report (aggregate numbers only, no URLs)
"""
from __future__ import annotations

import argparse
import json
import time
from datetime import datetime, timezone
from pathlib import Path

import numpy as np

from src.models.calibration import StackCalibrator, classify, sigmoid
from src.models.char_cnn import load_checkpoint
from src.models.ngram_lr import NgramLR, fit_with_c_search

from .baselines import C_GRID
from .calibrate import choose_thresholds, fit_logistic, outcome_from, print_outcomes, site_weights
from .data import CACHE_DIR, SPLITS_DIR, SplitData, file_sha256, load_split, split_path
from .metrics import binary_metrics
from .summarize import SLICES
from .train_cnn import REPORTS_DIR, RUNS_DIR, predict_logits, resolve_device, to_tensors

NGRAM = "char_ngram_lr"
FOLDS = 5


# --------------------------------------------------------------------- pieces
def site_folds(groups, k: int = FOLDS, seed: int = 13) -> np.ndarray:
    """Fold number for every row; all rows of one website share a fold."""
    sites, inv = np.unique(np.asarray(groups, dtype=str), return_inverse=True)
    if len(sites) < k:
        raise ValueError(f"need at least {k} websites for {k}-fold cross-fitting")
    fold_of_site = np.random.default_rng(seed).permutation(len(sites)) % k
    return fold_of_site[inv]


def fit_candidate(x, y, groups, max_false_alarm: float, max_missed: float):
    """Calibration weights + website-counted thresholds, all fitted on (x, y)."""
    w, b = fit_logistic(x, y)
    p = sigmoid(x @ w + b)
    t_phishing, t_safe = choose_thresholds(p, y, max_false_alarm, max_missed,
                                           site_weights(y, groups))
    return w, b, t_phishing, t_safe


def crossfit(x, y, groups, folds, max_false_alarm: float, max_missed: float):
    """Out-of-fold probabilities and outcomes: each fold is judged by the other folds' fit."""
    p = np.empty(len(y))
    out = np.empty(len(y), dtype="<U11")              # longest outcome name: LIKELY_SAFE
    for f in np.unique(folds):
        tr, te = folds != f, folds == f
        w, b, tp, ts = fit_candidate(x[tr], y[tr], groups[tr], max_false_alarm, max_missed)
        p[te] = sigmoid(x[te] @ w + b)
        out[te] = classify(p[te], tp, ts)
    return p, out


def evaluate_candidate(members: list[str], x: np.ndarray, val: SplitData, folds: np.ndarray,
                       max_false_alarm: float, max_missed: float) -> dict:
    y, groups = val.y, np.asarray(val.groups, dtype=object)
    try:
        p_oof, out_oof = crossfit(x, y, groups, folds, max_false_alarm, max_missed)
        w, b, tp, ts = fit_candidate(x, y, groups, max_false_alarm, max_missed)
    except ValueError as exc:          # e.g. a member gets weight <= 0: it adds nothing
        return {"members": members, "error": str(exc)}
    cal = StackCalibrator(tuple(members), tuple(float(v) for v in w), b, tp, ts)
    m = binary_metrics(y, p_oof)
    masks = val.slices()
    return {"members": members, "calibrator": cal.to_config(),
            "crossfit_val": {
                "pr_auc": m.get("pr_auc"), "roc_auc": m.get("roc_auc"),
                "recall_at_fpr_per_url": m.get("recall_at_fpr"), "ece": m["ece"],
                "slices_pr_auc": {s: binary_metrics(y[masks[s]], p_oof[masks[s]]).get("pr_auc")
                                  for s in SLICES[val.mode] if masks[s].any()},
                "outcomes": outcome_from(out_oof, y, groups)}}


def load_or_train_ngram(mode: str, splits: Path, val: SplitData, path: Path,
                        expected_train_sha: str | None, retrain: bool = False,
                        c_grid=C_GRID) -> tuple[NgramLR, str]:
    train_sha = file_sha256(split_path(mode, "train", splits))
    if expected_train_sha and train_sha != expected_train_sha:
        raise ValueError("the training split changed since the CNN run was trained")
    want = {"train": train_sha, "val": val.file_sha256}
    if path.exists() and not retrain:
        model = NgramLR.load(path)
        if model.meta.get("mode") == mode and model.meta.get("data_sha256") == want:
            return model, "reused"
        print(f"[{mode}] {path} was trained on other data: retraining", flush=True)
    t0 = time.perf_counter()
    train = load_split(mode, "train", splits)
    print(f"[{mode}] training the n-gram model on {len(train)} URLs (takes a few minutes)...",
          flush=True)
    model, _ = fit_with_c_search(train.texts, train.y, val.texts, val.y, c_grid)
    model.meta.update(mode=mode, data_sha256=want, train_seconds=round(time.perf_counter() - t0, 1),
                      created_at=datetime.now(timezone.utc).isoformat(timespec="seconds"))
    model.save(path)
    return model, "trained"


# --------------------------------------------------------------------- run
def run_ensemble(cnn_run: Path, *, splits: Path = SPLITS_DIR, device: str = "auto",
                 cache_dir: Path | None = CACHE_DIR, max_false_alarm: float = 0.005,
                 max_missed: float = 0.05, folds: int = FOLDS, seed: int = 13,
                 retrain_ngram: bool = False, runs_dir: Path = RUNS_DIR,
                 reports_dir: Path = REPORTS_DIR, c_grid=C_GRID) -> dict:
    cnn_run = Path(cnn_run)
    ckpt = cnn_run / "best.pt"
    if not ckpt.exists():
        raise FileNotFoundError(f"{ckpt} not found: train the CNN run first")
    dev = resolve_device(device)
    model, tokenizer, scaler, meta = load_checkpoint(ckpt, map_location=dev)
    model.to(dev)
    mode = meta["mode"]
    val = load_split(mode, "val", splits)
    if val.file_sha256 != meta["data_sha256"]["val"]:
        raise ValueError("the validation split changed since the CNN run was trained")

    ngram_path = Path(runs_dir) / f"{mode}_ngram" / "model.npz"
    ngram, status = load_or_train_ngram(mode, splits, val, ngram_path,
                                        meta["data_sha256"].get("train"), retrain_ngram, c_grid)
    l_cnn = predict_logits(model, to_tensors(val, tokenizer, scaler, dev, cache_dir))
    l_ngram = ngram.logits(val.texts)

    name = cnn_run.name
    candidates = {name: ([name], l_cnn[:, None]),
                  NGRAM: ([NGRAM], l_ngram[:, None]),
                  f"{name}+{NGRAM}": ([name, NGRAM], np.column_stack([l_cnn, l_ngram]))}
    fold_ids = site_folds(val.groups, folds, seed)
    results = {cand: evaluate_candidate(members, x, val, fold_ids, max_false_alarm, max_missed)
               for cand, (members, x) in candidates.items()}

    report = {
        "mode": mode, "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "unit": "website", "budgets": {"max_false_alarm": max_false_alarm, "max_missed": max_missed},
        "folds": folds, "seed": seed,
        "members": {
            name: {"kind": "char_cnn", "path": ckpt.as_posix(), "sha256": file_sha256(ckpt),
                   "model_config": meta.get("model_config")},
            NGRAM: {"kind": NGRAM, "path": ngram_path.as_posix(), "sha256": file_sha256(ngram_path),
                    "C": ngram.meta.get("C"), "vocabulary": ngram.vocabulary_size, "status": status}},
        "fitted_on": {"split": "val", "sha256": val.file_sha256, "rows": len(val)},
        "candidates": results,
        "note": ("crossfit_val numbers are out-of-fold over validation websites. Each calibrator "
                 "is fitted on all of validation. The test split was not read."),
    }
    text = json.dumps(report, indent=2) + "\n"
    out_dir = Path(runs_dir) / f"{name}_ensemble"
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "ensemble.json").write_text(text, encoding="utf-8")
    Path(reports_dir).mkdir(parents=True, exist_ok=True)
    (Path(reports_dir) / f"ensemble_{name}.json").write_text(text, encoding="utf-8")
    return report


# --------------------------------------------------------------------- printing
def _pct(v) -> str:
    return "-" if v is None else f"{100 * v:.2f}%"


def print_report(r: dict) -> None:
    b = r["budgets"]
    print(f"validation, mode={r['mode']}, cross-fitted over websites ({r['folds']} folds); "
          f"budgets (every website counts once): false alarm <= {_pct(b['max_false_alarm'])}, "
          f"missed <= {_pct(b['max_missed'])}")
    ng = r["members"][NGRAM]
    print(f"  n-gram model: {ng['status']}, C={ng['C']}, {ng['vocabulary']} n-grams")
    slices = SLICES[r["mode"]]
    head = ["candidate", "PR-AUC", *[f"[{s}]" for s in slices], "false alarm", "caught", "missed",
            "safe sites flagged", "right@1%", "right@5%", "uncertain@1%"]
    rows = [head]
    ok = {cand: res for cand, res in r["candidates"].items() if "error" not in res}
    for cand, res in ok.items():
        cv, o = res["crossfit_val"], res["crossfit_val"]["outcomes"]
        proj = o["projected_by_phishing_base_rate"]
        fmt = lambda v: "-" if v is None else f"{v:.4f}"
        rows.append([cand, fmt(cv["pr_auc"]), *[fmt(cv["slices_pr_auc"].get(s)) for s in slices],
                     _pct(o["false_alarm_rate"]), _pct(o["phishing_caught_rate"]),
                     _pct(o["missed_rate"]),
                     f"{o['websites']['safe_with_a_PHISHING_verdict']}/{o['websites']['safe']}",
                     _pct(proj["0.01"]["precision_of_PHISHING"]),
                     _pct(proj["0.05"]["precision_of_PHISHING"]),
                     _pct(proj["0.01"]["uncertain_share"])])
    widths = [max(len(row[i]) for row in rows) for i in range(len(head))]
    for row in rows:
        print("  " + "  ".join(c.ljust(w) for c, w in zip(row, widths)))
    for cand, res in r["candidates"].items():
        if "error" in res:
            print(f"  {cand}: not usable ({res['error']})")
    for cand, res in ok.items():
        c = res["calibrator"]
        if len(c["members"]) > 1:
            parts = " + ".join(f"{w:.3f}*{m}" for m, w in zip(c["members"], c["weights"]))
            print(f"  combined: p = sigmoid({parts} {c['bias']:+.3f})")
    print("  outcome details (cross-fitted):")
    for cand, res in ok.items():
        print(f"    {cand}")
        print_outcomes("val", res["crossfit_val"]["outcomes"], indent="      ")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--cnn-run", type=Path, required=True, help="trained CNN/hybrid run directory")
    ap.add_argument("--max-false-alarm", type=float, default=0.005)
    ap.add_argument("--max-missed", type=float, default=0.05)
    ap.add_argument("--folds", type=int, default=FOLDS)
    ap.add_argument("--splits", type=Path, default=SPLITS_DIR)
    ap.add_argument("--device", choices=("auto", "cpu", "cuda"), default="auto")
    ap.add_argument("--retrain-ngram", action="store_true", help="ignore a saved n-gram model")
    args = ap.parse_args(argv)
    report = run_ensemble(args.cnn_run, splits=args.splits, device=args.device, cache_dir=CACHE_DIR,
                          max_false_alarm=args.max_false_alarm, max_missed=args.max_missed,
                          folds=args.folds, retrain_ngram=args.retrain_ngram, runs_dir=RUNS_DIR,
                          reports_dir=REPORTS_DIR, c_grid=C_GRID)
    print_report(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
