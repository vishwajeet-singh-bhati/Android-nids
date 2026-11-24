"""Classic (non-deep-learning) baselines the CNN must beat.

    python -m src.training.baselines                 # both modes, validation only
    python -m src.training.baselines --mode domain
    python -m src.training.baselines --with-test     # ONLY for the final comparison

Models
  shortcut_probe  logistic regression on 4 length/shape numbers. Not a real
                  detector: if it scores high, the data still has a shortcut.
  features_lr     logistic regression on the structural features.
  features_hgb    gradient-boosted trees on the structural features.
  char_ngram_lr   TF-IDF of character 2..5-grams + logistic regression (C picked
                  on validation): the classic strong URL baseline.

The test split is not touched unless --with-test is given, so it stays an
honest, unseen final exam. Reports go to reports/baselines_<mode>.json and
contain only aggregate numbers, never URLs.
"""
from __future__ import annotations

import argparse
import json
import platform
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

import numpy as np
import sklearn
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.linear_model import LogisticRegression

from src.models.calibration import sigmoid
from src.models.ngram_lr import fit_with_c_search
from src.preprocessing.feature_extractor import FeatureExtractor, FeatureScaler

from .data import CACHE_DIR, MODES, SPLITS_DIR, SplitData, load_features, load_split
from .metrics import binary_metrics, slice_metrics

REPORTS_DIR = Path("reports")
SHORTCUT_FEATURES = ("url_length", "path_length", "query_length", "num_subdomain_labels")
C_GRID = (1.0, 3.0, 10.0, 30.0, 100.0)  # first run picked 10.0, the old grid's edge


def _evaluate(name: str, score_fn: Callable[[SplitData, np.ndarray], np.ndarray],
              evals: dict[str, tuple[SplitData, np.ndarray]], extra: dict, t0: float) -> dict:
    result = {"train_seconds": round(time.perf_counter() - t0, 2), **extra}
    for split, (data, feats) in evals.items():
        score = score_fn(data, feats)
        result[split] = {"overall": binary_metrics(data.y, score),
                         "slices": slice_metrics(data.y, score, data.slices())}
    print(f"  {name:15s} " + "  ".join(
        f"{s}: PR-AUC {result[s]['overall'].get('pr_auc', float('nan')):.4f} "
        f"recall@1%FPR {result[s]['overall'].get('recall_at_fpr', {}).get('0.01', {}).get('recall', float('nan')):.4f}"
        for s in evals))
    return result


def run_baselines(mode: str, root: Path = SPLITS_DIR, with_test: bool = False, seed: int = 13,
                  cache_dir: Path | None = CACHE_DIR, c_grid=C_GRID, models=None) -> dict:
    t_load = time.perf_counter()
    train = load_split(mode, "train", root)
    val = load_split(mode, "val", root)
    names = FeatureExtractor().feature_names
    f_train = load_features(train, names, cache_dir)
    evals = {"val": (val, load_features(val, names, cache_dir))}
    if with_test:
        test = load_split(mode, "test", root)
        evals["test"] = (test, load_features(test, names, cache_dir))
    print(f"[{mode}] loaded in {time.perf_counter() - t_load:.1f}s "
          f"(train {len(train)}, val {len(val)})")

    wanted = set(models or ("shortcut_probe", "features_lr", "features_hgb", "char_ngram_lr"))
    results: dict[str, dict] = {}

    # --- logistic regression on scaled feature subsets
    for name, subset in (("shortcut_probe", SHORTCUT_FEATURES), ("features_lr", names)):
        if name not in wanted:
            continue
        t0 = time.perf_counter()
        cols = [names.index(f) for f in subset]
        scaler = FeatureScaler.fit(subset, f_train[:, cols])
        model = LogisticRegression(max_iter=2000).fit(scaler.transform(f_train[:, cols]), train.y)
        results[name] = _evaluate(
            name, lambda d, f, m=model, s=scaler, c=cols: m.predict_proba(s.transform(f[:, c]))[:, 1],
            evals, {"features": list(subset)}, t0)

    # --- gradient-boosted trees (scale-free, so raw features)
    if "features_hgb" in wanted:
        t0 = time.perf_counter()
        hgb = HistGradientBoostingClassifier(max_iter=300, random_state=seed).fit(f_train, train.y)
        results["features_hgb"] = _evaluate(
            "features_hgb", lambda d, f: hgb.predict_proba(f)[:, 1], evals,
            {"features": list(names), "n_iter": int(hgb.n_iter_)}, t0)

    # --- character n-gram TF-IDF + logistic regression, C chosen on validation
    if "char_ngram_lr" in wanted:
        t0 = time.perf_counter()
        ngram, search = fit_with_c_search(train.texts, train.y, val.texts, val.y, c_grid)
        results["char_ngram_lr"] = _evaluate(
            "char_ngram_lr", lambda d, f: sigmoid(ngram.logits(d.texts)), evals,
            {"vocabulary": ngram.vocabulary_size, "C": ngram.meta["C"], "val_pr_auc_by_C": search}, t0)

    return {
        "mode": mode,
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "seed": seed,
        "evaluated_splits": list(evals),
        "data": {s: {"rows": len(d), "phishing": int(d.y.sum()), "sha256": d.file_sha256}
                 for s, (d, _) in {"train": (train, None), **evals}.items()},
        "versions": {"python": platform.python_version(), "sklearn": sklearn.__version__,
                     "numpy": np.__version__},
        "note": "Probabilities are uncalibrated; threshold 0.5 is only a reference point.",
        "models": results,
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--mode", choices=(*MODES, "both"), default="both")
    ap.add_argument("--splits", type=Path, default=SPLITS_DIR)
    ap.add_argument("--out", type=Path, default=REPORTS_DIR)
    ap.add_argument("--with-test", action="store_true",
                    help="also score the test split (final comparison only)")
    ap.add_argument("--seed", type=int, default=13)
    args = ap.parse_args(argv)
    args.out.mkdir(parents=True, exist_ok=True)
    for mode in (MODES if args.mode == "both" else (args.mode,)):
        report = run_baselines(mode, args.splits, args.with_test, args.seed,
                               cache_dir=CACHE_DIR, c_grid=C_GRID)
        path = args.out / f"baselines_{mode}.json"
        path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(f"[{mode}] report written to {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
