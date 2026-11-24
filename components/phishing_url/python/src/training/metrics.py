"""Evaluation metrics for a phishing score in [0, 1] (1 = phishing).

Accuracy is reported but deliberately not the headline: with ~16% phishing a
model that always says "benign" is 84% accurate. The headline numbers are
ranking quality (ROC-AUC, PR-AUC), the operating point that matters on a device
(how many phishing URLs we catch while wrongly flagging at most 0.1% / 1% of
safe URLs), and calibration (Brier score, ECE), which the three-outcome
thresholds rely on.

confusion_matrix is [[tn, fp], [fn, tp]]: rows = true label (safe, phishing),
columns = prediction at `threshold` (safe, phishing). The three-outcome
version (PHISHING / UNCERTAIN / LIKELY_SAFE per class) is in the calibration
and ensemble reports under "counts".
"""
from __future__ import annotations

import numpy as np
from sklearn.metrics import average_precision_score, roc_auc_score, roc_curve

FPR_TARGETS = (0.001, 0.01, 0.05)


def _check(y: np.ndarray, score: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    y = np.asarray(y)
    score = np.asarray(score, dtype=np.float64)
    if y.ndim != 1 or y.shape != score.shape:
        raise ValueError("y and score must be 1-D arrays of the same length")
    if not np.isin(y, (0, 1)).all():
        raise ValueError("y must contain only 0 and 1")
    if not np.isfinite(score).all() or (score < 0).any() or (score > 1).any():
        raise ValueError("score must be finite probabilities in [0, 1]")
    return y.astype(np.int64), score


def expected_calibration_error(y: np.ndarray, score: np.ndarray, bins: int = 10) -> float:
    y, score = _check(y, score)
    if len(y) == 0:
        return float("nan")
    idx = np.minimum((score * bins).astype(int), bins - 1)
    ece = 0.0
    for b in range(bins):
        m = idx == b
        if m.any():
            ece += m.mean() * abs(score[m].mean() - y[m].mean())
    return float(ece)


def recall_at_fpr(y: np.ndarray, score: np.ndarray, target: float) -> dict[str, float | None]:
    """Best recall (TPR) whose false-positive rate is <= target, and its threshold."""
    fpr, tpr, thr = roc_curve(y, score)
    ok = fpr <= target
    i = int(np.argmax(np.where(ok, tpr, -1.0)))
    threshold = float(min(thr[i], 1.0))
    return {"recall": float(tpr[i]), "fpr": float(fpr[i]), "threshold": threshold}


def binary_metrics(y: np.ndarray, score: np.ndarray, threshold: float = 0.5) -> dict:
    y, score = _check(y, score)
    n_pos = int(y.sum())
    out: dict = {"n": int(len(y)), "n_phishing": n_pos, "n_benign": int(len(y) - n_pos)}
    if len(y) == 0:
        return out
    pred = score >= threshold
    tp = int((pred & (y == 1)).sum())
    fp = int((pred & (y == 0)).sum())
    fn = int((~pred & (y == 1)).sum())
    tn = int((~pred & (y == 0)).sum())
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / n_pos if n_pos else None
    out["at_threshold"] = {
        "threshold": threshold, "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": precision, "recall": recall,
        "f1": (2 * precision * recall / (precision + recall)
               if precision and recall else (0.0 if precision is not None and recall is not None else None)),
        "fpr": fp / (fp + tn) if fp + tn else None,
        "accuracy": (tp + tn) / len(y),
        "confusion_matrix": [[tn, fp], [fn, tp]],
    }
    out["brier"] = float(np.mean((score - y) ** 2))
    out["ece"] = expected_calibration_error(y, score)
    if 0 < n_pos < len(y):  # ranking metrics need both classes
        out["roc_auc"] = float(roc_auc_score(y, score))
        out["pr_auc"] = float(average_precision_score(y, score))
        out["recall_at_fpr"] = {str(t): recall_at_fpr(y, score, t) for t in FPR_TARGETS}
    return out


def slice_metrics(y: np.ndarray, score: np.ndarray, slices: dict[str, np.ndarray],
                  threshold: float = 0.5) -> dict[str, dict]:
    y, score = _check(y, score)
    out = {}
    for name, mask in slices.items():
        mask = np.asarray(mask, dtype=bool)
        if mask.shape != y.shape:
            raise ValueError(f"slice {name!r} has the wrong length")
        out[name] = binary_metrics(y[mask], score[mask], threshold)
    return out
