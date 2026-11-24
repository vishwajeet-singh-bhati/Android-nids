"""Probability calibration and cost-sensitive operating-point selection.

Thresholds are selected on validation data with an explicit asymmetric cost,
never silently fixed at 0.5. This module also provides the metrics needed to
justify whether the scores deserve to be called calibrated probabilities.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Sequence

import numpy as np
from scipy.optimize import minimize_scalar
from scipy.special import softmax

from ..config import LABELS


@dataclass(frozen=True)
class ThresholdSelection:
    threshold: float
    recall: float
    precision: float
    false_positive_rate: float
    false_negatives: int
    false_positives: int
    expected_cost: float


def softmax_logits(logits: np.ndarray) -> np.ndarray:
    logits = np.asarray(logits, dtype=float)
    if logits.ndim == 1:
        logits = logits.reshape(1, -1)
    return softmax(logits, axis=1)


def fit_temperature(logits: np.ndarray, y_true: Sequence[str], *, labels: Sequence[str] = LABELS) -> float:
    """Fit one scalar temperature on validation logits by minimizing NLL."""

    logits = np.asarray(logits, dtype=float)
    if logits.ndim != 2 or logits.shape[1] != len(labels):
        raise ValueError("logits must have one column per label")
    index = {label: i for i, label in enumerate(labels)}
    targets = np.asarray([index[label] for label in y_true], dtype=int)

    def nll(log_temperature: float) -> float:
        temperature = float(np.exp(log_temperature))
        probabilities = softmax(logits / temperature, axis=1)
        chosen = probabilities[np.arange(len(targets)), targets]
        return float(-np.mean(np.log(np.clip(chosen, 1e-12, 1.0))))

    result = minimize_scalar(nll, bounds=(np.log(0.05), np.log(10.0)), method="bounded")
    return float(np.exp(result.x))


def multiclass_brier(probabilities: np.ndarray, y_true: Sequence[str], *, labels: Sequence[str] = LABELS) -> float:
    index = {label: i for i, label in enumerate(labels)}
    one_hot = np.zeros_like(np.asarray(probabilities, dtype=float))
    for row, label in enumerate(y_true):
        one_hot[row, index[label]] = 1.0
    return float(np.mean(np.sum((np.asarray(probabilities) - one_hot) ** 2, axis=1)))


def expected_calibration_error(
    probabilities: np.ndarray,
    y_true: Sequence[str],
    *,
    n_bins: int = 10,
    labels: Sequence[str] = LABELS,
) -> float:
    """Top-label ECE. Confidence is the max predicted probability."""

    probabilities = np.asarray(probabilities, dtype=float)
    index = {label: i for i, label in enumerate(labels)}
    predictions = probabilities.argmax(axis=1)
    confidences = probabilities.max(axis=1)
    correct = np.asarray([index[label] for label in y_true]) == predictions
    ece = 0.0
    for lower in np.linspace(0.0, 1.0, n_bins + 1)[:-1]:
        upper = lower + 1.0 / n_bins
        mask = (confidences >= lower) & (confidences < upper)
        if not np.any(mask):
            continue
        accuracy = float(np.mean(correct[mask]))
        confidence = float(np.mean(confidences[mask]))
        ece += abs(accuracy - confidence) * float(np.mean(mask))
    return float(ece)


def select_threshold(
    y_smishing: Sequence[int],
    p_smishing: Sequence[float],
    *,
    cost_fn: float = 10.0,
    cost_fp: float = 1.0,
    thresholds: Sequence[float] | None = None,
    min_recall: float | None = None,
    min_precision: float | None = None,
) -> ThresholdSelection:
    """Choose the threshold minimizing C_FN*FN + C_FP*FP on validation data.

    ``min_recall`` and ``min_precision`` are optional safety floors. If no
    threshold meets them, the cost-optimal point is still returned so the
    shortfall is visible in reports rather than silently hidden.
    """

    y = np.asarray(y_smishing, dtype=int)
    p = np.asarray(p_smishing, dtype=float)
    if len(y) != len(p):
        raise ValueError("y_smishing and p_smishing must have the same length")
    candidates = np.asarray(
        thresholds if thresholds is not None else np.linspace(0.01, 0.99, 197)
    )
    best: ThresholdSelection | None = None
    best_feasible: ThresholdSelection | None = None
    positives = max(1, int(y.sum()))
    negatives = max(1, int(len(y) - y.sum()))

    for threshold in candidates:
        predicted = (p >= threshold).astype(int)
        fn = int(np.sum((y == 1) & (predicted == 0)))
        fp = int(np.sum((y == 0) & (predicted == 1)))
        tp = int(np.sum((y == 1) & (predicted == 1)))
        tn = int(np.sum((y == 0) & (predicted == 0)))
        recall = tp / positives
        precision = tp / max(1, tp + fp)
        fpr = fp / negatives
        cost = cost_fn * fn + cost_fp * fp
        candidate = ThresholdSelection(
            threshold=float(threshold),
            recall=float(recall),
            precision=float(precision),
            false_positive_rate=float(fpr),
            false_negatives=fn,
            false_positives=fp,
            expected_cost=float(cost),
        )
        if best is None or _better(candidate, best):
            best = candidate
        feasible = (min_recall is None or recall >= min_recall) and (
            min_precision is None or precision >= min_precision
        )
        if feasible:
            if best_feasible is None or _better(candidate, best_feasible):
                best_feasible = candidate
    assert best is not None
    return best_feasible or best


def _better(candidate: ThresholdSelection, best: ThresholdSelection) -> bool:
    if candidate.expected_cost < best.expected_cost - 1e-12:
        return True
    if abs(candidate.expected_cost - best.expected_cost) <= 1e-12:
        if candidate.recall > best.recall + 1e-12:
            return True
        if abs(candidate.recall - best.recall) <= 1e-12:
            return candidate.threshold > best.threshold
    return False


def select_risk_thresholds(
    y_true: Sequence[str],
    probabilities: np.ndarray,
    *,
    cost_fn: float = 10.0,
    cost_fp: float = 1.0,
    suspicious_fp_weight: float = 0.2,
    min_high_recall: float | None = 0.85,
    min_high_precision: float | None = 0.80,
) -> dict[str, float]:
    """Select high and suspicious smishing thresholds with different FP costs.

    A high-risk mistake is treated as a blocking/urgent error. The suspicious
    band is a review prompt, so its false-positive cost is discounted but not
    ignored. Both points are chosen on validation only.

    The high band is deliberately precision-oriented: it should be safe to
    interrupt the user. The suspicious band is recall-oriented and is where
    uncertain messages get a "verify before acting" prompt.
    """

    index = {label: i for i, label in enumerate(LABELS)}
    y_smishing = np.asarray([1 if label == "smishing" else 0 for label in y_true])
    p_smishing = np.asarray(probabilities)[:, index["smishing"]]

    high = select_threshold(
        y_smishing,
        p_smishing,
        cost_fn=cost_fn,
        cost_fp=cost_fp,
        min_recall=min_high_recall,
        min_precision=min_high_precision,
    )
    suspicious = select_threshold(
        y_smishing,
        p_smishing,
        cost_fn=cost_fn,
        cost_fp=cost_fp * suspicious_fp_weight,
        thresholds=np.linspace(0.01, max(high.threshold, 0.02), 100),
        min_recall=min_high_recall,
    )
    high_feasible = (
        (min_high_recall is None or high.recall >= min_high_recall - 1e-12)
        and (min_high_precision is None or high.precision >= min_high_precision - 1e-12)
    )
    suspicious_feasible = (
        min_high_recall is None or suspicious.recall >= min_high_recall - 1e-12
    )
    return {
        "high_threshold": high.threshold,
        "suspicious_threshold": min(suspicious.threshold, high.threshold),
        "high_recall": high.recall,
        "high_precision": high.precision,
        "high_fpr": high.false_positive_rate,
        "high_expected_cost": high.expected_cost,
        "high_feasible": bool(high_feasible),
        "suspicious_recall": suspicious.recall,
        "suspicious_precision": suspicious.precision,
        "suspicious_fpr": suspicious.false_positive_rate,
        "suspicious_expected_cost": suspicious.expected_cost,
        "suspicious_feasible": bool(suspicious_feasible),
        "min_high_recall": min_high_recall,
        "min_high_precision": min_high_precision,
    }


def threshold_sweep(
    y_smishing: Sequence[int],
    p_smishing: Sequence[float],
    *,
    thresholds: Sequence[float] | None = None,
) -> list[dict[str, float]]:
    """Return a compact table for the evaluation report."""

    y = np.asarray(y_smishing, dtype=int)
    p = np.asarray(p_smishing, dtype=float)
    rows: list[dict[str, float]] = []
    for threshold in thresholds if thresholds is not None else np.linspace(0.05, 0.95, 19):
        predicted = (p >= threshold).astype(int)
        tp = int(np.sum((y == 1) & (predicted == 1)))
        fn = int(np.sum((y == 1) & (predicted == 0)))
        fp = int(np.sum((y == 0) & (predicted == 1)))
        tn = int(np.sum((y == 0) & (predicted == 0)))
        rows.append(
            {
                "threshold": float(threshold),
                "recall": tp / max(1, tp + fn),
                "precision": tp / max(1, tp + fp),
                "fpr": fp / max(1, fp + tn),
                "fn": float(fn),
                "fp": float(fp),
            }
        )
    return rows
