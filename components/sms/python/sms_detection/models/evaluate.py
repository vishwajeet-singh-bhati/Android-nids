"""Evaluation metrics, risk-band diagnostics and report plots."""

from __future__ import annotations

from pathlib import Path
from typing import Mapping, Sequence

import numpy as np
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    confusion_matrix,
    f1_score,
    log_loss,
    precision_recall_fscore_support,
)

from ..config import LABELS
from ..models.calibrate import expected_calibration_error, multiclass_brier
from ..policy.risk_fusion import RiskPolicy, rule_based_classify
from ..preprocessing.indicators import IndicatorResult


def compute_metrics(
    y_true: Sequence[str],
    y_pred: Sequence[str],
    *,
    probabilities: np.ndarray | None = None,
) -> dict:
    y_true = list(y_true)
    y_pred = list(y_pred)
    labels = list(LABELS)
    cm = confusion_matrix(y_true, y_pred, labels=labels)
    precision, recall, f1, support = precision_recall_fscore_support(
        y_true, y_pred, labels=labels, zero_division=0
    )
    per_class = {
        label: {
            "precision": float(precision[i]),
            "recall": float(recall[i]),
            "f1": float(f1[i]),
            "support": int(support[i]),
        }
        for i, label in enumerate(labels)
    }
    smishing_index = labels.index("smishing")
    non_smishing = [label for label in labels if label != "smishing"]
    smishing_support = int(support[smishing_index])
    non_smishing_support = int(sum(support[labels.index(label)] for label in non_smishing))
    smishing_fp = sum(
        1 for truth, pred in zip(y_true, y_pred) if truth != "smishing" and pred == "smishing"
    )
    ham_support = int(support[labels.index("ham")])
    ham_fp = sum(1 for truth, pred in zip(y_true, y_pred) if truth == "ham" and pred != "ham")

    result = {
        "rows": len(y_true),
        "accuracy": float(accuracy_score(y_true, y_pred)) if y_true else 0.0,
        "macro_f1": float(f1_score(y_true, y_pred, labels=labels, average="macro", zero_division=0)),
        "weighted_f1": float(
            f1_score(y_true, y_pred, labels=labels, average="weighted", zero_division=0)
        ),
        "per_class": per_class,
        "confusion_matrix": cm.tolist(),
        "confusion_matrix_labels": labels,
        "smishing_recall": float(recall[smishing_index]),
        "smishing_false_negative_rate": float(1.0 - recall[smishing_index]),
        "smishing_precision": float(precision[smishing_index]),
        "smishing_false_positive_rate": float(
            smishing_fp / non_smishing_support if non_smishing_support else 0.0
        ),
        "smishing_support": smishing_support,
        "ham_false_positive_rate": float(ham_fp / ham_support if ham_support else 0.0),
        "ham_support": ham_support,
        "predicted_counts": {
            label: int(sum(1 for pred in y_pred if pred == label)) for label in labels
        },
    }

    if probabilities is not None and len(probabilities) == len(y_true):
        probabilities = np.asarray(probabilities, dtype=float)
        try:
            result["log_loss"] = _log_loss_sorted(y_true, probabilities)
        except ValueError:
            result["log_loss"] = None
        result["multiclass_brier"] = float(multiclass_brier(probabilities, y_true))
        result["ece_10bin"] = float(expected_calibration_error(probabilities, y_true))
        result["mean_confidence"] = float(probabilities.max(axis=1).mean())
        if smishing_support and non_smishing_support:
            binary = np.asarray([1 if label == "smishing" else 0 for label in y_true])
            result["smishing_average_precision"] = float(
                average_precision_score(binary, probabilities[:, smishing_index])
            )
        else:
            result["smishing_average_precision"] = None
    return result


def _log_loss_sorted(y_true: Sequence[str], probabilities: np.ndarray) -> float:
    """sklearn >=1.9 requires labels in lexicographic order and matching columns."""

    sorted_labels = sorted(LABELS)
    columns = [LABELS.index(label) for label in sorted_labels]
    return float(log_loss(y_true, probabilities[:, columns], labels=sorted_labels))


def risk_metrics(
    y_true: Sequence[str],
    probabilities: np.ndarray,
    indicators: Sequence[IndicatorResult],
    policy: RiskPolicy,
) -> dict:
    labels: list[str] = []
    levels: list[str] = []
    for label, prob_row, indicator in zip(y_true, probabilities, indicators):
        scores = {name: float(prob_row[i]) for i, name in enumerate(LABELS)}
        assessment = policy.assess(scores, indicator)
        labels.append(assessment.label)
        levels.append(assessment.risk_level)

    smishing_total = max(1, sum(1 for label in y_true if label == "smishing"))
    ham_total = max(1, sum(1 for label in y_true if label == "ham"))
    high_total = max(1, sum(1 for level in levels if level == "high"))
    flagged_total = max(1, sum(1 for level in levels if level != "low"))
    return {
        "high_rate": sum(1 for level in levels if level == "high") / max(1, len(levels)),
        "flagged_rate": sum(1 for level in levels if level != "low") / max(1, len(levels)),
        "high_smishing_recall": sum(
            1 for truth, level in zip(y_true, levels) if truth == "smishing" and level == "high"
        )
        / smishing_total,
        "high_smishing_precision": sum(
            1 for truth, level in zip(y_true, levels) if truth == "smishing" and level == "high"
        )
        / high_total,
        "smishing_flagged_rate": sum(
            1 for truth, level in zip(y_true, levels) if truth == "smishing" and level != "low"
        )
        / smishing_total,
        "ham_flagged_rate": sum(
            1 for truth, level in zip(y_true, levels) if truth == "ham" and level != "low"
        )
        / ham_total,
        "ham_high_rate": sum(
            1 for truth, level in zip(y_true, levels) if truth == "ham" and level == "high"
        )
        / ham_total,
        "flagged_total": int(flagged_total),
        "high_total": int(high_total),
        "risk_levels": _counts(levels),
        "final_labels": _counts(labels),
        # Evaluate the product output after rule/risk fusion, not just argmax.
        "policy_metrics": compute_metrics(y_true, labels),
    }


def rules_predictions(indicators: Sequence[IndicatorResult]) -> tuple[list[str], np.ndarray]:
    predictions: list[str] = []
    probabilities: list[list[float]] = []
    for indicator in indicators:
        decision = rule_based_classify(indicator)
        predictions.append(decision.label)
        probabilities.append([decision.scores[label] for label in LABELS])
    return predictions, np.asarray(probabilities, dtype=float)


def _counts(values: Sequence[str]) -> dict[str, int]:
    return {value: int(sum(1 for item in values if item == value)) for value in sorted(set(values))}


def plot_confusion_matrix(metrics: Mapping, path: str | Path, *, title: str) -> Path:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    matrix = np.asarray(metrics["confusion_matrix"])
    labels = metrics["confusion_matrix_labels"]
    fig, ax = plt.subplots(figsize=(5.5, 4.5))
    image = ax.imshow(matrix, interpolation="nearest", cmap="Blues")
    fig.colorbar(image, ax=ax, fraction=0.046, pad=0.04)
    ax.set(
        xticks=np.arange(len(labels)),
        yticks=np.arange(len(labels)),
        xticklabels=labels,
        yticklabels=labels,
        ylabel="True label",
        xlabel="Predicted label",
        title=title,
    )
    plt.setp(ax.get_xticklabels(), rotation=30, ha="right")
    threshold = matrix.max() / 2.0 if matrix.size else 0.0
    for i in range(matrix.shape[0]):
        for j in range(matrix.shape[1]):
            ax.text(
                j,
                i,
                str(int(matrix[i, j])),
                ha="center",
                va="center",
                color="white" if matrix[i, j] > threshold else "black",
            )
    fig.tight_layout()
    fig.savefig(path, dpi=160)
    plt.close(fig)
    return path
