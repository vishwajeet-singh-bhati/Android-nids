"""Evaluation for an independent Indian SMS benchmark.

The evaluator accepts only structured labels and optional metadata; raw message
text stays in memory and is never placed in the aggregate report. Model
selection and threshold tuning are out of scope: this module measures a frozen
detector on a separately collected benchmark.
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from typing import Any, Mapping, Sequence

import numpy as np
import pandas as pd
from sklearn.metrics import f1_score

from ..config import LABELS
from .evaluate import compute_metrics

SLICE_COLUMNS = ("language", "sender_type", "scam_type", "collection_month", "source")
WILSON_Z = 1.959963984540054


def wilson_interval(
    successes: int, n: int, *, z: float = WILSON_Z
) -> dict[str, Any]:
    """Wilson score interval for a binomial proportion."""

    if n <= 0:
        return {"successes": int(successes), "n": int(n), "low": None, "high": None}
    p = successes / n
    denominator = 1.0 + z * z / n
    centre = (p + z * z / (2.0 * n)) / denominator
    half_width = (
        z
        * np.sqrt(p * (1.0 - p) / n + z * z / (4.0 * n * n))
        / denominator
    )
    return {
        "successes": int(successes),
        "n": int(n),
        "low": float(max(0.0, centre - half_width)),
        "high": float(min(1.0, centre + half_width)),
    }


def bootstrap_macro_f1(
    y_true: Sequence[str],
    y_pred: Sequence[str],
    *,
    replicates: int = 1000,
    seed: int = 42,
) -> dict[str, Any] | None:
    """Bootstrap interval for macro-F1. Disabled when replicates <= 0."""

    y_true = np.asarray(list(y_true), dtype=object)
    y_pred = np.asarray(list(y_pred), dtype=object)
    if replicates <= 0 or len(y_true) < 2 or len(y_true) != len(y_pred):
        return None
    rng = np.random.default_rng(seed)
    values: list[float] = []
    for _ in range(replicates):
        indices = rng.integers(0, len(y_true), size=len(y_true))
        values.append(
            float(
                f1_score(
                    y_true[indices],
                    y_pred[indices],
                    labels=list(LABELS),
                    average="macro",
                    zero_division=0,
                )
            )
        )
    low, high = np.percentile(values, [2.5, 97.5])
    return {
        "low": float(low),
        "high": float(high),
        "n": int(len(y_true)),
        "replicates": int(replicates),
        "method": "bootstrap",
    }


def predict_rows(frame: pd.DataFrame, detector: Any) -> list[dict[str, Any]]:
    """Run a detector over a benchmark and return local per-row diagnostics.

    The returned records include the raw message because they are intended for a
    private, git-ignored audit file. Never place them in an aggregate report.
    """

    frame = frame.reset_index(drop=True)
    if "text" not in frame.columns or "label" not in frame.columns:
        raise ValueError("Benchmark must contain text and label columns")
    rows: list[dict[str, Any]] = []
    for row in frame.itertuples(index=False):
        sender = getattr(row, "sender", None)
        if sender is None or (isinstance(sender, float) and np.isnan(sender)):
            sender = None
        else:
            sender = str(sender) or None
        known_sender = _coerce_known_sender(getattr(row, "known_sender", False))
        result = detector.predict_sms(
            str(row.text), sender=sender, known_sender=known_sender
        )
        scores = {label: float(result.scores[label]) for label in LABELS}
        rows.append(
            {
                "eval_id": getattr(row, "eval_id", ""),
                "text": str(row.text),
                "true_label": str(row.label),
                "language": getattr(row, "language", "unknown"),
                "sender": sender,
                "sender_type": getattr(row, "sender_type", "unknown"),
                "scam_type": getattr(row, "scam_type", "unspecified"),
                "collection_month": getattr(row, "collection_month", "unknown"),
                "source": getattr(row, "source", "local"),
                "policy_label": str(result.label),
                "classifier_label": LABELS[int(np.argmax([scores[label] for label in LABELS]))],
                "risk_level": str(result.risk_level),
                "scores": scores,
                "evidence_codes": [item.code for item in result.evidence],
                "action_codes": list(result.recommended_action_codes),
                "leakage_splits": str(getattr(row, "leakage_splits", "") or ""),
            }
        )
    return rows


def evaluate_benchmark(
    frame: pd.DataFrame,
    detector: Any,
    *,
    name: str,
    metadata: Mapping[str, Any] | None = None,
    target_prevalence: float | None = None,
    bootstrap_replicates: int = 1000,
    min_slice_rows: int = 20,
) -> dict[str, Any]:
    """Run a frozen detector on a labelled benchmark and return an aggregate report."""

    frame = frame.reset_index(drop=True).copy()
    if frame.empty:
        raise ValueError("Benchmark has no rows after filtering")
    required = {"text", "label"}
    missing = required.difference(frame.columns)
    if missing:
        raise ValueError(f"Benchmark is missing columns: {sorted(missing)}")

    labels = frame["label"].astype(str).tolist()
    invalid = sorted(set(labels) - set(LABELS))
    if invalid:
        raise ValueError(
            f"Benchmark contains labels outside {LABELS}: {invalid}. "
            "Filter uncertain/ambiguous rows before evaluation."
        )

    predictions = predict_rows(frame, detector)
    policy_labels = [row["policy_label"] for row in predictions]
    classifier_labels = [row["classifier_label"] for row in predictions]
    risk_levels = [row["risk_level"] for row in predictions]
    probabilities = [
        [float(row["scores"][label]) for label in LABELS] for row in predictions
    ]
    evidence_counts: Counter[str] = Counter()
    for row in predictions:
        evidence_counts.update(row["evidence_codes"])

    y_true = np.asarray(labels, dtype=object)
    y_policy = np.asarray(policy_labels, dtype=object)
    y_classifier = np.asarray(classifier_labels, dtype=object)
    probability_matrix = np.asarray(probabilities, dtype=float)

    policy_metrics = compute_metrics(
        y_true, y_policy, probabilities=probability_matrix
    )
    classifier_metrics = compute_metrics(
        y_true, y_classifier, probabilities=probability_matrix
    )
    risk = _risk_summary(y_true, policy_labels, risk_levels)
    intervals = _intervals(
        y_true,
        y_policy,
        y_classifier,
        risk,
        bootstrap_replicates=bootstrap_replicates,
    )
    benchmark = _benchmark_summary(frame)
    benchmark["name"] = name
    benchmark.update(dict(metadata or {}))
    binary_spam = _binary_spam_summary(y_true, y_policy, y_classifier)
    limitations = [
        "This benchmark is not a random sample of all Indian SMS traffic.",
        "Do not tune thresholds on this benchmark if it is a final test set.",
        "External and Indian datasets may contain campaign/template duplication.",
        "Scores are uncalibrated; precision depends on real-world prevalence.",
        "Small slices and small smishing counts have wide confidence intervals.",
        "The detector is a screening aid, not a certainty engine.",
    ]
    if benchmark["label_counts"].get("smishing", 0) == 0:
        limitations.insert(
            1,
            "This benchmark has no smishing labels, so smishing recall, smishing "
            "precision and high-band smishing metrics are not estimable. Use the "
            "binary spam/ham view and per-class diagnostics instead.",
        )
    report: dict[str, Any] = {
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "benchmark": benchmark,
        "model": _model_summary(detector),
        "policy_metrics": policy_metrics,
        "classifier_metrics": classifier_metrics,
        "risk": risk,
        "confidence_intervals": intervals,
        "slices": _slice_report(
            frame,
            y_true,
            y_policy,
            y_classifier,
            probability_matrix,
            risk_levels,
            min_slice_rows=min_slice_rows,
            bootstrap_replicates=bootstrap_replicates,
        ),
        "prevalence_adjusted": _prevalence_adjusted(
            benchmark, policy_metrics, risk, target_prevalence
        ),
        "evidence_counts": dict(sorted(evidence_counts.items())),
        "limitations": limitations,
    }
    if binary_spam is not None:
        report["binary_spam_metrics"] = binary_spam
    return report


def render_markdown(report: Mapping[str, Any]) -> str:
    """Render an aggregate-only Markdown summary; never includes SMS bodies."""

    benchmark = report["benchmark"]
    policy = report["policy_metrics"]
    classifier = report["classifier_metrics"]
    risk = report["risk"]
    lines = [
        f"# Indian SMS Benchmark Evaluation — {benchmark.get('name', 'unnamed')}",
        "",
        f"Generated: {report.get('created_utc', 'unknown')}",
        f"Model: `{report.get('model', {}).get('model_version', 'unknown')}`",
        "",
        "## Benchmark",
        "",
        f"- Evaluated rows: **{benchmark.get('rows', 0):,}**",
        f"- Input rows: **{benchmark.get('input_rows', benchmark.get('rows', 0)):,}**",
        f"- Excluded uncertain rows: **{benchmark.get('excluded_uncertain_rows', 0):,}**",
        f"- Dropped empty rows: **{benchmark.get('dropped_empty_rows', 0):,}**",
        f"- Dropped leakage rows: **{benchmark.get('dropped_overlap_rows', 0):,}**",
        f"- Sample smishing prevalence: **{_pct(benchmark.get('sample_smishing_prevalence'))}**",
        "",
        "| Label | Rows |",
        "|---|---:|",
    ]
    for label in LABELS:
        lines.append(f"| `{label}` | {benchmark.get('label_counts', {}).get(label, 0):,} |")

    if benchmark.get("label_counts", {}).get("smishing", 0) == 0:
        lines.extend(
            [
                "",
                "> **No smishing labels in this benchmark.** Smishing-specific "
                "metrics are not estimable. The binary spam/ham view below is the "
                "interpretable result for this source.",
            ]
        )

    leakage = benchmark.get("leakage", {})
    lines.extend(
        [
            "",
            "### Leakage check",
            "",
            f"- Checked: **{leakage.get('checked', False)}**",
            f"- Overlap rows: **{leakage.get('overlap_rows', 0):,}**",
            f"- Overlap groups: **{leakage.get('overlap_groups', 0):,}**",
            f"- Overlap by split: `{leakage.get('overlap_by_split', {})}`",
            "",
            "## Headline policy metrics",
            "",
            "| Metric | Value | 95% interval |",
            "|---|---:|---:|",
            f"| Macro-F1 | {_num(policy.get('macro_f1'))} | {_ratio_interval(report['confidence_intervals'].get('policy', {}).get('macro_f1'))} |",
            f"| Smishing recall | {_pct(policy.get('smishing_recall'))} | {_interval(report['confidence_intervals'].get('policy', {}).get('smishing_recall'))} |",
            f"| Smishing precision | {_pct(policy.get('smishing_precision'))} | {_interval(report['confidence_intervals'].get('policy', {}).get('smishing_precision'))} |",
            f"| Ham false-positive rate | {_pct(policy.get('ham_false_positive_rate'))} | {_interval(report['confidence_intervals'].get('policy', {}).get('ham_false_positive_rate'))} |",
            f"| High-band smishing recall | {_pct(risk.get('high_smishing_recall'))} | {_interval(report['confidence_intervals'].get('risk', {}).get('high_smishing_recall'))} |",
            f"| High-band precision | {_pct(risk.get('high_smishing_precision'))} | {_interval(report['confidence_intervals'].get('risk', {}).get('high_smishing_precision'))} |",
            f"| Ham high-risk rate | {_pct(risk.get('ham_high_rate'))} | {_interval(report['confidence_intervals'].get('risk', {}).get('ham_high_rate'))} |",
            "",
            "## Classifier-only diagnostics",
            "",
            "| Metric | Value |",
            "|---|---:|",
            f"| Macro-F1 | {_num(classifier.get('macro_f1'))} |",
            f"| Smishing recall | {_pct(classifier.get('smishing_recall'))} |",
            f"| Smishing precision | {_pct(classifier.get('smishing_precision'))} |",
            f"| Ham false-positive rate | {_pct(classifier.get('ham_false_positive_rate'))} |",
        ]
    )

    binary_spam = report.get("binary_spam_metrics")
    if binary_spam:
        lines.extend(
            [
                "",
                "## Binary spam/ham view",
                "",
                "This source has no smishing labels. `any non-ham` treats either "
                "`spam` or `smishing` as flagged; `exact spam` requires the policy "
                "to say `spam` and therefore exposes smishing overclassification.",
                "",
                "| View | Precision | Recall | F1 | Ham FP rate |",
                "|---|---:|---:|---:|---:|",
            ]
        )
        for key, label in (
            ("policy_any_non_ham", "Policy: any non-ham"),
            ("policy_exact_spam", "Policy: exact spam"),
            ("classifier_any_non_ham", "Classifier: any non-ham"),
            ("classifier_exact_spam", "Classifier: exact spam"),
        ):
            metrics = binary_spam.get(key, {})
            lines.append(
                f"| {label} | {_pct(metrics.get('precision'))} | "
                f"{_pct(metrics.get('recall'))} | {_num(metrics.get('f1'))} | "
                f"{_pct(metrics.get('ham_false_positive_rate'))} |"
            )

    adjusted = report.get("prevalence_adjusted")
    if adjusted:
        lines.extend(
            [
                "",
                "## Prevalence-adjusted precision",
                "",
                f"- Target smishing prevalence: **{_pct(adjusted.get('target_smishing_prevalence'))}**",
                f"- Policy smishing precision: **{_pct(adjusted.get('policy_smishing_precision'))}**",
                f"- High-band precision: **{_pct(adjusted.get('high_smishing_precision'))}**",
                "",
                "Recall is prevalence-independent; precision is not. Use this table when the benchmark was enriched for scams.",
            ]
        )

    slices = report.get("slices", {})
    if slices:
        lines.extend(["", "## Slices", ""])
        for dimension, values in slices.items():
            lines.extend(
                [
                    f"### {dimension}",
                    "",
                    "| Slice | Rows | Smishing recall | High-band recall | Ham high-risk |",
                    "|---|---:|---:|---:|---:|",
                ]
            )
            for value, bundle in values.items():
                policy_bundle = bundle.get("policy", {})
                risk_bundle = bundle.get("risk", {})
                lines.append(
                    f"| `{value}` | {bundle.get('rows', 0)} | "
                    f"{_pct_support(policy_bundle.get('smishing_recall'), policy_bundle.get('smishing_support', 0))} | "
                    f"{_pct_support(risk_bundle.get('high_smishing_recall'), risk_bundle.get('smishing_support', 0))} | "
                    f"{_pct_support(risk_bundle.get('ham_high_rate'), risk_bundle.get('ham_support', 0))} |"
                )
            lines.append("")

    lines.extend(["## Limitations", ""])
    for limitation in report.get("limitations", []):
        lines.append(f"- {limitation}")
    lines.append("")
    return "\n".join(lines)


def _benchmark_summary(frame: pd.DataFrame) -> dict[str, Any]:
    label_counts = Counter(frame["label"].astype(str))
    rows = len(frame)
    group_values = (
        frame["group_id"].astype(str).str.strip()
        if "group_id" in frame.columns
        else pd.Series([""] * rows)
    )
    non_empty_groups = group_values[group_values.str.len() > 0]
    return {
        "rows": int(rows),
        "label_counts": {label: int(label_counts.get(label, 0)) for label in LABELS},
        "sample_smishing_prevalence": float(
            label_counts.get("smishing", 0) / rows if rows else 0.0
        ),
        "unique_groups": (
            int(non_empty_groups.nunique()) if not non_empty_groups.empty else None
        ),
        "language_counts": _value_counts(frame, "language"),
        "sender_type_counts": _value_counts(frame, "sender_type"),
        "scam_type_counts": _value_counts(frame, "scam_type"),
        "collection_month_counts": _value_counts(frame, "collection_month"),
        "source_counts": _value_counts(frame, "source"),
    }


def _model_summary(detector: Any) -> dict[str, Any]:
    metadata = getattr(detector, "metadata", {}) or {}
    policy = getattr(detector, "policy", None)
    return {
        "model_version": getattr(detector, "model_version", "unknown"),
        "policy_version": getattr(policy, "policy_version", "unknown"),
        "thresholds": {
            "high": getattr(policy, "high_threshold", None),
            "suspicious": getattr(policy, "suspicious_threshold", None),
            "evidence_free_high": getattr(policy, "evidence_free_high_threshold", None),
        },
        "selected_experiment": metadata.get("selected_experiment"),
        "feature_count": metadata.get("feature_count"),
    }


def _binary_spam_summary(
    y_true: np.ndarray,
    y_policy: np.ndarray,
    y_classifier: np.ndarray,
) -> dict[str, Any] | None:
    """Binary spam/ham view for sources that do not label smishing.

    ``any_non_ham`` treats both spam and smishing predictions as flagged. The
    ``exact_spam`` view is stricter and exposes smishing overclassification.
    """

    spam_support = int(sum(1 for label in y_true if label == "spam"))
    ham_support = int(sum(1 for label in y_true if label == "ham"))
    smishing_support = int(sum(1 for label in y_true if label == "smishing"))
    if spam_support == 0 or smishing_support > 0:
        return None

    def view(predictions: np.ndarray, predicate) -> dict[str, Any]:
        tp = fp = fn = tn = 0
        for truth, prediction in zip(y_true, predictions):
            actual_spam = truth == "spam"
            actual_ham = truth == "ham"
            predicted_positive = bool(predicate(str(prediction)))
            if actual_spam and predicted_positive:
                tp += 1
            elif actual_ham and predicted_positive:
                fp += 1
            elif actual_spam:
                fn += 1
            elif actual_ham:
                tn += 1
        precision = _ratio(tp, tp + fp)
        recall = _ratio(tp, tp + fn)
        f1 = (
            2.0 * precision * recall / (precision + recall)
            if precision + recall
            else 0.0
        )
        return {
            "true_positive": tp,
            "false_positive": fp,
            "false_negative": fn,
            "true_negative": tn,
            "predicted_positive": tp + fp,
            "precision": precision,
            "recall": recall,
            "f1": float(f1),
            "ham_false_positive_rate": _ratio(fp, fp + tn),
        }

    any_non_ham = lambda label: label != "ham"
    exact_spam = lambda label: label == "spam"
    return {
        "support": spam_support,
        "ham_support": ham_support,
        "note": (
            "No smishing labels exist in this source. 'any_non_ham' counts either "
            "spam or smishing as flagged; 'exact_spam' penalises smishing "
            "overclassification."
        ),
        "policy_any_non_ham": view(y_policy, any_non_ham),
        "policy_exact_spam": view(y_policy, exact_spam),
        "classifier_any_non_ham": view(y_classifier, any_non_ham),
        "classifier_exact_spam": view(y_classifier, exact_spam),
    }


def _risk_summary(
    y_true: np.ndarray, policy_labels: Sequence[str], risk_levels: Sequence[str]
) -> dict[str, Any]:
    smishing_support = int(sum(1 for label in y_true if label == "smishing"))
    ham_support = int(sum(1 for label in y_true if label == "ham"))
    non_smishing_support = int(len(y_true) - smishing_support)
    high_total = int(sum(1 for level in risk_levels if level == "high"))
    high_smishing = int(
        sum(
            1
            for truth, level in zip(y_true, risk_levels)
            if truth == "smishing" and level == "high"
        )
    )
    flagged_total = int(sum(1 for level in risk_levels if level != "low"))
    ham_high = int(
        sum(
            1
            for truth, level in zip(y_true, risk_levels)
            if truth == "ham" and level == "high"
        )
    )
    ham_flagged = int(
        sum(
            1
            for truth, level in zip(y_true, risk_levels)
            if truth == "ham" and level != "low"
        )
    )
    smishing_flagged = int(
        sum(
            1
            for truth, level in zip(y_true, risk_levels)
            if truth == "smishing" and level != "low"
        )
    )
    return {
        "rows": int(len(y_true)),
        "smishing_support": smishing_support,
        "ham_support": ham_support,
        "non_smishing_support": non_smishing_support,
        "high_total": high_total,
        "high_smishing_count": high_smishing,
        "flagged_total": flagged_total,
        "ham_high_count": ham_high,
        "ham_flagged_count": ham_flagged,
        "smishing_flagged_count": smishing_flagged,
        "high_smishing_recall": _ratio(high_smishing, smishing_support),
        "high_smishing_precision": _ratio(high_smishing, high_total),
        "smishing_flagged_rate": _ratio(smishing_flagged, smishing_support),
        "ham_high_rate": _ratio(ham_high, ham_support),
        "ham_flagged_rate": _ratio(ham_flagged, ham_support),
        "flagged_rate": _ratio(flagged_total, len(y_true)),
        "high_rate": _ratio(high_total, len(y_true)),
        "risk_levels": _counts(risk_levels),
        "final_labels": _counts(policy_labels),
    }


def _intervals(
    y_true: np.ndarray,
    y_policy: np.ndarray,
    y_classifier: np.ndarray,
    risk: Mapping[str, Any],
    *,
    bootstrap_replicates: int,
) -> dict[str, Any]:
    policy_tp, policy_fp, policy_tn, policy_fn = _binary_counts(y_true, y_policy)
    classifier_tp, classifier_fp, classifier_tn, classifier_fn = _binary_counts(
        y_true, y_classifier
    )
    smishing_support = risk["smishing_support"]
    ham_support = risk["ham_support"]
    non_smishing_support = risk["non_smishing_support"]
    policy_ham_fp = int(
        sum(1 for truth, pred in zip(y_true, y_policy) if truth == "ham" and pred != "ham")
    )
    classifier_ham_fp = int(
        sum(
            1
            for truth, pred in zip(y_true, y_classifier)
            if truth == "ham" and pred != "ham"
        )
    )
    high_non_smishing = max(0, int(risk["high_total"]) - int(risk["high_smishing_count"]))
    return {
        "policy": {
            "smishing_recall": wilson_interval(policy_tp, smishing_support),
            "smishing_precision": wilson_interval(
                policy_tp, policy_tp + policy_fp
            ),
            "ham_false_positive_rate": wilson_interval(policy_ham_fp, ham_support),
            "macro_f1": bootstrap_macro_f1(
                y_true, y_policy, replicates=bootstrap_replicates
            ),
        },
        "classifier": {
            "smishing_recall": wilson_interval(classifier_tp, smishing_support),
            "smishing_precision": wilson_interval(
                classifier_tp, classifier_tp + classifier_fp
            ),
            "ham_false_positive_rate": wilson_interval(
                classifier_ham_fp, ham_support
            ),
            "macro_f1": bootstrap_macro_f1(
                y_true, y_classifier, replicates=bootstrap_replicates
            ),
        },
        "risk": {
            "high_smishing_recall": wilson_interval(
                int(risk["high_smishing_count"]), smishing_support
            ),
            "high_smishing_precision": wilson_interval(
                int(risk["high_smishing_count"]), int(risk["high_total"])
            ),
            "ham_high_rate": wilson_interval(int(risk["ham_high_count"]), ham_support),
            "ham_flagged_rate": wilson_interval(
                int(risk["ham_flagged_count"]), ham_support
            ),
            "smishing_flagged_rate": wilson_interval(
                int(risk["smishing_flagged_count"]), smishing_support
            ),
            "high_non_smishing_rate": wilson_interval(
                high_non_smishing, non_smishing_support
            ),
        },
    }


def _slice_report(
    frame: pd.DataFrame,
    y_true: np.ndarray,
    y_policy: np.ndarray,
    y_classifier: np.ndarray,
    probabilities: np.ndarray,
    risk_levels: Sequence[str],
    *,
    min_slice_rows: int,
    bootstrap_replicates: int,
) -> dict[str, Any]:
    if min_slice_rows < 1:
        min_slice_rows = 1
    result: dict[str, Any] = {}
    for column in SLICE_COLUMNS:
        if column not in frame.columns:
            continue
        groups = frame.groupby(column, dropna=False, sort=True).indices
        entries: dict[str, Any] = {}
        for value, positions in groups.items():
            positions = np.asarray(positions)
            if len(positions) < min_slice_rows:
                continue
            key = "unknown" if pd.isna(value) else str(value)
            entries[key] = _metrics_bundle(
                y_true[positions],
                y_policy[positions],
                y_classifier[positions],
                probabilities[positions],
                [risk_levels[index] for index in positions],
                bootstrap_replicates=bootstrap_replicates,
            )
        if entries:
            result[column] = entries
    return result


def _metrics_bundle(
    y_true: np.ndarray,
    y_policy: np.ndarray,
    y_classifier: np.ndarray,
    probabilities: np.ndarray,
    risk_levels: Sequence[str],
    *,
    bootstrap_replicates: int,
) -> dict[str, Any]:
    policy = compute_metrics(y_true, y_policy, probabilities=probabilities)
    classifier = compute_metrics(
        y_true, y_classifier, probabilities=probabilities
    )
    risk = _risk_summary(y_true, y_policy.tolist(), risk_levels)
    return {
        "rows": int(len(y_true)),
        "label_counts": {label: int(sum(1 for value in y_true if value == label)) for label in LABELS},
        "policy": policy,
        "classifier": classifier,
        "risk": risk,
        "confidence_intervals": _intervals(
            y_true,
            y_policy,
            y_classifier,
            risk,
            bootstrap_replicates=bootstrap_replicates,
        ),
    }


def _prevalence_adjusted(
    benchmark: Mapping[str, Any],
    policy: Mapping[str, Any],
    risk: Mapping[str, Any],
    target_prevalence: float | None,
) -> dict[str, Any] | None:
    if target_prevalence is None:
        return None
    if not 0.0 <= target_prevalence <= 1.0:
        raise ValueError("target_prevalence must be between 0 and 1")
    non_smishing_support = int(risk["non_smishing_support"])
    high_fpr = (
        max(0, int(risk["high_total"]) - int(risk["high_smishing_count"]))
        / non_smishing_support
        if non_smishing_support
        else 0.0
    )
    policy_fpr = float(policy.get("smishing_false_positive_rate", 0.0))
    return {
        "target_smishing_prevalence": float(target_prevalence),
        "sample_smishing_prevalence": float(
            benchmark.get("sample_smishing_prevalence", 0.0)
        ),
        "policy_smishing_precision": _ppv(
            float(policy.get("smishing_recall", 0.0)),
            policy_fpr,
            target_prevalence,
        ),
        "high_smishing_precision": _ppv(
            float(risk.get("high_smishing_recall", 0.0)),
            high_fpr,
            target_prevalence,
        ),
        "note": (
            "Recall is prevalence-independent; precision/PPV is adjusted to the "
            "requested target prevalence. Do not use raw benchmark precision if "
            "the benchmark over-sampled scams."
        ),
    }


def _ppv(recall: float, false_positive_rate: float, prevalence: float) -> float | None:
    denominator = recall * prevalence + false_positive_rate * (1.0 - prevalence)
    if denominator <= 0.0:
        return None
    return float((recall * prevalence) / denominator)


def _binary_counts(
    y_true: np.ndarray, y_pred: np.ndarray
) -> tuple[int, int, int, int]:
    tp = fp = tn = fn = 0
    for truth, pred in zip(y_true, y_pred):
        if truth == "smishing" and pred == "smishing":
            tp += 1
        elif truth != "smishing" and pred == "smishing":
            fp += 1
        elif truth != "smishing" and pred != "smishing":
            tn += 1
        else:
            fn += 1
    return tp, fp, tn, fn


def _ratio(numerator: int, denominator: int) -> float:
    return float(numerator / denominator) if denominator else 0.0


def _value_counts(frame: pd.DataFrame, column: str) -> dict[str, int]:
    if column not in frame.columns:
        return {}
    values = frame[column].fillna("unknown").astype(str).str.strip()
    return {
        str(key): int(value)
        for key, value in values.value_counts().sort_index().items()
    }


def _counts(values: Sequence[str]) -> dict[str, int]:
    return {
        str(key): int(value)
        for key, value in sorted(Counter(values).items())
    }


def _coerce_known_sender(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, (bool, np.bool_)):
        return bool(value)
    if isinstance(value, float) and np.isnan(value):
        return False
    return str(value).strip().lower() in {"1", "true", "yes", "y"}


def _pct(value: Any) -> str:
    if value is None:
        return "n/a"
    return f"{100.0 * float(value):.1f}%"


def _pct_support(value: Any, support: Any) -> str:
    if not support:
        return "n/a"
    return _pct(value)


def _num(value: Any) -> str:
    if value is None:
        return "n/a"
    return f"{float(value):.3f}"


def _interval(value: Mapping[str, Any] | None) -> str:
    if not value or value.get("low") is None or value.get("high") is None:
        return "n/a"
    return f"{100.0 * float(value['low']):.1f}–{100.0 * float(value['high']):.1f}%"


def _ratio_interval(value: Mapping[str, Any] | None) -> str:
    if not value or value.get("low") is None or value.get("high") is None:
        return "n/a"
    return f"{float(value['low']):.3f}–{float(value['high']):.3f}"
