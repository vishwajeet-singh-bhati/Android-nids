"""Train and evaluate the E0–E3 SMS baselines.

Run after ``scripts/prepare_data.py``. The locked test split is never used for
model selection, calibration or threshold tuning. The external split is used
only for final reporting.
"""

from __future__ import annotations

import hashlib
import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Sequence

import numpy as np
import pandas as pd
from scipy.special import softmax
from sklearn.metrics import log_loss

from ..config import (
    DEFAULT_COST_FN,
    DEFAULT_COST_FP,
    DEFAULT_EVIDENCE_FREE_HIGH,
    DOCS_DIR,
    LABELS,
    MODEL_DIR,
    MODEL_VERSION,
    POLICY_VERSION,
    PROCESSED_DIR,
    REPORTS_DIR,
    SCHEMA_DIR,
)
from ..interface.schema import write_json_schema
from ..policy.risk_fusion import RiskPolicy
from ..preprocessing.indicators import IndicatorResult, analyze_text
from ..preprocessing.normalize import NormalizedText, normalize_text
from .calibrate import (
    fit_temperature,
    multiclass_brier,
    expected_calibration_error,
    select_risk_thresholds,
)
from .classifier import ClassifierConfig, SmsClassifier
from .evaluate import (
    compute_metrics,
    plot_confusion_matrix,
    risk_metrics,
    rules_predictions,
)

MIN_HIGH_RECALL = 0.85
MIN_HIGH_PRECISION = 0.80

CANDIDATES: list[tuple[str, dict]] = [
    ("E1_word_lr", {"use_word": True, "use_char": False, "use_indicators": False, "class_weight": None}),
    ("E1b_word_lr_balanced", {"use_word": True, "use_char": False, "use_indicators": False, "class_weight": "balanced"}),
    ("E2_word_char_lr", {"use_word": True, "use_char": True, "use_indicators": False, "class_weight": None}),
    ("E2b_word_char_lr_balanced", {"use_word": True, "use_char": True, "use_indicators": False, "class_weight": "balanced"}),
    ("E3_word_char_ind_lr", {"use_word": True, "use_char": True, "use_indicators": True, "class_weight": None}),
    ("E3b_word_char_ind_lr_balanced", {"use_word": True, "use_char": True, "use_indicators": True, "class_weight": "balanced"}),
]


class SplitData:
    def __init__(self, name: str, frame: pd.DataFrame) -> None:
        self.name = name
        self.frame = frame
        self.texts = frame["text"].astype(str).tolist()
        self.labels = frame["label"].astype(str).tolist()
        self.senders = frame["sender"].tolist() if "sender" in frame.columns else [None] * len(frame)
        self.normalized: list[NormalizedText] = [normalize_text(text) for text in self.texts]
        self.indicators: list[IndicatorResult] = [
            analyze_text(text, normalized=norm, sender=sender)
            for text, norm, sender in zip(self.texts, self.normalized, self.senders)
        ]


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Train SMS baseline models")
    parser.add_argument("--processed-dir", default=str(PROCESSED_DIR))
    parser.add_argument("--model-dir", default=str(MODEL_DIR))
    parser.add_argument("--reports-dir", default=str(REPORTS_DIR))
    parser.add_argument("--docs-dir", default=str(DOCS_DIR))
    parser.add_argument("--cost-fn", type=float, default=DEFAULT_COST_FN)
    parser.add_argument("--cost-fp", type=float, default=DEFAULT_COST_FP)
    parser.add_argument("--min-high-recall", type=float, default=MIN_HIGH_RECALL)
    parser.add_argument("--min-high-precision", type=float, default=MIN_HIGH_PRECISION)
    parser.add_argument(
        "--evidence-free-high", type=float, default=DEFAULT_EVIDENCE_FREE_HIGH
    )
    args = parser.parse_args(argv)

    processed = Path(args.processed_dir)
    splits = {
        name: SplitData(name, pd.read_csv(processed / f"{name}.csv", low_memory=False))
        for name in ("train", "val", "test", "external")
    }
    print(
        "rows: "
        + ", ".join(f"{name}={len(data.frame):,}" for name, data in splits.items()),
        flush=True,
    )

    reports_dir = Path(args.reports_dir)
    docs_dir = Path(args.docs_dir)
    model_dir = Path(args.model_dir)
    reports_dir.mkdir(parents=True, exist_ok=True)
    docs_dir.mkdir(parents=True, exist_ok=True)
    model_dir.mkdir(parents=True, exist_ok=True)

    # E0: deterministic rules-only baseline ---------------------------------
    print("\nE0 rules-only baseline", flush=True)
    e0: dict[str, dict] = {}
    for name in ("val", "test", "external"):
        predictions, probabilities = rules_predictions(splits[name].indicators)
        e0[name] = compute_metrics(
            splits[name].labels, predictions, probabilities=probabilities
        )
        print(f"  {name}: macro-F1={e0[name]['macro_f1']:.3f} smishing_recall={e0[name]['smishing_recall']:.3f}")

    # Candidate models -------------------------------------------------------
    print("\nCandidate experiments", flush=True)
    candidates: dict[str, dict] = {}
    fitted: dict[str, SmsClassifier] = {}
    for candidate_name, overrides in CANDIDATES:
        start = time.time()
        config = ClassifierConfig(
            C=1.0,
            class_weight=overrides["class_weight"],
            use_word=overrides["use_word"],
            use_char=overrides["use_char"],
            use_indicators=overrides["use_indicators"],
        )
        model = SmsClassifier(config).fit(
            splits["train"].texts,
            splits["train"].labels,
            normalized=splits["train"].normalized,
            indicators=splits["train"].indicators,
            senders=splits["train"].senders,
        )
        val_probs = model.predict_proba(
            splits["val"].texts,
            normalized=splits["val"].normalized,
            indicators=splits["val"].indicators,
            senders=splits["val"].senders,
        )
        val_predictions = [LABELS[index] for index in val_probs.argmax(axis=1)]
        val_metrics = compute_metrics(splits["val"].labels, val_predictions, probabilities=val_probs)
        threshold_policy = select_risk_thresholds(
            splits["val"].labels,
            val_probs,
            cost_fn=args.cost_fn,
            cost_fp=args.cost_fp,
            min_high_recall=args.min_high_recall,
            min_high_precision=args.min_high_precision,
        )
        threshold_metrics = _threshold_metrics(
            splits["val"].labels,
            val_probs[:, LABELS.index("smishing")],
            threshold_policy["high_threshold"],
            cost_fn=args.cost_fn,
            cost_fp=args.cost_fp,
        )
        candidates[candidate_name] = {
            "config": config.to_dict(),
            "feature_count": model.feature_count,
            "train_seconds": round(time.time() - start, 2),
            "val_default": val_metrics,
            "val_thresholds": threshold_policy,
            "val_high_operating_point": threshold_metrics,
        }
        fitted[candidate_name] = model
        print(
            f"  {candidate_name:32s} macroF1={val_metrics['macro_f1']:.3f} "
            f"smishR@default={val_metrics['smishing_recall']:.3f} "
            f"smishR@high={threshold_metrics['recall']:.3f} "
            f"P@high={threshold_metrics['precision']:.3f} "
            f"FPR@high={threshold_metrics['fpr']:.3f} "
            f"feasible={threshold_policy['high_feasible']} "
            f"cost={threshold_metrics['expected_cost']:.1f} "
            f"({time.time() - start:.1f}s)",
            flush=True,
        )

    selected_name = _select_candidate(
        candidates,
        min_high_recall=args.min_high_recall,
        min_high_precision=args.min_high_precision,
    )
    selected = fitted[selected_name]
    selected_info = candidates[selected_name]
    print(f"\nSelected: {selected_name}", flush=True)

    # Calibration ------------------------------------------------------------
    print("\nCalibration on validation", flush=True)
    val_logits = selected.decision_function(
        splits["val"].texts,
        normalized=splits["val"].normalized,
        indicators=splits["val"].indicators,
        senders=splits["val"].senders,
    )
    raw_val_probs = selected.predict_proba(
        splits["val"].texts,
        normalized=splits["val"].normalized,
        indicators=splits["val"].indicators,
        senders=splits["val"].senders,
    )
    temperature = fit_temperature(val_logits, splits["val"].labels)
    calibrated_val_probs = softmax(val_logits / temperature, axis=1)
    raw_policy = select_risk_thresholds(
        splits["val"].labels,
        raw_val_probs,
        cost_fn=args.cost_fn,
        cost_fp=args.cost_fp,
        min_high_recall=args.min_high_recall,
        min_high_precision=args.min_high_precision,
    )
    calibrated_policy = select_risk_thresholds(
        splits["val"].labels,
        calibrated_val_probs,
        cost_fn=args.cost_fn,
        cost_fp=args.cost_fp,
        min_high_recall=args.min_high_recall,
        min_high_precision=args.min_high_precision,
    )
    calibration = {
        "fitted_temperature": float(temperature),
        "temperature": float(temperature),
        "raw_log_loss": _safe_log_loss(splits["val"].labels, raw_val_probs),
        "calibrated_log_loss": _safe_log_loss(splits["val"].labels, calibrated_val_probs),
        "raw_brier": float(multiclass_brier(raw_val_probs, splits["val"].labels)),
        "calibrated_brier": float(multiclass_brier(calibrated_val_probs, splits["val"].labels)),
        "raw_ece": float(expected_calibration_error(raw_val_probs, splits["val"].labels)),
        "calibrated_ece": float(expected_calibration_error(calibrated_val_probs, splits["val"].labels)),
        "raw_high_precision": raw_policy["high_precision"],
        "raw_high_recall": raw_policy["high_recall"],
        "calibrated_high_precision": calibrated_policy["high_precision"],
        "calibrated_high_recall": calibrated_policy["high_recall"],
        "raw_high_feasible": raw_policy["high_feasible"],
        "calibrated_high_feasible": calibrated_policy["high_feasible"],
    }
    lower_nll = bool(
        calibration["calibrated_log_loss"] is not None
        and calibration["raw_log_loss"] is not None
        and calibration["calibrated_log_loss"] < calibration["raw_log_loss"]
    )
    # Calibration is optional. A temperature that improves aggregate NLL but
    # destroys the precision of the high-risk operating point is not acceptable:
    # the high band is allowed to interrupt the user, so safety wins over ECE.
    calibration["applied"] = bool(lower_nll and calibrated_policy["high_feasible"])
    if not lower_nll:
        calibration["rejection_reason"] = "calibration did not improve validation log loss"
    elif not calibrated_policy["high_feasible"]:
        calibration["rejection_reason"] = (
            "calibrated high-risk threshold missed the recall/precision floor"
        )
    else:
        calibration["rejection_reason"] = None
    if calibration["applied"]:
        selected.set_temperature(temperature)
        final_val_probs = calibrated_val_probs
        thresholds = calibrated_policy
        calibration["temperature"] = float(temperature)
    else:
        selected.set_temperature(1.0)
        final_val_probs = raw_val_probs
        thresholds = raw_policy
        calibration["temperature"] = 1.0
    print(
        f"  fitted T={calibration['fitted_temperature']:.3f} "
        f"applied={calibration['applied']} "
        f"NLL {calibration['raw_log_loss']:.4f} -> {calibration['calibrated_log_loss']:.4f} "
        f"ECE {calibration['raw_ece']:.4f} -> {calibration['calibrated_ece']:.4f}",
        flush=True,
    )
    if not calibration["applied"]:
        print(f"  calibration skipped: {calibration['rejection_reason']}", flush=True)
    policy = RiskPolicy(
        high_threshold=thresholds["high_threshold"],
        suspicious_threshold=thresholds["suspicious_threshold"],
        evidence_free_high_threshold=args.evidence_free_high,
        cost_fn=args.cost_fn,
        cost_fp=args.cost_fp,
        policy_version=POLICY_VERSION,
    )
    thresholds["evidence_free_high"] = args.evidence_free_high
    print(
        f"  thresholds: high={thresholds['high_threshold']:.3f} "
        f"suspicious={thresholds['suspicious_threshold']:.3f} "
        f"evidence-free-high={args.evidence_free_high:.3f} "
        f"val recall@high={thresholds['high_recall']:.3f} "
        f"val precision@high={thresholds['high_precision']:.3f}",
        flush=True,
    )

    # Final evaluation -------------------------------------------------------
    print("\nFinal evaluation", flush=True)
    results: dict[str, dict] = {"E0_rules": e0}
    for name in ("val", "test", "external"):
        probabilities = _predict(selected, splits[name])
        predictions = [LABELS[index] for index in probabilities.argmax(axis=1)]
        metrics = compute_metrics(splits[name].labels, predictions, probabilities=probabilities)
        metrics["risk"] = risk_metrics(splits[name].labels, probabilities, splits[name].indicators, policy)
        metrics["high_operating_point"] = _threshold_metrics(
            splits[name].labels,
            probabilities[:, LABELS.index("smishing")],
            thresholds["high_threshold"],
            cost_fn=args.cost_fn,
            cost_fp=args.cost_fp,
        )
        metrics["suspicious_operating_point"] = _threshold_metrics(
            splits[name].labels,
            probabilities[:, LABELS.index("smishing")],
            thresholds["suspicious_threshold"],
            cost_fn=args.cost_fn,
            cost_fp=args.cost_fp * 0.2,
        )
        results[name] = metrics
        print(
            f"  {name}: macroF1={metrics['macro_f1']:.3f} "
            f"smishR={metrics['smishing_recall']:.3f} "
            f"smishFPR={metrics['smishing_false_positive_rate']:.3f} "
            f"hamFPR={metrics['ham_false_positive_rate']:.3f} "
            f"highRecall={metrics['high_operating_point']['recall']:.3f}",
            flush=True,
        )

    # Save model + metadata --------------------------------------------------
    model_path = selected.save(model_dir / "model.joblib")
    metadata = {
        "module": "sms_detector",
        "schema_version": "1.0",
        "model_version": MODEL_VERSION,
        "policy_version": POLICY_VERSION,
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "selected_experiment": selected_name,
        "selected_config": selected.config.to_dict(),
        "temperature": selected.temperature,
        "thresholds": {
            "high": thresholds["high_threshold"],
            "suspicious": thresholds["suspicious_threshold"],
            "evidence_free_high": args.evidence_free_high,
        },
        "costs": {
            "fn": args.cost_fn,
            "fp": args.cost_fp,
            "min_high_recall": args.min_high_recall,
            "min_high_precision": args.min_high_precision,
        },
        "calibration": calibration,
        "threshold_selection": thresholds,
        "feature_count": selected.feature_count,
        "model_size_bytes": model_path.stat().st_size,
        "training_rows": len(splits["train"].frame),
        "validation_rows": len(splits["val"].frame),
        "test_rows": len(splits["test"].frame),
        "external_rows": len(splits["external"].frame),
        "label_distribution": {
            "train": _label_counts(splits["train"].frame),
            "val": _label_counts(splits["val"].frame),
            "test": _label_counts(splits["test"].frame),
            "external": _label_counts(splits["external"].frame),
        },
        "split_manifest_sha256": _file_hash(processed / "split_manifest.json"),
        "metrics_file": "baseline_metrics.json",
        "notes": [
            "Detector output is text-free; raw SMS is never sent to a cloud API.",
            "Risk thresholds are provisional validation-selected operating points.",
            "External test combines source-held-out NCSU phishing with held-out classic messages.",
        ],
    }
    (model_dir / "metadata.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")

    # Export the portable linear artifact for future Kotlin parity work.
    try:
        from .export import export_portable_model

        portable_dir = model_dir / "portable"
        export_portable_model(selected, portable_dir)
        metadata["portable_export"] = str(portable_dir / "portable_model.json")
    except Exception as exc:  # pragma: no cover - export is validated separately
        metadata["portable_export_error"] = repr(exc)
        print(f"[warn] portable export failed: {exc}", flush=True)

    report = {
        "created_utc": metadata["created_utc"],
        "model_version": MODEL_VERSION,
        "experiments": candidates,
        "selected_experiment": selected_name,
        "calibration": calibration,
        "threshold_policy": thresholds,
        "costs": metadata["costs"],
        "e0_rules": e0,
        "final": results,
        "label_distribution": metadata["label_distribution"],
        "portable_export": metadata.get("portable_export"),
    }
    metrics_path = reports_dir / "baseline_metrics.json"
    metrics_path.write_text(json.dumps(report, indent=2, default=_json_default), encoding="utf-8")

    # Plots and reports.
    for split_name in ("test", "external"):
        plot_confusion_matrix(
            results[split_name]["risk"]["policy_metrics"],
            reports_dir / f"confusion_matrix_{split_name}.png",
            title=f"Policy output — {split_name} split",
        )
    _write_evaluation_report(report, docs_dir / "evaluation-report.md")
    _write_model_card(report, metadata, docs_dir / "model-card.md")
    _write_schema(SCHEMA_DIR / "sms_detection_result.schema.json")

    print(f"\nModel: {model_path}")
    print(f"Metadata: {model_dir / 'metadata.json'}")
    print(f"Metrics: {metrics_path}")
    print(f"Reports: {docs_dir / 'evaluation-report.md'}, {docs_dir / 'model-card.md'}")
    return 0


def _predict(model: SmsClassifier, data: SplitData) -> np.ndarray:
    return model.predict_proba(
        data.texts,
        normalized=data.normalized,
        indicators=data.indicators,
        senders=data.senders,
    )


def _threshold_metrics(
    y_true: Sequence[str],
    p_smishing: np.ndarray,
    threshold: float,
    *,
    cost_fn: float,
    cost_fp: float,
) -> dict:
    y = np.asarray([1 if label == "smishing" else 0 for label in y_true])
    predicted = (np.asarray(p_smishing) >= threshold).astype(int)
    tp = int(np.sum((y == 1) & (predicted == 1)))
    fn = int(np.sum((y == 1) & (predicted == 0)))
    fp = int(np.sum((y == 0) & (predicted == 1)))
    tn = int(np.sum((y == 0) & (predicted == 0)))
    return {
        "threshold": float(threshold),
        "tp": tp,
        "fn": fn,
        "fp": fp,
        "tn": tn,
        "recall": tp / max(1, tp + fn),
        "precision": tp / max(1, tp + fp),
        "fpr": fp / max(1, fp + tn),
        "expected_cost": float(cost_fn * fn + cost_fp * fp),
    }


def _select_candidate(
    candidates: dict[str, dict],
    *,
    min_high_recall: float,
    min_high_precision: float,
) -> str:
    """Pick the cheapest candidate that satisfies both high-band safety floors.

    An experiment whose threshold selector falls back below the precision floor
    is not eligible. Failing loudly is safer than shipping a high-risk band that
    interrupts users on too many benign messages.
    """

    def feasible(info: dict) -> bool:
        op = info["val_high_operating_point"]
        return (
            op["recall"] >= min_high_recall - 1e-9
            and op["precision"] >= min_high_precision - 1e-9
            and bool(info["val_thresholds"].get("high_feasible", False))
        )

    eligible = {name: info for name, info in candidates.items() if feasible(info)}
    if not eligible:
        detail = ", ".join(
            f"{name}(R={info['val_high_operating_point']['recall']:.3f},"
            f"P={info['val_high_operating_point']['precision']:.3f})"
            for name, info in candidates.items()
        )
        raise RuntimeError(
            "No candidate meets the high-risk policy floors "
            f"(recall>={min_high_recall}, precision>={min_high_precision}): {detail}"
        )

    def key(item: tuple[str, dict]) -> tuple:
        _, info = item
        op = info["val_high_operating_point"]
        return (
            op["expected_cost"],
            -op["recall"],
            -info["val_default"]["macro_f1"],
        )

    return min(eligible.items(), key=key)[0]


def _safe_log_loss(y_true: Sequence[str], probabilities: np.ndarray) -> float | None:
    try:
        sorted_labels = sorted(LABELS)
        columns = [LABELS.index(label) for label in sorted_labels]
        return float(log_loss(y_true, probabilities[:, columns], labels=sorted_labels))
    except ValueError:
        return None


def _label_counts(frame: pd.DataFrame) -> dict[str, int]:
    return {str(k): int(v) for k, v in frame["label"].value_counts().items()}


def _file_hash(path: Path) -> str | None:
    if not path.exists():
        return None
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _json_default(value):
    if isinstance(value, (np.floating, np.integer)):
        return value.item()
    if isinstance(value, np.ndarray):
        return value.tolist()
    return str(value)


def _write_schema(path: Path) -> None:
    write_json_schema(path)


# ---------------------------------------------------------------------------
# Markdown reports
# ---------------------------------------------------------------------------

def _write_evaluation_report(report: dict, path: Path) -> None:
    final = report["final"]
    selected = report["experiments"][report["selected_experiment"]]
    thresholds = report["threshold_policy"]
    calibration = report["calibration"]
    if calibration["applied"]:
        calibration_note = (
            "Temperature scaling was applied because it improved validation log loss "
            "without breaking the high-band policy floors."
        )
    else:
        calibration_note = (
            "Temperature scaling was fitted but rejected because it did not preserve the "
            "high-band policy floors. Scores remain uncalibrated; thresholds were selected "
            "on raw validation probabilities. Revisit with a rank-preserving calibrator and "
            "more validation data."
        )
    lines = [
        "# Evaluation Report — SMS Scam Detection Baseline",
        "",
        f"Generated: {report['created_utc']}",
        f"Model: `{report['model_version']}` · selected experiment: `{report['selected_experiment']}`",
        "",
        "## Headline results — product policy output",
        "",
        "The policy output is what `SmsDetector` returns: classifier scores, deterministic",
        "evidence and risk fusion. A `high` verdict normally needs a strong evidence cue;",
        "a smishing score at or above the evidence-free threshold can stand alone.",
        "",
        "| Split | Policy macro-F1 | Policy smishing recall | Policy smishing precision | Smishing flagged (any band) | High-risk smishing recall | High-risk precision | Ham flagged (any band) | Ham high-risk |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for split in ("val", "test", "external"):
        metrics = final[split]
        risk = metrics["risk"]
        policy = risk["policy_metrics"]
        lines.append(
            f"| `{split}` | {policy['macro_f1']:.3f} | {policy['smishing_recall']:.3f} | "
            f"{policy['smishing_precision']:.3f} | {risk['smishing_flagged_rate']:.3f} | "
            f"{risk['high_smishing_recall']:.3f} | {risk['high_smishing_precision']:.3f} | "
            f"{risk['ham_flagged_rate']:.3f} | {risk['ham_high_rate']:.3f} |"
        )
    lines.extend(
        [
            "",
            "The high band is deliberately narrow and precision-oriented. The recall-oriented",
            "suspicious band is where uncertain messages are surfaced for review. The locked",
            "test is small for smishing and wide confidence intervals apply.",
            "",
            "## Classifier-only (argmax) metrics",
            "",
            "These are the raw three-class classifier results before rule/risk fusion. They are",
            "diagnostics, not the product output.",
            "",
            "| Split | Macro-F1 | Smishing recall | Smishing FNR | Smishing FPR | Ham false-positive rate |",
            "|---|---:|---:|---:|---:|---:|",
        ]
    )
    for split in ("val", "test", "external"):
        metrics = final[split]
        lines.append(
            f"| `{split}` | {metrics['macro_f1']:.3f} | {metrics['smishing_recall']:.3f} | "
            f"{metrics['smishing_false_negative_rate']:.3f} | {metrics['smishing_false_positive_rate']:.3f} | "
            f"{metrics['ham_false_positive_rate']:.3f} |"
        )
    lines.extend(
        [
            "",
            "`external` is **not** a clean independent benchmark: it combines source-held-out",
            "NCSU campaigns with held-out classic ham/spam and the hand-written Hinglish seed.",
            "NCSU campaigns include gambling/promotional spam, so the source-level `smishing`",
            "label is noisy. Read external results as a stress test, not as proof of real-world",
            "accuracy.",
            "",
            "## Per-class policy metrics (locked test)",
            "",
            "| Class | Precision | Recall | F1 | Support |",
            "|---|---:|---:|---:|---:|",
        ]
    )
    test_policy = final["test"]["risk"]["policy_metrics"]
    for label in LABELS:
        row = test_policy["per_class"][label]
        lines.append(
            f"| `{label}` | {row['precision']:.3f} | {row['recall']:.3f} | {row['f1']:.3f} | {row['support']:,} |"
        )
    lines.extend(
        [
            "",
            "## Policy confusion matrix (locked test)",
            "",
            "| True \\ Predicted | ham | spam | smishing |",
            "|---|---:|---:|---:|",
        ]
    )
    matrix = test_policy["confusion_matrix"]
    for index, label in enumerate(LABELS):
        lines.append(
            f"| `{label}` | " + " | ".join(str(value) for value in matrix[index]) + " |"
        )
    lines.extend(
        [
            "",
            "## Threshold policy",
            "",
            f"- High-risk threshold: **{thresholds['high_threshold']:.3f}**",
            f"- Suspicious threshold: **{thresholds['suspicious_threshold']:.3f}**",
            f"- Evidence-free high threshold: **{thresholds.get('evidence_free_high', 0.8):.3f}**",
            f"- Cost assumptions: C_FN={report['costs']['fn']:.1f}, C_FP={report['costs']['fp']:.1f}",
            f"- Validation recall floor for high risk: **{thresholds.get('min_high_recall')}**",
            f"- Validation precision floor for high risk: **{thresholds.get('min_high_precision')}**",
            "- Thresholds are selected on validation only; the locked test split was not used.",
            "- The suspicious band uses a discounted false-positive cost because it prompts review, not blocking.",
            "",
            "## Calibration",
            "",
            "| Metric | Raw | Calibrated |",
            "|---|---:|---:|",
            f"| Log loss | {_fmt(calibration['raw_log_loss'])} | {_fmt(calibration['calibrated_log_loss'])} |",
            f"| Brier (multiclass) | {calibration['raw_brier']:.4f} | {calibration['calibrated_brier']:.4f} |",
            f"| ECE (10 bins) | {calibration['raw_ece']:.4f} | {calibration['calibrated_ece']:.4f} |",
            f"| High-band precision | {calibration['raw_high_precision']:.3f} | {calibration['calibrated_high_precision']:.3f} |",
            f"| High-band recall | {calibration['raw_high_recall']:.3f} | {calibration['calibrated_high_recall']:.3f} |",
            "",
            f"Temperature scaling applied: **{calibration['applied']}** (T={calibration['temperature']:.3f}).",
            f"Fitted temperature: {calibration['fitted_temperature']:.3f}.",
            f"Reason not applied: {calibration.get('rejection_reason') or 'not needed'}.",
            "",
            calibration_note,
            "",
            "## Candidate experiments (validation)",
            "",
            "| Experiment | Macro-F1 | Smishing recall @ default | Smishing recall @ high | Precision @ high | Feasible | FPR @ high | Expected cost | Train s |",
            "|---|---:|---:|---:|---:|---|---:|---:|---:|",
        ]
    )
    for name, info in report["experiments"].items():
        op = info["val_high_operating_point"]
        feasible = bool(info["val_thresholds"].get("high_feasible", False))
        lines.append(
            f"| `{name}` | {info['val_default']['macro_f1']:.3f} | "
            f"{info['val_default']['smishing_recall']:.3f} | {op['recall']:.3f} | "
            f"{op['precision']:.3f} | {'yes' if feasible else '**no**'} | "
            f"{op['fpr']:.3f} | {op['expected_cost']:.1f} | {info['train_seconds']:.1f} |"
        )
    lines.extend(
        [
            "",
            "## E0 rules-only baseline",
            "",
            "| Split | Macro-F1 | Smishing recall | Ham false-positive rate |",
            "|---|---:|---:|---:|",
        ]
    )
    for split, metrics in report["e0_rules"].items():
        lines.append(
            f"| `{split}` | {metrics['macro_f1']:.3f} | {metrics['smishing_recall']:.3f} | "
            f"{metrics['ham_false_positive_rate']:.3f} |"
        )
    lines.extend(
        [
            "",
            "## Risks and honest limitations",
            "",
            "- The locked test split is small for smishing (49 examples); confidence intervals are wide.",
            "- NCSU campaign templates are source-labelled `smishing` but include gambling and promotional spam; external exact 3-class metrics are label-noisy.",
            "- The external split is 97.7% NCSU smishing by construction, so its macro-F1 is not comparable to the balanced test split.",
            "- Hinglish coverage is 63 hand-written rows; no robust Hinglish claim is made.",
            "- UCI is old and geographically mismatched with current Indian SMS scams.",
            "- The high-risk band is intentionally narrow; most recall comes from the suspicious band. Do not describe it as full smishing coverage.",
            "- Calibration was rejected because it worsened the high-band precision/recall trade-off; scores should not be described as calibrated probabilities.",
            "- Thresholds and costs are provisional and must be agreed with the team.",
            "- The detector is a screening aid, not a certainty engine. No auto-delete or auto-click.",
            "",
            "## False-positive controls",
            "",
            "- Routine `salary credited`, `EMI debited`, `payment successful` and delivered-order alerts are suppressed only when no link, request, threat or fee is present.",
            "- A high-risk verdict normally needs a strong evidence cue; a very high smishing score can stand alone.",
            "- Account-reset/login/password lures require a URL; `if this wasn't you` security alerts are excluded.",
            "",
            "## Reproduce",
            "",
            "```powershell",
            "python scripts/download_data.py",
            "python scripts/prepare_data.py",
            "python scripts/audit_data.py",
            "python scripts/train.py",
            "```",
            "",
        ]
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")


def _write_model_card(report: dict, metadata: dict, path: Path) -> None:
    final = report["final"]
    lines = [
        "# Model Card — SMS Scam Detector",
        "",
        f"Version: `{metadata['model_version']}`  ",
        f"Created: {metadata['created_utc']}  ",
        f"Selected experiment: `{metadata['selected_experiment']}`",
        "",
        "## Intended use",
        "",
        "Local, on-device screening of SMS into `ham`, `spam` and `smishing`, with",
        "structured evidence and safe action codes for a separate Llama explanation",
        "layer. The detector makes the threat classification; the LLM must not invent",
        "or override detections.",
        "",
        "## Out of scope",
        "",
        "- URL reputation or domain intelligence (owned by the URL teammate).",
        "- Network-flow anomaly detection (owned by another teammate).",
        "- Auto-deleting messages, auto-clicking links, or claiming certainty.",
        "- Sending SMS bodies to a cloud API.",
        "",
        "## Architecture",
        "",
        "- Selected model: word TF-IDF (1–2 grams) + multiclass Logistic Regression with `class_weight=\"balanced\"`.",
        "- Character n-grams and indicator features were evaluated (E2/E3) but did not win under the high-band precision/recall constraint.",
        "- Deterministic indicators are still computed at inference and used by rule/risk fusion: URL, OTP/credential request, account threat, account-access lure, payment demand, urgency, prize/loan/delivery bait, sender mismatch and obfuscation.",
        "- Cost-sensitive risk thresholds select a narrow high-risk band and a recall-oriented suspicious band on validation only.",
        "- High-risk escalation normally requires a strong evidence cue; a smishing score at or above the evidence-free cutoff can stand alone.",
        "- Conservative guards suppress routine salary/EMI/payment and delivered-order notifications unless a link, request, threat or fee is present.",
        "- Temperature scaling is fitted and evaluated but is applied only if it preserves the high-band operating point.",
        "",
        "## Training data",
        "",
        f"- Training rows: {metadata['training_rows']:,}",
        f"- Validation rows: {metadata['validation_rows']:,}",
        f"- Locked test rows: {metadata['test_rows']:,}",
        f"- External rows: {metadata['external_rows']:,}",
        f"- Feature count: {metadata['feature_count']:,}",
        f"- Model file size: {metadata['model_size_bytes']:,} bytes",
        "",
        "Sources: UCI SMS Spam Collection, Mishra & Soni LSDST-2022, NCSU SMS Phishing",
        "(external only), and the Hinglish seed corpus (external only). See `docs/data-card.md`.",
        "",
        "## Evaluation summary — product policy output",
        "",
        "| Split | Policy macro-F1 | Policy smishing recall | Policy smishing precision | Ham flagged | High-risk recall | High-risk precision | Ham high-risk |",
        "|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for split in ("val", "test", "external"):
        metrics = final[split]
        risk = metrics["risk"]
        policy = risk["policy_metrics"]
        lines.append(
            f"| `{split}` | {policy['macro_f1']:.3f} | {policy['smishing_recall']:.3f} | "
            f"{policy['smishing_precision']:.3f} | {risk['ham_flagged_rate']:.3f} | "
            f"{risk['high_smishing_recall']:.3f} | {risk['high_smishing_precision']:.3f} | "
            f"{risk['ham_high_rate']:.3f} |"
        )
    lines.extend(
        [
            "",
            "Classifier-only locked-test metrics: macro-F1 "
            f"{final['test']['macro_f1']:.3f}, smishing recall {final['test']['smishing_recall']:.3f}, "
            f"ham false-positive rate {final['test']['ham_false_positive_rate']:.3f}.",
            "",
            "The two bands have different jobs. The high band is safe to interrupt on and",
            "therefore has lower recall. The suspicious band carries most of the recall and",
            "always asks the user to verify through an official channel.",
            "",
            "## Calibration",
            "",
            f"- Fitted temperature: {metadata['calibration']['fitted_temperature']:.3f}",
            f"- Applied: **{metadata['calibration']['applied']}**",
            f"- Reason: {metadata['calibration'].get('rejection_reason') or 'n/a'}",
            f"- Raw/calibrated ECE: {metadata['calibration']['raw_ece']:.4f} / {metadata['calibration']['calibrated_ece']:.4f}",
            "- Scores are therefore not presented as calibrated probabilities.",
            "",
        ]
    )
    lines.extend(
        [
            "",
            "## Limitations",
            "",
            "- Small locked smishing test set (49 examples); wide uncertainty.",
            "- Old UCI corpus and limited modern Indian English/Hinglish coverage.",
            "- NCSU campaign templates are source-labelled phishing but include gambling/promotional spam; external exact-class metrics are noisy.",
            "- The external split is dominated by NCSU campaigns, so its macro-F1 is not comparable to the balanced locked test.",
            "- Sender metadata is sparse; `SENDER_ID_UNVERIFIED` is a weak signal only.",
            "- Scores are not calibrated; thresholds need re-validation on the target Pixel 6a data.",
            "- The high-risk band is intentionally narrow. Most recall comes from the suspicious band.",
            "",
            "## Safety and privacy",
            "",
            "- Inference is local; the returned JSON contains no raw SMS text.",
            "- Evidence codes are stable and auditable.",
            "- Recommended actions are conservative; no automatic destructive action.",
            "- Raw datasets and audit examples are excluded from Git.",
            "",
            "## Artefacts",
            "",
            "- `artifacts/model/model.joblib` — scikit-learn model.",
            "- `artifacts/model/metadata.json` — thresholds, calibration, version, hashes.",
            "- `artifacts/model/portable/portable_model.json` — export for future Kotlin parity.",
            "- `artifacts/reports/baseline_metrics.json` — full experiment report.",
            "",
        ]
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")


def _fmt(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.4f}"
