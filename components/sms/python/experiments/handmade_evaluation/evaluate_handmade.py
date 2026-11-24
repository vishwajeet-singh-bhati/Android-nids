"""Evaluate the existing TF-IDF detector and MobileBERT-22 on the handmade dataset.

The source dataset is raw SMS text and is treated as read-only. All evaluation
outputs are written under experiments/handmade_evaluation/results/. The saved
TF-IDF model, its risk thresholds, the MobileBERT-22 checkpoint, and all previous
experiment results are read-only inputs.

Every dataset row is provisionally treated as smishing. Therefore the reported
"detection rate" is a coverage/recall measure, not precision or accuracy.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import statistics
import sys
from datetime import datetime, timezone
from importlib.metadata import version
from pathlib import Path

import numpy as np
import pandas as pd
import torch
from transformers import AutoModelForSequenceClassification, AutoTokenizer

EXPERIMENT_DIR = Path(__file__).resolve().parent
REPO_ROOT = EXPERIMENT_DIR.parents[1]
SRC_DIR = REPO_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from sms_detection.config import LABELS  # noqa: E402
from sms_detection.predictor import SmsDetector  # noqa: E402
from sms_detection.preprocessing.indicators import analyze_text  # noqa: E402
from sms_detection.preprocessing.normalize import normalize_text  # noqa: E402

REQUESTED_DATASET = EXPERIMENT_DIR / "smishing_dataset.csv"
FALLBACK_DATASET = (
    REPO_ROOT / "experiments" / "mobilebert" / "handmade_dataset" / "smishing_dataset.csv"
)
BASELINE_MODEL_DIR = REPO_ROOT / "artifacts" / "model"
MOBILEBERT_CHECKPOINT = (
    REPO_ROOT
    / "experiments"
    / "mobilebert"
    / "checkpoints"
    / "mobilebert22_lr5e5_bs16_e4"
    / "best"
)
OUTPUT_DIR = EXPERIMENT_DIR / "results"
MOBILEBERT_MAX_LENGTH = 128
MOBILEBERT_BATCH_SIZE = 32
PROVISIONAL_LABEL = "smishing"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def hash_tree(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        digest.update(str(path.relative_to(root)).replace("\\", "/").encode("utf-8"))
        digest.update(b"\0")
        digest.update(sha256_file(path).encode("ascii"))
        digest.update(b"\n")
    return digest.hexdigest()


def json_dump(path: Path, payload: object) -> None:
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def resolve_dataset(provided: str | None) -> Path:
    if provided:
        path = Path(provided).expanduser().resolve()
        if not path.exists():
            raise FileNotFoundError(f"dataset not found: {path}")
        return path
    for candidate in (REQUESTED_DATASET, FALLBACK_DATASET):
        if candidate.exists():
            return candidate
    raise FileNotFoundError(
        "No handmade dataset found. Looked for:\n"
        f"  - {REQUESTED_DATASET}\n"
        f"  - {FALLBACK_DATASET}"
    )


def load_dataset(path: Path) -> pd.DataFrame:
    frame = pd.read_csv(path)
    required = {"ID", "Category", "Message", "Tactic"}
    missing = required - set(frame.columns)
    if missing:
        raise ValueError(f"{path} is missing columns: {sorted(missing)}")
    if frame.isna().any().any():
        raise ValueError(f"{path} contains null values")
    frame = frame.copy()
    frame["ID"] = frame["ID"].astype(int)
    frame["Category"] = frame["Category"].astype(str)
    frame["Message"] = frame["Message"].astype(str)
    frame["Tactic"] = frame["Tactic"].astype(str)
    if not frame["ID"].is_unique:
        raise ValueError("ID values must be unique")
    if frame["Message"].str.strip().eq("").any():
        raise ValueError("Message values must not be empty")
    return frame


def load_mobilebert():
    tokenizer = AutoTokenizer.from_pretrained(MOBILEBERT_CHECKPOINT, local_files_only=True)
    model = AutoModelForSequenceClassification.from_pretrained(
        MOBILEBERT_CHECKPOINT, local_files_only=True
    )
    model.eval()
    id2label = {int(key): value for key, value in model.config.id2label.items()}
    label_order = [id2label[index] for index in range(len(id2label))]
    if label_order != list(LABELS):
        raise ValueError(f"Unexpected MobileBERT label order: {label_order}")
    return tokenizer, model, label_order


def tokenize_model_texts(tokenizer, texts: list[str]):
    return tokenizer(
        texts,
        padding=False,
        truncation=True,
        max_length=MOBILEBERT_MAX_LENGTH,
        return_attention_mask=True,
        return_token_type_ids=True,
    )


def batch_from_encoding(tokenizer, encoding, indices: list[int]):
    keys = [
        key
        for key in ("input_ids", "attention_mask", "token_type_ids")
        if key in encoding
    ]
    return tokenizer.pad(
        {key: [encoding[key][index] for index in indices] for key in keys},
        padding=True,
        return_tensors="pt",
    )


def predict_mobilebert(tokenizer, model, model_texts: list[str]) -> np.ndarray:
    encoding = tokenize_model_texts(tokenizer, model_texts)
    probabilities = np.zeros((len(model_texts), len(LABELS)), dtype=np.float64)
    with torch.inference_mode():
        for start in range(0, len(model_texts), MOBILEBERT_BATCH_SIZE):
            indices = list(
                range(start, min(start + MOBILEBERT_BATCH_SIZE, len(model_texts)))
            )
            batch = batch_from_encoding(tokenizer, encoding, indices)
            logits = model(**batch).logits
            probabilities[indices] = (
                torch.softmax(logits, dim=-1).cpu().numpy().astype(np.float64)
            )
    return probabilities


def model_stats(
    labels: list[str],
    confidences: list[float],
    smishing_probabilities: list[float],
) -> dict:
    rows = len(labels)
    counts = {label: sum(1 for value in labels if value == label) for label in LABELS}
    detected = counts["smishing"]
    return {
        "rows": rows,
        "detected_smishing": detected,
        "detection_rate": detected / rows if rows else 0.0,
        "missed_smishing": rows - detected,
        "spam_predictions": counts["spam"],
        "ham_predictions": counts["ham"],
        "label_counts": counts,
        "mean_confidence": float(np.mean(confidences)) if confidences else 0.0,
        "median_confidence": float(np.median(confidences)) if confidences else 0.0,
        "mean_smishing_probability": float(np.mean(smishing_probabilities))
        if smishing_probabilities
        else 0.0,
    }


def aggregate_rows(predictions: pd.DataFrame, group_column: str) -> pd.DataFrame:
    rows = []
    for group_value, subset in predictions.groupby(group_column, sort=True):
        tfidf_detected = subset["tfidf_detector_label"].eq("smishing")
        tfidf_classifier_detected = subset["tfidf_classifier_label"].eq("smishing")
        mobilebert_detected = subset["mobilebert_label"].eq("smishing")
        both_detected = tfidf_detected & mobilebert_detected
        only_tfidf = tfidf_detected & ~mobilebert_detected
        only_mobilebert = ~tfidf_detected & mobilebert_detected
        neither = ~tfidf_detected & ~mobilebert_detected
        row = {
            group_column: group_value,
            "messages": int(len(subset)),
            "tfidf_detector_detected": int(tfidf_detected.sum()),
            "tfidf_detector_detection_rate": float(tfidf_detected.mean()),
            "tfidf_detector_missed": int((~tfidf_detected).sum()),
            "tfidf_detector_spam_predictions": int(
                subset["tfidf_detector_label"].eq("spam").sum()
            ),
            "tfidf_detector_ham_predictions": int(
                subset["tfidf_detector_label"].eq("ham").sum()
            ),
            "tfidf_classifier_detected": int(tfidf_classifier_detected.sum()),
            "tfidf_classifier_detection_rate": float(tfidf_classifier_detected.mean()),
            "tfidf_classifier_missed": int((~tfidf_classifier_detected).sum()),
            "mobilebert_detected": int(mobilebert_detected.sum()),
            "mobilebert_detection_rate": float(mobilebert_detected.mean()),
            "mobilebert_missed": int((~mobilebert_detected).sum()),
            "mobilebert_spam_predictions": int(
                subset["mobilebert_label"].eq("spam").sum()
            ),
            "mobilebert_ham_predictions": int(
                subset["mobilebert_label"].eq("ham").sum()
            ),
            "both_detected": int(both_detected.sum()),
            "only_tfidf_detected": int(only_tfidf.sum()),
            "only_mobilebert_detected": int(only_mobilebert.sum()),
            "neither_detected": int(neither.sum()),
            "tfidf_mean_confidence": float(subset["tfidf_confidence"].mean()),
            "mobilebert_mean_confidence": float(subset["mobilebert_confidence"].mean()),
            "tfidf_mean_smishing_probability": float(
                subset["tfidf_p_smishing"].mean()
            ),
            "mobilebert_mean_smishing_probability": float(
                subset["mobilebert_p_smishing"].mean()
            ),
        }
        if group_column == "Tactic":
            row["Category"] = "; ".join(sorted(subset["Category"].unique().tolist()))
        rows.append(row)
    result = pd.DataFrame(rows)
    if group_column == "Tactic":
        first_columns = ["Tactic", "Category", "messages"]
    else:
        first_columns = ["Category", "messages"]
    other_columns = [column for column in result.columns if column not in first_columns]
    return result[first_columns + other_columns]


def percentage(value: float) -> str:
    return f"{100 * value:.1f}%"


def markdown_table(headers: list[str], rows: list[list[object]]) -> str:
    lines = ["| " + " | ".join(headers) + " |", "|" + "|".join(["---"] * len(headers)) + "|"]
    for row in rows:
        lines.append("| " + " | ".join(str(value) for value in row) + " |")
    return "\n".join(lines)


def format_list(items: list[str], empty: str = "None") -> str:
    if not items:
        return f"- {empty}"
    return "\n".join(f"- {item}" for item in items)


def write_report(
    path: Path,
    dataset_path: Path,
    predictions: pd.DataFrame,
    overall: dict,
    comparison: dict,
    category_table: pd.DataFrame,
    tactic_table: pd.DataFrame,
    tactic_summary: dict,
    detector_summary: dict,
    model_dir: Path,
    dataset_sha256: str,
    dataset_unchanged: bool,
) -> None:
    overall_headers = [
        "Model",
        "Smishing detected",
        "Detection rate",
        "Missed",
        "Spam pred.",
        "Ham pred.",
        "Mean confidence",
        "Mean p(smishing)",
    ]
    overall_rows = []
    for key, label in (
        ("tfidf_detector", "TF-IDF full detector"),
        ("tfidf_classifier_only", "TF-IDF classifier only (diagnostic)"),
        ("mobilebert", "MobileBERT-22"),
    ):
        stats = overall[key]
        overall_rows.append(
            [
                label,
                stats["detected_smishing"],
                percentage(stats["detection_rate"]),
                stats["missed_smishing"],
                stats["spam_predictions"],
                stats["ham_predictions"],
                f"{stats['mean_confidence']:.3f}",
                f"{stats['mean_smishing_probability']:.3f}",
            ]
        )

    category_rows = []
    for _, row in category_table.iterrows():
        category_rows.append(
            [
                row["Category"],
                int(row["messages"]),
                f"{int(row['tfidf_detector_detected'])} ({percentage(row['tfidf_detector_detection_rate'])})",
                f"{int(row['tfidf_detector_missed'])} ({int(row['tfidf_detector_spam_predictions'])}/{int(row['tfidf_detector_ham_predictions'])})",
                f"{int(row['mobilebert_detected'])} ({percentage(row['mobilebert_detection_rate'])})",
                f"{int(row['mobilebert_missed'])} ({int(row['mobilebert_spam_predictions'])}/{int(row['mobilebert_ham_predictions'])})",
                int(row["only_tfidf_detected"]),
                int(row["only_mobilebert_detected"]),
                int(row["neither_detected"]),
            ]
        )

    cross = comparison["label_crosstab"]
    cross_headers = ["TF-IDF full detector \\ MobileBERT-22"] + list(LABELS)
    cross_rows = []
    for left_label in LABELS:
        cross_rows.append(
            [left_label]
            + [int(cross.get(left_label, {}).get(right_label, 0)) for right_label in LABELS]
        )

    thresholds = detector_summary["thresholds"]
    lines = [
        "# Handmade smishing evaluation",
        "",
        f"Generated: `{utc_now()}`",
        "",
        f"Dataset: `{dataset_path}`",
        "",
        f"Dataset SHA-256: `{dataset_sha256}`",
        "",
        f"Source dataset unchanged after run: **{dataset_unchanged}**",
        "",
        "## Assumption",
        "",
        "All 100 messages are provisionally treated as **smishing**. Because there",
        "are no non-smishing controls, the detection rate is a coverage/recall",
        "measure. Precision, specificity, and false-positive rate are not defined",
        "for this evaluation.",
        "",
        "## Models and decision rules",
        "",
        "### TF-IDF full detector (primary)",
        "",
        f"The existing `SmsDetector.from_artifact(\"{model_dir}\")` pipeline is",
        "used unchanged. Its saved risk policy thresholds are applied exactly as",
        f"stored in `{model_dir / 'metadata.json'}`:",
        "",
        f"- high: `{thresholds['high']}`",
        f"- suspicious: `{thresholds['suspicious']}`",
        f"- evidence_free_high: `{thresholds['evidence_free_high']}`",
        "",
        "The primary TF-IDF label is the detector's final `ham`/`spam`/`smishing`",
        "label after the risk policy. The classifier-only argmax is recorded as a",
        "diagnostic because MobileBERT-22 has no equivalent policy layer.",
        "",
        "### MobileBERT-22",
        "",
        "The existing fine-tuned 22-layer checkpoint is loaded read-only from",
        "`experiments/mobilebert/checkpoints/mobilebert22_lr5e5_bs16_e4/best`.",
        "Input is `normalize_text(message).model_text`, truncated at 128 tokens.",
        "The reported label is the softmax argmax. No policy thresholds were",
        "applied or created for MobileBERT.",
        "",
        "## Overall comparison",
        "",
        markdown_table(overall_headers, overall_rows),
        "",
        "`Mean confidence` is the mean maximum class probability. For TF-IDF it",
        "can belong to a class different from the final policy label when a rule",
        "override occurs; `tfidf_predicted_label_score` in `predictions.csv` is the",
        "score assigned to the final label.",
        "",
        "## Detection agreement",
        "",
        f"- Both detectors predicted smishing: **{comparison['both_detected']}**",
        f"- Only TF-IDF predicted smishing: **{comparison['only_tfidf_detected']}**",
        f"- Only MobileBERT predicted smishing: **{comparison['only_mobilebert_detected']}**",
        f"- Neither predicted smishing: **{comparison['neither_detected']}**",
        f"- Exact three-class label agreement: **{comparison['same_label']}/100**",
        f"- TF-IDF classifier-only vs MobileBERT exact label agreement: **{comparison['classifier_same_label']}/100**",
        "",
        markdown_table(cross_headers, cross_rows),
        "",
        "## Category-wise comparison",
        "",
        markdown_table(
            [
                "Category",
                "N",
                "TF-IDF detected (rate)",
                "TF-IDF missed (spam/ham)",
                "MobileBERT detected (rate)",
                "MobileBERT missed (spam/ham)",
                "Only TF-IDF",
                "Only MobileBERT",
                "Neither",
            ],
            category_rows,
        ),
        "",
        "Full per-category details, including classifier-only results and mean",
        "confidences, are in `category_comparison.csv`.",
        "",
        "## Tactic-wise comparison",
        "",
        f"- Unique tactic values: **{tactic_summary['unique_tactics']}**",
        f"- Tactic groups where both models detected every message: **{tactic_summary['both_detected_tactics']}**",
        f"- Tactic groups where only TF-IDF detected at least one message: **{tactic_summary['only_tfidf_tactics']}**",
        f"- Tactic groups where only MobileBERT detected at least one message: **{tactic_summary['only_mobilebert_tactics']}**",
        f"- Tactic groups where neither model detected any message: **{tactic_summary['neither_detected_tactics']}**",
        "",
        "Because most tactics have exactly one message, the full tactic table is",
        "descriptive rather than statistical. See `tactic_comparison.csv` for all",
        "100 rows.",
        "",
        "### Tactics with at least one TF-IDF miss",
        "",
        format_list(tactic_summary["tfidf_missed_tactics"]),
        "",
        "### Tactics with at least one MobileBERT miss",
        "",
        format_list(tactic_summary["mobilebert_missed_tactics"]),
        "",
        "### Tactics missed by both models",
        "",
        format_list(tactic_summary["both_missed_tactics"]),
        "",
        "## Per-message outputs",
        "",
        "- `predictions.csv`: every message plus both models' labels, class",
        "  probabilities, confidence scores, TF-IDF risk level, and evidence codes.",
        "- `predictions_text_free.csv`: the same predictions without SMS bodies.",
        "- `summary.json`: machine-readable overall and comparison results.",
        "- `category_comparison.csv`: category aggregates.",
        "- `tactic_comparison.csv`: tactic aggregates.",
        "- `manifest.json`: hashes, environment, thresholds, and output inventory.",
        "",
        "## Caveats",
        "",
        "- All examples are positive; this cannot estimate false positives or",
        "  precision.",
        "- The TF-IDF primary result includes its existing risk policy, while",
        "  MobileBERT-22 has no policy layer. The classifier-only TF-IDF row is",
        "  provided to expose that difference.",
        "- The dataset is small and tactic labels are mostly unique; category and",
        "  tactic rates should not be over-interpreted.",
        "- No model was retrained, no threshold was changed, and no previous",
        "  experiment result was modified.",
        "- Processing is local only; no SMS text was sent to a cloud service.",
        "",
    ]
    path.write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", default=None, help="Optional dataset CSV path.")
    parser.add_argument(
        "--model-dir",
        default=str(BASELINE_MODEL_DIR),
        help="Saved detector artifact directory to evaluate.",
    )
    parser.add_argument(
        "--output-dir",
        default=str(OUTPUT_DIR),
        help="Directory for evaluation outputs.",
    )
    args = parser.parse_args()

    model_dir = Path(args.model_dir).expanduser().resolve()
    output_dir = Path(args.output_dir).expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    dataset_path = resolve_dataset(args.dataset)
    dataset_hash_before = sha256_file(dataset_path)
    baseline_model_hash_before = sha256_file(model_dir / "model.joblib")
    mobilebert_model_hash_before = sha256_file(
        MOBILEBERT_CHECKPOINT / "model.safetensors"
    )
    previous_results_hash_before = hash_tree(REPO_ROOT / "experiments" / "mobilebert" / "results")

    frame = load_dataset(dataset_path)
    messages = frame["Message"].tolist()
    normalized = [normalize_text(message) for message in messages]
    model_texts = [item.model_text for item in normalized]
    indicators = [
        analyze_text(message, normalized=norm)
        for message, norm in zip(messages, normalized)
    ]

    detector = SmsDetector.from_artifact(model_dir)
    detector_summary = detector.artifact_summary()
    tfidf_probabilities = detector.classifier.predict_proba(
        messages,
        normalized=normalized,
        indicators=indicators,
    )
    tfidf_probabilities = np.asarray(tfidf_probabilities, dtype=np.float64)
    tfidf_classifier_labels = [
        LABELS[int(index)] for index in np.argmax(tfidf_probabilities, axis=1)
    ]

    tokenizer, mobilebert_model, label_order = load_mobilebert()
    if label_order != list(LABELS):
        raise ValueError("MobileBERT label order does not match project labels")
    mobilebert_probabilities = predict_mobilebert(tokenizer, mobilebert_model, model_texts)
    mobilebert_labels = [
        LABELS[int(index)] for index in np.argmax(mobilebert_probabilities, axis=1)
    ]

    records: list[dict] = []
    for index, row in frame.iterrows():
        result = detector.predict_sms(messages[index])
        assessment = detector.policy.assess(result.scores, indicators[index])
        if assessment.label != result.label:
            raise RuntimeError("TF-IDF policy result changed between calls")
        scores = {label: float(result.scores[label]) for label in LABELS}
        tfidf_label = result.label
        tfidf_classifier_label = tfidf_classifier_labels[index]
        mobilebert_label = mobilebert_labels[index]
        tfidf_confidence = max(scores.values())
        mobilebert_confidence = float(mobilebert_probabilities[index].max())
        records.append(
            {
                "ID": int(row["ID"]),
                "Category": row["Category"],
                "Tactic": row["Tactic"],
                "Message": row["Message"],
                "provisional_true_label": PROVISIONAL_LABEL,
                "tfidf_detector_label": tfidf_label,
                "tfidf_classifier_label": tfidf_classifier_label,
                "tfidf_risk_level": result.risk_level,
                "tfidf_rule_label": assessment.rule_label,
                "tfidf_rule_triggered": bool(assessment.rule_triggered),
                "tfidf_p_ham": round(scores["ham"], 6),
                "tfidf_p_spam": round(scores["spam"], 6),
                "tfidf_p_smishing": round(scores["smishing"], 6),
                "tfidf_confidence": round(tfidf_confidence, 6),
                "tfidf_predicted_label_score": round(scores[tfidf_label], 6),
                "tfidf_classifier_confidence": round(
                    float(tfidf_probabilities[index].max()), 6
                ),
                "tfidf_classifier_predicted_label_score": round(
                    float(tfidf_probabilities[index][LABELS.index(tfidf_classifier_label)]),
                    6,
                ),
                "tfidf_evidence": ";".join(
                    item.code for item in result.evidence if item.present
                ),
                "tfidf_detected_smishing": int(tfidf_label == "smishing"),
                "mobilebert_label": mobilebert_label,
                "mobilebert_p_ham": round(
                    float(mobilebert_probabilities[index][LABELS.index("ham")]), 6
                ),
                "mobilebert_p_spam": round(
                    float(mobilebert_probabilities[index][LABELS.index("spam")]), 6
                ),
                "mobilebert_p_smishing": round(
                    float(mobilebert_probabilities[index][LABELS.index("smishing")]), 6
                ),
                "mobilebert_confidence": round(mobilebert_confidence, 6),
                "mobilebert_predicted_label_score": round(
                    float(mobilebert_probabilities[index][LABELS.index(mobilebert_label)]),
                    6,
                ),
                "mobilebert_detected_smishing": int(mobilebert_label == "smishing"),
            }
        )

    predictions = pd.DataFrame(records)
    predictions.to_csv(output_dir / "predictions.csv", index=False, encoding="utf-8")
    predictions.drop(columns=["Message"]).to_csv(
        output_dir / "predictions_text_free.csv", index=False, encoding="utf-8"
    )

    overall = {
        "tfidf_detector": model_stats(
            predictions["tfidf_detector_label"].tolist(),
            predictions["tfidf_confidence"].tolist(),
            predictions["tfidf_p_smishing"].tolist(),
        ),
        "tfidf_classifier_only": model_stats(
            predictions["tfidf_classifier_label"].tolist(),
            predictions["tfidf_classifier_confidence"].tolist(),
            predictions["tfidf_p_smishing"].tolist(),
        ),
        "mobilebert": model_stats(
            predictions["mobilebert_label"].tolist(),
            predictions["mobilebert_confidence"].tolist(),
            predictions["mobilebert_p_smishing"].tolist(),
        ),
    }

    tfidf_detected = predictions["tfidf_detector_label"].eq("smishing")
    mobilebert_detected = predictions["mobilebert_label"].eq("smishing")
    tfidf_classifier_detected = predictions["tfidf_classifier_label"].eq("smishing")
    both_detected = tfidf_detected & mobilebert_detected
    only_tfidf = tfidf_detected & ~mobilebert_detected
    only_mobilebert = ~tfidf_detected & mobilebert_detected
    neither = ~tfidf_detected & ~mobilebert_detected
    crosstab = pd.crosstab(
        predictions["tfidf_detector_label"],
        predictions["mobilebert_label"],
    ).reindex(index=list(LABELS), columns=list(LABELS), fill_value=0)
    comparison = {
        "both_detected": int(both_detected.sum()),
        "only_tfidf_detected": int(only_tfidf.sum()),
        "only_mobilebert_detected": int(only_mobilebert.sum()),
        "neither_detected": int(neither.sum()),
        "same_label": int(
            (predictions["tfidf_detector_label"] == predictions["mobilebert_label"]).sum()
        ),
        "classifier_same_label": int(
            (predictions["tfidf_classifier_label"] == predictions["mobilebert_label"]).sum()
        ),
        "label_agreement": float(
            (
                predictions["tfidf_detector_label"]
                == predictions["mobilebert_label"]
            ).mean()
        ),
        "classifier_label_agreement": float(
            (
                predictions["tfidf_classifier_label"]
                == predictions["mobilebert_label"]
            ).mean()
        ),
        "label_crosstab": {
            left: {
                right: int(crosstab.loc[left, right]) for right in LABELS
            }
            for left in LABELS
        },
    }

    category_table = aggregate_rows(predictions, "Category")
    category_table.to_csv(
        output_dir / "category_comparison.csv", index=False, encoding="utf-8"
    )
    tactic_table = aggregate_rows(predictions, "Tactic")
    tactic_table.to_csv(
        output_dir / "tactic_comparison.csv", index=False, encoding="utf-8"
    )

    tactics_both = int(
        (
            tactic_table["both_detected"].eq(tactic_table["messages"])
        ).sum()
    )
    only_tfidf_tactics = sorted(
        tactic_table.loc[tactic_table["only_tfidf_detected"] > 0, "Tactic"].tolist()
    )
    only_mobilebert_tactics = sorted(
        tactic_table.loc[tactic_table["only_mobilebert_detected"] > 0, "Tactic"].tolist()
    )
    neither_tactics = sorted(
        tactic_table.loc[tactic_table["neither_detected"] > 0, "Tactic"].tolist()
    )
    tfidf_missed_tactics = sorted(
        tactic_table.loc[tactic_table["tfidf_detector_missed"] > 0, "Tactic"].tolist()
    )
    mobilebert_missed_tactics = sorted(
        tactic_table.loc[tactic_table["mobilebert_missed"] > 0, "Tactic"].tolist()
    )
    both_missed_tactics = sorted(
        set(tfidf_missed_tactics) & set(mobilebert_missed_tactics)
    )
    tactic_summary = {
        "unique_tactics": int(tactic_table["Tactic"].nunique()),
        "both_detected_tactics": tactics_both,
        "only_tfidf_tactics": len(only_tfidf_tactics),
        "only_mobilebert_tactics": len(only_mobilebert_tactics),
        "neither_detected_tactics": len(neither_tactics),
        "tfidf_missed_tactics": tfidf_missed_tactics,
        "mobilebert_missed_tactics": mobilebert_missed_tactics,
        "both_missed_tactics": both_missed_tactics,
        "only_tfidf_tactics_list": only_tfidf_tactics,
        "only_mobilebert_tactics_list": only_mobilebert_tactics,
        "neither_detected_tactics_list": neither_tactics,
    }

    dataset_hash_after = sha256_file(dataset_path)
    baseline_model_hash_after = sha256_file(model_dir / "model.joblib")
    mobilebert_model_hash_after = sha256_file(
        MOBILEBERT_CHECKPOINT / "model.safetensors"
    )
    previous_results_hash_after = hash_tree(
        REPO_ROOT / "experiments" / "mobilebert" / "results"
    )
    dataset_unchanged = dataset_hash_before == dataset_hash_after
    baseline_unchanged = baseline_model_hash_before == baseline_model_hash_after
    mobilebert_unchanged = mobilebert_model_hash_before == mobilebert_model_hash_after
    previous_results_unchanged = (
        previous_results_hash_before == previous_results_hash_after
    )

    summary = {
        "created_utc": utc_now(),
        "dataset": {
            "path": str(dataset_path),
            "requested_path": str(REQUESTED_DATASET),
            "rows": int(len(frame)),
            "columns": list(frame.columns),
            "categories": int(frame["Category"].nunique()),
            "tactics": int(frame["Tactic"].nunique()),
            "provisional_true_label": PROVISIONAL_LABEL,
            "sha256": dataset_hash_before,
        },
        "overall": overall,
        "comparison": comparison,
        "tactic_summary": tactic_summary,
        "notes": [
            "All 100 rows are provisionally treated as smishing; no negatives exist.",
            "Detection rate is therefore coverage/recall, not precision or accuracy.",
            "TF-IDF primary labels come from the existing SmsDetector risk policy.",
            "MobileBERT-22 labels are softmax argmax; no policy thresholds exist.",
            "No retraining and no threshold changes were performed.",
        ],
    }
    json_dump(output_dir / "summary.json", summary)

    manifest = {
        "created_utc": utc_now(),
        "dataset": {
            "path": str(dataset_path),
            "requested_path": str(REQUESTED_DATASET),
            "sha256": dataset_hash_before,
            "unchanged_after_run": dataset_unchanged,
        },
        "baseline_detector": {
            "path": str(model_dir),
            "model_sha256": baseline_model_hash_before,
            "unchanged_after_run": baseline_unchanged,
            "summary": detector_summary,
        },
        "mobilebert": {
            "checkpoint": str(MOBILEBERT_CHECKPOINT),
            "model_sha256": mobilebert_model_hash_before,
            "unchanged_after_run": mobilebert_unchanged,
            "num_hidden_layers": int(mobilebert_model.config.num_hidden_layers),
            "labels": list(LABELS),
            "max_length": MOBILEBERT_MAX_LENGTH,
            "batch_size": MOBILEBERT_BATCH_SIZE,
        },
        "previous_mobilebert_results": {
            "path": str(REPO_ROOT / "experiments" / "mobilebert" / "results"),
            "tree_sha256": previous_results_hash_before,
            "unchanged_after_run": previous_results_unchanged,
        },
        "environment": {
            "python": sys.version,
            "platform": platform.platform(),
            "torch": torch.__version__,
            "transformers": version("transformers"),
            "pandas": pd.__version__,
            "numpy": np.__version__,
            "cpu_threads": torch.get_num_threads(),
            "cuda_available": torch.cuda.is_available(),
        },
        "outputs": {},
        "notes": [
            "Source dataset, saved models, and previous experiment results were read-only.",
            "No SMS text was sent to a cloud service.",
        ],
    }
    for output_name in (
        "predictions.csv",
        "predictions_text_free.csv",
        "summary.json",
        "category_comparison.csv",
        "tactic_comparison.csv",
    ):
        output_path = output_dir / output_name
        manifest["outputs"][output_name] = {
            "bytes": output_path.stat().st_size,
            "sha256": sha256_file(output_path),
        }

    json_dump(output_dir / "manifest.json", manifest)
    write_report(
        output_dir / "comparison_report.md",
        dataset_path,
        predictions,
        overall,
        comparison,
        category_table,
        tactic_table,
        tactic_summary,
        detector_summary,
        model_dir,
        dataset_hash_before,
        dataset_unchanged,
    )

    print(f"dataset={dataset_path}")
    print(f"rows={len(frame)} categories={frame['Category'].nunique()} tactics={frame['Tactic'].nunique()}")
    print(f"tfidf_thresholds={detector_summary['thresholds']}")
    for key, label in (
        ("tfidf_detector", "TF-IDF full detector"),
        ("tfidf_classifier_only", "TF-IDF classifier only"),
        ("mobilebert", "MobileBERT-22"),
    ):
        stats = overall[key]
        print(
            f"{label}: detected={stats['detected_smishing']}/{stats['rows']} "
            f"rate={stats['detection_rate']:.4f} missed={stats['missed_smishing']} "
            f"spam={stats['spam_predictions']} ham={stats['ham_predictions']} "
            f"mean_conf={stats['mean_confidence']:.4f} "
            f"mean_p_smishing={stats['mean_smishing_probability']:.4f}"
        )
    print(
        "agreement: "
        f"both={comparison['both_detected']} "
        f"only_tfidf={comparison['only_tfidf_detected']} "
        f"only_mobilebert={comparison['only_mobilebert_detected']} "
        f"neither={comparison['neither_detected']} "
        f"same_label={comparison['same_label']}/100"
    )
    print(f"dataset_unchanged={dataset_unchanged}")
    print(f"baseline_model_unchanged={baseline_unchanged}")
    print(f"mobilebert_model_unchanged={mobilebert_unchanged}")
    print(f"previous_results_unchanged={previous_results_unchanged}")
    print(f"outputs={output_dir}")


if __name__ == "__main__":
    main()
