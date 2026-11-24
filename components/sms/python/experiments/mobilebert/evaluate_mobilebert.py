"""Single-use evaluation of MobileBERT and the TF-IDF baseline on the same split.

By default this evaluates the locked test split exactly once. It writes only
aggregate results; per-example predictions are opt-in with
``--write-per-example`` and are never written by default.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import time
from pathlib import Path

import numpy as np
import pandas as pd
import torch
from transformers import AutoModelForSequenceClassification, AutoTokenizer

from common import (
    BASELINE_MODEL_DIR,
    BASELINE_REPORT,
    DEFAULT_MAX_LENGTH,
    EXPERIMENT_DIR,
    ID2LABEL,
    LABELS,
    available_ram_mb,
    batch_from_encoding,
    configure_cpu_threads,
    encode_texts,
    iter_batches,
    json_dump,
    load_split,
    metrics_from_predictions,
    model_summary,
    rss_mb,
    seed_everything,
    timestamp_utc,
)

from sms_detection.models.classifier import SmsClassifier
from sms_detection.preprocessing.indicators import analyze_text
from sms_detection.preprocessing.normalize import normalize_text


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--split", default="test", choices=["val", "test"])
    parser.add_argument("--checkpoint", default=None)
    parser.add_argument("--batch-size", type=int, default=32)
    parser.add_argument("--max-length", type=int, default=DEFAULT_MAX_LENGTH)
    parser.add_argument("--threads", type=int, default=8)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--write-per-example", action="store_true")
    parser.add_argument("--output-suffix", default=None)
    return parser.parse_args()


def sha256_text_lines(values: list[str]) -> str:
    digest = hashlib.sha256()
    for value in values:
        digest.update(str(value).encode("utf-8"))
        digest.update(b"\n")
    return digest.hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def tree_size_bytes(path: Path) -> int:
    return sum(p.stat().st_size for p in path.rglob("*") if p.is_file())


def predict_mobilebert(model, tokenizer, encoding, labels: torch.Tensor, batch_size: int):
    model.eval()
    logits_parts = []
    with torch.inference_mode():
        for indices in iter_batches(list(range(len(labels))), batch_size):
            batch = batch_from_encoding(tokenizer, encoding, indices)
            logits_parts.append(model(**batch).logits.cpu())
    logits = torch.cat(logits_parts, dim=0)
    probs = torch.softmax(logits, dim=-1).numpy()
    preds = [ID2LABEL[int(value)] for value in np.argmax(probs, axis=1).tolist()]
    return probs, preds


def baseline_predictions(frame, baseline_model):
    raw_texts = frame["text"].astype(str).tolist()
    normalized = [normalize_text(text) for text in raw_texts]
    indicators = [
        analyze_text(text, normalized=norm)
        for text, norm in zip(raw_texts, normalized)
    ]
    probs = baseline_model.predict_proba(
        raw_texts,
        normalized=normalized,
        indicators=indicators,
    )
    preds = [LABELS[int(value)] for value in np.argmax(probs, axis=1).tolist()]
    return probs, preds, normalized, indicators


def measure_baseline_latency(frame, baseline_model, normalized, indicators) -> dict:
    raw_texts = frame["text"].astype(str).tolist()
    baseline_model.predict_proba(raw_texts, normalized=normalized, indicators=indicators)
    start = time.perf_counter()
    baseline_model.predict_proba(raw_texts, normalized=normalized, indicators=indicators)
    batch_seconds = time.perf_counter() - start

    single_count = min(100, len(raw_texts))
    for index in range(min(5, single_count)):
        norm = normalize_text(raw_texts[index])
        ind = analyze_text(raw_texts[index], normalized=norm)
        baseline_model.predict_proba([raw_texts[index]], normalized=[norm], indicators=[ind])
    start = time.perf_counter()
    for index in range(single_count):
        norm = normalize_text(raw_texts[index])
        ind = analyze_text(raw_texts[index], normalized=norm)
        baseline_model.predict_proba([raw_texts[index]], normalized=[norm], indicators=[ind])
    single_seconds = time.perf_counter() - start
    return {
        "batch_rows": len(raw_texts),
        "batch_seconds_preprocessed": batch_seconds,
        "batch_ms_per_message": 1000 * batch_seconds / len(raw_texts),
        "single_iterations": single_count,
        "single_ms_per_message_end_to_end": 1000 * single_seconds / single_count,
        "note": "Baseline batch timing starts after normalization and indicator extraction; single timing includes both.",
    }


def measure_mobilebert_latency(model, tokenizer, texts, encoding, batch_size, max_length) -> dict:
    model.eval()
    with torch.inference_mode():
        for start in range(0, min(5, len(texts)), batch_size):
            batch = batch_from_encoding(tokenizer, encoding, list(range(start, min(start + batch_size, len(texts)))))
            model(**batch)

    start = time.perf_counter()
    encoding_inclusive = encode_texts(tokenizer, texts, max_length)
    with torch.inference_mode():
        for indices in iter_batches(list(range(len(texts))), batch_size):
            batch = batch_from_encoding(tokenizer, encoding_inclusive, indices)
            model(**batch)
    batch_seconds = time.perf_counter() - start

    start = time.perf_counter()
    with torch.inference_mode():
        for indices in iter_batches(list(range(len(texts))), batch_size):
            batch = batch_from_encoding(tokenizer, encoding, indices)
            model(**batch)
    forward_seconds = time.perf_counter() - start

    single_count = min(100, len(texts))
    for index in range(min(5, single_count)):
        single = tokenizer(
            [texts[index]],
            padding=True,
            truncation=True,
            max_length=max_length,
            return_tensors="pt",
        )
        with torch.inference_mode():
            model(**single)
    start = time.perf_counter()
    for index in range(single_count):
        single = tokenizer(
            [texts[index]],
            padding=True,
            truncation=True,
            max_length=max_length,
            return_tensors="pt",
        )
        with torch.inference_mode():
            model(**single)
    single_seconds = time.perf_counter() - start

    return {
        "batch_rows": len(texts),
        "batch_seconds_end_to_end": batch_seconds,
        "batch_ms_per_message_end_to_end": 1000 * batch_seconds / len(texts),
        "batch_seconds_forward_only": forward_seconds,
        "batch_ms_per_message_forward_only": 1000 * forward_seconds / len(texts),
        "single_iterations": single_count,
        "single_ms_per_message_end_to_end": 1000 * single_seconds / single_count,
        "note": "End-to-end includes tokenization and dynamic padding; forward-only starts from pre-tokenized inputs.",
    }


def comparison_markdown(result: dict) -> str:
    baseline = result["baseline_metrics"]
    mobile = result["mobilebert_metrics"]
    rows = [
        ("Accuracy", "accuracy", "{:.4f}", True),
        ("Macro-F1", "macro_f1", "{:.4f}", True),
        ("Smishing recall", "smishing_recall", "{:.4f}", True),
        ("Smishing precision", "smishing_precision", "{:.4f}", True),
        ("Ham false-positive rate", "ham_false_positive_rate", "{:.4f}", False),
    ]
    lines = [
        "# MobileBERT vs TF-IDF — aggregate comparison",
        "",
        f"Evaluation split: `{result['split']}` ({result['rows']} rows).",
        "Both models were evaluated on the same rows in the same order; the "
        "message-id and prediction hashes are recorded in the JSON result.",
        "",
        "MobileBERT is the documented 22-layer stability variant of "
        "`google/mobilebert-uncased`; it is not a standard 24-layer result.",
        "Only classifier outputs are compared. The existing risk-policy "
        "thresholds are not applied to MobileBERT.",
        "",
        "| Metric | TF-IDF E1b | MobileBERT-22 | Difference |",
        "|---|---:|---:|---:|",
    ]
    for label, key, fmt, higher_is_better in rows:
        base = baseline[key]
        mob = mobile[key]
        delta = mob - base
        lines.append(
            f"| {label} | {fmt.format(base)} | {fmt.format(mob)} | {delta:+.4f} |"
        )
    lines.extend(
        [
            "",
            "## Per-class metrics",
            "",
            "| Class | Model | Precision | Recall | F1 | Support |",
            "|---|---|---:|---:|---:|---:|",
        ]
    )
    for class_name in LABELS:
        for model_name, metrics in (("TF-IDF", baseline), ("MobileBERT-22", mobile)):
            row = metrics["per_class"][class_name]
            lines.append(
                f"| {class_name} | {model_name} | {row['precision']:.4f} | "
                f"{row['recall']:.4f} | {row['f1']:.4f} | {row['support']} |"
            )
    lines.extend(
        [
            "",
            "## Caveats",
            "",
            "- The 24-layer pretrained model produced extreme final-layer activations "
            "in the Hugging Face implementation; the final two encoder layers were "
            "omitted for this run.",
            "- Scores are classifier outputs, not calibrated probabilities.",
            "- The test split was loaded only by this evaluation script, after model "
            "selection and early stopping were complete.",
            "- This is a single test evaluation; no test-set tuning was performed.",
        ]
    )
    return "\n".join(lines) + "\n"


def main() -> None:
    args = parse_args()
    configure_cpu_threads(args.threads)
    seed_everything(args.seed)
    suffix = args.output_suffix or args.split
    results_dir = EXPERIMENT_DIR / "results"
    results_dir.mkdir(parents=True, exist_ok=True)

    checkpoint = Path(args.checkpoint) if args.checkpoint else (
        EXPERIMENT_DIR / "checkpoints" / "mobilebert22_lr5e5_bs16_e4" / "best"
    )
    if not checkpoint.exists():
        raise FileNotFoundError(f"checkpoint not found: {checkpoint}")

    frame = load_split(args.split)
    texts = frame["text"].astype(str).tolist()
    model_texts = frame["model_text"].tolist()
    y_true = frame["label"].astype(str).tolist()
    labels = torch.tensor([LABELS.index(label) for label in y_true], dtype=torch.long)

    tokenizer = AutoTokenizer.from_pretrained(checkpoint)
    model = AutoModelForSequenceClassification.from_pretrained(checkpoint)
    model.eval()

    encoding = encode_texts(tokenizer, model_texts, args.max_length)
    mobile_probs, mobile_preds = predict_mobilebert(
        model, tokenizer, encoding, labels, args.batch_size
    )
    mobile_metrics = metrics_from_predictions(y_true, mobile_preds)

    baseline_model = SmsClassifier.load(BASELINE_MODEL_DIR / "model.joblib")
    baseline_probs, baseline_preds, normalized, indicators = baseline_predictions(
        frame, baseline_model
    )
    baseline_metrics = metrics_from_predictions(y_true, baseline_preds)

    if args.split == "test":
        baseline_artifact = json.loads(BASELINE_REPORT.read_text(encoding="utf-8"))["final"]["test"]
        artifact_check = {
            "stored_macro_f1": baseline_artifact["macro_f1"],
            "recomputed_macro_f1": baseline_metrics["macro_f1"],
            "stored_accuracy": baseline_artifact["accuracy"],
            "recomputed_accuracy": baseline_metrics["accuracy"],
            "stored_smishing_recall": baseline_artifact["smishing_recall"],
            "recomputed_smishing_recall": baseline_metrics["smishing_recall"],
            "matches": all(
                abs(float(baseline_artifact[key]) - float(baseline_metrics[key])) < 1e-12
                for key in ("macro_f1", "accuracy", "smishing_recall")
            ),
        }
    else:
        artifact_check = {"skipped": "baseline artifact check is defined only for the locked test split"}

    mobile_ids = frame["message_id"].astype(str).tolist()
    same_examples = {
        "both_models_used_same_frame": True,
        "rows": len(frame),
        "baseline_rows": len(baseline_preds),
        "mobilebert_rows": len(mobile_preds),
        "rows_match": len(baseline_preds) == len(mobile_preds) == len(y_true),
        "labels_match": sha256_text_lines(y_true) == sha256_text_lines(
            frame["label"].astype(str).tolist()
        ),
        "message_id_sha256": sha256_text_lines(mobile_ids),
        "labels_sha256": sha256_text_lines(y_true),
        "baseline_prediction_sha256": sha256_text_lines(baseline_preds),
        "mobilebert_prediction_sha256": sha256_text_lines(mobile_preds),
        "disagreement_rows": int(sum(a != b for a, b in zip(baseline_preds, mobile_preds))),
    }

    baseline_latency = measure_baseline_latency(frame, baseline_model, normalized, indicators)
    mobile_latency = measure_mobilebert_latency(
        model, tokenizer, model_texts, encoding, args.batch_size, args.max_length
    )

    model_size = {
        "baseline_model_bytes": (BASELINE_MODEL_DIR / "model.joblib").stat().st_size,
        "mobilebert_checkpoint_bytes": tree_size_bytes(checkpoint),
        "mobilebert_parameter_count": int(model_summary(model)["total_parameters"]),
        "baseline_feature_count": int(
            len(baseline_model.word_vectorizer.vocabulary_) if baseline_model.word_vectorizer else 0
        ),
        "mobilebert_checkpoint_files": {
            str(path.relative_to(checkpoint)): path.stat().st_size
            for path in sorted(checkpoint.rglob("*"))
            if path.is_file()
        },
    }

    result = {
        "created_utc": timestamp_utc(),
        "split": args.split,
        "rows": len(frame),
        "checkpoint": str(checkpoint),
        "labels": list(LABELS),
        "mobilebert_model": "google/mobilebert-uncased 22-layer stability variant",
        "mobilebert_num_hidden_layers": int(model.config.num_hidden_layers),
        "test_split_loaded_by_this_script": args.split == "test",
        "baseline_metrics": baseline_metrics,
        "mobilebert_metrics": mobile_metrics,
        "delta_mobilebert_minus_baseline": {
            key: float(mobile_metrics[key] - baseline_metrics[key])
            for key in ("accuracy", "macro_f1", "smishing_recall", "smishing_precision", "ham_false_positive_rate")
        },
        "baseline_artifact_check": artifact_check,
        "same_examples": same_examples,
        "latency": {"baseline": baseline_latency, "mobilebert": mobile_latency},
        "model_size": model_size,
        "environment": {
            "torch": torch.__version__,
            "cuda_available": torch.cuda.is_available(),
            "threads": torch.get_num_threads(),
            "available_ram_mb": available_ram_mb(),
            "rss_mb": rss_mb(),
        },
        "hashes": {
            "split_csv_sha256": sha256_file(EXPERIMENT_DIR.parents[1] / "data" / "processed" / f"{args.split}.csv"),
            "baseline_model_sha256": sha256_file(BASELINE_MODEL_DIR / "model.joblib"),
        },
        "per_example_written": args.write_per_example,
        "policy_note": "Classifier-only comparison; existing risk thresholds were not applied to MobileBERT.",
    }

    json_dump(results_dir / f"test_metrics_{suffix}.json", result)
    (results_dir / f"comparison_{suffix}.md").write_text(
        comparison_markdown(result), encoding="utf-8"
    )

    if args.write_per_example:
        per_example = pd.DataFrame(
            {
                "message_id": frame["message_id"].astype(str),
                "true_label": y_true,
                "baseline_pred": baseline_preds,
                "mobilebert_pred": mobile_preds,
                "baseline_p_ham": baseline_probs[:, 0],
                "baseline_p_spam": baseline_probs[:, 1],
                "baseline_p_smishing": baseline_probs[:, 2],
                "mobilebert_p_ham": mobile_probs[:, 0],
                "mobilebert_p_spam": mobile_probs[:, 1],
                "mobilebert_p_smishing": mobile_probs[:, 2],
            }
        )
        per_example.to_csv(
            results_dir / f"test_predictions_{suffix}.csv",
            index=False,
            encoding="utf-8",
        )

    print(json.dumps(result, indent=2))
    print("wrote", results_dir / f"test_metrics_{suffix}.json")
    print("wrote", results_dir / f"comparison_{suffix}.md")


if __name__ == "__main__":
    main()
