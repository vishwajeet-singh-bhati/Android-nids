"""Final FP32 / PTQ / QAT comparison on the locked test split.

This is the only script that loads test.csv. It must be run only after QAT and
PTQ checkpoints and .pte artifacts are frozen.
"""

from __future__ import annotations

import argparse
import json
import statistics
import time
import traceback
from pathlib import Path

import numpy as np
import pandas as pd
import torch

from qat_common import (
    ARTIFACTS_DIR,
    BASE_CHECKPOINT,
    CHECKPOINTS_DIR,
    CONFIG_PATH,
    DEFAULT_EVAL_BATCH_SIZE,
    DEFAULT_MAX_LENGTH,
    DEFAULT_SEED,
    LABELS,
    LOGS_DIR,
    REPO_ROOT,
    RESULTS_DIR,
    ExportWrapper,
    configure_environment,
    file_sha256,
    file_size_bytes,
    iter_fixed_batches,
    load_base_model_and_tokenizer,
    load_encoded_split,
    load_json,
    load_ptq_converted,
    load_qat_converted,
    metrics_for_logits,
    predict_logits,
    rss_snapshot,
    save_json,
    setup_logger,
    synthetic_inputs,
    timestamp_utc,
)

QAT_CHECKPOINT = CHECKPOINTS_DIR / "qat_lr1e5_bs16_e2_best.pt"
PTQ_CHECKPOINT = CHECKPOINTS_DIR / "ptq_static_int8_prepared.pt"
QAT_PTE_B16 = ARTIFACTS_DIR / "qat_int8_b16.pte"
QAT_PTE_B1 = ARTIFACTS_DIR / "qat_int8_b1.pte"
PTQ_PTE_B16 = ARTIFACTS_DIR / "ptq_int8_b16.pte"
PTQ_PTE_B1 = ARTIFACTS_DIR / "ptq_int8_b1.pte"
TEST_CSV = REPO_ROOT / "data" / "processed" / "test.csv"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", default="comparison_test")
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--threads", type=int, default=8)
    return parser.parse_args()


def directory_size_bytes(path: Path) -> int:
    if not path.exists():
        return 0
    return int(sum(item.stat().st_size for item in path.rglob("*") if item.is_file()))


def load_pte(path: Path):
    from executorch.runtime import Runtime

    if not path.exists():
        raise FileNotFoundError(path)
    runtime = Runtime.get()
    program = runtime.load_program(str(path))
    method = program.load_method("forward")
    return program, method


def pte_logits(method, tokenizer, encoding, batch_size: int, max_length: int):
    chunks = []
    for _, tensors, actual in iter_fixed_batches(
        tokenizer, encoding, batch_size=batch_size, max_length=max_length
    ):
        output = method.execute(list(tensors))[0]
        logits = torch.from_numpy(np.asarray(output)).float()
        chunks.append(logits[:actual])
    return torch.cat(chunks, dim=0)


def benchmark(fn, *, warmup: int = 2, repeats: int = 5) -> dict:
    for _ in range(warmup):
        fn()
    runs = []
    for _ in range(repeats):
        start = time.perf_counter()
        fn()
        runs.append(time.perf_counter() - start)
    ordered = sorted(runs)
    return {
        "runs_seconds": [float(value) for value in runs],
        "median_seconds": float(statistics.median(runs)),
        "min_seconds": float(ordered[0]),
        "max_seconds": float(ordered[-1]),
    }


def logits_comparison(left: torch.Tensor, right: torch.Tensor) -> dict:
    difference = (left - right).abs()
    return {
        "rows": int(left.shape[0]),
        "max_abs_diff": float(difference.max()),
        "mean_abs_diff": float(difference.mean()),
        "argmax_agreement": float(
            (left.argmax(dim=-1) == right.argmax(dim=-1)).float().mean()
        ),
    }


def write_predictions(
    path: Path,
    frame: pd.DataFrame,
    labels: list[str],
    logits: torch.Tensor,
    predictions: list[str],
) -> None:
    payload = {
        "message_id": frame["message_id"].astype(str).tolist(),
        "label": labels,
        "prediction": predictions,
        "logit_ham": logits[:, 0].tolist(),
        "logit_spam": logits[:, 1].tolist(),
        "logit_smishing": logits[:, 2].tolist(),
    }
    pd.DataFrame(payload).to_csv(path, index=False)


def confusion_markdown(metrics: dict) -> list[str]:
    matrix = metrics["confusion_matrix"]
    labels = metrics["confusion_matrix_labels"]
    lines = [
        "| true \\ predicted | " + " | ".join(labels) + " |",
        "|---|" + "---:|" * len(labels),
    ]
    for index, label in enumerate(labels):
        lines.append(
            f"| {label} | " + " | ".join(str(int(value)) for value in matrix[index]) + " |"
        )
    return lines


def metric_row(name: str, metrics: dict, latency: dict | None = None) -> str:
    latency_text = ""
    if latency is not None:
        latency_text = f" | {latency['median_seconds'] * 1000:.2f}"
    return (
        f"| {name} | {metrics['accuracy']:.6f} | {metrics['macro_f1']:.6f} | "
        f"{metrics['smishing_precision']:.6f} | {metrics['smishing_recall']:.6f} | "
        f"{metrics['ham_false_positive_rate']:.6f}{latency_text} |"
    )


def main() -> None:
    args = parse_args()
    actual_threads = configure_environment(seed=args.seed, threads=args.threads)
    config = load_json(CONFIG_PATH)
    max_length = int(config.get("max_length", DEFAULT_MAX_LENGTH))
    batch_size = int(config.get("eval_batch_size", DEFAULT_EVAL_BATCH_SIZE))
    qat_scope = str(config.get("qat", {}).get("quantization_scope", "linear_only"))
    ptq_scope = str(config.get("ptq", {}).get("quantization_scope", "linear_only"))
    log_path = LOGS_DIR / f"{args.tag}.log"
    logger = setup_logger(f"evaluate_{args.tag}", log_path)
    logger.info(
        "Starting final comparison tag=%s threads=%s batch_size=%s",
        args.tag,
        actual_threads,
        batch_size,
    )
    logger.info("Base FP32 checkpoint: %s", BASE_CHECKPOINT)

    for path in (QAT_CHECKPOINT, PTQ_CHECKPOINT, QAT_PTE_B16, QAT_PTE_B1):
        if not path.exists():
            raise FileNotFoundError(f"Required artifact missing: {path}")

    rss_baseline = rss_snapshot()
    model, tokenizer = load_base_model_and_tokenizer()
    wrapper = ExportWrapper(model).eval()
    test_frame, test_encoding, test_labels = load_encoded_split("test", tokenizer)
    test_hash = file_sha256(TEST_CSV) if TEST_CSV.exists() else None
    logger.info(
        "Test rows=%s label_counts=%s hash=%s",
        len(test_labels),
        test_frame["label"].value_counts().to_dict(),
        test_hash,
    )
    rss_after_test_load = rss_snapshot()

    inputs16 = synthetic_inputs(tokenizer, batch_size, max_length=max_length)
    inputs1 = synthetic_inputs(tokenizer, 1, max_length=max_length)

    # FP32 reference through the same normalized, truncated, fixed-padded inputs.
    fp32_logits = predict_logits(
        wrapper, tokenizer, test_encoding, batch_size=batch_size, max_length=max_length
    )
    fp32_metrics, fp32_preds = metrics_for_logits(test_labels, fp32_logits)
    write_predictions(
        RESULTS_DIR / "predictions_fp32.csv",
        test_frame,
        test_labels,
        fp32_logits,
        fp32_preds,
    )
    logger.info("FP32 macro_f1=%.6f accuracy=%.6f", fp32_metrics["macro_f1"], fp32_metrics["accuracy"])
    rss_after_fp32 = rss_snapshot()

    ptq16, ptq_payload = load_ptq_converted(
        PTQ_CHECKPOINT, wrapper, inputs16, scope=ptq_scope
    )
    qat16, qat_payload = load_qat_converted(
        QAT_CHECKPOINT, wrapper, inputs16, scope=qat_scope
    )
    logger.info(
        "Loaded PTQ/QAT converted models; PTQ val macro_f1=%s QAT val macro_f1=%s",
        (ptq_payload.get("val_metrics") or {}).get("macro_f1"),
        (qat_payload.get("val_metrics") or {}).get("macro_f1"),
    )

    ptq_logits = predict_logits(
        ptq16, tokenizer, test_encoding, batch_size=batch_size, max_length=max_length
    )
    qat_logits = predict_logits(
        qat16, tokenizer, test_encoding, batch_size=batch_size, max_length=max_length
    )
    ptq_metrics, ptq_preds = metrics_for_logits(test_labels, ptq_logits)
    qat_metrics, qat_preds = metrics_for_logits(test_labels, qat_logits)
    write_predictions(
        RESULTS_DIR / "predictions_ptq.csv",
        test_frame,
        test_labels,
        ptq_logits,
        ptq_preds,
    )
    write_predictions(
        RESULTS_DIR / "predictions_qat.csv",
        test_frame,
        test_labels,
        qat_logits,
        qat_preds,
    )
    logger.info("PTQ macro_f1=%.6f accuracy=%.6f", ptq_metrics["macro_f1"], ptq_metrics["accuracy"])
    logger.info("QAT macro_f1=%.6f accuracy=%.6f", qat_metrics["macro_f1"], qat_metrics["accuracy"])
    rss_after_ptq_qat = rss_snapshot()

    # Batch-1 PyTorch models are needed to verify the deployment-shaped .pte.
    qat1, _ = load_qat_converted(
        QAT_CHECKPOINT, wrapper, inputs1, scope=qat_scope
    )
    ptq1, _ = load_ptq_converted(
        PTQ_CHECKPOINT, wrapper, inputs1, scope=ptq_scope
    )
    qat_logits_b1 = predict_logits(
        qat1, tokenizer, test_encoding, batch_size=1, max_length=max_length
    )
    ptq_logits_b1 = predict_logits(
        ptq1, tokenizer, test_encoding, batch_size=1, max_length=max_length
    )
    qat_metrics_b1, qat_preds_b1 = metrics_for_logits(test_labels, qat_logits_b1)
    ptq_metrics_b1, ptq_preds_b1 = metrics_for_logits(test_labels, ptq_logits_b1)
    write_predictions(
        RESULTS_DIR / "predictions_qat_b1.csv",
        test_frame,
        test_labels,
        qat_logits_b1,
        qat_preds_b1,
    )
    write_predictions(
        RESULTS_DIR / "predictions_ptq_b1.csv",
        test_frame,
        test_labels,
        ptq_logits_b1,
        ptq_preds_b1,
    )
    logger.info(
        "Batch-1 PyTorch: QAT macro_f1=%.6f PTQ macro_f1=%.6f",
        qat_metrics_b1["macro_f1"],
        ptq_metrics_b1["macro_f1"],
    )

    # Load and execute the exported .pte artifacts.
    qat_program_b16, qat_method_b16 = load_pte(QAT_PTE_B16)
    qat_program_b1, qat_method_b1 = load_pte(QAT_PTE_B1)
    qat_pte_logits_b16 = pte_logits(qat_method_b16, tokenizer, test_encoding, batch_size, max_length)
    qat_pte_logits_b1 = pte_logits(qat_method_b1, tokenizer, test_encoding, 1, max_length)
    qat_pte_metrics_b16, qat_pte_preds_b16 = metrics_for_logits(test_labels, qat_pte_logits_b16)
    qat_pte_metrics_b1, qat_pte_preds_b1 = metrics_for_logits(test_labels, qat_pte_logits_b1)
    write_predictions(
        RESULTS_DIR / "predictions_qat_pte_b16.csv",
        test_frame,
        test_labels,
        qat_pte_logits_b16,
        qat_pte_preds_b16,
    )
    write_predictions(
        RESULTS_DIR / "predictions_qat_pte_b1.csv",
        test_frame,
        test_labels,
        qat_pte_logits_b1,
        qat_pte_preds_b1,
    )
    logger.info(
        "QAT .pte: b16 macro_f1=%.6f b1 macro_f1=%.6f",
        qat_pte_metrics_b16["macro_f1"],
        qat_pte_metrics_b1["macro_f1"],
    )

    ptq_pte_metrics_b16 = None
    ptq_pte_metrics_b1 = None
    ptq_pte_logits_b16 = None
    ptq_pte_logits_b1 = None
    if PTQ_PTE_B16.exists():
        ptq_program_b16, ptq_method_b16 = load_pte(PTQ_PTE_B16)
        ptq_pte_logits_b16 = pte_logits(ptq_method_b16, tokenizer, test_encoding, batch_size, max_length)
        ptq_pte_metrics_b16, ptq_pte_preds_b16 = metrics_for_logits(test_labels, ptq_pte_logits_b16)
        write_predictions(
            RESULTS_DIR / "predictions_ptq_pte_b16.csv",
            test_frame,
            test_labels,
            ptq_pte_logits_b16,
            ptq_pte_preds_b16,
        )
    if PTQ_PTE_B1.exists():
        ptq_program_b1, ptq_method_b1 = load_pte(PTQ_PTE_B1)
        ptq_pte_logits_b1 = pte_logits(ptq_method_b1, tokenizer, test_encoding, 1, max_length)
        ptq_pte_metrics_b1, ptq_pte_preds_b1 = metrics_for_logits(test_labels, ptq_pte_logits_b1)
        write_predictions(
            RESULTS_DIR / "predictions_ptq_pte_b1.csv",
            test_frame,
            test_labels,
            ptq_pte_logits_b1,
            ptq_pte_preds_b1,
        )
    rss_after_pte = rss_snapshot()

    with torch.inference_mode():
        fp32_latency_b1 = benchmark(lambda: wrapper(*inputs1))
        fp32_latency_b16 = benchmark(lambda: wrapper(*inputs16))
        ptq_latency_b1 = benchmark(lambda: ptq1(*inputs1))
        ptq_latency_b16 = benchmark(lambda: ptq16(*inputs16))
        qat_latency_b1 = benchmark(lambda: qat1(*inputs1))
        qat_latency_b16 = benchmark(lambda: qat16(*inputs16))
    qat_pte_latency_b1 = benchmark(lambda: qat_method_b1.execute(list(inputs1)))
    qat_pte_latency_b16 = benchmark(lambda: qat_method_b16.execute(list(inputs16)))
    ptq_pte_latency_b1 = (
        benchmark(lambda: ptq_method_b1.execute(list(inputs1)))
        if PTQ_PTE_B1.exists()
        else None
    )
    ptq_pte_latency_b16 = (
        benchmark(lambda: ptq_method_b16.execute(list(inputs16)))
        if PTQ_PTE_B16.exists()
        else None
    )

    export_qat_b16 = load_json(RESULTS_DIR / "export_qat_int8_b16.json") if (RESULTS_DIR / "export_qat_int8_b16.json").exists() else {}
    export_qat_b1 = load_json(RESULTS_DIR / "export_qat_int8_b1.json") if (RESULTS_DIR / "export_qat_int8_b1.json").exists() else {}
    export_ptq_b16 = load_json(RESULTS_DIR / "export_ptq_int8_b16.json") if (RESULTS_DIR / "export_ptq_int8_b16.json").exists() else {}

    comparison = {
        "created_utc": timestamp_utc(),
        "status": "ok",
        "test": {
            "split": "locked test",
            "rows": len(test_labels),
            "label_counts": test_frame["label"].value_counts().to_dict(),
            "sha256": test_hash,
            "loaded_for_training": False,
            "loaded_for_model_selection": False,
            "prior_use": "FP32 final evaluation was already performed once; this is a repeated final comparison.",
        },
        "inputs": {
            "max_length": max_length,
            "eval_batch_size": batch_size,
            "preprocessing": "existing normalize_text(...).model_text and tokenizer; fixed padding only for export shapes",
            "same_examples_for_all_models": True,
        },
        "models": {
            "fp32": {
                "metrics": fp32_metrics,
                "checkpoint_bytes": directory_size_bytes(BASE_CHECKPOINT),
                "latency_b1": fp32_latency_b1,
                "latency_b16": fp32_latency_b16,
            },
            "ptq": {
                "metrics": ptq_metrics,
                "metrics_b1": ptq_metrics_b1,
                "checkpoint_bytes": file_size_bytes(PTQ_CHECKPOINT),
                "latency_b1": ptq_latency_b1,
                "latency_b16": ptq_latency_b16,
            },
            "qat": {
                "metrics": qat_metrics,
                "metrics_b1": qat_metrics_b1,
                "checkpoint_bytes": file_size_bytes(QAT_CHECKPOINT),
                "latency_b1": qat_latency_b1,
                "latency_b16": qat_latency_b16,
                "validation_metrics": qat_payload.get("val_metrics"),
            },
            "qat_pte_b16": {
                "metrics": qat_pte_metrics_b16,
                "pte_bytes": file_size_bytes(QAT_PTE_B16),
                "latency_b16": qat_pte_latency_b16,
            },
            "qat_pte_b1": {
                "metrics": qat_pte_metrics_b1,
                "pte_bytes": file_size_bytes(QAT_PTE_B1),
                "latency_b1": qat_pte_latency_b1,
            },
            "ptq_pte_b16": {
                "metrics": ptq_pte_metrics_b16,
                "pte_bytes": file_size_bytes(PTQ_PTE_B16),
                "latency_b16": ptq_pte_latency_b16,
            } if ptq_pte_metrics_b16 is not None else None,
            "ptq_pte_b1": {
                "metrics": ptq_pte_metrics_b1,
                "pte_bytes": file_size_bytes(PTQ_PTE_B1),
                "latency_b1": ptq_pte_latency_b1,
            } if ptq_pte_metrics_b1 is not None else None,
        },
        "pte_verification": {
            "qat_pte_b16_vs_qat_pytorch_b16": logits_comparison(qat_pte_logits_b16, qat_logits),
            "qat_pte_b1_vs_qat_pytorch_b1": logits_comparison(qat_pte_logits_b1, qat_logits_b1),
            "ptq_pte_b16_vs_ptq_pytorch_b16": logits_comparison(ptq_pte_logits_b16, ptq_logits) if ptq_pte_logits_b16 is not None else None,
            "ptq_pte_b1_vs_ptq_pytorch_b1": logits_comparison(ptq_pte_logits_b1, ptq_logits_b1) if ptq_pte_logits_b1 is not None else None,
            "qat_pte_b16_vs_fp32": logits_comparison(qat_pte_logits_b16, fp32_logits),
            "qat_pte_b1_vs_fp32": logits_comparison(qat_pte_logits_b1, fp32_logits),
        },
        "precision": {
            "qat_b16": export_qat_b16.get("precision"),
            "qat_b1": export_qat_b1.get("precision"),
            "ptq_b16": export_ptq_b16.get("precision"),
        },
        "sizes": {
            "fp32_checkpoint_bytes": directory_size_bytes(BASE_CHECKPOINT),
            "ptq_prepared_checkpoint_bytes": file_size_bytes(PTQ_CHECKPOINT),
            "qat_best_checkpoint_bytes": file_size_bytes(QAT_CHECKPOINT),
            "qat_pte_b16_bytes": file_size_bytes(QAT_PTE_B16),
            "qat_pte_b1_bytes": file_size_bytes(QAT_PTE_B1),
            "ptq_pte_b16_bytes": file_size_bytes(PTQ_PTE_B16),
            "ptq_pte_b1_bytes": file_size_bytes(PTQ_PTE_B1),
        },
        "rss_mib": {
            "baseline": rss_baseline,
            "after_test_load": rss_after_test_load,
            "after_fp32": rss_after_fp32,
            "after_ptq_qat_pytorch": rss_after_ptq_qat,
            "after_pte_load": rss_after_pte,
            "note": "Cumulative process RSS; not an isolated peak-RSS measurement.",
        },
        "limitations": [
            "QAT graph was captured in eval mode, so dropout was disabled during QAT fine-tuning.",
            "The exported model is hybrid INT8/FP32, not fully INT8.",
            "Global add/mul activation quantization collapsed validation smishing recall to 0; the final QAT/PTQ models therefore use the linear-only scope.",
            "XNNPACK partitioning produced many delegate segments; latency improvement is not assumed.",
            "The locked test split was already evaluated once for FP32; this is a repeated final comparison.",
            "Only 49 smishing examples are present in the test split.",
            "Windows CPU only; no Android or phone latency claim.",
        ],
        "config": config,
    }

    save_json(RESULTS_DIR / f"{args.tag}.json", comparison)

    lines = [
        "# MobileBERT-22 FP32 / PTQ / QAT comparison",
        "",
        f"Created: `{comparison['created_utc']}`",
        "",
        "## Test set",
        "",
        f"- Locked test rows: **{len(test_labels)}**",
        f"- Label counts: `{test_frame['label'].value_counts().to_dict()}`",
        f"- SHA-256: `{test_hash}`",
        "- Test loaded only for this final comparison; no QAT training or model selection used it.",
        "",
        "## Accuracy and error metrics",
        "",
        "| Model | Accuracy | Macro-F1 | Smishing precision | Smishing recall | Ham FPR | Latency (ms) |",
        "|---|---:|---:|---:|---:|---:|---:|",
        metric_row("FP32 PyTorch", fp32_metrics, fp32_latency_b16),
        metric_row("PTQ PyTorch", ptq_metrics, ptq_latency_b16),
        metric_row("QAT PyTorch", qat_metrics, qat_latency_b16),
        metric_row("QAT `.pte` b16", qat_pte_metrics_b16, qat_pte_latency_b16),
        metric_row("QAT `.pte` b1", qat_pte_metrics_b1, qat_pte_latency_b1),
    ]
    if ptq_pte_metrics_b16 is not None:
        lines.append(metric_row("PTQ `.pte` b16", ptq_pte_metrics_b16, ptq_pte_latency_b16))
    if ptq_pte_metrics_b1 is not None:
        lines.append(metric_row("PTQ `.pte` b1", ptq_pte_metrics_b1, ptq_pte_latency_b1))
    lines += [
        "",
        "Latency values are PyTorch/ExecuTorch model-forward medians, not end-to-end tokenization latency.",
        "",
        "## Confusion matrices",
        "",
        "### FP32",
        "",
        *confusion_markdown(fp32_metrics),
        "",
        "### PTQ",
        "",
        *confusion_markdown(ptq_metrics),
        "",
        "### QAT",
        "",
        *confusion_markdown(qat_metrics),
        "",
        "### QAT ExecuTorch `.pte`, batch 16",
        "",
        *confusion_markdown(qat_pte_metrics_b16),
        "",
        "## ExecuTorch runtime verification",
        "",
        "| Comparison | Max abs logit diff | Mean abs logit diff | Argmax agreement |",
        "|---|---:|---:|---:|",
    ]
    for name, values in comparison["pte_verification"].items():
        if values is None:
            continue
        lines.append(
            f"| {name} | {values['max_abs_diff']:.6g} | {values['mean_abs_diff']:.6g} | {values['argmax_agreement']:.6f} |"
        )
    lines += [
        "",
        "## Size",
        "",
        "| Artifact | Bytes | MiB |",
        "|---|---:|---:|",
        f"| FP32 checkpoint directory | {comparison['sizes']['fp32_checkpoint_bytes']} | {comparison['sizes']['fp32_checkpoint_bytes'] / 1024 / 1024:.2f} |",
        f"| PTQ prepared checkpoint | {comparison['sizes']['ptq_prepared_checkpoint_bytes']} | {comparison['sizes']['ptq_prepared_checkpoint_bytes'] / 1024 / 1024:.2f} |",
        f"| QAT best checkpoint | {comparison['sizes']['qat_best_checkpoint_bytes']} | {comparison['sizes']['qat_best_checkpoint_bytes'] / 1024 / 1024:.2f} |",
        f"| QAT `.pte` b16 | {comparison['sizes']['qat_pte_b16_bytes']} | {comparison['sizes']['qat_pte_b16_bytes'] / 1024 / 1024:.2f} |",
        f"| QAT `.pte` b1 | {comparison['sizes']['qat_pte_b1_bytes']} | {comparison['sizes']['qat_pte_b1_bytes'] / 1024 / 1024:.2f} |",
        f"| PTQ `.pte` b16 | {comparison['sizes']['ptq_pte_b16_bytes']} | {comparison['sizes']['ptq_pte_b16_bytes'] / 1024 / 1024:.2f} |",
        f"| PTQ `.pte` b1 | {comparison['sizes']['ptq_pte_b1_bytes']} | {comparison['sizes']['ptq_pte_b1_bytes'] / 1024 / 1024:.2f} |",
        "",
        "## Latency",
        "",
        "| Model | Batch 1 median (ms) | Batch 16 median (ms) | Batch 16 ms/message |",
        "|---|---:|---:|---:|",
        f"| FP32 PyTorch | {fp32_latency_b1['median_seconds'] * 1000:.2f} | {fp32_latency_b16['median_seconds'] * 1000:.2f} | {fp32_latency_b16['median_seconds'] / 16 * 1000:.2f} |",
        f"| PTQ PyTorch | {ptq_latency_b1['median_seconds'] * 1000:.2f} | {ptq_latency_b16['median_seconds'] * 1000:.2f} | {ptq_latency_b16['median_seconds'] / 16 * 1000:.2f} |",
        f"| QAT PyTorch | {qat_latency_b1['median_seconds'] * 1000:.2f} | {qat_latency_b16['median_seconds'] * 1000:.2f} | {qat_latency_b16['median_seconds'] / 16 * 1000:.2f} |",
        f"| QAT `.pte` | {qat_pte_latency_b1['median_seconds'] * 1000:.2f} | {qat_pte_latency_b16['median_seconds'] * 1000:.2f} | {qat_pte_latency_b16['median_seconds'] / 16 * 1000:.2f} |",
    ]
    if ptq_pte_latency_b16 is not None and ptq_pte_latency_b1 is not None:
        lines.append(
            f"| PTQ `.pte` | {ptq_pte_latency_b1['median_seconds'] * 1000:.2f} | {ptq_pte_latency_b16['median_seconds'] * 1000:.2f} | {ptq_pte_latency_b16['median_seconds'] / 16 * 1000:.2f} |"
        )
    lines += [
        "",
        "## Precision and unsupported operators",
        "",
    ]
    for label, export_payload in (
        ("QAT b16", export_qat_b16),
        ("QAT b1", export_qat_b1),
        ("PTQ b16", export_ptq_b16),
    ):
        if not export_payload:
            lines.append(f"- {label}: export summary missing")
            continue
        precision = export_payload.get("precision", {})
        graph = precision.get("graph", {})
        edge = precision.get("edge", {})
        lines.append(
            f"- {label}: `.pte` {export_payload.get('pte_bytes')} bytes; "
            f"delegate calls {edge.get('delegate_calls')}; "
            f"int8 tensors {graph.get('int8_tensor_count')}; "
            f"state dtypes {graph.get('state_dtypes')}."
        )
        ops = edge.get("aten_and_delegate_ops", {})
        non_delegate = {
            key: value for key, value in ops.items() if "executorch_call_delegate" not in key
        }
        lines.append(f"  - Non-delegate ops: `{non_delegate}`")
    lines += [
        "",
        "## RAM",
        "",
        f"Cumulative process RSS (MiB): `{comparison['rss_mib']}`",
        "",
        "## Limitations",
        "",
        *[f"- {item}" for item in comparison["limitations"]],
        "",
        "## Artifact paths",
        "",
        f"- QAT `.pte` batch 1: `{QAT_PTE_B1}`",
        f"- QAT `.pte` batch 16: `{QAT_PTE_B16}`",
        f"- PTQ `.pte` batch 1: `{PTQ_PTE_B1}`",
        f"- PTQ `.pte` batch 16: `{PTQ_PTE_B16}`",
        f"- Full JSON: `{RESULTS_DIR / f'{args.tag}.json'}`",
    ]
    (RESULTS_DIR / f"{args.tag}.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    logger.info("Wrote %s and %s", RESULTS_DIR / f"{args.tag}.json", RESULTS_DIR / f"{args.tag}.md")
    logger.info("Comparison complete: %s", json.dumps(comparison, indent=2))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        configure_environment()
        logger = setup_logger("evaluate_failure", LOGS_DIR / "evaluate_failure.log")
        failure = {
            "created_utc": timestamp_utc(),
            "status": "failed",
            "error_type": type(error).__name__,
            "error": str(error),
            "traceback": traceback.format_exc(),
        }
        save_json(RESULTS_DIR / "evaluate_failure.json", failure)
        logger.exception("Evaluation failed")
        raise
