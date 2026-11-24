"""Static PTQ baseline for the same MobileBERT-22 checkpoint.

Calibration uses only train.csv. No test split or handmade examples are read.
"""

from __future__ import annotations

import argparse
import json
import time
import traceback
from pathlib import Path

import torch

from qat_common import (
    BASE_CHECKPOINT,
    CHECKPOINTS_DIR,
    CONFIG_PATH,
    DEFAULT_BATCH_SIZE,
    DEFAULT_EVAL_BATCH_SIZE,
    DEFAULT_MAX_LENGTH,
    DEFAULT_SEED,
    LOGS_DIR,
    RESULTS_DIR,
    ExportWrapper,
    configure_environment,
    convert_prepared,
    count_fake_quant_modules,
    graph_summary,
    iter_fixed_batches,
    load_base_model_and_tokenizer,
    load_encoded_split,
    load_json,
    metrics_for_logits,
    predict_logits,
    prepare_ptq_graph,
    rss_snapshot,
    save_json,
    set_observers,
    setup_logger,
    synthetic_inputs,
    timestamp_utc,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", default="ptq_static_int8")
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--threads", type=int, default=8)
    parser.add_argument(
        "--calibration-batches",
        type=int,
        default=0,
        help="0 means all train batches; otherwise cap calibration batches.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    actual_threads = configure_environment(seed=args.seed, threads=args.threads)
    config = load_json(CONFIG_PATH)
    batch_size = int(config.get("batch_size", DEFAULT_BATCH_SIZE))
    eval_batch_size = int(config.get("eval_batch_size", DEFAULT_EVAL_BATCH_SIZE))
    max_length = int(config.get("max_length", DEFAULT_MAX_LENGTH))
    quantization_scope = str(config.get("ptq", {}).get("quantization_scope", "linear_only"))
    log_path = LOGS_DIR / f"{args.tag}.log"
    logger = setup_logger(f"ptq_{args.tag}", log_path)
    logger.info("Starting PTQ baseline tag=%s threads=%s", args.tag, actual_threads)
    logger.info("Base checkpoint: %s", BASE_CHECKPOINT)

    model, tokenizer = load_base_model_and_tokenizer()
    wrapper = ExportWrapper(model).eval()
    train_frame, train_encoding, train_labels = load_encoded_split("train", tokenizer)
    val_frame, val_encoding, val_labels = load_encoded_split("val", tokenizer)
    logger.info("train_rows=%s val_rows=%s", len(train_labels), len(val_labels))
    logger.info("train_label_counts=%s", train_frame["label"].value_counts().to_dict())

    example_inputs = synthetic_inputs(tokenizer, batch_size, max_length=max_length)
    prepared = prepare_ptq_graph(wrapper, example_inputs, scope=quantization_scope)
    logger.info(
        "PTQ prepared; fake_quant_modules=%s scope=%s",
        count_fake_quant_modules(prepared),
        quantization_scope,
    )

    set_observers(prepared, True)
    calibrated_batches = 0
    calibrated_rows = 0
    started = time.perf_counter()
    with torch.no_grad():
        for _, tensors, actual in iter_fixed_batches(
            tokenizer, train_encoding, batch_size=batch_size, max_length=max_length
        ):
            prepared(*tensors)
            calibrated_batches += 1
            calibrated_rows += actual
            if calibrated_batches % 25 == 0:
                logger.info(
                    "calibration batches=%s rows=%s elapsed=%.1fs",
                    calibrated_batches,
                    calibrated_rows,
                    time.perf_counter() - started,
                )
            if args.calibration_batches and calibrated_batches >= args.calibration_batches:
                break
    calibration_seconds = time.perf_counter() - started
    set_observers(prepared, False)
    logger.info(
        "calibration complete batches=%s rows=%s seconds=%.1f",
        calibrated_batches,
        calibrated_rows,
        calibration_seconds,
    )

    checkpoint_path = CHECKPOINTS_DIR / f"{args.tag}_prepared.pt"
    payload = {
        "created_utc": timestamp_utc(),
        "kind": "ptq",
        "tag": args.tag,
        "base_checkpoint": str(BASE_CHECKPOINT),
        "seed": args.seed,
        "batch_size": batch_size,
        "max_length": max_length,
        "calibration_batches": calibrated_batches,
        "calibration_rows": calibrated_rows,
        "calibration_seconds": calibration_seconds,
        "val_metrics": None,
        "config": config,
        "state_dict": prepared.state_dict(),
    }
    torch.save(payload, checkpoint_path)
    logger.info("Saved PTQ prepared state to %s", checkpoint_path)

    converted = convert_prepared(prepared)
    val_logits = predict_logits(
        converted,
        tokenizer,
        val_encoding,
        batch_size=eval_batch_size,
        max_length=max_length,
    )
    val_metrics, _ = metrics_for_logits(val_labels, val_logits)
    logger.info(
        "PTQ validation macro_f1=%.6f accuracy=%.6f smishing_recall=%.6f",
        val_metrics["macro_f1"],
        val_metrics["accuracy"],
        val_metrics["smishing_recall"],
    )

    payload["val_metrics"] = val_metrics
    torch.save(payload, checkpoint_path)
    summary = {
        "created_utc": timestamp_utc(),
        "status": "ok",
        "tag": args.tag,
        "quantization_scope": quantization_scope,
        "base_checkpoint": str(BASE_CHECKPOINT),
        "prepared_checkpoint": str(checkpoint_path),
        "prepared_checkpoint_bytes": int(checkpoint_path.stat().st_size),
        "calibration_batches": calibrated_batches,
        "calibration_rows": calibrated_rows,
        "calibration_seconds": calibration_seconds,
        "val_metrics": val_metrics,
        "graph": graph_summary(converted),
        "rss_end_mib": rss_snapshot(),
        "test_split_loaded": False,
        "config": config,
    }
    save_json(RESULTS_DIR / f"{args.tag}_summary.json", summary)
    logger.info("PTQ complete: %s", json.dumps(summary, indent=2))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        configure_environment()
        logger = setup_logger("ptq_failure", LOGS_DIR / "ptq_failure.log")
        failure = {
            "created_utc": timestamp_utc(),
            "status": "failed",
            "error_type": type(error).__name__,
            "error": str(error),
            "traceback": traceback.format_exc(),
        }
        save_json(RESULTS_DIR / "ptq_failure.json", failure)
        logger.exception("PTQ failed")
        raise
