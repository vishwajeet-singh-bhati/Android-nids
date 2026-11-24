"""QAT fine-tuning for the existing MobileBERT-22 SMS classifier.

This script reads only train.csv and val.csv. It never loads test.csv. The
best validation macro-F1 checkpoint is saved for conversion/export.
"""

from __future__ import annotations

import argparse
import json
import math
import random
import time
import traceback
from pathlib import Path

import torch
import torch.nn.functional as F
from transformers import get_linear_schedule_with_warmup

from qat_common import (
    ARTIFACTS_DIR,
    BASE_CHECKPOINT,
    CHECKPOINTS_DIR,
    CONFIG_PATH,
    DEFAULT_BATCH_SIZE,
    DEFAULT_CLASS_WEIGHTS,
    DEFAULT_EPOCHS,
    DEFAULT_EVAL_BATCH_SIZE,
    DEFAULT_GRAD_CLIP,
    DEFAULT_LR,
    DEFAULT_MAX_LENGTH,
    DEFAULT_PATIENCE,
    DEFAULT_SEED,
    DEFAULT_WARMUP_RATIO,
    DEFAULT_WEIGHT_DECAY,
    LABEL2ID,
    LOGS_DIR,
    OBSERVER_WARMUP_STEPS,
    RESULTS_DIR,
    ExportWrapper,
    configure_environment,
    count_fake_quant_modules,
    fixed_batch,
    iter_fixed_batches,
    load_base_model_and_tokenizer,
    load_encoded_split,
    load_json,
    metrics_for_logits,
    model_logits,
    predict_logits,
    prepare_qat_graph,
    rss_snapshot,
    save_json,
    set_observers,
    setup_logger,
    synthetic_inputs,
    timestamp_utc,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--smoke", action="store_true", help="Run the 20-step smoke test only.")
    parser.add_argument("--tag", default=None)
    parser.add_argument("--epochs", type=int, default=None)
    parser.add_argument("--max-steps", type=int, default=None)
    parser.add_argument("--lr", type=float, default=None)
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--threads", type=int, default=8)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    actual_threads = configure_environment(seed=args.seed, threads=args.threads)
    config = load_json(CONFIG_PATH)
    qat_cfg = config.get("qat", {})

    smoke = bool(args.smoke)
    tag = args.tag or ("qat_smoke" if smoke else "qat_lr1e5_bs16_e2")
    batch_size = int(config.get("batch_size", DEFAULT_BATCH_SIZE))
    eval_batch_size = int(config.get("eval_batch_size", DEFAULT_EVAL_BATCH_SIZE))
    max_length = int(config.get("max_length", DEFAULT_MAX_LENGTH))
    class_weights = torch.tensor(
        config.get("class_weights", DEFAULT_CLASS_WEIGHTS), dtype=torch.float32
    )
    lr = float(args.lr if args.lr is not None else qat_cfg.get("learning_rate", DEFAULT_LR))
    weight_decay = float(qat_cfg.get("weight_decay", DEFAULT_WEIGHT_DECAY))
    grad_clip = float(qat_cfg.get("gradient_clip", DEFAULT_GRAD_CLIP))
    warmup_ratio = float(qat_cfg.get("warmup_ratio", DEFAULT_WARMUP_RATIO))
    observer_warmup_steps = int(
        qat_cfg.get("observer_warmup_steps", OBSERVER_WARMUP_STEPS)
    )
    observer_warmup_shuffle = bool(qat_cfg.get("observer_warmup_shuffle", True))
    freeze_observers = bool(qat_cfg.get("freeze_observers_after_warmup", True))
    quantization_scope = str(qat_cfg.get("quantization_scope", "linear_only"))

    if smoke:
        epochs = 1
        max_steps = int(args.max_steps if args.max_steps is not None else qat_cfg.get("smoke_test_steps", 20))
        patience = 0
        warmup_steps = max(1, min(2, max_steps // 10))
    else:
        epochs = int(args.epochs if args.epochs is not None else qat_cfg.get("epochs", DEFAULT_EPOCHS))
        max_steps = args.max_steps
        patience = int(qat_cfg.get("patience", DEFAULT_PATIENCE))
        warmup_steps = None  # computed after steps_per_epoch is known

    log_path = LOGS_DIR / f"train_{tag}.log"
    logger = setup_logger(f"qat_train_{tag}", log_path)
    logger.info("Starting QAT run tag=%s smoke=%s", tag, smoke)
    logger.info("Base checkpoint: %s", BASE_CHECKPOINT)
    logger.info("Seed=%s threads=%s batch_size=%s eval_batch_size=%s max_length=%s", args.seed, actual_threads, batch_size, eval_batch_size, max_length)
    logger.info("lr=%s weight_decay=%s grad_clip=%s epochs=%s max_steps=%s", lr, weight_decay, grad_clip, epochs, max_steps)

    model, tokenizer = load_base_model_and_tokenizer()
    wrapper = ExportWrapper(model).eval()
    train_frame, train_encoding, train_labels = load_encoded_split("train", tokenizer)
    val_frame, val_encoding, val_labels = load_encoded_split("val", tokenizer)
    logger.info("train_rows=%s val_rows=%s", len(train_labels), len(val_labels))
    logger.info("train_label_counts=%s", train_frame["label"].value_counts().to_dict())
    logger.info("val_label_counts=%s", val_frame["label"].value_counts().to_dict())

    example_inputs = synthetic_inputs(tokenizer, batch_size, max_length=max_length)
    prepared = prepare_qat_graph(wrapper, example_inputs, scope=quantization_scope)
    fake_quant_count = count_fake_quant_modules(prepared)
    logger.info(
        "QAT prepared; fake_quant_modules=%s scope=%s",
        fake_quant_count,
        quantization_scope,
    )
    logger.info("prepared_graph_nodes=%s", len(prepared.graph.nodes))

    steps_per_epoch = math.ceil(len(train_labels) / batch_size)
    if max_steps is None:
        total_steps = steps_per_epoch * epochs
    else:
        total_steps = int(max_steps)
    if not smoke and warmup_steps is None:
        warmup_steps = max(1, int(round(total_steps * warmup_ratio)))
    logger.info("steps_per_epoch=%s total_steps=%s warmup_steps=%s", steps_per_epoch, total_steps, warmup_steps)

    # Initialize the fake-quant observers on real train batches before gradient
    # steps. The CSV is label-sorted, so sequential warmup would see only ham;
    # shuffle first so every class contributes to the activation ranges.
    set_observers(prepared, True)
    warmup_order = list(range(len(train_labels)))
    if observer_warmup_shuffle:
        random.Random(args.seed + 1000).shuffle(warmup_order)
    observer_batches = 0
    observer_rows = 0
    with torch.no_grad():
        for start in range(0, len(warmup_order), batch_size):
            if observer_batches >= observer_warmup_steps:
                break
            indices = warmup_order[start : start + batch_size]
            tensors, actual = fixed_batch(
                tokenizer,
                train_encoding,
                indices,
                batch_size=batch_size,
                pad_to_batch=True,
                max_length=max_length,
            )
            prepared(*tensors)
            observer_batches += 1
            observer_rows += actual
    logger.info(
        "observer warmup batches=%s rows=%s shuffled=%s",
        observer_batches,
        observer_rows,
        observer_warmup_shuffle,
    )
    if freeze_observers:
        set_observers(prepared, False)
        logger.info("Observers frozen after warmup")

    trainable_parameters = [p for p in prepared.parameters() if p.requires_grad]
    optimizer = torch.optim.AdamW(
        trainable_parameters, lr=lr, weight_decay=weight_decay
    )
    scheduler = get_linear_schedule_with_warmup(
        optimizer,
        num_warmup_steps=warmup_steps,
        num_training_steps=max(total_steps, 1),
    )

    history: list[dict] = []
    best_macro_f1 = -1.0
    best_epoch = -1
    best_metrics = None
    best_path = CHECKPOINTS_DIR / f"{tag}_best.pt"
    global_step = 0
    started = time.perf_counter()
    rss_start = rss_snapshot()
    logger.info("RSS before QAT training: %.1f MiB", rss_start)

    try:
        for epoch in range(epochs):
            epoch_start = time.perf_counter()
            order = list(range(len(train_labels)))
            random.Random(args.seed + epoch).shuffle(order)
            running_loss = 0.0
            loss_count = 0
            epoch_steps = 0

            for start in range(0, len(order), batch_size):
                if max_steps is not None and global_step >= max_steps:
                    break
                indices = order[start : start + batch_size]
                tensors, actual = fixed_batch(
                    tokenizer,
                    train_encoding,
                    indices,
                    batch_size=batch_size,
                    pad_to_batch=True,
                    max_length=max_length,
                )
                labels = torch.tensor(
                    [LABEL2ID[label] for label in (train_labels[i] for i in indices)],
                    dtype=torch.long,
                )

                optimizer.zero_grad(set_to_none=True)
                logits = model_logits(prepared, tensors)[:actual]
                loss = F.cross_entropy(logits, labels, weight=class_weights)
                if not torch.isfinite(loss):
                    raise RuntimeError(f"Non-finite loss at global step {global_step + 1}")
                loss.backward()
                torch.nn.utils.clip_grad_norm_(trainable_parameters, grad_clip)
                optimizer.step()
                scheduler.step()

                global_step += 1
                epoch_steps += 1
                loss_value = float(loss.detach().cpu())
                running_loss += loss_value
                loss_count += 1

                if global_step % 10 == 0 or global_step == 1:
                    logger.info(
                        "epoch=%s step=%s loss=%.6f lr=%.3e elapsed=%.1fs",
                        epoch + 1,
                        global_step,
                        loss_value,
                        scheduler.get_last_lr()[0],
                        time.perf_counter() - started,
                    )

                if max_steps is not None and global_step >= max_steps:
                    break

            # Validation must not update the QAT observer ranges.
            set_observers(prepared, False)
            val_logits = predict_logits(
                prepared,
                tokenizer,
                val_encoding,
                batch_size=eval_batch_size,
                max_length=max_length,
            )
            val_metrics, _ = metrics_for_logits(val_labels, val_logits)
            if not freeze_observers:
                set_observers(prepared, True)
            epoch_loss = running_loss / max(loss_count, 1)
            epoch_seconds = time.perf_counter() - epoch_start
            history.append(
                {
                    "epoch": epoch + 1,
                    "global_step": global_step,
                    "steps": epoch_steps,
                    "train_loss": epoch_loss,
                    "val_metrics": val_metrics,
                    "seconds": epoch_seconds,
                }
            )
            logger.info(
                "epoch=%s done steps=%s train_loss=%.6f val_macro_f1=%.6f val_accuracy=%.6f val_smishing_recall=%.6f seconds=%.1f",
                epoch + 1,
                global_step,
                epoch_loss,
                val_metrics["macro_f1"],
                val_metrics["accuracy"],
                val_metrics["smishing_recall"],
                epoch_seconds,
            )

            improved = val_metrics["macro_f1"] > best_macro_f1
            if improved:
                best_macro_f1 = float(val_metrics["macro_f1"])
                best_epoch = epoch + 1
                best_metrics = val_metrics
                payload = {
                    "created_utc": timestamp_utc(),
                    "kind": "qat",
                    "tag": tag,
                    "smoke": smoke,
                    "base_checkpoint": str(BASE_CHECKPOINT),
                    "seed": args.seed,
                    "batch_size": batch_size,
                    "max_length": max_length,
                    "epoch": best_epoch,
                    "global_step": global_step,
                    "val_metrics": best_metrics,
                    "history": history,
                    "config": config,
                    "fake_quant_modules": fake_quant_count,
                    "state_dict": prepared.state_dict(),
                }
                torch.save(payload, best_path)
                logger.info("Saved new best QAT state to %s", best_path)

            if max_steps is not None and global_step >= max_steps:
                break
            if not improved and best_epoch >= 0 and (epoch + 1 - best_epoch) >= patience:
                logger.info("Early stopping after epoch %s", epoch + 1)
                break

        if not best_path.exists():
            raise RuntimeError("No QAT best checkpoint was saved")

        elapsed = time.perf_counter() - started
        summary = {
            "created_utc": timestamp_utc(),
            "status": "ok",
            "tag": tag,
            "smoke": smoke,
            "quantization_scope": quantization_scope,
            "base_checkpoint": str(BASE_CHECKPOINT),
            "best_checkpoint": str(best_path),
            "best_checkpoint_bytes": int(best_path.stat().st_size),
            "best_epoch": best_epoch,
            "best_val_macro_f1": best_macro_f1,
            "best_val_metrics": best_metrics,
            "history": history,
            "global_step": global_step,
            "elapsed_seconds": elapsed,
            "rss_start_mib": rss_start,
            "rss_end_mib": rss_snapshot(),
            "fake_quant_modules": fake_quant_count,
            "train_rows": len(train_labels),
            "val_rows": len(val_labels),
            "test_split_loaded": False,
            "config": config,
        }
        save_json(RESULTS_DIR / f"train_{tag}.json", summary)
        logger.info("QAT training complete: %s", json.dumps(summary, indent=2))
    except Exception as error:
        failure = {
            "created_utc": timestamp_utc(),
            "status": "failed",
            "tag": tag,
            "smoke": smoke,
            "error_type": type(error).__name__,
            "error": str(error),
            "traceback": traceback.format_exc(),
            "global_step": global_step,
            "history": history,
        }
        save_json(RESULTS_DIR / f"train_{tag}_failure.json", failure)
        logger.exception("QAT training failed")
        raise


if __name__ == "__main__":
    main()
