"""Fine-tune the stable 22-layer MobileBERT variant on the existing SMS splits.

This script reads the existing train/validation splits only. It does not load or
evaluate the locked test split. The final test evaluation is a separate,
single-use script.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import time
from pathlib import Path

import numpy as np
import torch
import torch.nn.functional as F
from transformers import AutoTokenizer, get_linear_schedule_with_warmup

from common import (
    DEFAULT_BATCH_SIZE,
    DEFAULT_CLASSIFIER_DROPOUT,
    DEFAULT_EPOCHS,
    DEFAULT_LR,
    DEFAULT_MAX_LENGTH,
    DEFAULT_NUM_LAYERS,
    DEFAULT_SEED,
    DEFAULT_WARMUP_RATIO,
    DEFAULT_WEIGHT_DECAY,
    EXPERIMENT_DIR,
    ID2LABEL,
    LABEL2ID,
    LABELS,
    available_ram_mb,
    batch_from_encoding,
    class_weights_from_frame,
    configure_cpu_threads,
    encode_texts,
    iter_batches,
    json_dump,
    load_mobilebert_classifier,
    load_split,
    metrics_from_predictions,
    model_summary,
    rss_mb,
    seed_everything,
    timestamp_utc,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-name", default="mobilebert22_lr5e5_bs16_e4")
    parser.add_argument("--epochs", type=int, default=DEFAULT_EPOCHS)
    parser.add_argument("--batch-size", type=int, default=DEFAULT_BATCH_SIZE)
    parser.add_argument("--eval-batch-size", type=int, default=32)
    parser.add_argument("--max-length", type=int, default=DEFAULT_MAX_LENGTH)
    parser.add_argument("--lr", type=float, default=DEFAULT_LR)
    parser.add_argument("--weight-decay", type=float, default=DEFAULT_WEIGHT_DECAY)
    parser.add_argument("--warmup-ratio", type=float, default=DEFAULT_WARMUP_RATIO)
    parser.add_argument("--patience", type=int, default=2)
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--num-layers", type=int, default=DEFAULT_NUM_LAYERS)
    parser.add_argument("--classifier-dropout", type=float, default=DEFAULT_CLASSIFIER_DROPOUT)
    parser.add_argument("--max-train", type=int, default=0, help="Optional debug cap; 0 means all rows.")
    parser.add_argument("--max-val", type=int, default=0, help="Optional debug cap; 0 means all rows.")
    parser.add_argument("--threads", type=int, default=8)
    return parser.parse_args()


def labels_tensor(frame) -> torch.Tensor:
    return torch.tensor([LABEL2ID[label] for label in frame["label"].tolist()], dtype=torch.long)


def evaluate(
    model,
    tokenizer,
    encoding,
    labels: torch.Tensor,
    *,
    batch_size: int,
) -> tuple[dict, np.ndarray, list[str]]:
    model.eval()
    logits_parts = []
    total_loss = 0.0
    total_rows = 0
    with torch.inference_mode():
        for indices in iter_batches(list(range(len(labels))), batch_size):
            batch = batch_from_encoding(tokenizer, encoding, indices)
            target = labels[indices]
            outputs = model(**batch)
            logits = outputs.logits
            logits_parts.append(logits.cpu())
            total_loss += float(F.cross_entropy(logits, target, reduction="sum"))
            total_rows += len(indices)
    logits = torch.cat(logits_parts, dim=0)
    probs = torch.softmax(logits, dim=-1).numpy()
    pred_indices = np.argmax(probs, axis=1)
    y_true = [ID2LABEL[int(value)] for value in labels.tolist()]
    y_pred = [ID2LABEL[int(value)] for value in pred_indices.tolist()]
    metrics = metrics_from_predictions(y_true, y_pred)
    metrics["loss_unweighted"] = total_loss / max(1, total_rows)
    return metrics, probs, y_pred


def save_checkpoint(model, tokenizer, output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    model.save_pretrained(output_dir)
    tokenizer.save_pretrained(output_dir)


def tree_size_bytes(path: Path) -> int:
    return sum(p.stat().st_size for p in path.rglob("*") if p.is_file())


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> None:
    args = parse_args()
    configure_cpu_threads(args.threads)
    seed_everything(args.seed)

    run_dir = EXPERIMENT_DIR / "checkpoints" / args.run_name
    best_dir = run_dir / "best"
    last_dir = run_dir / "last"
    results_dir = EXPERIMENT_DIR / "results"
    logs_dir = EXPERIMENT_DIR / "logs"
    results_dir.mkdir(parents=True, exist_ok=True)
    logs_dir.mkdir(parents=True, exist_ok=True)

    tokenizer = AutoTokenizer.from_pretrained("google/mobilebert-uncased")
    model, config = load_mobilebert_classifier(
        num_layers=args.num_layers,
        classifier_dropout=args.classifier_dropout,
    )

    train = load_split("train")
    val = load_split("val")
    if args.max_train:
        train = train.head(args.max_train).copy()
    if args.max_val:
        val = val.head(args.max_val).copy()

    train_encoding = encode_texts(tokenizer, train["model_text"].tolist(), args.max_length)
    val_encoding = encode_texts(tokenizer, val["model_text"].tolist(), args.max_length)
    train_labels = labels_tensor(train)
    val_labels = labels_tensor(val)
    class_weights = class_weights_from_frame(train)
    criterion = torch.nn.CrossEntropyLoss(weight=class_weights)

    steps_per_epoch = math.ceil(len(train) / args.batch_size)
    total_steps = max(1, steps_per_epoch * args.epochs)
    warmup_steps = max(1, int(total_steps * args.warmup_ratio))
    optimizer = torch.optim.AdamW(
        model.parameters(),
        lr=args.lr,
        weight_decay=args.weight_decay,
    )
    scheduler = get_linear_schedule_with_warmup(
        optimizer,
        num_warmup_steps=warmup_steps,
        num_training_steps=total_steps,
    )

    config_payload = {
        "created_utc": timestamp_utc(),
        "experiment": "mobilebert_22_layer_stability_variant",
        "run_name": args.run_name,
        "model_name": "google/mobilebert-uncased",
        "model_num_hidden_layers": args.num_layers,
        "stability_note": (
            "The published 24-layer checkpoint produces extreme final-layer activations "
            "in the Hugging Face implementation. The first 22 layers are stable; the "
            "final two encoder layers are omitted. This is not a standard 24-layer "
            "MobileBERT result."
        ),
        "classifier_dropout": args.classifier_dropout,
        "max_length": args.max_length,
        "batch_size": args.batch_size,
        "eval_batch_size": args.eval_batch_size,
        "epochs": args.epochs,
        "learning_rate": args.lr,
        "weight_decay": args.weight_decay,
        "warmup_ratio": args.warmup_ratio,
        "warmup_steps": warmup_steps,
        "total_steps": total_steps,
        "patience": args.patience,
        "seed": args.seed,
        "labels": list(LABELS),
        "class_weights": [float(value) for value in class_weights.tolist()],
        "train_rows": len(train),
        "val_rows": len(val),
        "train_label_counts": train["label"].value_counts().to_dict(),
        "val_label_counts": val["label"].value_counts().to_dict(),
        "input_preprocessing": "sms_detection.preprocessing.normalize.normalize_text(...).model_text",
        "test_split_loaded": False,
        "model_summary": model_summary(model),
        "torch": torch.__version__,
        "cuda_available": torch.cuda.is_available(),
        "threads": torch.get_num_threads(),
        "hash_train_csv": sha256_file(EXPERIMENT_DIR.parents[1] / "data" / "processed" / "train.csv"),
        "hash_val_csv": sha256_file(EXPERIMENT_DIR.parents[1] / "data" / "processed" / "val.csv"),
        "hash_test_csv_not_evaluated": sha256_file(
            EXPERIMENT_DIR.parents[1] / "data" / "processed" / "test.csv"
        ),
    }
    json_dump(results_dir / f"training_config_{args.run_name}.json", config_payload)

    print(f"run_name={args.run_name}")
    print(f"model=google/mobilebert-uncased layers={args.num_layers}")
    print(f"train_rows={len(train)} val_rows={len(val)}")
    print(f"steps_per_epoch={steps_per_epoch} total_steps={total_steps} warmup_steps={warmup_steps}")
    print(f"class_weights={class_weights.tolist()}")
    print(f"model_summary={json.dumps(model_summary(model))}")
    print(f"rss_mb={rss_mb():.1f} available_ram_mb={available_ram_mb():.1f}")

    history = []
    best_macro_f1 = -1.0
    best_epoch = -1
    bad_epochs = 0
    rng = np.random.default_rng(args.seed)
    train_start = time.perf_counter()

    for epoch in range(1, args.epochs + 1):
        epoch_start = time.perf_counter()
        model.train()
        order = rng.permutation(len(train)).tolist()
        running_loss = 0.0
        seen = 0
        for step, indices in enumerate(iter_batches(order, args.batch_size), start=1):
            batch = batch_from_encoding(tokenizer, train_encoding, indices)
            target = train_labels[indices]
            optimizer.zero_grad(set_to_none=True)
            outputs = model(**batch)
            loss = criterion(outputs.logits, target)
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            optimizer.step()
            scheduler.step()
            running_loss += float(loss.detach()) * len(indices)
            seen += len(indices)
            if step % 50 == 0 or step == steps_per_epoch:
                print(
                    f"epoch={epoch} step={step}/{steps_per_epoch} "
                    f"loss={running_loss / max(1, seen):.6f} "
                    f"lr={scheduler.get_last_lr()[0]:.3e} "
                    f"elapsed_s={time.perf_counter() - epoch_start:.1f} "
                    f"rss_mb={rss_mb():.1f}"
                )

        train_loss = running_loss / max(1, seen)
        val_metrics, _, _ = evaluate(
            model,
            tokenizer,
            val_encoding,
            val_labels,
            batch_size=args.eval_batch_size,
        )
        epoch_seconds = time.perf_counter() - epoch_start
        record = {
            "epoch": epoch,
            "train_loss_weighted": train_loss,
            "val_metrics": val_metrics,
            "epoch_seconds": epoch_seconds,
            "rss_mb": rss_mb(),
            "available_ram_mb": available_ram_mb(),
            "lr": scheduler.get_last_lr()[0],
        }
        history.append(record)
        json_dump(results_dir / f"training_history_{args.run_name}.json", history)
        print(
            f"epoch={epoch} train_loss={train_loss:.6f} "
            f"val_loss={val_metrics['loss_unweighted']:.6f} "
            f"val_accuracy={val_metrics['accuracy']:.6f} "
            f"val_macro_f1={val_metrics['macro_f1']:.6f} "
            f"val_smishing_recall={val_metrics['smishing_recall']:.6f} "
            f"val_ham_fpr={val_metrics['ham_false_positive_rate']:.6f} "
            f"epoch_seconds={epoch_seconds:.1f}"
        )

        improved = val_metrics["macro_f1"] > best_macro_f1 + 1e-8
        if improved:
            best_macro_f1 = val_metrics["macro_f1"]
            best_epoch = epoch
            bad_epochs = 0
            save_checkpoint(model, tokenizer, best_dir)
            json_dump(results_dir / f"best_validation_metrics_{args.run_name}.json", {
                "epoch": epoch,
                "val_metrics": val_metrics,
                "selection_metric": "macro_f1",
                "checkpoint": str(best_dir),
                "best_checkpoint_bytes": tree_size_bytes(best_dir),
            })
            print(f"epoch={epoch} new_best_macro_f1={best_macro_f1:.6f} checkpoint={best_dir}")
        else:
            bad_epochs += 1
            print(f"epoch={epoch} no_improvement bad_epochs={bad_epochs} best_epoch={best_epoch}")
            if bad_epochs >= args.patience:
                print(f"early_stopping at epoch={epoch}")
                break

    save_checkpoint(model, tokenizer, last_dir)
    total_seconds = time.perf_counter() - train_start
    summary = {
        "created_utc": timestamp_utc(),
        "run_name": args.run_name,
        "best_epoch": best_epoch,
        "best_val_macro_f1": best_macro_f1,
        "total_seconds": total_seconds,
        "epochs_completed": len(history),
        "early_stopped": len(history) < args.epochs,
        "best_checkpoint": str(best_dir),
        "last_checkpoint": str(last_dir),
        "best_checkpoint_bytes": tree_size_bytes(best_dir),
        "last_checkpoint_bytes": tree_size_bytes(last_dir),
        "test_split_loaded": False,
        "history": history,
    }
    json_dump(results_dir / f"training_summary_{args.run_name}.json", summary)
    print("training_complete")
    print(json.dumps({k: summary[k] for k in summary if k != "history"}, indent=2))


if __name__ == "__main__":
    main()
