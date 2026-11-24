"""Measure practical CPU speed and memory for the 22-layer MobileBERT variant."""

from __future__ import annotations

import json
import time

import torch
from transformers import AutoTokenizer

from common import (
    DEFAULT_BATCH_SIZE,
    DEFAULT_CLASSIFIER_DROPOUT,
    DEFAULT_LR,
    DEFAULT_MAX_LENGTH,
    DEFAULT_NUM_LAYERS,
    EXPERIMENT_DIR,
    available_ram_mb,
    batch_from_encoding,
    class_weights_from_frame,
    configure_cpu_threads,
    encode_texts,
    json_dump,
    load_mobilebert_classifier,
    load_split,
    model_summary,
    rss_mb,
    seed_everything,
    timestamp_utc,
)


def main() -> None:
    threads = configure_cpu_threads(8)
    seed_everything()
    tokenizer = AutoTokenizer.from_pretrained("google/mobilebert-uncased")
    model, config = load_mobilebert_classifier(
        num_layers=DEFAULT_NUM_LAYERS,
        classifier_dropout=DEFAULT_CLASSIFIER_DROPOUT,
    )
    train = load_split("train")
    encoding = encode_texts(tokenizer, train["model_text"].tolist(), DEFAULT_MAX_LENGTH)
    labels = torch.tensor(
        [{"ham": 0, "spam": 1, "smishing": 2}[label] for label in train["label"].tolist()],
        dtype=torch.long,
    )
    weights = class_weights_from_frame(train)
    criterion = torch.nn.CrossEntropyLoss(weight=weights)
    optimizer = torch.optim.AdamW(model.parameters(), lr=DEFAULT_LR, weight_decay=0.01)

    print(f"timestamp={timestamp_utc()}")
    print(f"torch={torch.__version__} cuda={torch.cuda.is_available()} threads={threads}")
    print("config=" + json.dumps({"num_hidden_layers": config.num_hidden_layers, "num_labels": config.num_labels}))
    print("model=" + json.dumps(model_summary(model)))
    print(f"rss_before={rss_mb():.1f}MB available={available_ram_mb():.1f}MB")

    results = {}
    for batch_size in (8, 16):
        indices = list(range(batch_size))
        batch = batch_from_encoding(tokenizer, encoding, indices)
        target = labels[indices]
        model.train()
        for _ in range(2):
            optimizer.zero_grad(set_to_none=True)
            outputs = model(**batch)
            loss = criterion(outputs.logits, target)
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            optimizer.step()
        times = []
        losses = []
        for _ in range(3):
            start = time.perf_counter()
            optimizer.zero_grad(set_to_none=True)
            outputs = model(**batch)
            loss = criterion(outputs.logits, target)
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            optimizer.step()
            times.append(time.perf_counter() - start)
            losses.append(float(loss.detach()))
        results[f"train_batch_{batch_size}"] = {
            "batch_size": batch_size,
            "mean_step_seconds": float(sum(times) / len(times)),
            "min_step_seconds": float(min(times)),
            "max_step_seconds": float(max(times)),
            "examples_per_second": float(batch_size / (sum(times) / len(times))),
            "losses": losses,
            "rss_mb": rss_mb(),
            "available_ram_mb": available_ram_mb(),
        }
        print(json.dumps(results[f"train_batch_{batch_size}"], indent=2))

    model.eval()
    eval_indices = list(range(min(256, len(train))))
    with torch.inference_mode():
        for start in range(0, len(eval_indices), 32):
            batch = batch_from_encoding(tokenizer, encoding, eval_indices[start : start + 32])
            model(**batch)
        start = time.perf_counter()
        for start_index in range(0, len(eval_indices), 32):
            batch = batch_from_encoding(tokenizer, encoding, eval_indices[start_index : start_index + 32])
            model(**batch)
        elapsed = time.perf_counter() - start
    results["eval_256"] = {
        "examples": len(eval_indices),
        "seconds": elapsed,
        "ms_per_message": 1000 * elapsed / len(eval_indices),
        "rss_mb": rss_mb(),
        "available_ram_mb": available_ram_mb(),
    }
    print(json.dumps(results["eval_256"], indent=2))

    payload = {
        "timestamp_utc": timestamp_utc(),
        "model_name": "google/mobilebert-uncased",
        "num_hidden_layers": DEFAULT_NUM_LAYERS,
        "torch": torch.__version__,
        "cuda_available": torch.cuda.is_available(),
        "threads": threads,
        "model_summary": model_summary(model),
        "results": results,
    }
    json_dump(EXPERIMENT_DIR / "results" / "probe_training.json", payload)
    print("wrote", EXPERIMENT_DIR / "results" / "probe_training.json")


if __name__ == "__main__":
    main()
