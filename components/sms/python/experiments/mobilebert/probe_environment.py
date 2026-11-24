"""Read-only speed, memory, and model-loading probe for MobileBERT."""

from __future__ import annotations

import json
import time
from pathlib import Path

import torch
from transformers import AutoModelForSequenceClassification, AutoTokenizer

from common import (
    DEFAULT_BATCH_SIZE,
    DEFAULT_MAX_LENGTH,
    EXPERIMENT_DIR,
    MODEL_NAME,
    available_ram_mb,
    configure_cpu_threads,
    json_dump,
    load_split,
    model_summary,
    rss_mb,
    seed_everything,
    timestamp_utc,
)


def tokenize(tokenizer, texts):
    return tokenizer(
        texts,
        padding=True,
        truncation=True,
        max_length=DEFAULT_MAX_LENGTH,
        return_tensors="pt",
    )


def step(model, optimizer, batch, labels):
    model.train()
    optimizer.zero_grad(set_to_none=True)
    outputs = model(**batch, labels=labels)
    loss = outputs.loss
    loss.backward()
    torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
    optimizer.step()
    return float(loss.detach())


def main() -> None:
    threads = configure_cpu_threads(8)
    seed_everything()

    print(f"timestamp={timestamp_utc()}")
    print(f"torch={torch.__version__} cuda_available={torch.cuda.is_available()}")
    print(f"threads={threads} cpus={torch.get_num_threads()}")
    print(f"rss_before_model_mb={rss_mb():.1f} available_ram_mb={available_ram_mb():.1f}")

    load_start = time.perf_counter()
    tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
    model = AutoModelForSequenceClassification.from_pretrained(
        MODEL_NAME,
        num_labels=3,
        id2label={0: "ham", 1: "spam", 2: "smishing"},
        label2id={"ham": 0, "spam": 1, "smishing": 2},
    )
    load_seconds = time.perf_counter() - load_start
    print(f"load_seconds={load_seconds:.2f}")
    print("model_summary=" + json.dumps(model_summary(model)))
    print(f"rss_after_model_mb={rss_mb():.1f} available_ram_mb={available_ram_mb():.1f}")
    print("tokenizer=" + tokenizer.__class__.__name__)
    print("model=" + model.__class__.__name__)

    train = load_split("train")
    sample_texts = train["model_text"].head(32).tolist()
    sample_labels = torch.tensor(
        [{"ham": 0, "spam": 1, "smishing": 2}[label] for label in train["label"].head(32)],
        dtype=torch.long,
    )
    optimizer = torch.optim.AdamW(model.parameters(), lr=3e-5, weight_decay=0.01)

    results = {}
    for batch_size in (8, 16):
        batch = tokenize(tokenizer, sample_texts[:batch_size])
        labels = sample_labels[:batch_size]
        # Warm-up step, then 3 measured steps.
        step(model, optimizer, batch, labels)
        times = []
        losses = []
        for _ in range(3):
            start = time.perf_counter()
            loss = step(model, optimizer, batch, labels)
            times.append(time.perf_counter() - start)
            losses.append(loss)
        results[f"batch_{batch_size}"] = {
            "batch_size": batch_size,
            "mean_step_seconds": float(sum(times) / len(times)),
            "min_step_seconds": float(min(times)),
            "max_step_seconds": float(max(times)),
            "losses": losses,
            "examples_per_second": float(batch_size / (sum(times) / len(times))),
            "rss_mb": rss_mb(),
            "available_ram_mb": available_ram_mb(),
        }
        print(json.dumps(results[f"batch_{batch_size}"], indent=2))

    # Inference speed on the same 32 examples.
    model.eval()
    batch = tokenize(tokenizer, sample_texts)
    with torch.inference_mode():
        model(**batch)
        start = time.perf_counter()
        for _ in range(3):
            model(**batch)
        infer_seconds = (time.perf_counter() - start) / 3
    results["inference_32"] = {
        "batch_size": len(sample_texts),
        "mean_seconds": float(infer_seconds),
        "ms_per_message": float(1000 * infer_seconds / len(sample_texts)),
        "rss_mb": rss_mb(),
        "available_ram_mb": available_ram_mb(),
    }
    print(json.dumps(results["inference_32"], indent=2))

    payload = {
        "timestamp_utc": timestamp_utc(),
        "model_name": MODEL_NAME,
        "torch": torch.__version__,
        "cuda_available": torch.cuda.is_available(),
        "threads": threads,
        "model_summary": model_summary(model),
        "load_seconds": load_seconds,
        "rss_before_model_mb": rss_mb(),
        "available_ram_mb": available_ram_mb(),
        "results": results,
    }
    json_dump(EXPERIMENT_DIR / "results" / "probe_environment.json", payload)
    print("wrote", EXPERIMENT_DIR / "results" / "probe_environment.json")


if __name__ == "__main__":
    main()
