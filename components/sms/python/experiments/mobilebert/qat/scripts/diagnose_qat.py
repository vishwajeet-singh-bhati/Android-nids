"""Diagnose QAT fake-quant behavior on train/validation only."""

from __future__ import annotations

import json
from collections import Counter

import torch

from qat_common import (
    CONFIG_PATH,
    DEFAULT_MAX_LENGTH,
    LOGS_DIR,
    RESULTS_DIR,
    ExportWrapper,
    configure_environment,
    iter_fixed_batches,
    load_base_model_and_tokenizer,
    load_encoded_split,
    load_json,
    metrics_for_logits,
    predict_logits,
    prepare_qat_graph,
    save_json,
    set_observers,
    setup_logger,
    timestamp_utc,
)


def logits_stats(logits: torch.Tensor) -> dict:
    return {
        "shape": list(logits.shape),
        "mean": logits.mean(dim=0).tolist(),
        "min": logits.min(dim=0).values.tolist(),
        "max": logits.max(dim=0).values.tolist(),
    }


def main() -> None:
    configure_environment(seed=42, threads=8)
    logger = setup_logger("diagnose_qat", LOGS_DIR / "diagnose_qat.log")
    config = load_json(CONFIG_PATH)
    max_length = int(config.get("max_length", DEFAULT_MAX_LENGTH))
    model, tokenizer = load_base_model_and_tokenizer()
    wrapper = ExportWrapper(model).eval()
    train_frame, train_encoding, train_labels = load_encoded_split("train", tokenizer)
    val_frame, val_encoding, val_labels = load_encoded_split("val", tokenizer)
    logger.info("train_rows=%s val_rows=%s", len(train_labels), len(val_labels))

    fp32_logits = predict_logits(wrapper, tokenizer, val_encoding, batch_size=16, max_length=max_length)
    fp32_metrics, fp32_preds = metrics_for_logits(val_labels, fp32_logits)

    example_inputs = None
    for _, tensors, _ in iter_fixed_batches(
        tokenizer, train_encoding, batch_size=16, max_length=max_length
    ):
        example_inputs = tensors
        break
    prepared = prepare_qat_graph(wrapper, example_inputs)
    set_observers(prepared, True)

    warmup_10 = 0
    warmup_50 = 0
    with torch.no_grad():
        for batch_index, (_, tensors, actual) in enumerate(
            iter_fixed_batches(tokenizer, train_encoding, batch_size=16, max_length=max_length)
        ):
            prepared(*tensors)
            warmup_50 += actual
            if batch_index < 10:
                warmup_10 += actual
            if batch_index + 1 >= 50:
                break
    logger.info("warmup_10_rows=%s warmup_50_rows=%s", warmup_10, warmup_50)

    set_observers(prepared, False)
    qat_50_logits = predict_logits(prepared, tokenizer, val_encoding, batch_size=16, max_length=max_length)
    qat_50_metrics, qat_50_preds = metrics_for_logits(val_labels, qat_50_logits)

    # Re-run with only 10 batches and evaluate there for a direct warmup comparison.
    prepared_10 = prepare_qat_graph(wrapper, example_inputs)
    set_observers(prepared_10, True)
    with torch.no_grad():
        for batch_index, (_, tensors, actual) in enumerate(
            iter_fixed_batches(tokenizer, train_encoding, batch_size=16, max_length=max_length)
        ):
            prepared_10(*tensors)
            if batch_index + 1 >= 10:
                break
    set_observers(prepared_10, False)
    qat_10_logits = predict_logits(prepared_10, tokenizer, val_encoding, batch_size=16, max_length=max_length)
    qat_10_metrics, qat_10_preds = metrics_for_logits(val_labels, qat_10_logits)

    result = {
        "created_utc": timestamp_utc(),
        "split": "validation",
        "fp32": {"metrics": fp32_metrics, "logits": logits_stats(fp32_logits)},
        "qat_after_10_warmup_batches": {
            "metrics": qat_10_metrics,
            "logits": logits_stats(qat_10_logits),
        },
        "qat_after_50_warmup_batches": {
            "metrics": qat_50_metrics,
            "logits": logits_stats(qat_50_logits),
        },
        "prediction_counts": {
            "fp32": dict(Counter(fp32_preds)),
            "qat_10": dict(Counter(qat_10_preds)),
            "qat_50": dict(Counter(qat_50_preds)),
        },
    }
    save_json(RESULTS_DIR / "diagnose_qat_val.json", result)
    logger.info("diagnostic=%s", json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
