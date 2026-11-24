"""Screen final-classifier fake-quant exclusions on validation only."""

from __future__ import annotations

import json
import random

import torch

from qat_common import (
    CONFIG_PATH,
    DEFAULT_MAX_LENGTH,
    LOGS_DIR,
    RESULTS_DIR,
    ExportWrapper,
    configure_environment,
    fixed_batch,
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


def eval_variant(prepared, tokenizer, val_encoding, val_labels, max_length: int):
    set_observers(prepared, False)
    logits = predict_logits(prepared, tokenizer, val_encoding, batch_size=16, max_length=max_length)
    metrics, predictions = metrics_for_logits(val_labels, logits)
    return metrics, predictions


def set_fake_quant(prepared, names: list[str], enabled: bool) -> None:
    for name in names:
        module = getattr(prepared, name)
        module.enable_fake_quant(bool(enabled))


def main() -> None:
    configure_environment(seed=42, threads=8)
    logger = setup_logger("diagnose_final_classifier", LOGS_DIR / "diagnose_final_classifier.log")
    config = load_json(CONFIG_PATH)
    max_length = int(config.get("max_length", DEFAULT_MAX_LENGTH))
    model, tokenizer = load_base_model_and_tokenizer()
    wrapper = ExportWrapper(model).eval()
    _, train_encoding, train_labels = load_encoded_split("train", tokenizer)
    _, val_encoding, val_labels = load_encoded_split("val", tokenizer)
    inputs = None
    for _, tensors, _ in fixed_batches(train_encoding, tokenizer, 16, max_length):
        inputs = tensors
        break
    prepared = prepare_qat_graph(wrapper, inputs)
    set_observers(prepared, True)
    order = list(range(len(train_labels)))
    random.Random(42 + 1000).shuffle(order)
    with torch.no_grad():
        for start in range(0, 50 * 16, 16):
            indices = order[start : start + 16]
            tensors, _ = fixed_batch(
                tokenizer, train_encoding, indices, batch_size=16, pad_to_batch=True, max_length=max_length
            )
            prepared(*tensors)
    logger.info("warmup complete")

    final_names = [
        "activation_post_process_1754",
        "activation_post_process_1755",
        "activation_post_process_1756",
    ]
    variants = {
        "qat_baseline": [],
        "final_input_off": [final_names[0]],
        "final_weight_off": [final_names[1]],
        "final_output_off": [final_names[2]],
        "final_all_off": final_names,
    }
    results = {"created_utc": timestamp_utc(), "variants": {}}
    for name, disabled in variants.items():
        if disabled:
            set_fake_quant(prepared, disabled, False)
        metrics, predictions = eval_variant(
            prepared, tokenizer, val_encoding, val_labels, max_length
        )
        results["variants"][name] = {
            "disabled": disabled,
            "metrics": metrics,
            "prediction_counts": {
                label: predictions.count(label) for label in ("ham", "spam", "smishing")
            },
        }
        logger.info(
            "%s macro_f1=%.6f accuracy=%.6f smishing_recall=%.6f predictions=%s",
            name,
            metrics["macro_f1"],
            metrics["accuracy"],
            metrics["smishing_recall"],
            results["variants"][name]["prediction_counts"],
        )
        if disabled:
            set_fake_quant(prepared, disabled, True)
    save_json(RESULTS_DIR / "diagnose_final_classifier.json", results)
    logger.info("results=%s", json.dumps(results, indent=2))


def fixed_batches(encoding, tokenizer, batch_size, max_length):
    from qat_common import iter_fixed_batches

    return iter_fixed_batches(tokenizer, encoding, batch_size=batch_size, max_length=max_length)


if __name__ == "__main__":
    main()
