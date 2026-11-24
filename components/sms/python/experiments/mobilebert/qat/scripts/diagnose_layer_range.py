"""Screen layer-wise fake-quant exclusions on validation only."""

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


def fake_quant_names_for_layers(prepared, layers: tuple[int, ...]) -> list[str]:
    nodes = list(prepared.graph.nodes)
    hits = [
        index
        for index, node in enumerate(nodes)
        if any(f"layer_{layer}" in (str(node.target) + str(node.args)) for layer in layers)
    ]
    if not hits:
        return []
    start, end = min(hits), max(hits)
    names = []
    for node in nodes[start : end + 1]:
        if node.op == "call_module" and str(node.target).startswith("activation_post_process_"):
            names.append(str(node.target))
    return sorted(set(names))


def main() -> None:
    configure_environment(seed=42, threads=8)
    logger = setup_logger("diagnose_layer_range", LOGS_DIR / "diagnose_layer_range.log")
    config = load_json(CONFIG_PATH)
    max_length = int(config.get("max_length", DEFAULT_MAX_LENGTH))
    model, tokenizer = load_base_model_and_tokenizer()
    wrapper = ExportWrapper(model).eval()
    _, train_encoding, train_labels = load_encoded_split("train", tokenizer)
    _, val_encoding, val_labels = load_encoded_split("val", tokenizer)
    example_inputs = None
    for _, tensors, _ in iter_fixed_batches(tokenizer, train_encoding, batch_size=16, max_length=max_length):
        example_inputs = tensors
        break
    prepared = prepare_qat_graph(wrapper, example_inputs)
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
    set_observers(prepared, False)
    logger.info("warmup complete")

    variants = {
        "layer_21_off": (21,),
        "layers_20_21_off": (20, 21),
        "layers_19_20_21_off": (19, 20, 21),
    }
    results = {"created_utc": timestamp_utc(), "variants": {}}
    for name, layers in variants.items():
        names = fake_quant_names_for_layers(prepared, layers)
        for module_name in names:
            getattr(prepared, module_name).enable_fake_quant(False)
        logits = predict_logits(prepared, tokenizer, val_encoding, batch_size=16, max_length=max_length)
        metrics, predictions = metrics_for_logits(val_labels, logits)
        results["variants"][name] = {
            "layers": list(layers),
            "disabled_count": len(names),
            "disabled_modules": names,
            "metrics": metrics,
            "prediction_counts": {
                label: predictions.count(label) for label in ("ham", "spam", "smishing")
            },
        }
        logger.info(
            "%s disabled=%s macro_f1=%.6f accuracy=%.6f smishing_recall=%.6f predictions=%s",
            name,
            len(names),
            metrics["macro_f1"],
            metrics["accuracy"],
            metrics["smishing_recall"],
            results["variants"][name]["prediction_counts"],
        )
        for module_name in names:
            getattr(prepared, module_name).enable_fake_quant(True)
    save_json(RESULTS_DIR / "diagnose_layer_range.json", results)
    logger.info("results=%s", json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
