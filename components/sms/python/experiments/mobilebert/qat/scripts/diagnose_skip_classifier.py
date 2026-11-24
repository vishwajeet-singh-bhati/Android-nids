"""Evaluate QAT with the final classifier left in FP32."""

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
    capture_graph,
    configure_environment,
    fixed_batch,
    load_base_model_and_tokenizer,
    load_encoded_split,
    load_json,
    metrics_for_logits,
    predict_logits,
    save_json,
    set_observers,
    setup_logger,
    timestamp_utc,
)


def build_quantizer():
    from executorch.backends.xnnpack.quantizer.xnnpack_quantizer import (
        XNNPACKQuantizer,
        get_symmetric_quantization_config,
    )

    quantizer = XNNPACKQuantizer().set_global(
        get_symmetric_quantization_config(is_per_channel=True, is_qat=True)
    )

    def filter_fn(node) -> bool:
        if node.target != torch.ops.aten.linear.default:
            return True
        for arg in node.args:
            if (
                isinstance(arg, torch.fx.Node)
                and arg.op == "get_attr"
                and "model_classifier" in str(arg.target)
            ):
                return False
        return True

    quantizer.set_filter_function(filter_fn)
    return quantizer


def main() -> None:
    from torchao.quantization.pt2e.quantize_pt2e import prepare_qat_pt2e

    configure_environment(seed=42, threads=8)
    logger = setup_logger("diagnose_skip_classifier", LOGS_DIR / "diagnose_skip_classifier.log")
    config = load_json(CONFIG_PATH)
    max_length = int(config.get("max_length", DEFAULT_MAX_LENGTH))
    model, tokenizer = load_base_model_and_tokenizer()
    wrapper = ExportWrapper(model).eval()
    _, train_encoding, train_labels = load_encoded_split("train", tokenizer)
    _, val_encoding, val_labels = load_encoded_split("val", tokenizer)
    example_inputs = None
    for _, tensors, _ in iter_fixed(train_encoding, tokenizer, 16, max_length):
        example_inputs = tensors
        break
    graph = capture_graph(wrapper, example_inputs)
    prepared = prepare_qat_pt2e(graph, build_quantizer())
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
    logger.info("warmup complete; nodes=%s", len(prepared.graph.nodes))
    for node in list(prepared.graph.nodes)[-12:]:
        logger.info("node op=%s target=%s name=%s", node.op, node.target, node.name)
    logits = predict_logits(prepared, tokenizer, val_encoding, batch_size=16, max_length=max_length)
    metrics, predictions = metrics_for_logits(val_labels, logits)
    result = {
        "created_utc": timestamp_utc(),
        "variant": "skip_final_classifier_linear_qat",
        "metrics": metrics,
        "prediction_counts": {
            label: predictions.count(label) for label in ("ham", "spam", "smishing")
        },
        "graph_nodes": len(prepared.graph.nodes),
    }
    save_json(RESULTS_DIR / "diagnose_skip_classifier.json", result)
    logger.info("result=%s", json.dumps(result, indent=2))


def iter_fixed(encoding, tokenizer, batch_size, max_length):
    from qat_common import iter_fixed_batches

    return iter_fixed_batches(tokenizer, encoding, batch_size=batch_size, max_length=max_length)


if __name__ == "__main__":
    main()
