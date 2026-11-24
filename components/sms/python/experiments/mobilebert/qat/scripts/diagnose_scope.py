"""Screen quantization-scope variants: linear-only vs add/mul exclusion."""

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
    iter_fixed_batches,
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


def build_quantizer(skip_targets):
    from executorch.backends.xnnpack.quantizer.xnnpack_quantizer import (
        XNNPACKQuantizer,
        get_symmetric_quantization_config,
    )

    quantizer = XNNPACKQuantizer().set_global(
        get_symmetric_quantization_config(is_per_channel=True, is_qat=True)
    )
    targets = set(skip_targets)

    def filter_fn(node) -> bool:
        return node.target not in targets

    quantizer.set_filter_function(filter_fn)
    return quantizer


def main() -> None:
    from torchao.quantization.pt2e.quantize_pt2e import prepare_qat_pt2e

    configure_environment(seed=42, threads=8)
    logger = setup_logger("diagnose_scope", LOGS_DIR / "diagnose_scope.log")
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
    variants = {
        "linear_only": (torch.ops.aten.add.Tensor, torch.ops.aten.mul.Tensor),
    }
    results = {"created_utc": timestamp_utc(), "variants": {}}
    for name, skip_targets in variants.items():
        prepared = prepare_qat_pt2e(capture_graph(wrapper, example_inputs), build_quantizer(skip_targets))
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
        fake_quant_count = sum(1 for module in prepared.modules() if hasattr(module, "observer_enabled"))
        logits = predict_logits(prepared, tokenizer, val_encoding, batch_size=16, max_length=max_length)
        metrics, predictions = metrics_for_logits(val_labels, logits)
        results["variants"][name] = {
            "skip_targets": [str(target) for target in skip_targets],
            "fake_quant_count": fake_quant_count,
            "metrics": metrics,
            "prediction_counts": {
                label: predictions.count(label) for label in ("ham", "spam", "smishing")
            },
        }
        logger.info(
            "%s fake_quant=%s macro_f1=%.6f accuracy=%.6f smishing_recall=%.6f predictions=%s",
            name,
            fake_quant_count,
            metrics["macro_f1"],
            metrics["accuracy"],
            metrics["smishing_recall"],
            results["variants"][name]["prediction_counts"],
        )
    save_json(RESULTS_DIR / "diagnose_scope.json", results)
    logger.info("results=%s", json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
