"""Inspect QAT graph placement around the final classifier."""

from __future__ import annotations

import torch

from qat_common import (
    CONFIG_PATH,
    DEFAULT_MAX_LENGTH,
    ExportWrapper,
    configure_environment,
    load_base_model_and_tokenizer,
    load_encoded_split,
    load_json,
    prepare_qat_graph,
    set_observers,
    synthetic_inputs,
)


def main() -> None:
    configure_environment(seed=42, threads=8)
    config = load_json(CONFIG_PATH)
    max_length = int(config.get("max_length", DEFAULT_MAX_LENGTH))
    model, tokenizer = load_base_model_and_tokenizer()
    wrapper = ExportWrapper(model).eval()
    inputs = synthetic_inputs(tokenizer, 16, max_length=max_length)
    prepared = prepare_qat_graph(wrapper, inputs)
    print("nodes", len(prepared.graph.nodes))
    nodes = list(prepared.graph.nodes)
    for index, node in enumerate(nodes[-120:]):
        print(index + len(nodes) - 120, node.op, node.target, node.name, tuple(node.args)[:3])
    print("--- fake quant modules ---")
    count = 0
    for name, module in prepared.named_modules():
        if hasattr(module, "observer_enabled"):
            count += 1
            if count <= 20 or count > 1577 - 20:
                print(count, name, type(module).__name__, module.scale.numel() if hasattr(module, "scale") else None)
    print("total", count)


if __name__ == "__main__":
    main()
