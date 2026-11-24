"""Inspect MobileBERT hidden-state growth by layer."""

from __future__ import annotations

import torch
from transformers import AutoModel, AutoTokenizer

from common import DEFAULT_MAX_LENGTH, MODEL_NAME, configure_cpu_threads, load_split


def stats(name, tensor):
    tensor = tensor.detach().float()
    print(
        f"{name:20s} shape={tuple(tensor.shape)} "
        f"min={float(tensor.min()): .4e} max={float(tensor.max()): .4e} "
        f"mean={float(tensor.mean()): .4e} std={float(tensor.std()): .4e}"
    )


def main() -> None:
    configure_cpu_threads(8)
    tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
    model = AutoModel.from_pretrained(MODEL_NAME)
    model.eval()
    frame = load_split("train")
    texts = frame["model_text"].head(2).tolist()
    batch = tokenizer(
        texts,
        padding=True,
        truncation=True,
        max_length=DEFAULT_MAX_LENGTH,
        return_tensors="pt",
    )
    print("normalization_type=", model.config.normalization_type)
    print("input_ids shape=", tuple(batch["input_ids"].shape))
    with torch.inference_mode():
        embedding_inputs = {"input_ids": batch["input_ids"]}
        if "token_type_ids" in batch:
            embedding_inputs["token_type_ids"] = batch["token_type_ids"]
        embeddings = model.embeddings(**embedding_inputs)
        stats("embeddings", embeddings)
        out = model(**batch, output_hidden_states=True)
        stats("last_hidden_state", out.last_hidden_state)
        if out.pooler_output is not None:
            stats("pooler_output", out.pooler_output)
        for i, hidden in enumerate(out.hidden_states):
            stats(f"hidden_{i}", hidden)


if __name__ == "__main__":
    main()
