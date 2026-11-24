"""Read-only probe of numerically stable MobileBERT variants."""

from __future__ import annotations

import json
import torch
from transformers import AutoConfig, AutoModelForSequenceClassification, AutoTokenizer

from common import (
    DEFAULT_MAX_LENGTH,
    MODEL_NAME,
    configure_cpu_threads,
    load_split,
    model_summary,
    seed_everything,
)


def stats(name, tensor):
    tensor = tensor.detach().float()
    print(
        f"{name:20s} shape={tuple(tensor.shape)} "
        f"min={float(tensor.min()): .4e} max={float(tensor.max()): .4e} "
        f"mean={float(tensor.mean()): .4e} std={float(tensor.std()): .4e}"
    )


def main() -> None:
    configure_cpu_threads(8)
    seed_everything()
    tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
    frame = load_split("train")
    texts = frame["model_text"].head(4).tolist()
    labels = torch.tensor(
        [{"ham": 0, "spam": 1, "smishing": 2}[label] for label in frame["label"].head(4)],
        dtype=torch.long,
    )
    batch = tokenizer(
        texts,
        padding=True,
        truncation=True,
        max_length=DEFAULT_MAX_LENGTH,
        return_tensors="pt",
    )

    for num_layers in (23, 22):
        print(f"\n=== MobileBERT with {num_layers} encoder layers ===")
        config = AutoConfig.from_pretrained(MODEL_NAME)
        config.num_hidden_layers = num_layers
        config.num_labels = 3
        config.id2label = {0: "ham", 1: "spam", 2: "smishing"}
        config.label2id = {"ham": 0, "spam": 1, "smishing": 2}
        model = AutoModelForSequenceClassification.from_pretrained(MODEL_NAME, config=config)
        model.eval()
        with torch.inference_mode():
            outputs = model(**batch)
            logits = outputs.logits
            hidden = model.mobilebert(**batch).last_hidden_state
        stats("last_hidden_state", hidden)
        stats("logits", logits)
        print("manual CE:", float(torch.nn.functional.cross_entropy(logits, labels)))
        print("summary:", json.dumps(model_summary(model)))


if __name__ == "__main__":
    main()
