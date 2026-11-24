"""Diagnose MobileBERT classification logits and loss before training."""

from __future__ import annotations

import json
import torch
from transformers import AutoModelForSequenceClassification, AutoTokenizer

from common import (
    DEFAULT_MAX_LENGTH,
    MODEL_NAME,
    configure_cpu_threads,
    load_split,
    model_summary,
    seed_everything,
)


def main() -> None:
    configure_cpu_threads(8)
    seed_everything()
    tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
    model = AutoModelForSequenceClassification.from_pretrained(
        MODEL_NAME,
        num_labels=3,
        id2label={0: "ham", 1: "spam", 2: "smishing"},
        label2id={"ham": 0, "spam": 1, "smishing": 2},
    )
    model.eval()
    train = load_split("train")
    texts = train["model_text"].head(4).tolist()
    labels = torch.tensor(
        [{"ham": 0, "spam": 1, "smishing": 2}[label] for label in train["label"].head(4)],
        dtype=torch.long,
    )
    batch = tokenizer(
        texts,
        padding=True,
        truncation=True,
        max_length=DEFAULT_MAX_LENGTH,
        return_tensors="pt",
    )
    with torch.inference_mode():
        outputs = model(**batch)
        logits = outputs.logits
        manual = torch.nn.functional.cross_entropy(logits, labels)
        base = model.mobilebert(**batch)
        pooled = base.pooler_output
    print("config:", json.dumps({
        "num_labels": model.config.num_labels,
        "problem_type": model.config.problem_type,
        "id2label": model.config.id2label,
        "label2id": model.config.label2id,
        "hidden_dropout_prob": model.config.hidden_dropout_prob,
        "attention_probs_dropout_prob": model.config.attention_probs_dropout_prob,
    }, indent=2))
    print("labels:", labels.tolist())
    print("logits:", logits.detach().cpu().tolist())
    print("logits stats:", float(logits.min()), float(logits.max()), float(logits.mean()), float(logits.std()))
    print("manual CE:", float(manual))
    print("model loss with labels:", float(outputs.loss) if outputs.loss is not None else None)
    print("pooled stats:", float(pooled.min()), float(pooled.max()), float(pooled.mean()), float(pooled.std()))
    print("classifier weight stats:", float(model.classifier.weight.min()), float(model.classifier.weight.max()), float(model.classifier.weight.std()))
    print("summary:", json.dumps(model_summary(model)))


if __name__ == "__main__":
    main()
