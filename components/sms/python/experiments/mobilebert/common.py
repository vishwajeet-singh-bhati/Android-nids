"""Shared utilities for the MobileBERT SMS experiment.

All experiment outputs stay under experiments/mobilebert/. The existing
TF-IDF model, datasets, splits, prediction pipeline, and thresholds are read-only
inputs and are never modified by this module.
"""

from __future__ import annotations

import json
import os
import random
import sys
import time
from pathlib import Path

# Set Hugging Face cache paths before importing transformers/huggingface_hub.
EXPERIMENT_DIR = Path(__file__).resolve().parent
REPO_ROOT = EXPERIMENT_DIR.parents[1]
HF_HOME = EXPERIMENT_DIR / "cache" / "huggingface"
os.environ.setdefault("HF_HOME", str(HF_HOME))
os.environ.setdefault("HF_HUB_DISABLE_SYMLINKS_WARNING", "1")
os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")

SRC_DIR = REPO_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402
import psutil  # noqa: E402
import torch  # noqa: E402
from sklearn.metrics import (  # noqa: E402
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_recall_fscore_support,
)

from sms_detection.preprocessing.normalize import normalize_text  # noqa: E402

LABELS = ("ham", "spam", "smishing")
LABEL2ID = {label: i for i, label in enumerate(LABELS)}
ID2LABEL = {i: label for i, label in enumerate(LABELS)}

DATA_DIR = REPO_ROOT / "data" / "processed"
BASELINE_MODEL_DIR = REPO_ROOT / "artifacts" / "model"
BASELINE_REPORT = REPO_ROOT / "artifacts" / "reports" / "baseline_metrics.json"

DEFAULT_MAX_LENGTH = 128
DEFAULT_BATCH_SIZE = 16
DEFAULT_EPOCHS = 4
DEFAULT_LR = 5e-5
DEFAULT_WEIGHT_DECAY = 0.01
DEFAULT_WARMUP_RATIO = 0.10
DEFAULT_SEED = 42
DEFAULT_NUM_LAYERS = 22
DEFAULT_CLASSIFIER_DROPOUT = 0.10
MODEL_NAME = "google/mobilebert-uncased"


def load_mobilebert_classifier(
    *,
    num_layers: int = DEFAULT_NUM_LAYERS,
    classifier_dropout: float = DEFAULT_CLASSIFIER_DROPOUT,
):
    """Load the stable 22-layer MobileBERT variant and a 3-class head.

    The published 24-layer checkpoint produces extreme activations in its final
    two encoder layers in the Hugging Face implementation. The first 22 layers
    are numerically stable; this limitation is documented in the experiment
    README and must be kept with every result.
    """
    from transformers import AutoConfig, AutoModelForSequenceClassification

    config = AutoConfig.from_pretrained(MODEL_NAME)
    config.num_hidden_layers = num_layers
    config.num_labels = len(LABELS)
    config.id2label = dict(ID2LABEL)
    config.label2id = dict(LABEL2ID)
    config.classifier_dropout = classifier_dropout
    model = AutoModelForSequenceClassification.from_pretrained(MODEL_NAME, config=config)
    return model, config


def encode_texts(tokenizer, texts: list[str], max_length: int = DEFAULT_MAX_LENGTH):
    return tokenizer(
        texts,
        padding=False,
        truncation=True,
        max_length=max_length,
        return_attention_mask=True,
        return_token_type_ids=True,
    )


def batch_from_encoding(tokenizer, encoding, indices: list[int]):
    keys = [key for key in ("input_ids", "attention_mask", "token_type_ids") if key in encoding]
    batch = {key: [encoding[key][index] for index in indices] for key in keys}
    return tokenizer.pad(batch, padding=True, return_tensors="pt")


def iter_batches(indices: list[int], batch_size: int):
    for start in range(0, len(indices), batch_size):
        yield indices[start : start + batch_size]


def seed_everything(seed: int = DEFAULT_SEED) -> None:
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(seed)


def configure_cpu_threads(threads: int = 8) -> int:
    threads = max(1, min(int(threads), os.cpu_count() or 1))
    torch.set_num_threads(threads)
    try:
        torch.set_num_interop_threads(1)
    except RuntimeError:
        pass
    return threads


def load_split(split: str) -> pd.DataFrame:
    path = DATA_DIR / f"{split}.csv"
    frame = pd.read_csv(path, low_memory=False)
    required = {"message_id", "text", "label", "split_group"}
    missing = required - set(frame.columns)
    if missing:
        raise ValueError(f"{path} is missing columns: {sorted(missing)}")
    model_texts = []
    for raw in frame["text"].astype(str).tolist():
        model_texts.append(normalize_text(raw).model_text)
    frame = frame.copy()
    frame["model_text"] = model_texts
    return frame


def class_weights_from_frame(frame: pd.DataFrame) -> torch.Tensor:
    counts = frame["label"].value_counts()
    n = len(frame)
    k = len(LABELS)
    weights = []
    for label in LABELS:
        count = int(counts.get(label, 0))
        weights.append(n / (k * count) if count else 0.0)
    return torch.tensor(weights, dtype=torch.float32)


def model_summary(model: torch.nn.Module) -> dict:
    total = sum(p.numel() for p in model.parameters())
    trainable = sum(p.numel() for p in model.parameters() if p.requires_grad)
    return {
        "total_parameters": int(total),
        "trainable_parameters": int(trainable),
        "dtype": str(next(model.parameters()).dtype),
    }


def rss_mb() -> float:
    return psutil.Process(os.getpid()).memory_info().rss / (1024 * 1024)


def available_ram_mb() -> float:
    return psutil.virtual_memory().available / (1024 * 1024)


def json_dump(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def metrics_from_predictions(
    y_true: list[str],
    y_pred: list[str],
) -> dict:
    """Compute the same classifier-level metrics used by the baseline report."""
    cm = confusion_matrix(y_true, y_pred, labels=list(LABELS))
    precision, recall, f1, support = precision_recall_fscore_support(
        y_true, y_pred, labels=list(LABELS), zero_division=0
    )
    per_class = {
        label: {
            "precision": float(precision[i]),
            "recall": float(recall[i]),
            "f1": float(f1[i]),
            "support": int(support[i]),
        }
        for i, label in enumerate(LABELS)
    }
    ham_index = LABELS.index("ham")
    ham_support = int(support[ham_index])
    ham_fp = sum(1 for truth, pred in zip(y_true, y_pred) if truth == "ham" and pred != "ham")
    return {
        "rows": len(y_true),
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "macro_f1": float(f1_score(y_true, y_pred, labels=list(LABELS), average="macro", zero_division=0)),
        "weighted_f1": float(
            f1_score(y_true, y_pred, labels=list(LABELS), average="weighted", zero_division=0)
        ),
        "per_class": per_class,
        "confusion_matrix": cm.tolist(),
        "confusion_matrix_labels": list(LABELS),
        "smishing_recall": float(recall[LABELS.index("smishing")]),
        "smishing_precision": float(precision[LABELS.index("smishing")]),
        "ham_false_positive_rate": float(ham_fp / ham_support if ham_support else 0.0),
        "ham_support": ham_support,
        "predicted_counts": {
            label: int(sum(1 for pred in y_pred if pred == label)) for label in LABELS
        },
    }


def timestamp_utc() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat()


def timed_call(fn):
    start = time.perf_counter()
    value = fn()
    return value, time.perf_counter() - start
