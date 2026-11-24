"""Shared utilities for the MobileBERT-22 QAT/PTQ experiment.

All outputs stay under experiments/mobilebert/qat/. Existing FP32 checkpoints,
data splits, TF-IDF artifacts, and risk-policy files are read-only inputs.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import random
import sys
from collections import Counter
from pathlib import Path
from typing import Iterable, Sequence

SCRIPT_DIR = Path(__file__).resolve().parent
QAT_DIR = SCRIPT_DIR.parent
EXPERIMENT_DIR = QAT_DIR.parent
REPO_ROOT = EXPERIMENT_DIR.parents[1]

# The venv bundles flatc but it is not on PATH.
FLATC_PATH = EXPERIMENT_DIR / ".venv" / "Scripts" / "flatc.exe"
os.environ.setdefault("FLATC_EXECUTABLE", str(FLATC_PATH))
os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")

if str(EXPERIMENT_DIR) not in sys.path:
    sys.path.insert(0, str(EXPERIMENT_DIR))

from common import (  # noqa: E402
    ID2LABEL,
    LABEL2ID,
    LABELS,
    configure_cpu_threads,
    encode_texts,
    json_dump,
    load_split,
    metrics_from_predictions,
    rss_mb,
    seed_everything,
    timestamp_utc,
)

import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402
import torch  # noqa: E402
from torch import nn  # noqa: E402
from transformers import AutoModelForSequenceClassification, AutoTokenizer  # noqa: E402

BASE_CHECKPOINT = (
    EXPERIMENT_DIR / "checkpoints" / "mobilebert22_lr5e5_bs16_e4" / "best"
)
CHECKPOINTS_DIR = QAT_DIR / "checkpoints"
RESULTS_DIR = QAT_DIR / "results"
LOGS_DIR = QAT_DIR / "logs"
ARTIFACTS_DIR = QAT_DIR / "artifacts"
CONFIG_PATH = QAT_DIR / "config.json"

DEFAULT_MAX_LENGTH = 128
DEFAULT_BATCH_SIZE = 16
DEFAULT_EVAL_BATCH_SIZE = 16
DEFAULT_SEED = 42
DEFAULT_CLASS_WEIGHTS = [0.4084819257259369, 2.507730484008789, 6.529790878295898]
DEFAULT_LR = 1e-5
DEFAULT_EPOCHS = 2
DEFAULT_PATIENCE = 1
DEFAULT_WARMUP_RATIO = 0.10
DEFAULT_WEIGHT_DECAY = 0.01
DEFAULT_GRAD_CLIP = 1.0
OBSERVER_WARMUP_STEPS = 10


class ExportWrapper(nn.Module):
    """Return only logits for a clean ExecuTorch graph."""

    def __init__(self, model: nn.Module):
        super().__init__()
        self.model = model

    def forward(
        self,
        input_ids: torch.Tensor,
        attention_mask: torch.Tensor,
        token_type_ids: torch.Tensor,
    ) -> torch.Tensor:
        return self.model(
            input_ids=input_ids,
            attention_mask=attention_mask,
            token_type_ids=token_type_ids,
        ).logits


def ensure_dirs() -> None:
    for path in (QAT_DIR, CHECKPOINTS_DIR, RESULTS_DIR, LOGS_DIR, ARTIFACTS_DIR):
        path.mkdir(parents=True, exist_ok=True)


def setup_logger(name: str, log_path: Path) -> logging.Logger:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    logger.handlers.clear()
    formatter = logging.Formatter(
        "%(asctime)s %(levelname)s %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
    )
    file_handler = logging.FileHandler(log_path, encoding="utf-8")
    file_handler.setFormatter(formatter)
    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    logger.addHandler(stream_handler)
    return logger


def configure_environment(seed: int = DEFAULT_SEED, threads: int = 8) -> int:
    ensure_dirs()
    seed_everything(seed)
    actual_threads = configure_cpu_threads(threads)
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    return actual_threads


def load_base_model_and_tokenizer():
    if not BASE_CHECKPOINT.exists():
        raise FileNotFoundError(f"Base checkpoint not found: {BASE_CHECKPOINT}")
    tokenizer = AutoTokenizer.from_pretrained(
        BASE_CHECKPOINT, local_files_only=True
    )
    model = AutoModelForSequenceClassification.from_pretrained(
        BASE_CHECKPOINT, local_files_only=True
    )
    model.eval()
    return model, tokenizer


def synthetic_inputs(
    tokenizer,
    batch_size: int = DEFAULT_BATCH_SIZE,
    *,
    max_length: int = DEFAULT_MAX_LENGTH,
) -> tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
    encoded = tokenizer(
        ["Example message with a link"] * batch_size,
        padding="max_length",
        truncation=True,
        max_length=max_length,
        return_tensors="pt",
    )
    keys = ["input_ids", "attention_mask", "token_type_ids"]
    if "token_type_ids" not in encoded:
        encoded["token_type_ids"] = torch.zeros_like(encoded["input_ids"])
    return tuple(encoded[key] for key in keys)


def load_encoded_split(split: str, tokenizer):
    frame = load_split(split)
    encoding = encode_texts(
        tokenizer, frame["model_text"].astype(str).tolist(), max_length=DEFAULT_MAX_LENGTH
    )
    labels = frame["label"].astype(str).tolist()
    return frame, encoding, labels


def _encoding_keys(encoding) -> list[str]:
    return [
        key
        for key in ("input_ids", "attention_mask", "token_type_ids")
        if key in encoding
    ]


def fixed_batch(
    tokenizer,
    encoding,
    indices: Sequence[int],
    *,
    batch_size: int = DEFAULT_BATCH_SIZE,
    pad_to_batch: bool = True,
    max_length: int = DEFAULT_MAX_LENGTH,
):
    """Build a fixed-[batch_size, max_length] batch from encoded rows.

    If pad_to_batch is true, the final short batch repeats its last row so the
    exported graph always sees the training batch size. Callers must slice the
    output back to len(indices).
    """
    indices = list(indices)
    if not indices:
        raise ValueError("Cannot build a batch from zero indices")
    keys = _encoding_keys(encoding)
    batch_indices = list(indices)
    if pad_to_batch and len(batch_indices) < batch_size:
        batch_indices.extend([batch_indices[-1]] * (batch_size - len(batch_indices)))
    batch = {
        key: [encoding[key][index] for index in batch_indices] for key in keys
    }
    padded = tokenizer.pad(
        batch,
        padding="max_length",
        max_length=max_length,
        return_tensors="pt",
    )
    tensors = tuple(padded[key] for key in keys)
    return tensors, len(indices)


def iter_fixed_batches(
    tokenizer,
    encoding,
    *,
    batch_size: int = DEFAULT_BATCH_SIZE,
    max_length: int = DEFAULT_MAX_LENGTH,
):
    total = len(encoding["input_ids"])
    for start in range(0, total, batch_size):
        indices = list(range(start, min(start + batch_size, total)))
        tensors, actual = fixed_batch(
            tokenizer,
            encoding,
            indices,
            batch_size=batch_size,
            pad_to_batch=True,
            max_length=max_length,
        )
        yield indices, tensors, actual


def model_logits(model, tensors) -> torch.Tensor:
    output = model(*tensors)
    if hasattr(output, "logits"):
        output = output.logits
    if isinstance(output, (tuple, list)):
        output = output[0]
    return output


def predict_logits(
    model,
    tokenizer,
    encoding,
    *,
    batch_size: int = DEFAULT_BATCH_SIZE,
    max_length: int = DEFAULT_MAX_LENGTH,
) -> torch.Tensor:
    chunks: list[torch.Tensor] = []
    with torch.inference_mode():
        for _, tensors, actual in iter_fixed_batches(
            tokenizer,
            encoding,
            batch_size=batch_size,
            max_length=max_length,
        ):
            logits = model_logits(model, tensors)[:actual]
            chunks.append(logits.detach().float().cpu())
    return torch.cat(chunks, dim=0)


def metrics_for_logits(labels: Sequence[str], logits: torch.Tensor):
    pred_ids = logits.argmax(dim=-1).tolist()
    predictions = [ID2LABEL[int(index)] for index in pred_ids]
    metrics = metrics_from_predictions(list(labels), predictions)
    return metrics, predictions


def set_observers(model: torch.fx.GraphModule, enabled: bool) -> int:
    count = 0
    for module in model.modules():
        if hasattr(module, "observer_enabled") and hasattr(module, "enable_observer"):
            module.enable_observer(bool(enabled))
            count += 1
    return count


def count_fake_quant_modules(model: torch.fx.GraphModule) -> int:
    return sum(1 for module in model.modules() if hasattr(module, "observer_enabled"))


DEFAULT_QUANTIZATION_SCOPE = "linear_only"


def _apply_quantization_scope(quantizer, scope: str):
    if scope == "linear_only":
        # Global add/mul activation quantization destroys the smishing class.
        # Keep the linear weights and activations quantized, but leave residual
        # adds and layer-norm multiplies in FP32.
        skip_targets = (torch.ops.aten.add.Tensor, torch.ops.aten.mul.Tensor)

        def filter_fn(node) -> bool:
            return node.target not in skip_targets

        quantizer.set_filter_function(filter_fn)
        return quantizer
    if scope in {"global", "full"}:
        return quantizer
    raise ValueError(f"Unsupported quantization scope: {scope}")


def make_qat_quantizer(scope: str = DEFAULT_QUANTIZATION_SCOPE):
    from executorch.backends.xnnpack.quantizer.xnnpack_quantizer import (
        XNNPACKQuantizer,
        get_symmetric_quantization_config,
    )

    quantizer = XNNPACKQuantizer().set_global(
        get_symmetric_quantization_config(is_per_channel=True, is_qat=True)
    )
    return _apply_quantization_scope(quantizer, scope)


def make_ptq_quantizer(scope: str = DEFAULT_QUANTIZATION_SCOPE):
    from executorch.backends.xnnpack.quantizer.xnnpack_quantizer import (
        XNNPACKQuantizer,
        get_symmetric_quantization_config,
    )

    quantizer = XNNPACKQuantizer().set_global(
        get_symmetric_quantization_config(is_per_channel=True, is_qat=False)
    )
    return _apply_quantization_scope(quantizer, scope)


def capture_graph(wrapper: nn.Module, inputs) -> torch.fx.GraphModule:
    return torch.export.export(wrapper, inputs).module()


def prepare_qat_graph(
    wrapper: nn.Module,
    inputs,
    scope: str = DEFAULT_QUANTIZATION_SCOPE,
) -> torch.fx.GraphModule:
    from torchao.quantization.pt2e.quantize_pt2e import prepare_qat_pt2e

    graph = capture_graph(wrapper, inputs)
    prepared = prepare_qat_pt2e(graph, make_qat_quantizer(scope))
    set_observers(prepared, True)
    return prepared


def prepare_ptq_graph(
    wrapper: nn.Module,
    inputs,
    scope: str = DEFAULT_QUANTIZATION_SCOPE,
) -> torch.fx.GraphModule:
    from torchao.quantization.pt2e.quantize_pt2e import prepare_pt2e

    graph = capture_graph(wrapper, inputs)
    prepared = prepare_pt2e(graph, make_ptq_quantizer(scope))
    set_observers(prepared, True)
    return prepared


def load_prepared_state(prepared: torch.fx.GraphModule, checkpoint_path: Path):
    payload = torch.load(checkpoint_path, map_location="cpu", weights_only=False)
    state_dict = payload.get("state_dict", payload)
    prepared.load_state_dict(state_dict, strict=True)
    return payload


def convert_prepared(prepared: torch.fx.GraphModule) -> torch.fx.GraphModule:
    from torchao.quantization.pt2e.quantize_pt2e import convert_pt2e

    set_observers(prepared, False)
    return convert_pt2e(prepared)


def load_qat_converted(
    checkpoint_path: Path,
    wrapper: nn.Module,
    inputs,
    scope: str = DEFAULT_QUANTIZATION_SCOPE,
):
    prepared = prepare_qat_graph(wrapper, inputs, scope=scope)
    payload = load_prepared_state(prepared, checkpoint_path)
    converted = convert_prepared(prepared)
    return converted, payload


def load_ptq_converted(
    checkpoint_path: Path,
    wrapper: nn.Module,
    inputs,
    scope: str = DEFAULT_QUANTIZATION_SCOPE,
):
    prepared = prepare_ptq_graph(wrapper, inputs, scope=scope)
    payload = load_prepared_state(prepared, checkpoint_path)
    converted = convert_prepared(prepared)
    return converted, payload


def graph_summary(model: torch.fx.GraphModule) -> dict:
    op_counts = Counter(str(node.target) for node in model.graph.nodes)
    state_dtypes = Counter(str(value.dtype) for value in model.state_dict().values())
    int8_tensors = [
        {
            "name": name,
            "shape": list(value.shape),
        }
        for name, value in model.state_dict().items()
        if value.dtype == torch.int8
    ]
    return {
        "op_counts": dict(op_counts),
        "state_dtypes": dict(state_dtypes),
        "int8_tensor_count": len(int8_tensors),
        "int8_tensor_examples": int8_tensors[:20],
        "parameter_count": int(sum(p.numel() for p in model.parameters())),
    }


def edge_graph_summary(edge_program_manager, method_name: str = "forward") -> dict:
    exported = edge_program_manager.exported_program(method_name)
    graph = exported.graph_module.graph
    op_counts = Counter(str(node.target) for node in graph.nodes)
    delegate_calls = sum(
        1 for node in graph.nodes if "executorch_call_delegate" in str(node.target)
    )
    non_delegated = sorted(
        key
        for key in op_counts
        if key.startswith("aten.") or "executorch" in key or "quantized" in key
    )
    return {
        "delegate_calls": int(delegate_calls),
        "op_counts": dict(op_counts),
        "aten_and_delegate_ops": {
            key: int(op_counts[key]) for key in non_delegated
        },
    }


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def file_size_bytes(path: Path) -> int:
    return int(path.stat().st_size) if path.exists() else 0


def save_json(path: Path, payload) -> None:
    json_dump(path, payload)


def load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def rss_snapshot() -> float:
    return float(rss_mb())


def dataset_manifest() -> dict:
    return {
        "train_csv": str(REPO_ROOT / "data" / "processed" / "train.csv"),
        "val_csv": str(REPO_ROOT / "data" / "processed" / "val.csv"),
        "test_csv": str(REPO_ROOT / "data" / "processed" / "test.csv"),
        "seed": DEFAULT_SEED,
        "max_length": DEFAULT_MAX_LENGTH,
    }
