"""Attempt a fixed-shape ExecuTorch export and runtime check.

Dynamic-shape export was already attempted and failed at torch.export because
the MobileBERT graph specialized the batch and sequence dimensions. This script
uses the standard fixed-shape fallback: batch=1, sequence length=128.
"""

from __future__ import annotations

import json
import time
import traceback
from pathlib import Path

import numpy as np
import torch
from transformers import AutoModelForSequenceClassification, AutoTokenizer

from common import EXPERIMENT_DIR, json_dump, timestamp_utc


class ExportWrapper(torch.nn.Module):
    def __init__(self, model):
        super().__init__()
        self.model = model

    def forward(self, input_ids, attention_mask, token_type_ids):
        return self.model(
            input_ids=input_ids,
            attention_mask=attention_mask,
            token_type_ids=token_type_ids,
        ).logits


def main() -> None:
    checkpoint = EXPERIMENT_DIR / "checkpoints" / "mobilebert22_lr5e5_bs16_e4" / "best"
    result_path = EXPERIMENT_DIR / "results" / "executorch_export_static.json"
    pte_path = EXPERIMENT_DIR / "checkpoints" / "mobilebert22_executorch_static.pte"
    payload = {
        "created_utc": timestamp_utc(),
        "checkpoint": str(checkpoint),
        "status": "started",
        "input_shape": [1, 128],
        "dynamic_shape_attempt": {
            "status": "failed",
            "reason": "torch.export constraint violation: batch and sequence dimensions were specialized",
            "evidence": "results/executorch_export.json",
        },
        "torch": torch.__version__,
        "stages": {},
    }
    if not checkpoint.exists():
        payload["status"] = "checkpoint_missing"
        json_dump(result_path, payload)
        print(json.dumps(payload, indent=2))
        return

    try:
        import executorch  # noqa: F401
        from executorch.exir import to_edge
        from executorch.runtime import Runtime
    except Exception as error:
        payload["status"] = "executorch_import_failed"
        payload["error_type"] = type(error).__name__
        payload["error"] = str(error)
        payload["traceback"] = traceback.format_exc()
        json_dump(result_path, payload)
        print(json.dumps(payload, indent=2))
        return

    model = AutoModelForSequenceClassification.from_pretrained(checkpoint)
    tokenizer = AutoTokenizer.from_pretrained(checkpoint)
    model.eval()
    wrapper = ExportWrapper(model).eval()

    example = tokenizer(
        "Example message with a link",
        return_tensors="pt",
        padding="max_length",
        truncation=True,
        max_length=128,
    )
    inputs = (
        example["input_ids"],
        example["attention_mask"],
        example.get("token_type_ids", torch.zeros_like(example["input_ids"])),
    )
    payload["stages"]["input_preparation"] = {
        "status": "ok",
        "shapes": [list(tensor.shape) for tensor in inputs],
        "dtypes": [str(tensor.dtype) for tensor in inputs],
    }

    try:
        export_start = time.perf_counter()
        exported = torch.export.export(wrapper, inputs)
        payload["stages"]["torch_export"] = {
            "status": "ok",
            "seconds": time.perf_counter() - export_start,
        }
    except Exception as error:
        payload["status"] = "torch_export_failed"
        payload["error_type"] = type(error).__name__
        payload["error"] = str(error)
        payload["traceback"] = traceback.format_exc()
        json_dump(result_path, payload)
        print(json.dumps(payload, indent=2))
        return

    try:
        edge_start = time.perf_counter()
        edge_program = to_edge(exported)
        payload["stages"]["to_edge"] = {
            "status": "ok",
            "seconds": time.perf_counter() - edge_start,
        }
    except Exception as error:
        payload["status"] = "to_edge_failed"
        payload["error_type"] = type(error).__name__
        payload["error"] = str(error)
        payload["traceback"] = traceback.format_exc()
        json_dump(result_path, payload)
        print(json.dumps(payload, indent=2))
        return

    try:
        pte_start = time.perf_counter()
        executorch_program = edge_program.to_executorch()
        pte_path.parent.mkdir(parents=True, exist_ok=True)
        with pte_path.open("wb") as handle:
            executorch_program.write_to_file(handle)
        payload["stages"]["to_executorch"] = {
            "status": "ok",
            "seconds": time.perf_counter() - pte_start,
            "pte_path": str(pte_path),
            "pte_bytes": pte_path.stat().st_size,
        }
        payload["status"] = "exported"
    except Exception as error:
        payload["status"] = "to_executorch_failed"
        payload["error_type"] = type(error).__name__
        payload["error"] = str(error)
        payload["traceback"] = traceback.format_exc()
        json_dump(result_path, payload)
        print(json.dumps(payload, indent=2))
        return

    try:
        runtime = Runtime.get()
        program = runtime.load_program(str(pte_path))
        method = program.load_method("forward")
        runtime_start = time.perf_counter()
        runtime_outputs = method.execute(list(inputs))
        runtime_seconds = time.perf_counter() - runtime_start
        with torch.inference_mode():
            torch_outputs = wrapper(*inputs)
        runtime_tensor = torch.from_numpy(np.asarray(runtime_outputs[0])).float()
        torch_tensor = torch_outputs.detach().float()
        max_abs_diff = float((runtime_tensor - torch_tensor).abs().max())
        payload["stages"]["runtime_execute"] = {
            "status": "ok",
            "seconds": runtime_seconds,
            "max_abs_diff": max_abs_diff,
            "output_shape": list(runtime_tensor.shape),
            "output_dtype": str(runtime_tensor.dtype),
            "output_min": float(runtime_tensor.min()),
            "output_max": float(runtime_tensor.max()),
            "torch_output_min": float(torch_tensor.min()),
            "torch_output_max": float(torch_tensor.max()),
        }
        payload["status"] = "runtime_verified"
    except Exception as error:
        payload["stages"]["runtime_execute"] = {
            "status": "failed",
            "error_type": type(error).__name__,
            "error": str(error),
            "traceback": traceback.format_exc(),
        }
        payload["status"] = "runtime_failed"

    json_dump(result_path, payload)
    print(json.dumps(payload, indent=2))


if __name__ == "__main__":
    main()
