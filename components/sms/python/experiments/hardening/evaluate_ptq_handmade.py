"""Evaluate the frozen PTQ ExecuTorch artifact on the handmade smishing set.

This is a local-only coverage check. It does not load the locked test split and
does not modify any model, threshold, dataset, or previous experiment result.
"""

from __future__ import annotations

import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd
import torch
from scipy.special import softmax
from transformers import AutoTokenizer

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parents[1]
QAT_SCRIPTS = REPO_ROOT / "experiments" / "mobilebert" / "qat" / "scripts"
if str(QAT_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(QAT_SCRIPTS))

from qat_common import (  # noqa: E402
    BASE_CHECKPOINT,
    DEFAULT_MAX_LENGTH,
    LABELS,
    ExportWrapper,
    iter_fixed_batches,
    load_base_model_and_tokenizer,
    predict_logits,
)

DATASET = REPO_ROOT / "experiments" / "mobilebert" / "handmade_dataset" / "smishing_dataset.csv"
PTQ_PTE_B1 = REPO_ROOT / "experiments" / "mobilebert" / "qat" / "artifacts" / "ptq_int8_b1.pte"
PTQ_PTE_B16 = REPO_ROOT / "experiments" / "mobilebert" / "qat" / "artifacts" / "ptq_int8_b16.pte"
OUTPUT_DIR = SCRIPT_DIR / "results"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_pte(path: Path):
    from executorch.runtime import Runtime

    runtime = Runtime.get()
    program = runtime.load_program(str(path))
    return program, program.load_method("forward")


def pte_logits(method, tokenizer, encoding, batch_size: int) -> torch.Tensor:
    chunks: list[torch.Tensor] = []
    for _, tensors, actual in iter_fixed_batches(
        tokenizer,
        encoding,
        batch_size=batch_size,
        max_length=DEFAULT_MAX_LENGTH,
    ):
        output = method.execute(list(tensors))[0]
        logits = torch.from_numpy(np.asarray(output)).float()
        chunks.append(logits[:actual])
    return torch.cat(chunks, dim=0)


def probability_rows(logits: torch.Tensor) -> np.ndarray:
    return softmax(logits.cpu().numpy().astype(np.float64), axis=1)


def prediction_stats(labels: list[str], probabilities: np.ndarray) -> dict:
    predicted = [LABELS[int(index)] for index in probabilities.argmax(axis=1)]
    counts = {label: predicted.count(label) for label in LABELS}
    rows = len(labels)
    detected = counts["smishing"]
    return {
        "rows": rows,
        "detected_smishing": detected,
        "detection_rate": detected / rows if rows else 0.0,
        "missed_smishing": rows - detected,
        "label_counts": counts,
        "mean_confidence": float(probabilities.max(axis=1).mean()) if rows else 0.0,
        "mean_smishing_probability": float(
            probabilities[:, LABELS.index("smishing")].mean()
        )
        if rows
        else 0.0,
    }


def main() -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    frame = pd.read_csv(DATASET)
    required = {"ID", "Tactic", "Message"}
    missing = required - set(frame.columns)
    if missing:
        raise ValueError(f"missing columns: {sorted(missing)}")
    if frame["Message"].isna().any():
        raise ValueError("dataset contains empty messages")

    from sms_detection.preprocessing.normalize import normalize_text

    messages = frame["Message"].astype(str).tolist()
    model_texts = [normalize_text(message).model_text for message in messages]
    tokenizer = AutoTokenizer.from_pretrained(BASE_CHECKPOINT, local_files_only=True)
    encoding = tokenizer(
        model_texts,
        padding=False,
        truncation=True,
        max_length=DEFAULT_MAX_LENGTH,
        return_attention_mask=True,
        return_token_type_ids=True,
    )

    model, _ = load_base_model_and_tokenizer()
    wrapper = ExportWrapper(model).eval()
    fp32_logits = predict_logits(
        wrapper,
        tokenizer,
        encoding,
        batch_size=1,
        max_length=DEFAULT_MAX_LENGTH,
    )

    results: dict[str, object] = {
        "created_utc": utc_now(),
        "dataset": {
            "path": str(DATASET),
            "sha256": sha256_file(DATASET),
            "rows": int(len(frame)),
            "provisional_true_label": "smishing",
        },
        "artifacts": {
            "fp32_checkpoint": str(BASE_CHECKPOINT),
            "ptq_b1": str(PTQ_PTE_B1),
            "ptq_b16": str(PTQ_PTE_B16),
        },
        "models": {},
        "limitations": [
            "All rows are provisionally smishing; precision and false-positive rate are undefined.",
            "The handmade set is a synthetic local benchmark, not a held-out production distribution.",
            "The .pte exports are hybrid INT8/FP32; this is not a fully INT8 deployment claim.",
        ],
    }

    reference_probabilities = probability_rows(fp32_logits)
    results["models"]["fp32"] = prediction_stats(
        frame["ID"].astype(str).tolist(), reference_probabilities
    )
    fp32_predictions = reference_probabilities.argmax(axis=1)

    for name, path, batch_size in (
        ("ptq_pte_b1", PTQ_PTE_B1, 1),
        ("ptq_pte_b16", PTQ_PTE_B16, 16),
    ):
        if not path.exists():
            continue
        _, method = load_pte(path)
        logits = pte_logits(method, tokenizer, encoding, batch_size)
        probabilities = probability_rows(logits)
        stats = prediction_stats(frame["ID"].astype(str).tolist(), probabilities)
        stats["pte_bytes"] = int(path.stat().st_size)
        stats["argmax_agreement_with_fp32"] = float(
            (probabilities.argmax(axis=1) == fp32_predictions).mean()
        )
        stats["max_abs_logit_difference_vs_fp32"] = float(
            np.abs(logits.cpu().numpy() - fp32_logits.cpu().numpy()).max()
        )
        results["models"][name] = stats

        predictions = pd.DataFrame(
            {
                "ID": frame["ID"].astype(int),
                "Tactic": frame["Tactic"].astype(str),
                "predicted_label": [LABELS[int(i)] for i in probabilities.argmax(axis=1)],
                "p_ham": probabilities[:, LABELS.index("ham")].round(6),
                "p_spam": probabilities[:, LABELS.index("spam")].round(6),
                "p_smishing": probabilities[:, LABELS.index("smishing")].round(6),
                "detected_smishing": (probabilities.argmax(axis=1) == LABELS.index("smishing")).astype(int),
            }
        )
        predictions.to_csv(
            OUTPUT_DIR / f"{name}_handmade_text_free.csv",
            index=False,
            encoding="utf-8",
        )

    results["comparison"] = {
        "fp32_detected": results["models"]["fp32"]["detected_smishing"],
        "ptq_b1_detected": results["models"].get("ptq_pte_b1", {}).get(
            "detected_smishing"
        ),
        "ptq_b16_detected": results["models"].get("ptq_pte_b16", {}).get(
            "detected_smishing"
        ),
    }
    (OUTPUT_DIR / "ptq_handmade.json").write_text(
        json.dumps(results, indent=2), encoding="utf-8"
    )
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
