"""Measure isolated process RSS for one model or .pte artifact."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import torch

from qat_common import (
    ARTIFACTS_DIR,
    BASE_CHECKPOINT,
    CHECKPOINTS_DIR,
    DEFAULT_BATCH_SIZE,
    DEFAULT_MAX_LENGTH,
    ExportWrapper,
    configure_environment,
    load_base_model_and_tokenizer,
    load_ptq_converted,
    load_qat_converted,
    rss_snapshot,
    save_json,
    setup_logger,
    synthetic_inputs,
    timestamp_utc,
)
from qat_common import LOGS_DIR, RESULTS_DIR


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kind", choices=["fp32", "ptq", "qat", "pte"], required=True)
    parser.add_argument("--batch-size", type=int, default=DEFAULT_BATCH_SIZE)
    parser.add_argument("--checkpoint", default=None)
    parser.add_argument("--pte", default=None)
    parser.add_argument("--tag", default=None)
    parser.add_argument("--threads", type=int, default=8)
    return parser.parse_args()


def raw_inputs(batch_size: int, max_length: int = DEFAULT_MAX_LENGTH):
    input_ids = torch.zeros((batch_size, max_length), dtype=torch.long)
    input_ids[:, 0] = 101
    input_ids[:, 1:5] = torch.tensor([2023, 2003, 1037, 2001])
    input_ids[:, 5] = 102
    attention_mask = torch.zeros_like(input_ids)
    attention_mask[:, :6] = 1
    token_type_ids = torch.zeros_like(input_ids)
    return input_ids, attention_mask, token_type_ids


def main() -> None:
    args = parse_args()
    configure_environment(seed=42, threads=args.threads)
    tag = args.tag or f"{args.kind}_b{args.batch_size}"
    logger = setup_logger(f"resources_{tag}", LOGS_DIR / f"resources_{tag}.log")
    baseline = rss_snapshot()
    logger.info("baseline_rss_mib=%.1f", baseline)

    if args.kind == "pte":
        pte_path = Path(args.pte) if args.pte else ARTIFACTS_DIR / f"{tag}.pte"
        from executorch.runtime import Runtime

        runtime = Runtime.get()
        program = runtime.load_program(str(pte_path))
        method = program.load_method("forward")
        after_load = rss_snapshot()
        inputs = raw_inputs(args.batch_size)
        method.execute(list(inputs))
        after_inference = rss_snapshot()
        result = {
            "kind": "pte",
            "tag": tag,
            "batch_size": args.batch_size,
            "pte_path": str(pte_path),
            "pte_bytes": int(pte_path.stat().st_size),
            "rss_mib": {
                "baseline": baseline,
                "after_load": after_load,
                "after_inference": after_inference,
                "delta_load": after_load - baseline,
                "delta_inference": after_inference - after_load,
            },
        }
    else:
        model, tokenizer = load_base_model_and_tokenizer()
        inputs = synthetic_inputs(tokenizer, args.batch_size, max_length=DEFAULT_MAX_LENGTH)
        wrapper = ExportWrapper(model).eval()
        if args.kind == "fp32":
            after_load = rss_snapshot()
            with torch.inference_mode():
                wrapper(*inputs)
            after_inference = rss_snapshot()
            checkpoint_bytes = int(
                sum(item.stat().st_size for item in BASE_CHECKPOINT.rglob("*") if item.is_file())
            )
        else:
            if args.checkpoint:
                checkpoint = Path(args.checkpoint)
            elif args.kind == "qat":
                checkpoint = CHECKPOINTS_DIR / "qat_lr1e5_bs16_e2_best.pt"
            else:
                checkpoint = CHECKPOINTS_DIR / "ptq_static_int8_prepared.pt"
            if args.kind == "qat":
                converted, _ = load_qat_converted(checkpoint, wrapper, inputs)
            else:
                converted, _ = load_ptq_converted(checkpoint, wrapper, inputs)
            after_load = rss_snapshot()
            with torch.inference_mode():
                converted(*inputs)
            after_inference = rss_snapshot()
            checkpoint_bytes = int(checkpoint.stat().st_size)
        result = {
            "kind": args.kind,
            "tag": tag,
            "batch_size": args.batch_size,
            "checkpoint_bytes": checkpoint_bytes,
            "rss_mib": {
                "baseline": baseline,
                "after_load": after_load,
                "after_inference": after_inference,
                "delta_load": after_load - baseline,
                "delta_inference": after_inference - after_load,
            },
        }

    result["created_utc"] = timestamp_utc()
    result["note"] = (
        "RSS is process-level and includes Python, PyTorch/ExecuTorch runtime, "
        "and model allocations. It is not a peak-RSS measurement."
    )
    save_json(RESULTS_DIR / f"resources_{tag}.json", result)
    logger.info("result=%s", json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
