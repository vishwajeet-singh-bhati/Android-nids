"""Convert a trained QAT/PTQ MobileBERT state into an XNNPACK INT8 .pte.

The script reconstructs the prepared graph for the requested batch size, loads
the trained state, converts to quantized PyTorch, exports through ExecuTorch,
then loads and executes the .pte with the ExecuTorch runtime.
"""

from __future__ import annotations

import argparse
import json
import os
import time
import traceback
from pathlib import Path

import numpy as np
import torch

from qat_common import (
    ARTIFACTS_DIR,
    CHECKPOINTS_DIR,
    DEFAULT_BATCH_SIZE,
    DEFAULT_MAX_LENGTH,
    ExportWrapper,
    configure_environment,
    convert_prepared,
    edge_graph_summary,
    graph_summary,
    load_base_model_and_tokenizer,
    load_prepared_state,
    load_json,
    make_ptq_quantizer,
    make_qat_quantizer,
    prepare_ptq_graph,
    prepare_qat_graph,
    save_json,
    setup_logger,
    synthetic_inputs,
    timestamp_utc,
)
from qat_common import CONFIG_PATH, LOGS_DIR, RESULTS_DIR


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kind", choices=["qat", "ptq"], required=True)
    parser.add_argument("--batch-size", type=int, default=DEFAULT_BATCH_SIZE)
    parser.add_argument("--checkpoint", default=None)
    parser.add_argument("--tag", default=None)
    parser.add_argument("--threads", type=int, default=8)
    return parser.parse_args()


def default_checkpoint(kind: str) -> Path:
    if kind == "qat":
        return CHECKPOINTS_DIR / "qat_lr1e5_bs16_e2_best.pt"
    return CHECKPOINTS_DIR / "ptq_static_int8_prepared.pt"


def export_with_session(converted, inputs, pte_path: Path, tag: str):
    from executorch.backends.xnnpack.partition.config.xnnpack_config import (
        ConfigPrecisionType,
    )
    from executorch.backends.xnnpack.partition.xnnpack_partitioner import (
        XnnpackPartitioner,
    )
    from executorch.backends.xnnpack.utils.configs import (
        get_xnnpack_edge_compile_config,
        get_xnnpack_executorch_backend_config,
    )
    from executorch.export import ExportRecipe, LoweringRecipe, export
    from executorch.export.recipe import Mode

    recipe = ExportRecipe(
        name=tag,
        lowering_recipe=LoweringRecipe(
            partitioners=[
                XnnpackPartitioner(
                    config_precisions=ConfigPrecisionType.STATIC_QUANT
                )
            ],
            edge_compile_config=get_xnnpack_edge_compile_config(),
        ),
        executorch_backend_config=get_xnnpack_executorch_backend_config(),
        mode=Mode.RELEASE,
        release_intermediate_artifacts=False,
    )
    session = export(
        converted,
        example_inputs=[inputs],
        export_recipe=recipe,
        artifact_dir=str(ARTIFACTS_DIR / f"export_{tag}"),
    )
    session.save_to_pte(str(pte_path))
    return session


def export_direct(converted, inputs, pte_path: Path):
    from executorch.backends.xnnpack.partition.config.xnnpack_config import (
        ConfigPrecisionType,
    )
    from executorch.backends.xnnpack.partition.xnnpack_partitioner import (
        XnnpackPartitioner,
    )
    from executorch.backends.xnnpack.utils.configs import (
        get_xnnpack_edge_compile_config,
        get_xnnpack_executorch_backend_config,
    )
    from executorch.exir import to_edge_transform_and_lower

    exported = torch.export.export(converted, inputs)
    edge = to_edge_transform_and_lower(
        exported,
        partitioner=[
            XnnpackPartitioner(
                config_precisions=ConfigPrecisionType.STATIC_QUANT
            )
        ],
        compile_config=get_xnnpack_edge_compile_config(),
    )
    executorch_program = edge.to_executorch(
        config=get_xnnpack_executorch_backend_config()
    )
    pte_path.parent.mkdir(parents=True, exist_ok=True)
    with pte_path.open("wb") as handle:
        executorch_program.write_to_file(handle)
    return edge


def main() -> None:
    args = parse_args()
    actual_threads = configure_environment(seed=42, threads=args.threads)
    if not os.environ.get("FLATC_EXECUTABLE"):
        bundled_flatc = Path(__file__).resolve().parents[2] / ".venv" / "Scripts" / "flatc.exe"
        if bundled_flatc.exists():
            os.environ["FLATC_EXECUTABLE"] = str(bundled_flatc)
    config = load_json(CONFIG_PATH)
    batch_size = int(args.batch_size)
    max_length = int(config.get("max_length", DEFAULT_MAX_LENGTH))
    quantization_scope = str(
        config.get("export", {}).get(
            "quantization_scope",
            config.get("qat", {}).get("quantization_scope", "linear_only"),
        )
    )
    tag = args.tag or f"{args.kind}_int8_b{batch_size}"
    checkpoint_path = Path(args.checkpoint) if args.checkpoint else default_checkpoint(args.kind)
    log_path = LOGS_DIR / f"export_{tag}.log"
    logger = setup_logger(f"export_{tag}", log_path)
    logger.info(
        "Starting export kind=%s batch_size=%s checkpoint=%s threads=%s",
        args.kind,
        batch_size,
        checkpoint_path,
        actual_threads,
    )

    model, tokenizer = load_base_model_and_tokenizer()
    wrapper = ExportWrapper(model).eval()
    inputs = synthetic_inputs(tokenizer, batch_size, max_length=max_length)
    logger.info("Input shapes=%s", [list(tensor.shape) for tensor in inputs])

    if args.kind == "qat":
        prepared = prepare_qat_graph(wrapper, inputs, scope=quantization_scope)
    else:
        prepared = prepare_ptq_graph(wrapper, inputs, scope=quantization_scope)
    payload = load_prepared_state(prepared, checkpoint_path)
    logger.info(
        "Loaded prepared state; source_tag=%s source_epoch=%s",
        payload.get("tag"),
        payload.get("epoch"),
    )
    converted = convert_prepared(prepared)
    logger.info("Converted quantized graph nodes=%s", len(converted.graph.nodes))

    with torch.inference_mode():
        torch_output = converted(*inputs).detach().float().cpu()

    pte_path = ARTIFACTS_DIR / f"{tag}.pte"
    started = time.perf_counter()
    session = None
    edge = None
    export_mode = "session"
    try:
        session = export_with_session(converted, inputs, pte_path, tag)
    except Exception:
        logger.exception("High-level ExportSession failed; trying direct lower-level export")
        export_mode = "direct"
        edge = export_direct(converted, inputs, pte_path)
    export_seconds = time.perf_counter() - started
    if not pte_path.exists():
        raise RuntimeError(f"Export did not produce {pte_path}")
    logger.info(
        "Exported %s in %.1fs; pte_bytes=%s",
        pte_path,
        export_seconds,
        pte_path.stat().st_size,
    )

    if session is not None:
        edge = session.get_edge_program_manager()
    if edge is None:
        raise RuntimeError("No edge program available for inspection")
    edge_summary = edge_graph_summary(edge, "forward")

    from executorch.runtime import Runtime

    runtime = Runtime.get()
    program = runtime.load_program(str(pte_path))
    method = program.load_method("forward")
    runtime_outputs = method.execute(list(inputs))
    runtime_output = torch.from_numpy(np.asarray(runtime_outputs[0])).float()
    max_abs_diff = float((runtime_output - torch_output).abs().max())
    argmax_agreement = float(
        (runtime_output.argmax(dim=-1) == torch_output.argmax(dim=-1)).float().mean()
    )
    finite = bool(torch.isfinite(runtime_output).all())
    logger.info(
        "Runtime verified; max_abs_diff=%.6g argmax_agreement=%.6f finite=%s",
        max_abs_diff,
        argmax_agreement,
        finite,
    )

    method.execute(list(inputs))
    timings = []
    for _ in range(3):
        start = time.perf_counter()
        method.execute(list(inputs))
        timings.append(time.perf_counter() - start)
    latency_seconds = sorted(timings)
    median_latency = latency_seconds[len(latency_seconds) // 2]

    summary = {
        "created_utc": timestamp_utc(),
        "status": "runtime_verified",
        "kind": args.kind,
        "tag": tag,
        "quantization_scope": quantization_scope,
        "checkpoint": str(checkpoint_path),
        "checkpoint_bytes": int(checkpoint_path.stat().st_size),
        "base_checkpoint": str(qat_common_base_checkpoint()),
        "batch_size": batch_size,
        "max_length": max_length,
        "input_shapes": [list(tensor.shape) for tensor in inputs],
        "export_mode": export_mode,
        "export_seconds": export_seconds,
        "pte_path": str(pte_path),
        "pte_bytes": int(pte_path.stat().st_size),
        "runtime": {
            "executed": True,
            "finite": finite,
            "output_shape": list(runtime_output.shape),
            "max_abs_diff_vs_quantized_pytorch": max_abs_diff,
            "argmax_agreement_vs_quantized_pytorch": argmax_agreement,
            "latency_seconds": timings,
            "median_latency_seconds": median_latency,
            "seconds_per_example_batch": median_latency / max(batch_size, 1),
        },
        "precision": {
            "graph": graph_summary(converted),
            "edge": edge_summary,
            "scope": "Hybrid INT8/FP32: Linear weights and activations are quantized; aten.add and aten.mul remain FP32, as do embeddings, bmm, softmax, div and other fallback ops outside the XNNPACK delegate.",
        },
        "source_payload": {
            "created_utc": payload.get("created_utc"),
            "tag": payload.get("tag"),
            "epoch": payload.get("epoch"),
            "global_step": payload.get("global_step"),
            "val_metrics": payload.get("val_metrics"),
        },
        "test_split_loaded": False,
        "config": config,
    }
    save_json(RESULTS_DIR / f"export_{tag}.json", summary)
    logger.info("Export summary: %s", json.dumps(summary, indent=2))


def qat_common_base_checkpoint() -> Path:
    from qat_common import BASE_CHECKPOINT

    return BASE_CHECKPOINT


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        configure_environment()
        logger = setup_logger("export_failure", LOGS_DIR / "export_failure.log")
        failure = {
            "created_utc": timestamp_utc(),
            "status": "failed",
            "error_type": type(error).__name__,
            "error": str(error),
            "traceback": traceback.format_exc(),
        }
        save_json(RESULTS_DIR / "export_failure.json", failure)
        logger.exception("Export failed")
        raise
