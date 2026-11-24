"""Frozen PTE inference on unique normalized inputs; no training/network calls."""
import json
import sys
import time
from pathlib import Path

import torch
from transformers import AutoTokenizer
from executorch.runtime import Runtime

ROOT = Path(__file__).resolve().parents[2]

def main():
    source, output = map(Path, sys.argv[1:3])
    torch.set_num_threads(2)
    tokenizer = AutoTokenizer.from_pretrained(ROOT / "experiments/mobilebert/checkpoints/mobilebert22_lr5e5_bs16_e4/best", local_files_only=True)
    program = Runtime.get().load_program(str(ROOT / "experiments/mobilebert/qat/artifacts/ptq_int8_b1.pte"))
    method = program.load_method("forward")
    rows = json.loads(source.read_text(encoding="utf-8"))
    with output.open("w", encoding="utf-8") as handle:
        for index, row in enumerate(rows):
            tokens = tokenizer(row["normalized"], padding="max_length", truncation=True, max_length=128, return_tensors="pt")
            start = time.perf_counter()
            z = torch.as_tensor(method.execute([tokens[k] for k in ("input_ids", "attention_mask", "token_type_ids")])[0]).float()[0]
            elapsed = (time.perf_counter() - start) * 1000
            assert z.numel() == 3 and torch.isfinite(z).all()
            handle.write(json.dumps({"key": row["key"], "logits": z.tolist(), "scores": torch.softmax(z, -1).tolist(), "forward_ms": elapsed}) + "\n")
            handle.flush()
            if (index + 1) % 50 == 0 or index + 1 == len(rows):
                print(f"PTE: {index + 1}/{len(rows)} unique normalized inputs", flush=True)

if __name__ == "__main__": main()
