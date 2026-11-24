"""Synthetic-only Python tokenizer/runtime oracle for the Android self-test.

Run with experiments/mobilebert/.venv/Scripts/python.exe. Never reads user SMS.
"""
import hashlib
import json
import sys
from pathlib import Path

import torch
from transformers import AutoTokenizer
from executorch.runtime import Runtime

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from sms_detection.preprocessing.normalize import normalize_text

SAMPLES = [
    "hii", "hello", "double your money in 2 days",
    "Your OTP is 123456. Do not share it with anyone.",
    "Sale ends today! Get 50% off shoes. Shop at https://example.invalid/sale",
    "Your electricity bill is overdue. Pay now at https://example.invalid/pay to avoid disconnection.",
    "Your KYC is expiring today. Click http://example.invalid/kyc and share OTP 482913 to avoid account block.",
    "Your parcel has been delivered. Thank you.",
    "Aapka bank account band hoga, OTP abhi share karo.",
    "नमस्ते आपका भुगतान सफल हुआ", "Café naïve résumé — ₹500 😀 中文",
    "[CLS] [MASK] [SEP] [URL] www.example.invalid", "longword" * 110,
    "statement " * 160,
]

def main():
    torch.set_num_threads(2)
    checkpoint = ROOT / "experiments/mobilebert/checkpoints/mobilebert22_lr5e5_bs16_e4/best"
    pte = ROOT / "experiments/mobilebert/qat/artifacts/ptq_int8_b1.pte"
    tokenizer = AutoTokenizer.from_pretrained(checkpoint, local_files_only=True)
    runtime = Runtime.get()
    program = runtime.load_program(str(pte))
    method = program.load_method("forward")
    rows = []
    for index, text in enumerate(SAMPLES):
        normalized = normalize_text(text).model_text
        encoded = tokenizer(normalized, padding="max_length", truncation=True, max_length=128, return_tensors="pt")
        inputs = [encoded[k] for k in ("input_ids", "attention_mask", "token_type_ids")]
        z = method.execute(inputs)[0].tolist()[0]
        rows.append({"id": index, "text": text, "normalized": normalized,
            "ids": inputs[0][0].tolist(), "mask": inputs[1][0].tolist(), "logits": z})
    out = ROOT / "android-app/app/src/main/assets/tier2_checks.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"pte_sha256": hashlib.sha256(pte.read_bytes()).hexdigest(),
        "source_runtime": "ExecuTorch Python 1.6.0", "cases": rows}, ensure_ascii=False), encoding="utf-8")
    print(f"Wrote {len(rows)} synthetic checks")

if __name__ == "__main__":
    main()
