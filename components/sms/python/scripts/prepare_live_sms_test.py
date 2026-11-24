"""Create hash-only Android reference and private sender checklist for the 100 SMS.

These are observed development examples, not an independent accuracy benchmark.
"""
import hashlib
import json
import re
import unicodedata
from pathlib import Path

import pandas as pd
from sms_detection.preprocessing.normalize import normalize_text

ROOT = Path(__file__).resolve().parents[1]

def canonical(text):
    return re.sub(r"\s+", " ", unicodedata.normalize("NFKC", text)).strip().lower()

def digest(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()

def main():
    source = ROOT / "experiments/mobilebert/handmade_dataset/smishing_dataset.csv"
    frame = pd.read_csv(source)
    assert len(frame) == 100 and frame.ID.is_unique
    references = [{"sample_id": int(r.ID), "exact_hash": digest(canonical(r.Message)),
        "template_hash": digest(normalize_text(r.Message).model_text),
        "category": r.Category, "tactic": r.Tactic} for r in frame.itertuples()]
    payload = {"expected_count": 100, "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        "ptq_sha256": hashlib.sha256((ROOT / "experiments/mobilebert/qat/artifacts/ptq_int8_b1.pte").read_bytes()).hexdigest(),
        "limitations": "Observed all-positive handmade development set; no precision or population-accuracy claim", "samples": references}
    output = ROOT / "android-app/app/src/main/assets/live_sms_reference.json"
    output.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    private = ROOT / "data/indian/live_sms_eval_v1"
    private.mkdir(parents=True, exist_ok=True)
    checklist = private / "sending_checklist.csv"
    if not checklist.exists():
        frame["sender_alias"] = ""
        frame["sent_at"] = ""
        frame["send_status"] = ""
        frame.to_csv(checklist, index=False, encoding="utf-8-sig")
    (private / "reference.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print("Prepared 100 hash-only references and local sending checklist.")

if __name__ == "__main__":
    main()
