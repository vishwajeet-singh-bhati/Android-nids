"""Text-free regression report for the current Tier-1 policy.

Previously inspected test and handmade sets are regression checks, not blind
benchmarks. No model training or threshold selection happens here.
"""
from __future__ import annotations

import json
from pathlib import Path

import pandas as pd

from sms_detection.config import POLICY_VERSION
from sms_detection.models.evaluate import compute_metrics
from sms_detection.predictor import load_detector


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    detector = load_detector(root / "artifacts/model")
    report = {"policy_version": POLICY_VERSION, "limitations": [
        "Previously observed sets; regression evidence only.",
        "Handmade set is all-positive and cannot measure precision.",
        "No Android runtime or Tier-2 cascade measurements.",
    ], "splits": {}}
    for split in ("val", "test", "handmade"):
        if split == "handmade":
            frame = pd.read_csv(root / "experiments/mobilebert/handmade_dataset/smishing_dataset.csv")
            texts = frame["Message"].astype(str).tolist()
            labels = ["smishing"] * len(texts)
        else:
            frame = pd.read_csv(root / f"data/processed/{split}.csv")
            texts, labels = frame["text"].astype(str).tolist(), frame["label"].tolist()
        results = detector.predict_batch(texts)
        flagged = [r.risk_level != "low" for r in results]
        report["splits"][split] = {
            "metrics": compute_metrics(labels, [r.label for r in results]),
            "review_or_high": sum(flagged),
            "high": sum(r.risk_level == "high" for r in results),
            "smishing_review_or_high": sum(f and y == "smishing" for f, y in zip(flagged, labels)),
            "smishing_support": labels.count("smishing"),
            "ham_review_or_high": sum(f and y == "ham" for f, y in zip(flagged, labels)),
            "ham_support": labels.count("ham"),
        }
    output = root / "artifacts/reports/policy_review_v2_regression.json"
    output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    for split, result in report["splits"].items():
        print(split, json.dumps({k: v for k, v in result.items() if k != "metrics"}))
    print(f"Wrote {output}")


if __name__ == "__main__":
    main()
