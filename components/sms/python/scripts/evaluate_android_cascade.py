"""Regression estimate of candidate Android routing using frozen desktop PTE logits.

No training, threshold selection, or fresh-test claim. Does not establish phone
parity or Indian false-positive performance. Keeps raw test messages local.
"""
import hashlib
import json
import re
from pathlib import Path

import numpy as np
import pandas as pd

from sms_detection.predictor import load_detector
from sms_detection.preprocessing.indicators import analyze_text

ROOT = Path(__file__).resolve().parents[1]


def main():
    predictions_path = ROOT / "experiments/mobilebert/qat/results/predictions_ptq_pte_b1.csv"
    frame = pd.read_csv(ROOT / "data/processed/test.csv")
    cached = pd.read_csv(predictions_path).set_index("message_id")
    assert cached.index.is_unique and set(frame.message_id) == set(cached.index)
    detector = load_detector(ROOT / "artifacts/model")
    rows = []
    for row in frame.itertuples():
        first = detector.predict_sms(str(row.text))
        flags = analyze_text(str(row.text)).flags
        benign = flags.get("BENIGN_TRANSACTIONAL") or flags.get("BENIGN_DELIVERY")
        route = not benign and (first.label != "ham" or first.risk_level != "low" or
            flags.get("URL_PRESENT") or first.scores["ham"] < 0.9 or
            detector.policy.assess(first.scores, analyze_text(str(row.text))).rule_triggered)
        promise = bool(re.search(r"\b(?:double|triple|2x|3x)\s+(?:your\s+)?(?:money|investment|capital)\b", str(row.text), re.I) and
            re.search(r"\b(?:in|within)\s+(?:[1-7]|one|two|three|four|five|six|seven)\s+(?:hours?|days?)\b", str(row.text), re.I) and
            not re.search(r"\b(?:beware of|avoid|do not trust|never trust|do not believe|not possible|cannot)\b", str(row.text), re.I))
        route = bool(route or (promise and not benign))
        ordinary_promo = first.label == "spam" and first.risk_level == "low" and flags.get("PROMOTIONAL_CONTENT") and analyze_text(str(row.text)).strong_cue_count() == 0 and not promise
        label, risk = first.label, first.risk_level
        if route:
            neural = cached.loc[row.message_id]
            assert row.label == neural["label"]
            label2 = neural["prediction"]
            if first.risk_level != "high" and not ordinary_promo:
                label = "spam" if promise and label2 == "ham" else label2
                if first.label == "ham" and first.risk_level == "low" and label2 == "spam" and analyze_text(str(row.text)).strong_cue_count() == 0 and not promise:
                    label = "ham"
                risk = "suspicious" if promise or label2 == "smishing" or first.risk_level == "suspicious" else "low"
        rows.append({"true": row.label, "first": first.label, "first_risk": first.risk_level,
            "label": label, "risk": risk, "tier2": bool(route)})
    def metrics(label_key, risk_key):
        return {
            "smishing_support": sum(r["true"] == "smishing" for r in rows),
            "smishing_label_correct": sum(r["true"] == "smishing" and r[label_key] == "smishing" for r in rows),
            "smishing_review_or_high": sum(r["true"] == "smishing" and r[risk_key] != "low" for r in rows),
            "ham_support": sum(r["true"] == "ham" for r in rows),
            "ham_review_or_high": sum(r["true"] == "ham" and r[risk_key] != "low" for r in rows),
            "ham_high": sum(r["true"] == "ham" and r[risk_key] == "high" for r in rows),
            "spam_support": sum(r["true"] == "spam" for r in rows),
            "spam_to_smishing": sum(r["true"] == "spam" and r[label_key] == "smishing" for r in rows),
        }
    report = {"rows": len(rows), "tier2_routed": sum(r["tier2"] for r in rows),
        "tier1": metrics("first", "first_risk"), "cascade": metrics("label", "risk"),
        "cached_predictions_sha256": hashlib.sha256(predictions_path.read_bytes()).hexdigest(),
        "limitations": ["Previously inspected test; regression only", "Uses cached Python PTE logits, not phone outputs", "No fresh Indian false-positive estimate", "Routing and fusion are provisional; no calibration claim"]}
    (ROOT / "artifacts/reports/android_cascade_regression.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
