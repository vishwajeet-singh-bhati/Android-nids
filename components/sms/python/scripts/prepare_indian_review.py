"""Prepare existing, observed local sources for human review; never trains.

Raw text is written only under ignored data/indian. Existing runs are immutable.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import pandas as pd

from sms_detection.data.review import build_pool, select_pilot, finalize_reviews
from sms_detection.data.indian_sms import check_leakage, load_reference_splits

ROOT = Path(__file__).resolve().parents[1]
PRIVATE = (ROOT / "data/indian").resolve()


def private_path(value: str) -> Path:
    path = Path(value).resolve()
    if not path.is_relative_to(PRIVATE):
        raise ValueError("Review data must stay under data/indian")
    return path


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    prepare = sub.add_parser("prepare")
    prepare.add_argument("--output-dir", default=str(PRIVATE / "review_v1"))
    prepare.add_argument("--pilot-size", type=int, default=400)
    finalize = sub.add_parser("finalize")
    finalize.add_argument("--run-dir", required=True)
    finalize.add_argument("--reviews", required=True)
    args = parser.parse_args()
    if args.command == "finalize":
        run = private_path(args.run_dir)
        manifest = json.loads((run / "manifest.json").read_text(encoding="utf-8"))
        registry_path = run / "review_pool.csv"
        if hashlib.sha256(registry_path.read_bytes()).hexdigest() != manifest["pool_sha256"]:
            raise ValueError("Review registry changed since preparation")
        reviews = pd.read_csv(private_path(args.reviews), keep_default_na=False, dtype=str)
        registry = pd.read_csv(registry_path, keep_default_na=False, dtype=str)
        data, stats = finalize_reviews(reviews, registry)
        target = run / "reviewed_development.csv"
        if target.exists():
            raise FileExistsError("Reviewed export already exists; preserve it and create a new run")
        data.to_csv(target, index=False, encoding="utf-8-sig")
        (run / "review_summary.json").write_text(json.dumps(stats, indent=2), encoding="utf-8")
        print(json.dumps(stats, indent=2))
        return

    out = private_path(args.output_dir)
    if out.exists():
        raise FileExistsError("Output directory already exists; use a new version to preserve review work")
    if args.pilot_size <= 0:
        raise ValueError("Pilot size must be positive")
    sources, frames, warnings = [], [], []
    def source(path, name, text_column, label_column, select=None):
        frame = pd.read_csv(path, keep_default_na=False)
        if select is not None:
            frame = select(frame)
        labels = frame[label_column].astype(str) if label_column else pd.Series("smishing", index=frame.index)
        frames.append(pd.DataFrame({"text": frame[text_column], "source": name,
            "source_label": labels, "source_row": frame.index.astype(str)}))
        sources.append({"file": str(path.relative_to(ROOT)), "rows_selected": len(frame),
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "usage": "previously_observed_development"})
    source(ROOT / "data/indian/india_spam_sms.csv", "kaggle_india_spam_sms", "text", "label")
    source(ROOT / "data/processed/external.csv", "hinglish_processed_observed", "text", "label",
        lambda f: f.loc[f.source_dataset.eq("hinglish_scam")])
    source(ROOT / "experiments/mobilebert/handmade_dataset/smishing_dataset.csv",
        "handmade_observed_synthetic", "Message", None)
    raw = ROOT / "data/raw/hinglish_scam/data.json"
    try:
        json.loads(raw.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        warnings.append(f"Raw Hinglish JSON invalid at line {error.lineno}, column {error.colno}; unchanged. Processed snapshot used.")
    pool, provenance, stats = build_pool(pd.concat(frames, ignore_index=True))
    refs = load_reference_splits(ROOT / "data/processed")
    if not refs:
        raise ValueError("Processed references required for contamination audit")
    audit, leakage = check_leakage(pool.rename(columns={"review_id": "eval_id"}), refs,
        drop_overlaps=False, near_duplicate=True)
    pilot = select_pilot(pool, provenance, args.pilot_size)
    out.mkdir(parents=True)
    pool.to_csv(out / "review_pool.csv", index=False, encoding="utf-8-sig")
    pilot.to_csv(out / "pilot_review.csv", index=False, encoding="utf-8-sig")
    provenance.to_csv(out / "source_labels_reference.csv", index=False, encoding="utf-8-sig")
    audit[["eval_id", "leakage_splits"]].to_csv(out / "overlap_audit.csv", index=False)
    manifest = {"purpose": "Human annotation development pool; no labels verified yet",
        "sources": sources, "warnings": warnings, "pool": stats, "pilot_rows": len(pilot),
        "leakage": leakage, "fresh_test_rows": 0,
        "pool_sha256": hashlib.sha256((out / "review_pool.csv").read_bytes()).hexdigest(),
        "model_predictions_used": False, "human_reviewed_rows": 0}
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(json.dumps({"pool": stats, "pilot_rows": len(pilot), "warnings": warnings,
        "reference_overlap_rows": leakage["overlap_rows"], "fresh_test_rows": 0}, indent=2))


if __name__ == "__main__":
    main()
