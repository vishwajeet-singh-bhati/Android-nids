"""Evaluate a frozen detector on a local Indian SMS benchmark.

The benchmark is intentionally separate from the training pipeline. Raw messages
stay local, are never sent to a cloud service, and are not written to the
aggregate report. Use ``--audit-output`` only for a private, git-ignored file.

Example::

    python scripts/evaluate_indian.py --input data/indian/benchmark.csv --name pilot

Expected CSV/JSON columns:

    text,label
    optional: language, sender, sender_type, scam_type,
              collection_date, group_id, source, known_sender
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sms_detection.config import MODEL_DIR, PROCESSED_DIR, REPORTS_DIR
from sms_detection.data.indian_sms import (
    BenchmarkFormatError,
    check_leakage,
    load_benchmark,
    load_reference_splits,
)
from sms_detection.models.indian_eval import (
    evaluate_benchmark,
    predict_rows,
    render_markdown,
)
from sms_detection.predictor import load_detector


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="evaluate-indian",
        description="Evaluate the SMS detector on a local Indian SMS benchmark",
    )
    parser.add_argument("--input", required=True, help="CSV, JSON, or JSONL benchmark")
    parser.add_argument("--name", default="indian", help="Report name/slug")
    parser.add_argument("--model-dir", default=str(MODEL_DIR))
    parser.add_argument("--processed-dir", default=str(PROCESSED_DIR))
    parser.add_argument("--output", default=None, help="Aggregate JSON report path")
    parser.add_argument("--markdown", default=None, help="Aggregate Markdown report path")
    parser.add_argument(
        "--target-prevalence",
        type=float,
        default=None,
        help="Optional realistic smishing prevalence for prevalence-adjusted precision",
    )
    parser.add_argument(
        "--min-slice-rows",
        type=int,
        default=20,
        help="Do not report metadata slices smaller than this",
    )
    parser.add_argument(
        "--bootstrap-replicates",
        type=int,
        default=1000,
        help="Bootstrap replicates for macro-F1 intervals (0 disables)",
    )
    parser.add_argument(
        "--audit-output",
        default=None,
        help="Optional private CSV containing raw text; keep it out of Git",
    )
    parser.add_argument(
        "--keep-overlaps",
        action="store_true",
        help="Report leakage but do not drop benchmark rows that overlap a split",
    )
    parser.add_argument(
        "--skip-leakage-check",
        action="store_true",
        help="Do not load processed splits for overlap checking",
    )
    parser.add_argument(
        "--no-near-duplicate",
        action="store_true",
        help="Use exact/template-only leakage grouping instead of MinHash clustering",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return _run(args)
    except (BenchmarkFormatError, FileNotFoundError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


def _run(args: argparse.Namespace) -> int:
    input_path = Path(args.input)
    frame = load_benchmark(input_path)
    input_rows = int(frame.attrs.get("input_rows", len(frame)))
    dropped_empty = int(frame.attrs.get("dropped_empty_rows", 0))

    uncertain_mask = frame["label"].astype(str).str.lower().eq("uncertain")
    excluded_uncertain = int(uncertain_mask.sum())
    frame = frame.loc[~uncertain_mask].reset_index(drop=True)
    if frame.empty:
        raise ValueError("Benchmark has no labelled rows after excluding uncertain rows")

    references = {}
    if not args.skip_leakage_check:
        references = load_reference_splits(args.processed_dir)
        if not references:
            print(
                "warning: no processed reference splits found; leakage check skipped",
                file=sys.stderr,
            )

    frame, leakage = check_leakage(
        frame,
        references,
        drop_overlaps=not args.keep_overlaps,
        near_duplicate=not args.no_near_duplicate,
    )
    if frame.empty:
        raise ValueError(
            "Benchmark has no rows after leakage filtering; "
            "inspect the overlap counts or use --keep-overlaps"
        )

    detector = load_detector(args.model_dir)
    metadata: dict[str, Any] = {
        "name": args.name,
        "input_file": input_path.name,
        "input_rows": input_rows,
        "excluded_uncertain_rows": excluded_uncertain,
        "dropped_empty_rows": dropped_empty,
        "dropped_overlap_rows": int(leakage.get("dropped_rows", 0)),
        "leakage": leakage,
        "created_utc": datetime.now(timezone.utc).isoformat(),
    }
    report = evaluate_benchmark(
        frame,
        detector,
        name=args.name,
        metadata=metadata,
        target_prevalence=args.target_prevalence,
        bootstrap_replicates=args.bootstrap_replicates,
        min_slice_rows=args.min_slice_rows,
    )
    if args.keep_overlaps and leakage.get("overlap_rows", 0):
        report["limitations"].append(
            "Leakage-overlap rows were retained; headline metrics may be optimistic."
        )

    slug = _slug(args.name)
    output_path = (
        Path(args.output)
        if args.output
        else REPORTS_DIR / f"indian_eval_{slug}.json"
    )
    markdown_path = (
        Path(args.markdown)
        if args.markdown
        else REPORTS_DIR / f"indian_eval_{slug}.md"
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    markdown_path.write_text(render_markdown(report), encoding="utf-8")

    if args.audit_output:
        audit_path = Path(args.audit_output)
        audit_path.parent.mkdir(parents=True, exist_ok=True)
        _write_audit(frame, detector, audit_path)
        print(
            f"Private audit written to {audit_path}. Keep raw SMS out of Git.",
            file=sys.stderr,
        )

    benchmark = report["benchmark"]
    policy = report["policy_metrics"]
    risk = report["risk"]
    print(
        "Evaluated "
        f"{benchmark['rows']:,} rows | "
        f"smishing recall={policy['smishing_recall']:.3f} | "
        f"smishing precision={policy['smishing_precision']:.3f} | "
        f"high-band recall={risk['high_smishing_recall']:.3f} | "
        f"ham high-risk={risk['ham_high_rate']:.3f}"
    )
    if leakage.get("checked"):
        print(
            "Leakage check: "
            f"overlap rows={leakage['overlap_rows']:,}, "
            f"dropped={leakage['dropped_rows']:,}"
        )
    print(f"Wrote {output_path}")
    print(f"Wrote {markdown_path}")
    return 0


def _write_audit(frame, detector, path: Path) -> None:
    rows = predict_rows(frame, detector)
    fields = [
        "eval_id",
        "text",
        "true_label",
        "policy_label",
        "classifier_label",
        "risk_level",
        "scores",
        "evidence_codes",
        "action_codes",
        "language",
        "sender_type",
        "scam_type",
        "collection_month",
        "source",
        "leakage_splits",
    ]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow(
                {
                    "eval_id": row["eval_id"],
                    "text": row["text"],
                    "true_label": row["true_label"],
                    "policy_label": row["policy_label"],
                    "classifier_label": row["classifier_label"],
                    "risk_level": row["risk_level"],
                    "scores": json.dumps(row["scores"], sort_keys=True),
                    "evidence_codes": "|".join(row["evidence_codes"]),
                    "action_codes": "|".join(row["action_codes"]),
                    "language": row["language"],
                    "sender_type": row["sender_type"],
                    "scam_type": row["scam_type"],
                    "collection_month": row["collection_month"],
                    "source": row["source"],
                    "leakage_splits": row["leakage_splits"],
                }
            )


def _slug(value: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9_-]+", "_", value.strip()).strip("_")
    return slug or "indian"


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
