"""Analyze an exported private run directory; aggregate JSON/Markdown only."""
import argparse
import json
from pathlib import Path
from sms_detection.data.live_eval import summarize

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--output-prefix", type=Path, required=True)
    args = parser.parse_args()
    config = json.loads((args.run_dir / "config.json").read_text(encoding="utf-8-sig"))
    events = []
    parse_errors = []
    path = args.run_dir / "events.jsonl"
    if path.exists():
        for number, line in enumerate(path.read_text(encoding="utf-8-sig").splitlines(), 1):
            if not line.strip(): continue
            try: events.append(json.loads(line))
            except json.JSONDecodeError: parse_errors.append(f"Invalid/incomplete JSON at line {number}")
    report = summarize(config, events)
    export_state = args.run_dir / "export_state.json"
    if export_state.exists():
        report["export_state"] = json.loads(export_state.read_text(encoding="utf-8-sig"))
    report["validation_errors"].extend(parse_errors)
    args.output_prefix.parent.mkdir(parents=True, exist_ok=True)
    args.output_prefix.with_suffix(".json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    lines = ["# Live SMS development test", "", f"Run: {report['run_id']}", "",
        "| Measure | Count |", "|---|---:|"]
    for key in ("expected_unique_samples", "received_events_all", "completed_events_all", "pending_events_all", "failed_events_all", "unique_samples_received", "duplicate_matched_receipts", "unmatched_events", "ambiguous_events", "first_attempt_completed_samples", "strict_smishing_first_attempt", "review_or_high_first_attempt", "notification_submitted_first_attempt"):
        lines.append(f"| {key} | {report[key]} |")
    lines += ["", f"First-attempt tiers: {report['first_attempt_tiers']}", "",
        f"Missing IDs: {report['missing_sample_ids']}", "", "## Limits", ""]
    lines += ["- " + x for x in report["limitations"]]
    if report["validation_errors"]: lines += ["", "## Log errors", "", *report["validation_errors"]]
    args.output_prefix.with_suffix(".md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(json.dumps({k: v for k, v in report.items() if k not in {"per_sample", "timings_ms_matched_events", "limitations"}}, indent=2))

if __name__ == "__main__": main()
