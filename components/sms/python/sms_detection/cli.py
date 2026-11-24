"""Command-line interface for local SMS detection and schema export."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .config import MODEL_DIR, SCHEMA_DIR
from .interface.schema import write_json_schema
from .predictor import SmsDetector


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sms-detect",
        description="Explainable local SMS ham/spam/smishing detector",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    predict = sub.add_parser("predict", help="Classify one SMS")
    predict.add_argument("text", nargs="?", help="SMS body; read from stdin if omitted")
    predict.add_argument("--sender", default=None)
    predict.add_argument("--known-sender", action="store_true")
    predict.add_argument("--model-dir", default=str(MODEL_DIR))

    batch = sub.add_parser("predict-batch", help="Classify messages from a JSON array")
    batch.add_argument("input", help="JSON file containing strings or {text,sender} objects")
    batch.add_argument("--output", default=None)
    batch.add_argument("--model-dir", default=str(MODEL_DIR))

    schema = sub.add_parser("schema", help="Write the public JSON Schema")
    schema.add_argument("--output", default=str(SCHEMA_DIR / "sms_detection_result.schema.json"))

    info = sub.add_parser("info", help="Print model metadata and thresholds")
    info.add_argument("--model-dir", default=str(MODEL_DIR))

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "schema":
        path = write_json_schema(args.output)
        print(f"Wrote {path}")
        return 0

    detector = SmsDetector.from_artifact(args.model_dir)

    if args.command == "info":
        print(json.dumps(detector.artifact_summary(), indent=2, ensure_ascii=False))
        return 0

    if args.command == "predict":
        text = args.text if args.text is not None else sys.stdin.read()
        result = detector.predict_sms(
            text, sender=args.sender, known_sender=args.known_sender
        )
        print(result.to_json())
        return 0

    if args.command == "predict-batch":
        payload = json.loads(Path(args.input).read_text(encoding="utf-8"))
        results = []
        for item in payload:
            if isinstance(item, str):
                results.append(detector.predict_sms(item).to_dict())
            else:
                results.append(
                    detector.predict_sms(
                        item["text"],
                        sender=item.get("sender"),
                        known_sender=bool(item.get("known_sender", False)),
                    ).to_dict()
                )
        text = json.dumps(results, indent=2, ensure_ascii=False)
        if args.output:
            Path(args.output).write_text(text, encoding="utf-8")
            print(f"Wrote {args.output}")
        else:
            print(text)
        return 0

    return 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
