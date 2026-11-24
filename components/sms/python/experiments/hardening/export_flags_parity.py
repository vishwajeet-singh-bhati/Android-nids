"""Export the full Python indicator-flag vector for Kotlin parity checks.

The default fixture is synthetic and safe to commit. Wider local fixtures may
contain raw SMS and should be written to the approved local temp directory.
"""

from __future__ import annotations

import argparse
import base64
from pathlib import Path

import pandas as pd

from export_kotlin_parity import HANDMADE, SYNTHETIC_CASES, TEST, VAL
from sms_detection.preprocessing.indicators import EVIDENCE_CODES, analyze_text

HEADER = ["id", "text_b64", "sender_b64", "flags", "strong_count"]


def b64(value: str | None) -> str:
    if value is None or value == "":
        return "-"
    return base64.b64encode(str(value).encode("utf-8")).decode("ascii")


def add_row(rows: list[list[str]], case_id: str, text: str, sender: str | None) -> None:
    result = analyze_text(text, sender=sender)
    bits = "".join("1" if result.flags.get(code, False) else "0" for code in EVIDENCE_CODES)
    rows.append([case_id, b64(text), b64(sender), bits, str(result.strong_cue_count())])


def add_dataframe(
    rows: list[list[str]],
    frame: pd.DataFrame,
    *,
    prefix: str,
    limit: int | None,
    seed: int,
) -> None:
    frame = frame[frame["text"].notna()]
    if limit is not None and len(frame) > limit:
        frame = frame.sample(n=limit, random_state=seed)
    for _, record in frame.iterrows():
        text = str(record["text"])
        if not text.strip():
            continue
        sender = record.get("sender")
        if pd.isna(sender):
            sender = None
        add_row(rows, f"{prefix}-{record['message_id']}", text, sender)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        type=Path,
        default=Path(__file__).resolve().parents[2]
        / "tier1-kotlin/fixtures/synthetic_flags_parity.tsv",
    )
    parser.add_argument("--include-handmade", action="store_true")
    parser.add_argument("--include-processed", type=int, default=0)
    parser.add_argument("--seed", type=int, default=20261111)
    args = parser.parse_args()

    rows: list[list[str]] = []
    for case_id, text, sender in SYNTHETIC_CASES:
        add_row(rows, case_id, text, sender)

    if args.include_handmade:
        handmade = pd.read_csv(HANDMADE)
        for _, record in handmade.iterrows():
            add_row(rows, f"handmade-{record['ID']}", str(record["Message"]), None)

    if args.include_processed > 0:
        add_dataframe(
            rows,
            pd.read_csv(VAL),
            prefix="val",
            limit=args.include_processed,
            seed=args.seed,
        )
        add_dataframe(
            rows,
            pd.read_csv(TEST),
            prefix="test",
            limit=args.include_processed,
            seed=args.seed,
        )

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write("\t".join(HEADER) + "\n")
        for row in rows:
            handle.write("\t".join(row) + "\n")

    print(f"wrote {len(rows)} cases to {args.output}")
    print(f"flags={len(EVIDENCE_CODES)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
