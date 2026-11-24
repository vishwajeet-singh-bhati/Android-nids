"""Prepare the Kaggle India Spam SMS collection as a local evaluation benchmark.

The source is binary (ham/spam), not smishing, and is not a random sample of
Indian traffic. This script only normalizes it, removes exact duplicate texts,
and writes the local benchmark expected by ``scripts/evaluate_indian.py``. It
never prints message bodies.
"""

from __future__ import annotations

import argparse
from pathlib import Path

import pandas as pd

from sms_detection.config import INDIAN_DIR, RAW_DIR
from sms_detection.data.load_sources import load_india_spam
from sms_detection.preprocessing.normalize import normalize_text

OUTPUT_COLUMNS = (
    "text",
    "label",
    "language",
    "sender",
    "sender_type",
    "scam_type",
    "collection_date",
    "group_id",
    "source",
    "known_sender",
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Prepare the Kaggle India Spam SMS collection for local evaluation"
    )
    parser.add_argument("--raw-dir", default=str(RAW_DIR))
    parser.add_argument("--output", default=str(INDIAN_DIR / "india_spam_sms.csv"))
    parser.add_argument(
        "--keep-exact-duplicates",
        action="store_true",
        help="Keep repeated normalized texts instead of retaining one copy",
    )
    return parser


def prepare_benchmark(
    raw_dir: str | Path = RAW_DIR,
    output: str | Path = INDIAN_DIR / "india_spam_sms.csv",
    *,
    deduplicate: bool = True,
) -> dict[str, int | str]:
    """Build the evaluation CSV and return aggregate-only preparation stats."""

    frame = load_india_spam(Path(raw_dir))
    if frame.empty:
        raise FileNotFoundError(
            "India Spam SMS source not found. Run scripts/download_data.py first."
        )

    frame = frame.copy()
    frame["text"] = frame["text"].astype(str).str.strip()
    frame = frame[frame["text"].str.len() > 0].copy()
    labels = set(frame["label"].astype(str))
    unsupported = labels.difference({"ham", "spam"})
    if unsupported:
        raise ValueError(f"Unexpected labels in Indian source: {sorted(unsupported)}")

    before = len(frame)
    if deduplicate:
        frame["_exact_key"] = [
            normalize_text(text).normalized.lower() for text in frame["text"].tolist()
        ]
        frame = frame.drop_duplicates("_exact_key", keep="first").copy()
    after = len(frame)

    benchmark = pd.DataFrame(
        {
            "text": frame["text"].values,
            "label": frame["label"].values,
            "language": frame["language"].values,
            "sender": "",
            "sender_type": "unknown",
            "scam_type": "unspecified",
            "collection_date": "",
            "group_id": "",
            "source": "kaggle_india_spam_sms",
            "known_sender": False,
        }
    )[list(OUTPUT_COLUMNS)]

    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    benchmark.to_csv(output, index=False, encoding="utf-8")

    counts = benchmark["label"].value_counts().to_dict()
    stats: dict[str, int | str] = {
        "input_rows": int(before),
        "output_rows": int(after),
        "dropped_exact_duplicate_rows": int(before - after),
        "ham_rows": int(counts.get("ham", 0)),
        "spam_rows": int(counts.get("spam", 0)),
        "output": str(output),
    }
    return stats


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    stats = prepare_benchmark(
        args.raw_dir,
        args.output,
        deduplicate=not args.keep_exact_duplicates,
    )
    print(
        "Prepared Indian source benchmark: "
        f"{stats['output_rows']:,} rows "
        f"({stats['ham_rows']:,} ham / {stats['spam_rows']:,} spam); "
        f"dropped {stats['dropped_exact_duplicate_rows']:,} exact duplicates."
    )
    print(f"Wrote {stats['output']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
