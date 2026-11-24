"""Export portable-model probabilities for Kotlin parity checks.

Default output is synthetic-only and safe to commit. Pass --include-handmade
and --include-processed for the wider local fixture; keep that fixture in a
local temp directory rather than the repository.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
from pathlib import Path

import numpy as np
import pandas as pd

from export_kotlin_parity import HANDMADE, SYNTHETIC_CASES, TEST, VAL
from sms_detection.models.export import PortableLinearClassifier

REPO = Path(__file__).resolve().parents[2]
MODEL = REPO / "artifacts/model/portable/portable_model.json"

HEADER = [
    "id",
    "text_b64",
    "sender_b64",
    "logit_ham",
    "logit_spam",
    "logit_smishing",
    "p_ham",
    "p_spam",
    "p_smishing",
    "label",
]


def b64(value: str | None) -> str:
    if value is None or value == "":
        return "-"
    return base64.b64encode(str(value).encode("utf-8")).decode("ascii")


def add_row(
    rows: list[list[str]],
    portable: PortableLinearClassifier,
    case_id: str,
    text: str,
    sender: str | None,
) -> None:
    logits = np.asarray(portable.decision_function(text, sender=sender), dtype=float)
    probabilities = portable.predict_proba(text, sender=sender)
    label = max(probabilities, key=probabilities.get)
    rows.append(
        [
            case_id,
            b64(text),
            b64(sender),
            *(f"{float(value):.17g}" for value in logits),
            *(f"{probabilities[name]:.17g}" for name in ("ham", "spam", "smishing")),
            label,
        ]
    )


def add_dataframe(
    rows: list[list[str]],
    portable: PortableLinearClassifier,
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
        add_row(rows, portable, f"{prefix}-{record['message_id']}", text, sender)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        type=Path,
        default=REPO / "tier1-kotlin/fixtures/synthetic_model_parity.tsv",
    )
    parser.add_argument("--include-handmade", action="store_true")
    parser.add_argument("--include-processed", type=int, default=0)
    parser.add_argument("--seed", type=int, default=20261111)
    args = parser.parse_args()

    portable = PortableLinearClassifier(MODEL)
    rows: list[list[str]] = []
    for case_id, text, sender in SYNTHETIC_CASES:
        add_row(rows, portable, case_id, text, sender)

    if args.include_handmade:
        handmade = pd.read_csv(HANDMADE)
        for _, record in handmade.iterrows():
            add_row(rows, portable, f"handmade-{record['ID']}", str(record["Message"]), None)

    if args.include_processed > 0:
        add_dataframe(
            rows,
            portable,
            pd.read_csv(VAL),
            prefix="val",
            limit=args.include_processed,
            seed=args.seed,
        )
        add_dataframe(
            rows,
            portable,
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

    digest = hashlib.sha256(MODEL.read_bytes()).hexdigest()
    print(f"wrote {len(rows)} cases to {args.output}")
    print(f"model_sha256={digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
