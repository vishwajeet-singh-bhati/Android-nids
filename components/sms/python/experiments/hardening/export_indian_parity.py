"""Export the external Indian SMS control set for all Kotlin parity layers.

The output fixtures contain raw SMS bodies encoded as base64. Write them only to
the approved local temp workspace, never to Git and never to a cloud service.
"""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path

import pandas as pd

from export_flags_parity import HEADER as FLAGS_HEADER
from export_flags_parity import add_row as add_flags_row
from export_model_parity import HEADER as MODEL_HEADER
from export_model_parity import add_row as add_model_row
from export_policy_parity import HEADER as POLICY_HEADER
from export_policy_parity import add_row as add_policy_row
from sms_detection.models.export import PortableLinearClassifier
from sms_detection.policy.risk_fusion import RiskPolicy

REPO = Path(__file__).resolve().parents[2]
MODEL = REPO / "artifacts/model/portable/portable_model.json"
DEFAULT_INPUT = REPO / "data/indian/india_spam_sms.csv"
HIGH_THRESHOLD = 0.385
SUSPICIOUS_THRESHOLD = 0.1009090909090909
EVIDENCE_FREE_HIGH_THRESHOLD = 0.80


def write_tsv(path: Path, header: list[str], rows: list[list[str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write("\t".join(header) + "\n")
        for row in rows:
            handle.write("\t".join(row) + "\n")
    digest = hashlib.sha256(path.read_bytes()).hexdigest().upper()
    print(f"wrote {len(rows)} cases to {path} sha256={digest}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--limit", type=int, default=None)
    args = parser.parse_args()

    frame = pd.read_csv(args.input)
    if args.limit is not None:
        frame = frame.head(args.limit)
    portable = PortableLinearClassifier(MODEL)
    policy = RiskPolicy(
        high_threshold=HIGH_THRESHOLD,
        suspicious_threshold=SUSPICIOUS_THRESHOLD,
        evidence_free_high_threshold=EVIDENCE_FREE_HIGH_THRESHOLD,
    )

    flags_rows: list[list[str]] = []
    model_rows: list[list[str]] = []
    policy_rows: list[list[str]] = []
    for index, record in frame.iterrows():
        text = str(record["text"])
        if not text.strip():
            continue
        sender = record.get("sender")
        if pd.isna(sender):
            sender = None
        case_id = f"india-{index}"
        add_flags_row(flags_rows, case_id, text, sender)
        add_model_row(model_rows, portable, case_id, text, sender)
        add_policy_row(policy_rows, portable, policy, case_id, text, sender)

    write_tsv(args.output_dir / "indian_flags_parity_local.tsv", FLAGS_HEADER, flags_rows)
    write_tsv(args.output_dir / "indian_model_parity_local.tsv", MODEL_HEADER, model_rows)
    write_tsv(args.output_dir / "indian_policy_parity_local.tsv", POLICY_HEADER, policy_rows)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
