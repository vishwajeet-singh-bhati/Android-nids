"""Export end-to-end policy decisions for Kotlin parity checks.

The oracle uses the exported portable linear model plus the Python risk-fusion
policy at the thresholds recorded in artifacts/model/metadata.json. Default
output is synthetic-only; wider fixtures should stay in the local temp area.
"""

from __future__ import annotations

import argparse
import base64
from pathlib import Path

import numpy as np
import pandas as pd

from export_kotlin_parity import HANDMADE, SYNTHETIC_CASES, TEST, VAL
from sms_detection.models.export import PortableLinearClassifier
from sms_detection.policy.risk_fusion import RiskPolicy, rule_based_classify
from sms_detection.preprocessing.indicators import analyze_text

REPO = Path(__file__).resolve().parents[2]
MODEL = REPO / "artifacts/model/portable/portable_model.json"
HIGH_THRESHOLD = 0.385
SUSPICIOUS_THRESHOLD = 0.1009090909090909
EVIDENCE_FREE_HIGH_THRESHOLD = 0.80

HEADER = [
    "id",
    "text_b64",
    "sender_b64",
    "label",
    "risk",
    "actions",
    "rule_label",
    "rule_triggered",
    "reason_codes",
    "p_ham",
    "p_spam",
    "p_smishing",
]


def b64(value: str | None) -> str:
    if value is None or value == "":
        return "-"
    return base64.b64encode(str(value).encode("utf-8")).decode("ascii")


def add_row(
    rows: list[list[str]],
    portable: PortableLinearClassifier,
    policy: RiskPolicy,
    case_id: str,
    text: str,
    sender: str | None,
) -> None:
    probabilities = portable.predict_proba(text, sender=sender)
    result = analyze_text(text, sender=sender)
    assessment = policy.assess(probabilities, result)
    rules = rule_based_classify(result)
    rows.append(
        [
            case_id,
            b64(text),
            b64(sender),
            assessment.label,
            assessment.risk_level,
            "|".join(assessment.recommended_action_codes),
            assessment.rule_label,
            "1" if assessment.rule_triggered else "0",
            "|".join(rules.reason_codes),
            *(f"{probabilities[name]:.17g}" for name in ("ham", "spam", "smishing")),
        ]
    )


def add_dataframe(
    rows: list[list[str]],
    portable: PortableLinearClassifier,
    policy: RiskPolicy,
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
        add_row(rows, portable, policy, f"{prefix}-{record['message_id']}", text, sender)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        type=Path,
        default=REPO / "tier1-kotlin/fixtures/synthetic_policy_parity.tsv",
    )
    parser.add_argument("--include-handmade", action="store_true")
    parser.add_argument("--include-processed", type=int, default=0)
    parser.add_argument("--seed", type=int, default=20261111)
    args = parser.parse_args()

    portable = PortableLinearClassifier(MODEL)
    policy = RiskPolicy(
        high_threshold=HIGH_THRESHOLD,
        suspicious_threshold=SUSPICIOUS_THRESHOLD,
        evidence_free_high_threshold=EVIDENCE_FREE_HIGH_THRESHOLD,
    )
    rows: list[list[str]] = []
    for case_id, text, sender in SYNTHETIC_CASES:
        add_row(rows, portable, policy, case_id, text, sender)

    if args.include_handmade:
        handmade = pd.read_csv(HANDMADE)
        for _, record in handmade.iterrows():
            add_row(
                rows,
                portable,
                policy,
                f"handmade-{record['ID']}",
                str(record["Message"]),
                None,
            )

    if args.include_processed > 0:
        add_dataframe(
            rows,
            portable,
            policy,
            pd.read_csv(VAL),
            prefix="val",
            limit=args.include_processed,
            seed=args.seed,
        )
        add_dataframe(
            rows,
            portable,
            policy,
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
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
