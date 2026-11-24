"""Export Python Tier-1 evidence to a Kotlin parity fixture.

The default fixture is synthetic and safe to keep in the repository. Optional
local modes append the handmade benchmark and sampled validation/test messages;
those bodies stay on disk and are not sent anywhere.

Usage:
    python experiments/hardening/export_kotlin_parity.py
    python experiments/hardening/export_kotlin_parity.py \
        --output experiments/hardening/results/kotlin_parity_local.tsv \
        --include-handmade --include-processed 100
"""

from __future__ import annotations

import argparse
import base64
from collections import Counter
from pathlib import Path

import pandas as pd

from sms_detection.preprocessing.indicators import (
    ACCOUNT_THREAT,
    APK_DOWNLOAD_LURE,
    DATA_HARVESTING,
    DELIVERY_BAIT,
    DELIVERY_UPDATE_LURE,
    DTH_UTILITY_THREAT,
    HIGH_DEMAND_GADGET_SCAM,
    IMPERSONATION,
    KYC_LANGUAGE,
    PAYMENT_REQUEST,
    SENDER_CLAIM_MISMATCH,
    SERVICE_INTERRUPTION_LURE,
    TASK_SCAM,
    TELECOM_LURE,
    URGENCY_LANGUAGE,
    URL_PRESENT,
    analyze_text,
)

REPO = Path(__file__).resolve().parents[2]
HANDMADE = REPO / "experiments/mobilebert/handmade_dataset/smishing_dataset.csv"
VAL = REPO / "data/processed/val.csv"
TEST = REPO / "data/processed/test.csv"

NEW_CODES = [
    DTH_UTILITY_THREAT,
    TASK_SCAM,
    TELECOM_LURE,
    DATA_HARVESTING,
    HIGH_DEMAND_GADGET_SCAM,
    APK_DOWNLOAD_LURE,
    DELIVERY_UPDATE_LURE,
    SERVICE_INTERRUPTION_LURE,
]

HEADER = [
    "id",
    "text_b64",
    "sender_b64",
    "normalized_b64",
    "model_text_b64",
    "urls_b64",
    "phone_count",
    "email_count",
    "url_present",
    "payment_request",
    "urgency",
    "delivery_bait",
    "kyc",
    "account_threat",
    "impersonation",
    "new_codes",
    "dlt",
]

SYNTHETIC_CASES: list[tuple[str, str, str | None]] = [
    (
        "dth_positive",
        "Your Tata Sky DTH will be disconnected today. Recharge now at http://dth-recharge.example/pay",
        None,
    ),
    (
        "dth_payment_only",
        "Your DTH will be disconnected. Pay the processing fee of Rs 200.",
        None,
    ),
    (
        "dth_benign",
        "Tata Sky: your DTH recharge of Rs 300 was successful. Thank you.",
        None,
    ),
    (
        "task_positive",
        "Earn Rs 500 per task! Like and share our posts on Telegram. Join http://task-earn.example",
        None,
    ),
    (
        "task_benign",
        "Please share your feedback in this survey. No payment is required.",
        None,
    ),
    (
        "telecom_positive",
        "Jio 5G: Get 100 GB data pack free! Recharge just Rs 9 at http://jio-offer.example",
        None,
    ),
    (
        "telecom_benign",
        "Jio: your data plan balance is 2 GB. Recharge with the MyJio app.",
        None,
    ),
    (
        "data_positive",
        "Your Aadhaar KYC is pending. Upload your Aadhaar and PAN card at http://kyc-update.example",
        None,
    ),
    (
        "data_benign",
        "Your Aadhaar update request was completed at the bank branch.",
        None,
    ),
    (
        "gadget_positive",
        "iPhone 15 pre-book only 5 units left. Pay token advance at http://gadget-deal.example",
        None,
    ),
    (
        "gadget_benign",
        "Apple sale: iPhone 15 available at a discount in the store.",
        None,
    ),
    (
        "apk_positive",
        "Install this APK to receive your refund: http://refund.example/app.apk",
        None,
    ),
    (
        "apk_benign",
        "Download our app from the Google Play Store.",
        None,
    ),
    (
        "delivery_positive",
        "Your parcel delivery failed due to an incomplete address. Update address at http://delivery-update.example",
        None,
    ),
    (
        "delivery_benign",
        "Your parcel was delivered today. Thank you.",
        None,
    ),
    (
        "service_positive",
        "Your cloud storage is full. Upgrade your plan at http://storage-help.example",
        None,
    ),
    (
        "service_benign",
        "Your broadband bill payment was successful. Service continues.",
        None,
    ),
    (
        "dlt_kyc_10digit",
        "Your KYC is pending. Complete verification now.",
        "9876543210",
    ),
    (
        "dlt_account_plus91",
        "Your SBI account will be blocked. Verify immediately.",
        "+91 98765 43210",
    ),
    (
        "dlt_transactional_sender",
        "Your KYC is pending. Complete verification now.",
        "AD-SBIBNK",
    ),
    (
        "dlt_benign",
        "Your order has been delivered today.",
        "9876543210",
    ),
    (
        "payment_positive",
        "Please pay the processing fee of Rs 200 to activate your loan.",
        None,
    ),
    (
        "payment_success",
        "Payment successful. Rs 200 debited.",
        None,
    ),
    (
        "payment_no_fee",
        "No processing fee required. Apply now.",
        None,
    ),
    (
        "otp_positive",
        "Your OTP is 482913. Share it with our delivery agent to reschedule your parcel.",
        None,
    ),
    (
        "otp_negation",
        "Never share your OTP with anyone. Our bank staff will not ask for it.",
        None,
    ),
    (
        "norm_url_phone_email",
        "Login at https://example.com/login or call 9876543210 / mail help@example.com",
        None,
    ),
    (
        "norm_leet",
        "L0gin to your acc0unt and verify your passw0rd",
        None,
    ),
    (
        "norm_zero_width",
        "Your acc\u200bount is blocked",
        None,
    ),
    (
        "norm_homoglyph",
        "Your \u0430ccount is blocked. Verify at http://bank.example",
        None,
    ),
    (
        "norm_caps",
        "YOUR ACCOUNT IS BLOCKED PLEASE VERIFY NOW",
        None,
    ),
    (
        "benign_url",
        "Read our privacy policy at https://example.com/privacy",
        None,
    ),
    (
        "norm_combining_mark",
        "Stay relaxed\u0308 and claim your prize at http://reward.example",
        None,
    ),
    (
        "norm_spaced_keywords",
        "Your loan is pre approved. This part time job has a one time offer. "
        "Auto debit is active. Re kyc is due. Non bailable notice. Sign in and top up.",
        None,
    ),
]


def b64(value: str | None) -> str:
    if value is None or value == "":
        return "-"
    return base64.b64encode(str(value).encode("utf-8")).decode("ascii")


def flag(value: bool) -> str:
    return "1" if value else "0"


def add_row(rows: list[list[str]], case_id: str, text: str, sender: str | None) -> None:
    result = analyze_text(text, sender=sender)
    norm = result.normalized
    new_codes = [code for code in NEW_CODES if result.flags.get(code, False)]
    rows.append(
        [
            case_id,
            b64(text),
            b64(sender),
            b64(norm.normalized),
            b64(norm.model_text),
            b64("\n".join(norm.urls)),
            str(len(norm.phones)),
            str(len(norm.emails)),
            flag(result.flags.get(URL_PRESENT, False)),
            flag(result.flags.get(PAYMENT_REQUEST, False)),
            flag(result.flags.get(URGENCY_LANGUAGE, False)),
            flag(result.flags.get(DELIVERY_BAIT, False)),
            flag(result.flags.get(KYC_LANGUAGE, False)),
            flag(result.flags.get(ACCOUNT_THREAT, False)),
            flag(result.flags.get(IMPERSONATION, False)),
            ",".join(new_codes) if new_codes else "-",
            flag(result.flags.get(SENDER_CLAIM_MISMATCH, False)),
        ]
    )


def add_dataframe(
    rows: list[list[str]],
    frame: pd.DataFrame,
    *,
    prefix: str,
    limit: int | None,
    seed: int,
) -> None:
    frame = frame[frame["text"].notna()].copy()
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
        default=REPO / "tier1-kotlin/fixtures/synthetic_parity.tsv",
    )
    parser.add_argument("--include-handmade", action="store_true")
    parser.add_argument(
        "--include-processed",
        type=int,
        default=0,
        help="Sample this many rows from each of val.csv and test.csv.",
    )
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
        add_dataframe(rows, pd.read_csv(VAL), prefix="val", limit=args.include_processed, seed=args.seed)
        add_dataframe(rows, pd.read_csv(TEST), prefix="test", limit=args.include_processed, seed=args.seed)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write("\t".join(HEADER) + "\n")
        for row in rows:
            handle.write("\t".join(row) + "\n")

    code_counts = Counter()
    dlt_count = 0
    for row in rows:
        for code in row[15].split(","):
            if code and code != "-":
                code_counts[code] += 1
        if row[16] == "1":
            dlt_count += 1
    print(f"wrote {len(rows)} cases to {args.output}")
    print("new-code counts: " + ", ".join(f"{code}={code_counts[code]}" for code in NEW_CODES))
    print(f"dlt_sender_mismatch={dlt_count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
