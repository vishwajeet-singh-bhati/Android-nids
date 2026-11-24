"""Safe, bounded user-facing action codes.

The detector never auto-clicks, auto-deletes or claims certainty. Actions are
conservative advice strings that the UI/Llama layer may phrase for the user.
"""

from __future__ import annotations

from ..preprocessing import indicators as ind


def action_codes(label: str, risk_level: str, flags: dict[str, bool]) -> list[str]:
    actions: list[str] = []

    if risk_level == "high":
        if flags.get(ind.URL_PRESENT):
            actions.append("DO_NOT_CLICK")
        if (
            flags.get(ind.OTP_REQUEST)
            or flags.get(ind.CREDENTIAL_REQUEST)
            or flags.get(ind.ACCOUNT_ACCESS_LURE)
        ):
            actions.append("DO_NOT_SHARE_OTP")
            actions.append("DO_NOT_SHARE_PERSONAL_INFO")
        if flags.get(ind.PAYMENT_REQUEST):
            actions.append("DO_NOT_SEND_MONEY")
        actions.extend(
            ["VERIFY_USING_OFFICIAL_CHANNEL", "REPORT_AS_SCAM"]
        )
    elif risk_level == "suspicious":
        if flags.get(ind.URL_PRESENT):
            actions.append("DO_NOT_CLICK")
        if (
            flags.get(ind.OTP_REQUEST)
            or flags.get(ind.CREDENTIAL_REQUEST)
            or flags.get(ind.ACCOUNT_ACCESS_LURE)
        ):
            actions.append("DO_NOT_SHARE_OTP")
            actions.append("DO_NOT_SHARE_PERSONAL_INFO")
        if flags.get(ind.PAYMENT_REQUEST):
            actions.append("DO_NOT_SEND_MONEY")
        actions.append("VERIFY_BEFORE_ACTING")
    elif label == "spam":
        actions.extend(["MARK_AS_SPAM", "DO_NOT_INTERACT"])
    else:
        actions.append("NO_ACTION")

    # Stable order, no duplicates.
    order = {
        "NO_ACTION": 0,
        "MARK_AS_SPAM": 1,
        "DO_NOT_INTERACT": 2,
        "DO_NOT_CLICK": 3,
        "DO_NOT_SHARE_OTP": 4,
        "DO_NOT_SHARE_PERSONAL_INFO": 5,
        "DO_NOT_SEND_MONEY": 6,
        "VERIFY_BEFORE_ACTING": 7,
        "VERIFY_USING_OFFICIAL_CHANNEL": 8,
        "REPORT_AS_SCAM": 9,
    }
    return sorted(dict.fromkeys(actions), key=lambda value: order.get(value, 99))
