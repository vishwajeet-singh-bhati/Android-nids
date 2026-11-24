"""Conservative SMS text normalization and obfuscation detection.

Design rules from the implementation plan:

* Preserve the raw message exactly for evidence display and auditing.
* Normalize a copy for the model.
* Replace URLs/emails/phone numbers with stable tokens so the model does not
  memorise individual domains, while keeping the extracted values available to
  the caller (and, later, the URL teammate).
* Do not destroy security-relevant punctuation, digits or obfuscation cues.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from typing import Any

# Unicode oddities that can be used to hide keywords.
ZERO_WIDTH_RE = re.compile("[\u200b-\u200f\u2060\ufeff\u00ad]")
FULLWIDTH_RE = re.compile("[\uff01-\uff5e]")

# Common Latin-lookalike characters from Cyrillic/Greek. Applied only when the
# message mixes scripts, so genuine Cyrillic/Greek text is not mangled.
HOMOGLYPHS = {
    "а": "a",
    "е": "e",
    "о": "o",
    "р": "p",
    "с": "c",
    "у": "y",
    "х": "x",
    "і": "i",
    "ј": "j",
    "ѕ": "s",
    "ԁ": "d",
    "ӏ": "l",
    "α": "a",
    "β": "b",
    "ε": "e",
    "ι": "i",
    "κ": "k",
    "ν": "v",
    "ο": "o",
    "ρ": "p",
    "τ": "t",
    "υ": "u",
    "χ": "x",
}

LEET_MAP = str.maketrans(
    {
        "0": "o",
        "1": "i",
        "3": "e",
        "4": "a",
        "5": "s",
        "7": "t",
        "@": "a",
        "$": "s",
    }
)

# Only de-leet tokens when the result is a recognised security/brand word.
# Otherwise tracking IDs such as "FD31289045" are wrongly treated as
# obfuscation and mangled in the model text.
LEET_SECURITY_WORDS = {
    "access",
    "account",
    "accounts",
    "alert",
    "amazon",
    "axis",
    "bank",
    "banking",
    "bhim",
    "block",
    "blocked",
    "claim",
    "click",
    "credit",
    "credited",
    "custom",
    "customs",
    "debit",
    "debited",
    "delivery",
    "flipkart",
    "free",
    "gift",
    "google",
    "government",
    "hack",
    "hacked",
    "hdfc",
    "icici",
    "income",
    "job",
    "kotak",
    "kyc",
    "loan",
    "login",
    "logins",
    "lottery",
    "netbanking",
    "netflix",
    "offer",
    "otp",
    "package",
    "parcel",
    "passcode",
    "password",
    "passwords",
    "pay",
    "payment",
    "paytm",
    "phonepe",
    "police",
    "prize",
    "refund",
    "reward",
    "sbi",
    "secure",
    "security",
    "suspend",
    "suspended",
    "tax",
    "upi",
    "update",
    "updated",
    "username",
    "verification",
    "verified",
    "verify",
    "wallet",
    "winner",
    "won",
}

EMAIL_RE = re.compile(
    r"(?i)(?<![\w.+-])[\w.+-]+@[\w-]+(?:\.[\w-]+)+"
)
PHONE_RE = re.compile(
    r"""(?ix)
    (?<!\d)
    (?:
        (?:\+?91[\s.-]?)?[6-9]\d{9}          # Indian mobile
        |0\d{2,4}[\s.-]?\d{6,8}              # Indian landline
        |1800[\s.-]?\d{2,4}[\s.-]?\d{4}      # toll-free
        |\+\d{1,3}[\s.-]?\d{6,14}            # international
    )
    (?!\d)
    """
)
URL_RE = re.compile(
    r"""(?ix)
    \b
    (?:
        (?:https?|ftp)://[^\s<>"']+
        |www\.[^\s<>"']+
        |(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+
         (?:com|net|org|in|co|io|ly|me|app|info|biz|xyz|online|site|link|click|top|club|shop|live|pro|icu|tk|ml|ga|cf|gq)
         (?::\d{2,5})?
         (?:/[^\s<>"']*)?
    )
    """
)

LONG_DIGIT_RE = re.compile(r"(?<!\d)\d{8,}(?!\d)")
SPACED_LETTERS_RE = re.compile(r"(?:\b[a-zA-Z]\s+){4,}[a-zA-Z]\b")
EXCESSIVE_PUNCT_RE = re.compile(r"[!?]{3,}|(?:[!?.,;:]\s*){5,}")
MIXED_SCRIPT_RE = re.compile(r"[A-Za-z]")
CYRILLIC_GREEK_RE = re.compile(r"[\u0400-\u04ff\u0370-\u03ff]")

URL_TOKEN = "url_present"
EMAIL_TOKEN = "email_present"
PHONE_TOKEN = "phone_present"


@dataclass(frozen=True)
class NormalizedText:
    raw: str
    normalized: str
    model_text: str
    urls: tuple[str, ...] = field(default_factory=tuple)
    emails: tuple[str, ...] = field(default_factory=tuple)
    phones: tuple[str, ...] = field(default_factory=tuple)
    flags: dict[str, bool] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "raw": self.raw,
            "normalized": self.normalized,
            "model_text": self.model_text,
            "urls": list(self.urls),
            "emails": list(self.emails),
            "phones": list(self.phones),
            "flags": dict(self.flags),
        }


def normalize_text(raw: str) -> NormalizedText:
    """Normalize one SMS without losing the original or its evidence cues."""

    if raw is None:
        raw = ""
    if not isinstance(raw, str):
        raw = str(raw)

    zero_width = bool(ZERO_WIDTH_RE.search(raw))
    fullwidth = bool(FULLWIDTH_RE.search(raw))
    mixed_script = bool(MIXED_SCRIPT_RE.search(raw) and CYRILLIC_GREEK_RE.search(raw))
    spaced_letters = bool(SPACED_LETTERS_RE.search(raw))
    excessive_punct = bool(EXCESSIVE_PUNCT_RE.search(raw))
    long_digits = bool(LONG_DIGIT_RE.search(PHONE_RE.sub(" ", raw)))
    excessive_caps = _is_excessive_caps(raw)
    leetspeak = _has_leet_token(raw)

    # 1. Unicode compatibility normalization and invisible character removal.
    text = unicodedata.normalize("NFKC", raw)
    text = ZERO_WIDTH_RE.sub("", text)

    # 2. De-homoglyph only mixed-script messages.
    if mixed_script:
        text = "".join(HOMOGLYPHS.get(ch.lower(), ch) if ch.lower() in HOMOGLYPHS else ch for ch in text)

    # 3. Extract structured entities from the normalized copy, then mask them.
    emails = tuple(dict.fromkeys(m.group(0) for m in EMAIL_RE.finditer(text)))
    text_without_emails = EMAIL_RE.sub(f" {EMAIL_TOKEN} ", text)
    urls = tuple(dict.fromkeys(m.group(0) for m in URL_RE.finditer(text_without_emails)))
    text_without_urls = URL_RE.sub(f" {URL_TOKEN} ", text_without_emails)
    phones = tuple(dict.fromkeys(m.group(0) for m in PHONE_RE.finditer(text_without_urls)))
    masked = PHONE_RE.sub(f" {PHONE_TOKEN} ", text_without_urls)

    # 4. Collapse whitespace but keep punctuation and digits.
    normalized = re.sub(r"\s+", " ", masked).strip()

    # 5. Build a lower-case model copy and undo common leetspeak only inside
    #    mixed alphanumeric tokens. Pure numbers (OTP codes, amounts) survive.
    model_text = " ".join(_deleet_token(token) for token in normalized.lower().split())

    flags = {
        "zero_width": zero_width,
        "fullwidth": fullwidth,
        "mixed_script_homoglyph": mixed_script,
        "spaced_letters": spaced_letters,
        "excessive_punctuation": excessive_punct,
        "excessive_caps": excessive_caps,
        "long_digit_string": long_digits,
        "leetspeak": leetspeak,
    }
    flags["obfuscated"] = any(
        flags[key]
        for key in (
            "zero_width",
            "fullwidth",
            "mixed_script_homoglyph",
            "spaced_letters",
            "leetspeak",
        )
    )

    return NormalizedText(
        raw=raw,
        normalized=normalized,
        model_text=model_text,
        urls=urls,
        emails=emails,
        phones=phones,
        flags=flags,
    )


def _is_excessive_caps(text: str) -> bool:
    letters = [ch for ch in text if ch.isalpha()]
    if len(letters) < 20:
        return False
    uppercase = sum(1 for ch in letters if ch.isupper())
    return uppercase / len(letters) >= 0.7


def _has_leet_token(text: str) -> bool:
    for token in re.findall(r"[A-Za-z0-9@$]+", text):
        if not (
            3 <= len(token) <= 20
            and re.search(r"[A-Za-z]", token)
            and re.search(r"[0-9@$]", token)
        ):
            continue
        if re.fullmatch(r"(?:rs|inr|usd|gbp|eur)?\d+(?:\.\d+)?", token, re.I):
            continue
        if token.translate(LEET_MAP).lower() in LEET_SECURITY_WORDS:
            return True
    return False


def _deleet_token(token: str) -> str:
    """Normalize only tokens that mix letters with obvious leet digits."""

    if not (3 <= len(token) <= 30):
        return token
    if not (re.search(r"[a-z]", token) and re.search(r"[0-9@$]", token)):
        return token
    # Preserve amounts, percentages, dimensions and pure identifiers.
    if re.fullmatch(r"(?:rs\.?|inr|usd|gbp|eur)?\d+(?:\.\d+)?%?", token, re.I):
        return token
    if re.fullmatch(r"\d+[a-z]{1,2}\d*", token, re.I):
        return token
    converted = token.translate(LEET_MAP)
    if converted.lower() in LEET_SECURITY_WORDS:
        return converted
    return token


def model_text_for(raw: str) -> str:
    """Convenience helper used by tests and lightweight callers."""

    return normalize_text(raw).model_text
