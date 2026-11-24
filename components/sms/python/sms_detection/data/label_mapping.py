"""Source metadata and label mapping into the project taxonomy.

Never silently turn a generic "spam" label into "smishing". Each source is
mapped explicitly and the original label is retained for audit.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..config import SOURCE_LICENSES


@dataclass(frozen=True)
class SourceMetadata:
    key: str
    name: str
    url: str
    license: str
    language: str
    notes: str


SOURCES: dict[str, SourceMetadata] = {
    "uci_sms_spam": SourceMetadata(
        key="uci_sms_spam",
        name="UCI SMS Spam Collection",
        url="https://archive.ics.uci.edu/dataset/228/sms",
        license=SOURCE_LICENSES["uci_sms_spam"],
        language="en",
        notes="5,574 English SMS; ham/spam only; classic UK/Singapore-oriented benchmark.",
    ),
    "lsdst_2022": SourceMetadata(
        key="lsdst_2022",
        name="Mishra & Soni LSDST-2022",
        url="https://data.mendeley.com/datasets/f45bkkt8pr/1",
        license=SOURCE_LICENSES["lsdst_2022"],
        language="en",
        notes="5,971 messages with ham/spam/smishing labels; labels partly image-derived.",
    ),
    "ncsu_sms_phishing": SourceMetadata(
        key="ncsu_sms_phishing",
        name="NCSU SMS Phishing Data Release",
        url="https://github.com/wspr-ncsu/sms-phishing",
        license=SOURCE_LICENSES["ncsu_sms_phishing"],
        language="en",
        notes="Modern campaign-oriented phishing release; the campaign corpus also contains promotional/gambling scams.",
    ),
    "hinglish_scam": SourceMetadata(
        key="hinglish_scam",
        name="Hinglish & English Financial Scam/Fraud Text Dataset",
        url="https://huggingface.co/datasets/bolewara/hinglish-scam-text-dataset",
        license=SOURCE_LICENSES["hinglish_scam"],
        language="en/hi-Latn",
        notes="Mostly UCI-derived; only 63 hand-written Hinglish rows. Seed/robustness only.",
    ),
    "india_spam_sms": SourceMetadata(
        key="india_spam_sms",
        name="India Spam SMS Classification (Kaggle)",
        url="https://www.kaggle.com/datasets/junioralive/india-spam-sms-classification",
        license=SOURCE_LICENSES["india_spam_sms"],
        language="en/hi-Latn",
        notes=(
            "2,267 real-world Indian telecom SMS; binary ham/spam labels only; "
            "predominantly Latin script; language not annotated; no smishing "
            "label and not a random population sample. Evaluation-only unless a "
            "disjoint training split is deliberately created."
        ),
    ),
    "synthetic_seed": SourceMetadata(
        key="synthetic_seed",
        name="Project synthetic Indian English/Hinglish seed",
        url="local",
        license=SOURCE_LICENSES["synthetic_seed"],
        language="en/hi-Latn",
        notes="Synthetic demo/robustness examples; not a representative benchmark.",
    ),
}


def map_label(source: str, raw_label: object) -> str | None:
    """Map a source label into ham/spam/smishing, or return None if unknown."""

    if raw_label is None:
        return None
    value = str(raw_label).strip().lower()
    if source == "uci_sms_spam":
        return {"ham": "ham", "spam": "spam"}.get(value)
    if source == "lsdst_2022":
        aliases = {
            "ham": "ham",
            "legitimate": "ham",
            "legit": "ham",
            "spam": "spam",
            "smishing": "smishing",
            "smish": "smishing",
            "phishing": "smishing",
            "malicious": "smishing",
        }
        return aliases.get(value)
    if source == "ncsu_sms_phishing":
        return "smishing"
    if source == "hinglish_scam":
        return {"0": "ham", "1": "smishing", "ham": "ham", "scam": "smishing"}.get(value)
    if source == "india_spam_sms":
        # The Kaggle source only distinguishes promotional/generic spam from ham.
        # Do not silently promote generic spam to smishing.
        return {"ham": "ham", "spam": "spam"}.get(value)
    if source == "synthetic_seed":
        return {"ham": "ham", "spam": "spam", "smishing": "smishing"}.get(value)
    return None
