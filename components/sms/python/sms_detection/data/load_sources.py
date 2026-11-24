"""Load, normalize and provenance-tag each public SMS source.

The unified table keeps the original text and source label. Normalized text is
derived later and never overwrites the raw message.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Iterable

import pandas as pd

from ..config import RAW_DIR
from ..preprocessing.normalize import normalize_text
from .label_mapping import SOURCES, map_label

UNIFIED_COLUMNS = [
    "message_id",
    "text",
    "label",
    "language",
    "source_dataset",
    "source_id",
    "sender",
    "has_url",
    "has_phone",
    "has_email",
    "campaign_id",
    "collection_date",
    "split_group",
    "annotation_note",
    "source_label",
    "license",
    "source_url",
    "dataset_version",
    "derived_from_uci",
]

TEXT_COLUMN_CANDIDATES = (
    "text",
    "message",
    "body",
    "sms",
    "content",
    "message_body",
    "sms_text",
    "msg",
)
LABEL_COLUMN_CANDIDATES = ("source_label", "label", "class", "category", "target", "type")


def load_all_sources(
    raw_dir: str | Path = RAW_DIR,
    *,
    include_hinglish: bool = True,
    include_ncsu: bool = True,
    include_india_spam: bool = False,
) -> pd.DataFrame:
    raw_dir = Path(raw_dir)
    frames = [load_uci(raw_dir), load_lsdst(raw_dir)]
    if include_ncsu:
        ncsu = load_ncsu(raw_dir)
        if not ncsu.empty:
            frames.append(ncsu)
    if include_hinglish:
        hinglish = load_hinglish(raw_dir)
        if not hinglish.empty:
            frames.append(hinglish)
    if include_india_spam:
        india_spam = load_india_spam(raw_dir)
        if not india_spam.empty:
            frames.append(india_spam)
    frames = [frame for frame in frames if not frame.empty]
    if not frames:
        raise RuntimeError("No raw datasets found. Run scripts/download_data.py first.")
    combined = pd.concat(frames, ignore_index=True)
    combined = combined.dropna(subset=["text"]).copy()
    combined["text"] = combined["text"].map(_clean_text)
    combined = combined[combined["text"].str.len() > 0].copy()
    combined = _add_flags(combined)
    combined = _add_hinglish_overlap(combined)
    return combined[UNIFIED_COLUMNS].reset_index(drop=True)


def load_uci(raw_dir: Path) -> pd.DataFrame:
    path = _find_file(raw_dir / "uci", names={"smsspamcollection", "sms spam collection"})
    if path is None:
        return _empty()
    frame = pd.read_csv(
        path,
        sep="\t",
        header=None,
        names=["source_label", "text"],
        encoding="latin-1",
        quoting=3,
        on_bad_lines="skip",
    )
    return _standardize(frame, "uci_sms_spam", path)


def load_lsdst(raw_dir: Path) -> pd.DataFrame:
    directory = raw_dir / "lsdst_2022"
    path = _find_file(directory, suffixes={".csv", ".xlsx", ".xls"})
    if path is None:
        return _empty()
    if path.suffix.lower() == ".csv":
        frame = _read_csv_robust(path)
    else:
        frame = pd.read_excel(path)
    return _standardize(frame, "lsdst_2022", path)


def load_ncsu(raw_dir: Path) -> pd.DataFrame:
    """Load NCSU campaign templates.

    The raw ``phishing_messages.csv`` is malformed in the public release: many
    rows put only a short fragment in the ``message`` column while the full SMS
    sits in another column. The campaign CSV is clean and carries one template
    per campaign, with campaign IDs and timestamps, so it is the safer external
    evaluation source.
    """

    campaigns_path = raw_dir / "ncsu_sms_phishing" / "phishing_campaigns.csv"
    path = campaigns_path
    if path.exists():
        frame = _read_csv_robust(path)
        columns = _column_lookup(frame)
        text_col = _first_present(columns, ("message", "text", "body", "content"))
        campaign_col = _first_present(columns, ("campaignid", "campaign_id", "campaign"))
        date_col = _first_present(columns, ("start timestamp", "first_seen", "timestamp", "date"))
        if text_col is not None:
            source_id = (
                frame[campaign_col].astype(str)
                if campaign_col is not None
                else frame.index.astype(str)
            )
            rows = pd.DataFrame(
                {
                    "source_label": "smishing",
                    "source_id": "ncsu-campaign-" + source_id,
                    "text": frame[text_col].map(_expand_ncsu_placeholders),
                    "sender": None,
                    "campaign_id": frame[campaign_col] if campaign_col is not None else None,
                    "collection_date": _parse_dates(frame[date_col]) if date_col else None,
                    "annotation_note": (
                        "NCSU campaign template; source-level phishing label. "
                        "Content review is still required because some campaigns are "
                        "promotional gambling spam rather than credential theft."
                    ),
                    "dataset_version": path.name,
                }
            )
            return _standardize(rows, "ncsu_sms_phishing", path)

    # Fallback for a future fixed release of the messages CSV.
    messages_path = raw_dir / "ncsu_sms_phishing" / "phishing_messages.csv"
    if not messages_path.exists():
        return _empty()
    frame = _read_csv_robust(messages_path)
    columns = _column_lookup(frame)
    text_col = _first_present(columns, TEXT_COLUMN_CANDIDATES)
    if text_col is None:
        return _empty()
    rows = pd.DataFrame(
        {
            "source_label": "smishing",
            "text": frame[text_col],
            "sender": None,
            "campaign_id": None,
            "collection_date": None,
        }
    )
    return _standardize(rows, "ncsu_sms_phishing", messages_path)


def _expand_ncsu_placeholders(value: object) -> str:
    text = str(value) if value is not None else ""
    text = re.sub(r"(?i)#URL", " https://campaign.invalid/path ", text)
    text = re.sub(r"(?i)#OTP", " 123456 ", text)
    text = re.sub(r"(?i)#PHONE", " +911234567890 ", text)
    text = re.sub(r"(?i)#EMAIL", " placeholder@example.invalid ", text)
    text = text.replace("[email\xa0protected]", "placeholder@example.invalid")
    return text


def load_hinglish(raw_dir: Path) -> pd.DataFrame:
    path = raw_dir / "hinglish_scam" / "data.json"
    if not path.exists():
        return _empty()
    payload = json.loads(path.read_text(encoding="utf-8"))
    rows = payload.get("rows", payload)
    frame = pd.DataFrame(rows)
    if "text" not in frame.columns or "label" not in frame.columns:
        return _empty()
    return _standardize(frame, "hinglish_scam", path)


def load_india_spam(raw_dir: Path) -> pd.DataFrame:
    """Load the Kaggle India Spam SMS collection (binary ham/spam).

    This is an evaluation-only source by default. It has no smishing labels and
    is not a random sample of Indian SMS traffic, so it must not be presented as
    a representative Indian benchmark or used to tune the locked test.
    """

    raw_dir = Path(raw_dir)
    directory = raw_dir / "india_spam_sms"
    path = _find_file(directory, names={"spam_ham_india"}, suffixes={".csv"})
    if path is None:
        return _empty()
    frame = _read_csv_robust(path)
    columns = _column_lookup(frame)
    text_col = _first_present(columns, TEXT_COLUMN_CANDIDATES)
    label_col = _first_present(columns, LABEL_COLUMN_CANDIDATES)
    if text_col is None or label_col is None:
        return _empty()
    frame = frame[frame[text_col].notna() & frame[label_col].notna()].copy()
    return _standardize(frame, "india_spam_sms", path)


def _standardize(frame: pd.DataFrame, source: str, path: Path) -> pd.DataFrame:
    if frame.empty:
        return _empty()
    columns = _column_lookup(frame)
    text_col = _first_present(columns, TEXT_COLUMN_CANDIDATES)
    label_col = _first_present(columns, LABEL_COLUMN_CANDIDATES)
    if text_col is None:
        raise ValueError(f"No text column found in {path}; columns={list(frame.columns)}")
    if label_col is None:
        if source in {"ncsu_sms_phishing"}:
            labels = pd.Series(["smishing"] * len(frame))
        else:
            raise ValueError(f"No label column found in {path}; columns={list(frame.columns)}")
    else:
        labels = frame[label_col]

    source_meta = SOURCES[source]
    if "source_id" in frame.columns:
        source_ids = frame["source_id"].astype(str).tolist()
    else:
        source_ids = [f"{source}-{index}" for index in range(len(frame))]
    mapped = [
        map_label(source, value)
        for value in labels
    ]
    valid = [value is not None for value in mapped]
    if not all(valid):
        unknown = sorted({str(value) for value, ok in zip(labels, valid) if not ok})
        print(f"[warn] {source}: dropping {valid.count(False)} rows with unknown labels: {unknown}")
    frame = frame.loc[valid].copy()
    mapped = [value for value in mapped if value is not None]
    frame["label"] = mapped
    frame["source_label"] = labels.loc[valid].astype(str).values
    frame["text"] = frame[text_col].astype(str).values
    frame["source_dataset"] = source
    frame["source_id"] = [source_ids[i] for i, ok in enumerate(valid) if ok]
    frame["language"] = source_meta.language
    if "annotation_note" not in frame.columns:
        frame["annotation_note"] = source_meta.notes
    frame["license"] = source_meta.license
    frame["source_url"] = source_meta.url
    if "dataset_version" not in frame.columns:
        frame["dataset_version"] = path.name
    frame["derived_from_uci"] = False
    frame["split_group"] = None
    if "sender" not in frame.columns:
        frame["sender"] = None
    if "campaign_id" not in frame.columns:
        frame["campaign_id"] = None
    if "collection_date" not in frame.columns:
        frame["collection_date"] = None
    if "has_url" not in frame.columns:
        frame["has_url"] = None
    if "has_phone" not in frame.columns:
        frame["has_phone"] = None
    if "has_email" not in frame.columns:
        frame["has_email"] = None
    frame["message_id"] = [
        _message_id(source, source_id, text)
        for source_id, text in zip(frame["source_id"], frame["text"])
    ]
    return frame


def _add_flags(frame: pd.DataFrame) -> pd.DataFrame:
    has_url: list[bool] = []
    has_phone: list[bool] = []
    has_email: list[bool] = []
    for text in frame["text"].tolist():
        normalized = normalize_text(text)
        has_url.append(bool(normalized.urls))
        has_phone.append(bool(normalized.phones))
        has_email.append(bool(normalized.emails))
    frame = frame.copy()
    frame["has_url"] = has_url
    frame["has_phone"] = has_phone
    frame["has_email"] = has_email
    return frame


def _add_hinglish_overlap(frame: pd.DataFrame) -> pd.DataFrame:
    uci = frame[frame["source_dataset"] == "uci_sms_spam"]
    if uci.empty:
        return frame
    uci_keys = {
        _exact_text_key(text)
        for text in uci["text"].tolist()
    }
    frame = frame.copy()
    is_hinglish = frame["source_dataset"] == "hinglish_scam"
    frame["derived_from_uci"] = [
        (source == "hinglish_scam" and _exact_text_key(text) in uci_keys)
        for source, text in zip(frame["source_dataset"], frame["text"])
    ]
    return frame


def _exact_text_key(text: str) -> str:
    normalized = normalize_text(text).normalized.lower()
    return hashlib.sha1(normalized.encode("utf-8")).hexdigest()


def _message_id(source: str, source_id: str, text: str) -> str:
    digest = hashlib.sha1(f"{source}|{source_id}|{text}".encode("utf-8")).hexdigest()
    return f"{source}-{digest[:16]}"


def _clean_text(value: object) -> str:
    if value is None:
        return ""
    text = str(value).replace("\x00", " ")
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = re.sub(r"[ \t]+", " ", text)
    return text.strip()


def _empty() -> pd.DataFrame:
    return pd.DataFrame(columns=UNIFIED_COLUMNS)


def _column_lookup(frame: pd.DataFrame) -> dict[str, str]:
    return {str(column).strip().lower(): column for column in frame.columns}


def _first_present(columns: dict[str, str], candidates: Iterable[str]) -> str | None:
    for candidate in candidates:
        if candidate in columns:
            return columns[candidate]
    return None


def _find_file(
    directory: Path,
    *,
    names: set[str] | None = None,
    suffixes: set[str] | None = None,
) -> Path | None:
    if not directory.exists():
        return None
    for path in directory.rglob("*"):
        if not path.is_file():
            continue
        if names is not None and path.stem.lower() not in names:
            continue
        if suffixes is not None and path.suffix.lower() not in suffixes:
            continue
        if path.name.startswith("~$") or path.name.startswith("."):
            continue
        return path
    return None


def _read_csv_robust(path: Path) -> pd.DataFrame:
    for encoding in ("utf-8-sig", "utf-8", "latin-1"):
        try:
            return pd.read_csv(path, encoding=encoding, low_memory=False, on_bad_lines="skip")
        except UnicodeDecodeError:
            continue
    return pd.read_csv(path, encoding="latin-1", low_memory=False, on_bad_lines="skip")


def _parse_dates(series: pd.Series) -> pd.Series:
    numeric = pd.to_numeric(series, errors="coerce")
    if numeric.notna().mean() > 0.8:
        return pd.to_datetime(numeric, unit="s", errors="coerce", utc=True)
    return pd.to_datetime(series, errors="coerce", utc=True)
