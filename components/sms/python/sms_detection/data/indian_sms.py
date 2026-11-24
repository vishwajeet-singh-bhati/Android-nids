"""Local Indian SMS benchmark loading, validation and leakage auditing.

Raw SMS is sensitive. This module keeps messages in memory, never logs them, and
returns only aggregate leakage information. The evaluation report itself is
produced by ``models.indian_eval`` and is text-free.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Iterable, Mapping

import pandas as pd

from .deduplicate import add_dedup_columns

TEXT_COLUMNS = ("text", "message", "body", "sms", "content", "msg")
LABEL_COLUMNS = ("label", "source_label")

BENCHMARK_COLUMNS = (
    "eval_id",
    "text",
    "label",
    "source_label",
    "language",
    "sender",
    "sender_type",
    "scam_type",
    "collection_date",
    "collection_month",
    "group_id",
    "source",
    "known_sender",
)

LABEL_ALIASES = {
    "ham": "ham",
    "legitimate": "ham",
    "legit": "ham",
    "spam": "spam",
    "promotional": "spam",
    "promo": "spam",
    "smishing": "smishing",
    "phishing": "smishing",
    "scam": "smishing",
    "fraud": "smishing",
    "uncertain": "uncertain",
    "unsure": "uncertain",
    "ambiguous": "uncertain",
    "unknown": "uncertain",
}


class BenchmarkFormatError(ValueError):
    """Raised when an Indian benchmark file cannot be evaluated safely."""


def load_benchmark(path: str | Path) -> pd.DataFrame:
    """Load a CSV/JSON/JSONL benchmark and validate its public metadata."""

    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Benchmark file not found: {path}")

    suffix = path.suffix.lower()
    if suffix == ".json":
        payload = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(payload, Mapping):
            payload = payload.get("rows", payload.get("data"))
        if not isinstance(payload, list):
            raise BenchmarkFormatError(
                "JSON benchmark must be a list or an object with a 'rows' list"
            )
        frame = pd.DataFrame(payload)
    elif suffix in {".jsonl", ".ndjson"}:
        frame = pd.read_json(path, lines=True)
    else:
        frame = _read_csv(path)

    return normalize_benchmark(frame)


def normalize_benchmark(frame: pd.DataFrame) -> pd.DataFrame:
    """Normalize column names, labels and optional metadata.

    Required input columns (case-insensitive)::

        text, label

    Optional columns::

        language, sender, sender_type, scam_type, collection_date,
        group_id, source, known_sender
    """

    if frame.empty:
        raise BenchmarkFormatError("Benchmark file has no rows")

    frame = frame.copy()
    frame.columns = [str(column).strip() for column in frame.columns]
    lookup = {column.lower(): column for column in frame.columns}

    text_column = _first_present(lookup, TEXT_COLUMNS)
    label_column = _first_present(lookup, LABEL_COLUMNS)
    if text_column is None:
        raise BenchmarkFormatError(
            f"Missing text column; expected one of {TEXT_COLUMNS}"
        )
    if label_column is None:
        raise BenchmarkFormatError(
            f"Missing label column; expected one of {LABEL_COLUMNS}"
        )

    text_values = frame[text_column].map(_clean_text)
    empty = text_values.str.len() == 0
    labels = frame[label_column].map(_map_label)
    invalid = labels.isna()
    if invalid.any():
        unknown = sorted(
            {
                str(value).strip()
                for value, bad in zip(frame[label_column], invalid)
                if bad
            }
        )
        raise BenchmarkFormatError(
            f"Unknown benchmark labels: {unknown}. "
            "Use ham/spam/smishing or uncertain/ambiguous."
        )

    optional = {
        "language": _optional_series(frame, lookup, ("language",), "unknown"),
        "sender": _optional_series(frame, lookup, ("sender", "sender_id"), ""),
        "sender_type": _optional_series(
            frame, lookup, ("sender_type", "sender_category"), "unknown"
        ),
        "scam_type": _optional_series(
            frame, lookup, ("scam_type", "scam_category", "category"), "unspecified"
        ),
        "source": _optional_series(frame, lookup, ("source",), "local"),
        "group_id": _optional_series(frame, lookup, ("group_id", "campaign_id"), ""),
    }

    raw_dates = _optional_series(
        frame, lookup, ("collection_date", "date"), ""
    )
    parsed_dates = pd.to_datetime(raw_dates, errors="coerce", utc=True)
    collection_date = parsed_dates.dt.strftime("%Y-%m-%d").fillna("")
    collection_month = parsed_dates.dt.strftime("%Y-%m").fillna("unknown")
    known_sender = _optional_series(
        frame, lookup, ("known_sender",), "false"
    ).map(_parse_bool)

    result = pd.DataFrame(
        {
            "eval_id": [
                _eval_id(text, index) for index, text in enumerate(text_values)
            ],
            "text": text_values,
            "label": labels,
            "source_label": frame[label_column].astype(str).str.strip(),
            "language": optional["language"],
            "sender": optional["sender"],
            "sender_type": optional["sender_type"],
            "scam_type": optional["scam_type"],
            "collection_date": collection_date,
            "collection_month": collection_month,
            "group_id": optional["group_id"],
            "source": optional["source"],
            "known_sender": known_sender,
        }
    )
    result = result.loc[~empty].reset_index(drop=True)
    result.attrs["input_rows"] = int(len(frame))
    result.attrs["dropped_empty_rows"] = int(empty.sum())
    return result[list(BENCHMARK_COLUMNS)]


def load_reference_splits(processed_dir: str | Path) -> dict[str, pd.DataFrame]:
    """Load only text columns from existing processed splits for leakage checks."""

    processed_dir = Path(processed_dir)
    references: dict[str, pd.DataFrame] = {}
    for split in ("train", "val", "test", "external"):
        path = processed_dir / f"{split}.csv"
        if not path.exists():
            continue
        frame = pd.read_csv(path, low_memory=False)
        if "text" not in frame.columns:
            raise BenchmarkFormatError(f"Reference split has no text column: {path}")
        text = frame["text"].dropna().astype(str)
        text = text[text.str.strip().str.len() > 0]
        if not text.empty:
            references[split] = pd.DataFrame({"text": text.tolist()})
    return references


def check_leakage(
    benchmark: pd.DataFrame,
    reference_frames: Mapping[str, pd.DataFrame],
    *,
    drop_overlaps: bool = True,
    near_duplicate: bool = True,
) -> tuple[pd.DataFrame, dict]:
    """Detect benchmark rows sharing an exact/template/near-dup group with a split.

    The combined corpus is reclustered so a benchmark template can be matched
    against the training/validation/test/external splits. No message text is
    included in the returned statistics.
    """

    benchmark = benchmark.reset_index(drop=True).copy()
    stats: dict = {
        "checked": False,
        "near_duplicate": near_duplicate,
        "reference_splits": {},
        "benchmark_groups": 0,
        "overlap_groups": 0,
        "overlap_rows": 0,
        "overlap_by_split": {},
        "dropped": False,
        "dropped_rows": 0,
    }
    usable = {
        str(split): frame
        for split, frame in reference_frames.items()
        if isinstance(frame, pd.DataFrame) and not frame.empty
    }
    if not usable:
        benchmark["leakage_splits"] = ""
        return benchmark, stats

    for split, frame in usable.items():
        if "text" not in frame.columns:
            raise BenchmarkFormatError(
                f"Reference split {split!r} has no text column"
            )

    benchmark_for_check = benchmark[["text", "eval_id"]].copy()
    benchmark_for_check["reference_split"] = None
    reference_parts: list[pd.DataFrame] = []
    for split, frame in usable.items():
        part = frame[["text"]].copy()
        part["text"] = part["text"].dropna().astype(str)
        part = part[part["text"].str.strip().str.len() > 0]
        part["reference_split"] = split
        reference_parts.append(part)
        stats["reference_splits"][split] = int(len(part))

    combined = pd.concat(
        [benchmark_for_check, *reference_parts], ignore_index=True
    )
    combined["message_id"] = [f"row-{index}" for index in range(len(combined))]
    grouped = add_dedup_columns(
        combined,
        near_duplicate=near_duplicate,
        drop_exact_duplicates=False,
    )

    group_to_splits: dict[str, set[str]] = {}
    for split, group in zip(
        grouped["reference_split"].iloc[len(benchmark_for_check) :],
        grouped["split_group"].iloc[len(benchmark_for_check) :],
    ):
        if split:
            group_to_splits.setdefault(group, set()).add(str(split))

    benchmark_groups = grouped["split_group"].iloc[: len(benchmark_for_check)]
    leakage: list[str] = []
    for group in benchmark_groups:
        leakage.append(";".join(sorted(group_to_splits.get(group, set()))))

    benchmark["leakage_splits"] = leakage
    overlap_mask = benchmark["leakage_splits"].str.len() > 0
    overlap_by_split = {
        split: int(
            sum(split in value.split(";") for value in benchmark["leakage_splits"])
        )
        for split in stats["reference_splits"]
    }
    stats.update(
        {
            "checked": True,
            "benchmark_groups": int(benchmark_groups.nunique()),
            "overlap_groups": int(
                benchmark_groups[overlap_mask.to_numpy()].nunique()
            ),
            "overlap_rows": int(overlap_mask.sum()),
            "overlap_by_split": overlap_by_split,
            "dropped": bool(drop_overlaps),
        }
    )
    if drop_overlaps:
        stats["dropped_rows"] = int(overlap_mask.sum())
        benchmark = benchmark.loc[~overlap_mask].reset_index(drop=True)
    return benchmark, stats


def _read_csv(path: Path) -> pd.DataFrame:
    for encoding in ("utf-8-sig", "utf-8", "latin-1"):
        try:
            return pd.read_csv(path, encoding=encoding, low_memory=False)
        except UnicodeDecodeError:
            continue
    raise BenchmarkFormatError(f"Could not decode CSV: {path}")


def _first_present(lookup: Mapping[str, str], candidates: Iterable[str]) -> str | None:
    for candidate in candidates:
        if candidate in lookup:
            return lookup[candidate]
    return None


def _optional_series(
    frame: pd.DataFrame,
    lookup: Mapping[str, str],
    candidates: Iterable[str],
    default: str,
) -> pd.Series:
    column = _first_present(lookup, candidates)
    if column is None:
        return pd.Series([default] * len(frame), index=frame.index, dtype="object")
    return frame[column].fillna(default).astype(str).str.strip()


def _clean_text(value: object) -> str:
    if value is None:
        return ""
    try:
        if pd.isna(value):
            return ""
    except (TypeError, ValueError):
        pass
    text = str(value).replace("\x00", " ")
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    return " ".join(text.split()).strip()


def _map_label(value: object) -> str | None:
    if value is None:
        return None
    try:
        if pd.isna(value):
            return None
    except (TypeError, ValueError):
        pass
    return LABEL_ALIASES.get(str(value).strip().lower())


def _parse_bool(value: object) -> bool:
    return str(value).strip().lower() in {"1", "true", "yes", "y"}


def _eval_id(text: str, index: int) -> str:
    digest = hashlib.sha1(f"{index}|{text}".encode("utf-8")).hexdigest()[:16]
    return f"indian-{digest}"
