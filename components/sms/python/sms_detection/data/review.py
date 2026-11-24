"""Human annotation gates for a local development SMS dataset.

Source labels and detector predictions are not ground truth. No classifier is
called here. Observed sources must never be exported as a fresh test benchmark.
"""
from __future__ import annotations

import pandas as pd

from .deduplicate import add_dedup_columns

LABELS = {"ham", "spam", "smishing", "uncertain"}
REVIEW_COLUMNS = [
    "review_id", "text", "language", "sender", "sender_type", "collection_date",
    "source", "group_id", "usage", "label_1", "reviewer_1", "notes_1",
    "label_2", "reviewer_2", "notes_2", "adjudicated_label", "adjudicator",
    "adjudication_notes", "scam_type",
]


def build_pool(frame: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame, dict]:
    frame = frame.copy().fillna("")
    if not {"text", "source", "source_label"}.issubset(frame):
        raise ValueError("Candidates require text, source and source_label")
    frame["text"] = frame["text"].astype(str)
    empty = frame.text.str.strip().eq("")
    frame = frame.loc[~empty].reset_index(drop=True)
    if frame.empty:
        raise ValueError("No nonempty candidate messages")
    frame["message_id"] = [f"candidate-{i}" for i in range(len(frame))]
    grouped = add_dedup_columns(frame, near_duplicate=True)
    grouped["review_id"] = grouped.exact_key.map(lambda k: "sms-" + k)
    provenance = grouped[["review_id", "source", "source_label"]].copy()
    provenance["source_row"] = grouped.get("source_row", pd.Series("", index=grouped.index))
    conflicts = grouped.groupby("review_id").source_label.nunique().gt(1).sum()
    pool = grouped.drop_duplicates("review_id").copy()
    for column in REVIEW_COLUMNS:
        if column not in pool:
            pool[column] = ""
    pool["group_id"] = pool.split_group
    pool["usage"] = "development_only"
    # No automatic language guesses or inherited labels in the review form.
    pool["language"] = "unknown"
    pool = pool[REVIEW_COLUMNS].sort_values("review_id").reset_index(drop=True)
    stats = {
        "input_rows": len(frame) + int(empty.sum()), "empty_rows_removed": int(empty.sum()),
        "unique_messages": len(pool), "exact_duplicates_removed": len(frame) - len(pool),
        "template_near_duplicate_groups": int(pool.group_id.nunique()),
        "messages_with_conflicting_source_labels": int(conflicts),
    }
    return pool, provenance, stats


def select_pilot(pool: pd.DataFrame, provenance: pd.DataFrame, limit: int = 400) -> pd.DataFrame:
    if limit <= 0:
        raise ValueError("Pilot size must be positive")
    # Round-robin across source-label strata; one representative per campaign
    # group avoids filling the pilot with one repeated promotional template.
    strata = provenance.drop_duplicates("review_id").set_index("review_id")
    work = pool.copy()
    work["stratum"] = work.review_id.map(
        (strata.source.astype(str) + ":" + strata.source_label.astype(str)).to_dict()
    )
    buckets = [g.sort_values("review_id").to_dict("records") for _, g in work.groupby("stratum")]
    selected, seen = [], set()
    while any(buckets) and len(selected) < limit:
        for bucket in buckets:
            while bucket:
                row = bucket.pop(0)
                if row["group_id"] not in seen:
                    selected.append(row)
                    seen.add(row["group_id"])
                    break
            if len(selected) >= limit:
                break
    return pd.DataFrame(selected, columns=REVIEW_COLUMNS)


def finalize_reviews(reviews: pd.DataFrame, registry: pd.DataFrame) -> tuple[pd.DataFrame, dict]:
    missing = set(REVIEW_COLUMNS) - set(reviews)
    if missing:
        raise ValueError("Missing review columns: " + ", ".join(sorted(missing)))
    reviews = reviews.copy().fillna("")
    if reviews.review_id.duplicated().any():
        raise ValueError("Duplicate review IDs")
    reference = registry.set_index("review_id")
    accepted, pending, uncertain = [], 0, 0
    for row in reviews.to_dict("records"):
        rid = row["review_id"]
        if rid not in reference.index:
            raise ValueError("Unknown review ID")
        original = reference.loc[rid]
        for key in ("text", "group_id", "source", "usage"):
            if str(row[key]) != str(original[key]):
                raise ValueError(f"Immutable field changed: {key}")
        for key in ("label_1", "label_2", "adjudicated_label"):
            row[key] = str(row[key]).strip().lower()
            if row[key] and row[key] not in LABELS:
                raise ValueError(f"Invalid label in {key}")
        r1, r2 = str(row["reviewer_1"]).strip(), str(row["reviewer_2"]).strip()
        if not (row["label_1"] and row["label_2"] and r1 and r2):
            pending += 1
            continue
        if r1.casefold() == r2.casefold():
            raise ValueError("Two distinct reviewers are required")
        if row["adjudicated_label"]:
            if not str(row["adjudicator"]).strip() or not str(row["adjudication_notes"]).strip():
                raise ValueError("Adjudication needs a reviewer identity and rationale")
            label = row["adjudicated_label"]
        elif row["label_1"] == row["label_2"]:
            label = row["label_1"]
        else:
            pending += 1
            continue
        if label == "uncertain":
            uncertain += 1
        accepted.append({**row, "label": label, "known_sender": False})
    columns = REVIEW_COLUMNS + ["label", "known_sender"]
    return pd.DataFrame(accepted, columns=columns), {
        "submitted_rows": len(reviews), "reviewed_rows": len(accepted),
        "pending_or_disputed_rows": pending, "uncertain_rows": uncertain,
        "usable_labelled_rows": len(accepted) - uncertain,
        "usage": "development_only", "fresh_test_rows": 0,
    }
