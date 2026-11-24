"""Audit the unified dataset and generate the data card.

Counts and provenance are written to docs/data-card.md and the full audit JSON
to artifacts/reports/data_audit.json. Raw message examples go only to the
git-ignored data/interim/audit_examples.csv.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

from sms_detection.config import (
    DOCS_DIR,
    INDIAN_DIR,
    INTERIM_DIR,
    PROCESSED_DIR,
    RAW_DIR,
    REPORTS_DIR,
    SOURCE_LICENSES,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Audit prepared SMS dataset")
    parser.add_argument("--processed-dir", default=str(PROCESSED_DIR))
    parser.add_argument("--raw-dir", default=str(RAW_DIR))
    parser.add_argument("--docs-dir", default=str(DOCS_DIR))
    parser.add_argument("--reports-dir", default=str(REPORTS_DIR))
    parser.add_argument(
        "--indian-benchmark",
        default=str(INDIAN_DIR / "india_spam_sms.csv"),
        help="Optional prepared Kaggle Indian source benchmark",
    )
    args = parser.parse_args(argv)

    processed = Path(args.processed_dir)
    all_path = processed / "all.csv"
    if not all_path.exists():
        raise SystemExit(f"Missing {all_path}; run scripts/prepare_data.py first.")
    frame = pd.read_csv(all_path, low_memory=False)
    split_manifest = _read_json(processed / "split_manifest.json")
    source_manifest = _read_json(Path(args.raw_dir) / "source_manifest.json")

    audit = _audit(frame, split_manifest, source_manifest)
    audit["indian_source_benchmark"] = _indian_source_audit(
        Path(args.indian_benchmark), Path(args.reports_dir)
    )
    reports_dir = Path(args.reports_dir)
    reports_dir.mkdir(parents=True, exist_ok=True)
    (reports_dir / "data_audit.json").write_text(
        json.dumps(audit, indent=2), encoding="utf-8"
    )

    docs_dir = Path(args.docs_dir)
    docs_dir.mkdir(parents=True, exist_ok=True)
    (docs_dir / "data-card.md").write_text(
        _data_card(audit), encoding="utf-8"
    )

    private_dir = Path(INTERIM_DIR)
    private_dir.mkdir(parents=True, exist_ok=True)
    _write_examples(frame, private_dir / "audit_examples.csv")

    print(_summary(audit))
    print(f"\nWrote {reports_dir / 'data_audit.json'}")
    print(f"Wrote {docs_dir / 'data-card.md'}")
    print(f"Wrote {private_dir / 'audit_examples.csv'} (private, git-ignored)")
    return 0


def _audit(
    frame: pd.DataFrame,
    split_manifest: dict,
    source_manifest: dict,
) -> dict:
    frame = frame.copy()
    frame["text_length"] = frame["text"].astype(str).str.len()
    frame["token_count"] = frame["text"].astype(str).str.split().str.len()
    source_license = (
        source_manifest.get("files", []) if isinstance(source_manifest, dict) else []
    )
    licenses: dict[str, list[str]] = {}
    for entry in source_license:
        licenses.setdefault(entry["dataset"], []).append(entry["license"])

    def crosstab(index: str, columns: str) -> dict:
        table = pd.crosstab(frame[index], frame[columns])
        return {
            str(row): {str(col): int(value) for col, value in values.items()}
            for row, values in table.iterrows()
        }

    return {
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "rows": int(len(frame)),
        "missing_text": int(frame["text"].isna().sum()),
        "duplicate_message_ids": int(frame["message_id"].duplicated().sum()),
        "sources": {
            str(k): int(v) for k, v in frame["source_dataset"].value_counts().items()
        },
        "labels": {str(k): int(v) for k, v in frame["label"].value_counts().items()},
        "splits": {str(k): int(v) for k, v in frame["split"].value_counts().items()},
        "language": {str(k): int(v) for k, v in frame["language"].value_counts().items()},
        "source_label": crosstab("source_dataset", "source_label"),
        "source_vs_label": crosstab("source_dataset", "label"),
        "split_vs_label": crosstab("split", "label"),
        "flags": {
            "has_url": int(frame["has_url"].fillna(False).astype(bool).sum()),
            "has_phone": int(frame["has_phone"].fillna(False).astype(bool).sum()),
            "has_email": int(frame["has_email"].fillna(False).astype(bool).sum()),
        },
        "length": {
            "min": int(frame["text_length"].min()),
            "median": float(frame["text_length"].median()),
            "mean": float(frame["text_length"].mean()),
            "p95": float(frame["text_length"].quantile(0.95)),
            "max": int(frame["text_length"].max()),
        },
        "tokens": {
            "median": float(frame["token_count"].median()),
            "mean": float(frame["token_count"].mean()),
        },
        "campaigns": int(frame["campaign_id"].dropna().nunique()),
        "groups": int(frame["split_group"].nunique()),
        "near_duplicate_clusters": int(frame["near_dup_cluster"].nunique()),
        "exact_duplicate_groups": int(frame["exact_key"].nunique()),
        "split_manifest": split_manifest,
        "source_manifest": source_manifest,
        "licenses": licenses,
    }


def _indian_source_audit(path: Path, reports_dir: Path) -> dict:
    result: dict = {
        "source": "Kaggle India Spam SMS Classification",
        "url": "https://www.kaggle.com/datasets/junioralive/india-spam-sms-classification",
        "license": SOURCE_LICENSES["india_spam_sms"],
        "benchmark_path": "data/indian/india_spam_sms.csv",
        "available": False,
        "usage": "evaluation-only; not part of the unified training table",
    }
    if not path.exists():
        return result
    frame = pd.read_csv(path, low_memory=False)
    result["available"] = True
    result["rows"] = int(len(frame))
    result["labels"] = {
        str(key): int(value) for key, value in frame["label"].value_counts().items()
    }
    report = _read_json(reports_dir / "indian_eval_kaggle_india_spam_sms.json")
    if report:
        benchmark = report.get("benchmark", {})
        result["evaluated_rows"] = int(benchmark.get("rows", 0))
        result["dropped_leakage_rows"] = int(
            benchmark.get("dropped_overlap_rows", 0)
        )
        result["evaluation_report"] = "artifacts/reports/indian_eval_kaggle_india_spam_sms.json"
    return result


def _summary(audit: dict) -> str:
    lines = [
        f"Rows: {audit['rows']:,}",
        f"Sources: {audit['sources']}",
        f"Labels: {audit['labels']}",
        f"Splits: {audit['splits']}",
        f"Groups: {audit['groups']:,}",
        f"Near-dup clusters: {audit['near_duplicate_clusters']:,}",
    ]
    return "\n".join(lines)


def _data_card(audit: dict) -> str:
    split_manifest = audit.get("split_manifest", {})
    duplicates = split_manifest.get("duplicates", {})
    sources = audit["sources"]
    labels = audit["labels"]
    splits = audit["splits"]

    lines = [
        "# Data Card — SMS Scam Detection",
        "",
        f"Generated: {audit['created_utc']}",
        "",
        "## Purpose",
        "",
        "This dataset card describes the unified table used to train and evaluate the",
        "SMS ham/spam/smishing detector. The raw messages are **not redistributed** by",
        "this repository; the download script fetches each source and records checksums.",
        "",
        "## Sources and licensing",
        "",
        "| Dataset | Rows in unified table | License / access note |",
        "|---|---:|---|",
    ]
    license_lookup = {
        "uci_sms_spam": "UCI SMS Spam Collection; check dataset page/readme for attribution and reuse terms",
        "lsdst_2022": "CC BY 4.0 (Mishra & Soni, DOI 10.17632/f45bkkt8pr.1)",
        "ncsu_sms_phishing": "Repository MIT; verify data-level provenance/third-party constraints",
        "hinglish_scam": "CC BY 4.0 (bolewara/hinglish-scam-text-dataset)",
    }
    for source, count in sorted(sources.items(), key=lambda item: -item[1]):
        lines.append(
            f"| `{source}` | {count:,} | {license_lookup.get(source, 'see source manifest')} |"
        )

    lines.extend(
        [
            "",
            "The raw file SHA-256 values are recorded in `data/raw/source_manifest.json`.",
            "Re-check licenses at the point of use; this card is not a redistribution licence.",
            "",
            "## Unified schema",
            "",
            "`message_id, text, label, language, source_dataset, source_id, has_url,",
            "has_phone, has_email, campaign_id, collection_date, split_group,",
            "annotation_note, source_label, license, source_url, dataset_version,",
            "derived_from_uci`",
            "",
            "`text` is the original message. Normalization is derived at training and",
            "inference time and never overwrites the raw value.",
            "",
            "## Label mapping",
            "",
            "- UCI `ham` → `ham`; UCI `spam` → `spam` (never silently promoted to smishing).",
            "- LSDST `ham` / `spam` / `smishing` → same three project labels.",
            "- NCSU phishing corpus → `smishing` (source-level label; content review still needed).",
            "- Hinglish dataset `0` → `ham`; `1` → `smishing`. Rows that duplicate UCI are",
            "  marked `derived_from_uci` and are not used as independent evidence.",
            "- Kaggle India Spam SMS `ham` / `spam` → same labels; it has no smishing",
            "  labels and is evaluation-only.",
            "",
            "## Class distribution",
            "",
            "| Label | Rows |",
            "|---|---:|",
        ]
    )
    for label, count in sorted(labels.items(), key=lambda item: -item[1]):
        lines.append(f"| `{label}` | {count:,} |")

    lines.extend(
        [
            "",
            "## Split distribution",
            "",
            "| Split | Rows |",
            "|---|---:|",
        ]
    )
    for split, count in sorted(splits.items()):
        lines.append(f"| `{split}` | {count:,} |")

    lines.extend(
        [
            "",
            "Split policy (see `data/processed/split_manifest.json`):",
            "",
            "- Group key: exact text + masked template + MinHash near-duplicate cluster + NCSU campaign.",
            "- No group appears in more than one split.",
            "- Main pool: UCI + LSDST. 10% of groups are reserved as `classic_holdout`.",
            "- Remaining pool: 70% train / 15% validation / 15% test by group.",
            "- External test: NCSU smishing (`ncsu_smishing`), held-out classic messages",
            "  (`classic_holdout`) and the 63 hand-written Hinglish rows (`hinglish_seed`).",
            "- External rows sharing a group with training are removed as leakage risk.",
            "",
            "## Duplicate audit",
            "",
            "| Metric | Value |",
            "|---|---:|",
        ]
    )
    duplicate_rows = [
        ("Exact duplicate rows (before drop)", duplicates.get("exact_duplicate_rows", 0)),
        ("Exact duplicate groups", duplicates.get("exact_duplicate_groups", 0)),
        ("Template groups", duplicates.get("template_groups", 0)),
        ("Near-duplicate clusters", duplicates.get("near_duplicate_clusters", 0)),
        ("Near-duplicate pairs", duplicates.get("near_duplicate_pairs", 0)),
        ("Largest cluster", duplicates.get("largest_cluster", 0)),
        ("External leakage rows dropped", duplicates.get("dropped_external_leakage_rows", 0)),
    ]
    for name, value in duplicate_rows:
        lines.append(f"| {name} | {value:,} |")

    indian = audit.get("indian_source_benchmark") or {}
    lines.extend(
        [
            "",
            "## Evaluation-only Indian source",
            "",
            "The Kaggle **India Spam SMS Classification** collection is downloaded",
            "separately and kept out of the unified training table and split assignment.",
            "It is a binary ham/spam source with no smishing labels and is not a random",
            "sample of Indian traffic.",
            "",
            f"- Source: {indian.get('url', 'https://www.kaggle.com/datasets/junioralive/india-spam-sms-classification')}",
            f"- License note: {indian.get('license', SOURCE_LICENSES['india_spam_sms'])}",
            f"- Prepared local rows: {indian.get('rows', 0):,} "
            f"({indian.get('labels', {}).get('ham', 0):,} ham / "
            f"{indian.get('labels', {}).get('spam', 0):,} spam)"
            if indian.get("available")
            else "- Prepared local rows: not present in this checkout",
            f"- Leakage-filtered evaluation rows: {indian.get('evaluated_rows', 0):,} "
            f"(dropped {indian.get('dropped_leakage_rows', 0):,} overlapping rows)"
            if indian.get("evaluated_rows") is not None
            else "- Leakage-filtered evaluation rows: not generated",
            "- The source benchmark is not used to train or tune the selected model;",
            "  it is not sufficient for claims of Indian smishing performance. Use a",
            "  separate, consented, independently sampled benchmark for those claims.",
            "- See `docs/indian-source-benchmark.md` for aggregate results and caveats.",
        ]
    )

    lines.extend(
        [
            "",
            "## Structural signals",
            "",
            f"- Messages with a URL: {audit['flags']['has_url']:,}",
            f"- Messages with a phone number: {audit['flags']['has_phone']:,}",
            f"- Messages with an email address: {audit['flags']['has_email']:,}",
            f"- Campaign IDs: {audit['campaigns']:,}",
            f"- Median length: {audit['length']['median']:.0f} characters",
            f"- 95th percentile length: {audit['length']['p95']:.0f} characters",
            "",
            "## Known limitations",
            "",
            "- UCI is old and largely UK/Singapore-oriented; it is a baseline and",
            "  regression corpus, not evidence of current Indian smishing performance.",
            "- LSDST-2022 is imbalanced (638 smishing vs 4,844 ham) and its labels were",
            "  partly derived from images converted to text. Inspect label quality before",
            "  making strong claims.",
            "- NCSU is a campaign-oriented phishing release. Its source label is treated",
            "  as smishing, but the campaign corpus includes gambling and promotional spam;",
            "  external exact-class metrics are label-noisy and should be read as a stress test.",
            "- The Hinglish dataset is mostly UCI-derived. Only 63 hand-written Hinglish",
            "  rows are new, so it cannot support a claim of robust Hinglish performance.",
            "- The Kaggle India Spam SMS source is binary ham/spam and not a random",
            "  representative sample. It is an external diagnostic, not proof of Indian",
            "  smishing performance, and it must not be used to tune the locked test.",
            "- No message body may be sent to a cloud service. Do not commit raw data or",
            "  audit examples; they can contain personal or sensitive content.",
            "",
            "## Reproduction",
            "",
            "```powershell",
            "python scripts/download_data.py",
            "python scripts/prepare_data.py",
            "python scripts/audit_data.py",
            "python scripts/prepare_india_source.py",
            "python scripts/evaluate_indian.py --input data/indian/india_spam_sms.csv --name kaggle_india_spam_sms",
            "```",
            "",
        ]
    )
    return "\n".join(lines)


def _write_examples(frame: pd.DataFrame, path: Path) -> None:
    columns = [
        "message_id",
        "source_dataset",
        "source_label",
        "label",
        "split",
        "text",
    ]
    examples = (
        frame.groupby(["source_dataset", "label"], group_keys=False)
        .head(3)[columns]
        .sort_values(["source_dataset", "label"])
    )
    examples.to_csv(path, index=False, encoding="utf-8")


def _read_json(path: Path) -> dict:
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    raise SystemExit(main())
