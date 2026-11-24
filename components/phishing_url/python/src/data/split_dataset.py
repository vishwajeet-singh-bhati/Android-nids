"""Clean samples.csv and split it into leakage-safe train/val/test sets.

Two datasets are produced, because the two input modes see different text:

  full_url/  model_string of full URLs (host + path + query). For HTTP traffic
             or links found in messages.
  domain/    hostnames only. For DNS / TLS-SNI traffic, where no path exists.

Training them together would teach "no path means benign" (Tranco rows are
domains, most phishing rows are URLs), so they are kept apart.

Cleaning rules (all counted in split_report.json):
  * Redirector links (URL shorteners, QR-code services) are removed from
    training. Their URL hides the destination, so learning from them would only
    teach "this shortener is evil". At inference they are routed to UNCERTAIN.
  * A text that appears with both labels is dropped (ambiguous).
  * Domain mode: a phishing host whose registered domain is itself popular
    (e.g. docs.google.com, a compromised small business site) is not labelled
    phishing at the host level; the host is legitimate, only one page is bad.
  * Each (split, label, group) keeps at most `cap_per_group` rows, so one
    abused platform (google.com had 5,260 phishing URLs) cannot dominate.

Leakage control: every row is assigned to a split by hashing its GROUP (the
registered domain, PSL private suffixes honoured), so all URLs of one site land
in the same split, in both datasets. Optionally, groups first seen after
`future_cutoff` form a separate `test_future` split for time-based evaluation.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import logging
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Literal, Sequence

import numpy as np

from ..preprocessing.url_normalizer import private_registered_domain
from .parsers import find_snapshots

logger = logging.getLogger(__name__)

GroupBy = Literal["private", "icann"]
SPLITS = ("train", "val", "test")
FUTURE_SPLIT = "test_future"
DEFAULT_FRACTIONS = (0.8, 0.1, 0.1)
OUT_COLUMNS = [
    "sample_id", "y", "label", "label_quality", "sources", "model_string", "canonical",
    "host", "group", "first_seen", "first_collected_at", "tranco_rank",
]
# "<host>/<one short code>" e.g. "qrco.de/bfX2a": the destination is not in the URL.
OPAQUE_RE = re.compile(r"^[^/]+/[A-Za-z0-9_-]{1,16}/?$")
_DOMAIN_RE = re.compile(r"[a-z0-9-]+(\.[a-z0-9-]+)+")


class SplitValidationError(AssertionError):
    """The produced splits violate a leakage or labelling invariant."""


# --------------------------------------------------------------------------- inputs
def load_redirectors(paths: Iterable[Path | str]) -> set[str]:
    """One domain per line; '#' comments and blank lines ignored; invalid lines skipped."""
    domains: set[str] = set()
    for path in paths:
        for line in Path(path).read_text(encoding="utf-8").splitlines():
            value = line.split("#", 1)[0].strip().lower().rstrip(".")
            if value and _DOMAIN_RE.fullmatch(value):
                domains.add(value)
    return domains


def read_samples(path: Path | str) -> list[dict[str, str]]:
    with Path(path).open(encoding="utf-8", newline="") as fh:
        reader = csv.DictReader(fh)
        required = {"sample_id", "label", "input_type", "model_string", "host",
                    "registered_domain", "group", "tranco_rank"}
        if not required <= set(reader.fieldnames or []):
            raise ValueError("samples.csv is missing required columns")
        rows = list(reader)
    bad = {r["label"] for r in rows} - {"phishing", "benign"}
    if bad:
        raise ValueError(f"unexpected labels in samples.csv: {sorted(bad)}")
    return rows


# --------------------------------------------------------------------------- pure helpers
def group_key(row: dict[str, str], group_by: GroupBy) -> str:
    if group_by == "icann":
        return row["group"]
    return private_registered_domain(row["host"]) or row["host"]


def is_redirector(row: dict[str, str], group: str, redirectors: set[str]) -> bool:
    return bool({row["host"], row["registered_domain"], group} & redirectors)


def _unit_hash(text: str) -> float:
    """Deterministic number in [0, 1) derived from text."""
    return int.from_bytes(hashlib.sha256(text.encode("utf-8")).digest()[:8], "big") / 2**64


def assign_split(group: str, seed: int, fractions: Sequence[float] = DEFAULT_FRACTIONS) -> str:
    u = _unit_hash(f"{seed}|{group}")
    if u < fractions[0]:
        return "train"
    if u < fractions[0] + fractions[1]:
        return "val"
    return "test"


def cap_rows(rows: list[dict[str, Any]], cap: int) -> tuple[list[dict[str, Any]], int]:
    """Keep at most `cap` rows per (split, label, group), chosen by hash (deterministic)."""
    buckets: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        buckets[(row["split"], row["label"], row["group"])].append(row)
    kept: list[dict[str, Any]] = []
    for bucket in buckets.values():
        bucket.sort(key=lambda r: hashlib.sha256(r["sample_id"].encode()).hexdigest())
        kept.extend(bucket[:cap])
    return kept, len(rows) - len(kept)


def drop_label_conflicts(rows: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], int]:
    labels: dict[str, set[str]] = defaultdict(set)
    for row in rows:
        labels[row["model_string"]].add(row["label"])
    kept = [r for r in rows if len(labels[r["model_string"]]) == 1]
    return kept, len(rows) - len(kept)


def opaque_candidates(rows: Iterable[dict[str, Any]], *, min_count: int = 20,
                      min_fraction: float = 0.9) -> list[list[Any]]:
    """Groups (not yet on any list) whose phishing URLs are almost all '<host>/<code>'."""
    total: Counter[str] = Counter()
    opaque: Counter[str] = Counter()
    for row in rows:
        total[row["group"]] += 1
        opaque[row["group"]] += bool(OPAQUE_RE.match(row["model_string"]))
    found = [[g, n, round(opaque[g] / n, 3)] for g, n in total.items()
             if n >= min_count and opaque[g] / n >= min_fraction]
    return sorted(found, key=lambda item: -item[1])


def _render_host(host: str) -> str:
    return f"[{host}]" if ":" in host else host


# --------------------------------------------------------------------------- datasets
def _split_for(group: str, seed: int, fractions: Sequence[float],
               future_groups: set[str]) -> str:
    return FUTURE_SPLIT if group in future_groups else assign_split(group, seed, fractions)


def _finish(rows: list[dict[str, Any]], seed: int, fractions: Sequence[float],
            future_groups: set[str], cap: int) -> tuple[list[dict[str, Any]], dict[str, int]]:
    rows, conflicts = drop_label_conflicts(rows)
    for row in rows:
        row["split"] = _split_for(row["group"], seed, fractions, future_groups)
        row["y"] = 1 if row["label"] == "phishing" else 0
    rows, capped = cap_rows(rows, cap)
    rows.sort(key=lambda r: (r["split"], r["sample_id"]))
    return rows, {"label_conflicts": conflicts, "capped": capped}


def build_full_url_rows(samples: list[dict[str, str]], groups: list[str],
                        redirectors: set[str]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    removed: Counter[str] = Counter()
    unlisted_phishing: list[dict[str, Any]] = []
    for sample, group in zip(samples, groups):
        if sample["input_type"] != "full_url":
            continue
        if is_redirector(sample, group, redirectors):
            removed[sample["label"]] += 1
            continue
        row = {col: sample.get(col, "") for col in OUT_COLUMNS if col not in ("y", "group")}
        row["group"] = group
        rows.append(row)
        if sample["label"] == "phishing":
            unlisted_phishing.append(row)
    return rows, {"redirectors_removed": dict(removed),
                  "redirector_candidates": opaque_candidates(unlisted_phishing)}


def build_domain_rows(samples: list[dict[str, str]], groups: list[str],
                      redirectors: set[str]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    benign_groups = {g for s, g in zip(samples, groups) if s["label"] == "benign"}
    hosts: dict[tuple[str, str], dict[str, Any]] = {}
    removed: Counter[str] = Counter()
    for sample, group in zip(samples, groups):
        label = sample["label"]
        if is_redirector(sample, group, redirectors):
            removed["redirector"] += 1
            continue
        if label == "phishing":
            popular_own_domain = (sample["tranco_rank"] != ""
                                  and group == sample["registered_domain"])
            if popular_own_domain or group in benign_groups:
                removed["phishing_on_popular_domain"] += 1
                continue
        host = _render_host(sample["host"])
        key = (label, host)
        if key in hosts:
            continue
        hosts[key] = {
            "sample_id": hashlib.sha256(f"domain|{label}|{host}".encode()).hexdigest()[:16],
            "label": label, "label_quality": sample.get("label_quality", ""),
            "sources": sample.get("sources", ""), "model_string": host, "canonical": host,
            "host": sample["host"], "group": group,
            "first_seen": sample.get("first_seen", ""),
            "first_collected_at": sample.get("first_collected_at", ""),
            "tranco_rank": sample["tranco_rank"],
        }
    return list(hosts.values()), {"removed": dict(removed)}


def future_groups_for(samples: list[dict[str, str]], groups: list[str],
                      cutoff: str | None) -> set[str]:
    """Groups whose EARLIEST phishing collection time is on/after cutoff (ISO, UTC)."""
    if cutoff is None:
        return set()
    earliest: dict[str, str] = {}
    for sample, group in zip(samples, groups):
        when = sample.get("first_collected_at", "")
        if sample["label"] == "phishing" and when:
            earliest[group] = min(earliest.get(group, when), when)
    return {g for g, when in earliest.items() if when >= cutoff}


# --------------------------------------------------------------------------- checks + stats
def validate_splits(rows: list[dict[str, Any]]) -> dict[str, bool]:
    """Raise SplitValidationError if any leakage invariant is broken."""
    group_splits: dict[str, set[str]] = defaultdict(set)
    text_splits: dict[str, set[str]] = defaultdict(set)
    ids: set[str] = set()
    for row in rows:
        group_splits[row["group"]].add(row["split"])
        text_splits[row["model_string"]].add(row["split"])
        if row["y"] not in (0, 1) or row["label"] not in ("phishing", "benign"):
            raise SplitValidationError("invalid label")
        if row["sample_id"] in ids:
            raise SplitValidationError("duplicate sample_id")
        ids.add(row["sample_id"])
    if any(len(s) > 1 for s in group_splits.values()):
        raise SplitValidationError("a group appears in more than one split")
    if any(len(s) > 1 for s in text_splits.values()):
        raise SplitValidationError("the same text appears in more than one split")
    return {"groups_disjoint": True, "texts_disjoint": True, "ids_unique": True}


def _p50(values: list[int]) -> float | None:
    return float(np.median(values)) if values else None


def describe(rows: list[dict[str, Any]], mode: str) -> dict[str, Any]:
    per_split: dict[str, Any] = {}
    for split in sorted({r["split"] for r in rows}):
        part = [r for r in rows if r["split"] == split]
        counts = Counter(r["label"] for r in part)
        per_split[split] = {
            "phishing": counts["phishing"], "benign": counts["benign"],
            "phishing_fraction": round(counts["phishing"] / len(part), 4),
            "groups": len({r["group"] for r in part}),
        }
    # Shortcut monitors: large gaps between labels here are warning signs.
    monitors: dict[str, Any] = {}
    for label in ("phishing", "benign"):
        part = [r for r in rows if r["label"] == label]
        texts = [r["model_string"] for r in part]
        entry: dict[str, Any] = {"median_length": _p50([len(t) for t in texts])}
        if mode == "full_url":
            entry["fraction_with_path_or_query"] = round(
                sum(not t.endswith("/") or t.count("/") > 1 or "?" in t for t in texts)
                / len(texts), 4) if texts else None
        else:
            entry["fraction_with_subdomain"] = round(
                sum(r["host"] != r["group"] for r in part) / len(part), 4) if part else None
        monitors[label] = entry
    return {"splits": per_split, "shortcut_monitors": monitors}


def _write(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=OUT_COLUMNS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


# --------------------------------------------------------------------------- driver
def build_splits(
    samples_path: Path | str,
    out_dir: Path | str,
    redirector_paths: Sequence[Path | str],
    *,
    seed: int = 13,
    cap_per_group: int = 50,
    fractions: Sequence[float] = DEFAULT_FRACTIONS,
    group_by: GroupBy = "private",
    future_cutoff: str | None = None,
) -> dict[str, Any]:
    if len(fractions) != 3 or any(f <= 0 for f in fractions) or abs(sum(fractions) - 1) > 1e-9:
        raise ValueError("fractions must be three positive numbers summing to 1")
    if cap_per_group < 1:
        raise ValueError("cap_per_group must be >= 1")
    if group_by not in ("private", "icann"):
        raise ValueError("group_by must be 'private' or 'icann'")
    if future_cutoff is not None:
        datetime.fromisoformat(future_cutoff)  # raises ValueError if malformed

    samples = read_samples(samples_path)
    redirectors = load_redirectors(redirector_paths)
    groups = [group_key(s, group_by) for s in samples]
    future = future_groups_for(samples, groups, future_cutoff)

    full_rows, full_info = build_full_url_rows(samples, groups, redirectors)
    full_rows, full_cleaning = _finish(full_rows, seed, fractions, future, cap_per_group)
    domain_rows, domain_info = build_domain_rows(samples, groups, redirectors)
    domain_rows, domain_cleaning = _finish(domain_rows, seed, fractions, future, cap_per_group)

    report: dict[str, Any] = {
        "built_at": datetime.now(timezone.utc).isoformat(),
        "seed": seed, "cap_per_group": cap_per_group, "fractions": list(fractions),
        "group_by": group_by, "future_cutoff": future_cutoff,
        "redirector_domains_loaded": len(redirectors),
        "warnings": [] if redirectors else ["no redirector list loaded"],
    }
    out_dir = Path(out_dir)
    for mode, rows, info, cleaning in (("full_url", full_rows, full_info, full_cleaning),
                                       ("domain", domain_rows, domain_info, domain_cleaning)):
        report[mode] = {"validation": validate_splits(rows), **info, **cleaning,
                        **describe(rows, mode)}
        for split in sorted({r["split"] for r in rows}):
            _write(out_dir / mode / f"{split}.csv", [r for r in rows if r["split"] == split])
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "split_report.json").write_text(json.dumps(report, indent=2) + "\n",
                                               encoding="utf-8")
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Clean and split the sample table.")
    parser.add_argument("--samples", default="data/processed/samples.csv")
    parser.add_argument("--out", default="data/processed/splits")
    parser.add_argument("--raw", default="data/raw")
    parser.add_argument("--local-redirectors", default="config/redirectors_local.txt")
    parser.add_argument("--seed", type=int, default=13)
    parser.add_argument("--cap", type=int, default=50)
    parser.add_argument("--group-by", choices=["private", "icann"], default="private")
    parser.add_argument("--future-cutoff", default=None,
                        help="ISO time, e.g. 2026-11-20T00:00:00+00:00")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    lists = find_snapshots(args.raw, "url_shorteners")[-1:]
    if not lists:
        logger.warning("no url_shorteners snapshot; run "
                       "python -m src.data.download_datasets --sources url_shorteners")
    if Path(args.local_redirectors).is_file():
        lists.append(Path(args.local_redirectors))
    try:
        report = build_splits(args.samples, args.out, lists, seed=args.seed,
                              cap_per_group=args.cap, group_by=args.group_by,
                              future_cutoff=args.future_cutoff)
    except (OSError, ValueError, SplitValidationError) as exc:
        logger.error("%s", exc)
        return 1
    for mode in ("full_url", "domain"):
        logger.info("%s: %s", mode, json.dumps(report[mode]["splits"]))
    logger.info("report written to %s", Path(args.out) / "split_report.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
