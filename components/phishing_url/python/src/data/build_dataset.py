"""Build the unified, normalized sample table from raw feed snapshots.

Writes into <out>:
  samples.csv        one row per unique sample
  rejected.csv       inputs the normalizer refused (value truncated, CSV-safe)
  build_report.json  statistics only; contains no raw URLs
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import logging
import random
from collections import Counter
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np

from ..preprocessing.url_normalizer import InvalidURLError, NormalizedURL, normalize_url
from .parsers import (
    RawRecord,
    find_snapshots,
    parse_commoncrawl,
    parse_openphish,
    parse_phishtank,
    parse_tranco,
    read_collected_at,
)

logger = logging.getLogger(__name__)

PHISHING_PARSERS = {"phishtank": parse_phishtank, "openphish": parse_openphish}
COLUMNS = [
    "sample_id", "label", "label_quality", "sources", "input_type", "canonical",
    "model_string", "host", "registered_domain", "group", "scheme",
    "has_path_or_query", "is_ip", "has_punycode", "first_seen", "first_collected_at",
    "tranco_rank", "host_conflict",
]
TRUNCATION_LENGTHS = (128, 192, 256, 384, 512)
_CSV_DANGER = ("=", "+", "-", "@", "\t", "\r")


class Reservoir:
    """Algorithm R: uniform random sample of k items from a stream, O(k) memory."""

    def __init__(self, k: int, rng: random.Random) -> None:
        self.k, self.rng, self.items, self.seen = k, rng, [], 0

    def add(self, item: Any) -> None:
        if self.seen < self.k:
            self.items.append(item)
        else:
            j = self.rng.randint(0, self.seen)
            if j < self.k:
                self.items[j] = item
        self.seen += 1


def _merge_time(a: str, b: str) -> str:
    """Earliest non-empty ISO timestamp (all are UTC, so strings order correctly)."""
    if not a:
        return b
    if not b:
        return a
    return min(a, b)


def _csv_safe(value: str) -> str:
    return "'" + value if value.startswith(_CSV_DANGER) else value


def _pct(values: list[int]) -> dict[str, float | int]:
    if not values:
        return {"n": 0}
    arr = np.asarray(values, dtype=np.int64)
    p50, p90, p95, p99 = (float(x) for x in np.percentile(arr, [50, 90, 95, 99]))
    return {"n": int(arr.size), "p50": p50, "p90": p90, "p95": p95, "p99": p99,
            "max": int(arr.max())}


def _make_row(rec: RawRecord, n: NormalizedURL) -> dict[str, Any]:
    benign = rec.label == "benign_weak"
    return {
        "label": "benign" if benign else "phishing",
        "sources": {rec.source},
        "input_type": n.input_type,
        "canonical": n.canonical,
        "model_string": n.model_string,
        "host": n.host,
        "registered_domain": n.registered_domain,
        "group": n.registered_domain or n.host,
        "scheme": n.scheme or "",
        "has_path_or_query": bool(n.input_type == "full_url" and (n.path != "/" or n.query)),
        "is_ip": n.is_ip,
        "has_punycode": n.has_punycode,
        "first_seen": rec.first_seen,
        "first_collected_at": rec.collected_at,
        "tranco_rank": int(rec.source_id) if benign and rec.source_id.isdigit() else "",
        "host_conflict": False,
    }


def _ingest(rec: RawRecord, rows: dict, rejected: list[dict[str, str]], dup: Counter) -> None:
    try:
        n = normalize_url(rec.value, rec.input_type)  # type: ignore[arg-type]
    except InvalidURLError as exc:
        rejected.append({"source": rec.source, "reason": exc.reason, "value": rec.value[:200]})
        return
    except Exception as exc:  # a normalizer bug must show up as a count, not kill the build
        logger.warning("unexpected normalizer error: %s", type(exc).__name__)
        rejected.append({"source": rec.source, "reason": "unexpected_error", "value": rec.value[:200]})
        return
    new = _make_row(rec, n)
    key = (new["label"], new["canonical"])
    old = rows.get(key)
    if old is None:
        rows[key] = new
        return
    dup[new["label"]] += 1
    old["sources"] |= new["sources"]
    old["first_seen"] = _merge_time(old["first_seen"], new["first_seen"])
    old["first_collected_at"] = _merge_time(old["first_collected_at"], new["first_collected_at"])


def _write_csv(path: Path, fieldnames: list[str], rows: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def build_dataset(raw_root: Path | str, out_dir: Path | str, *, benign_count: int = 200_000,
                  homepage_count: int = 20_000, seed: int = 13,
                  phishing_snapshots: str = "all") -> dict[str, Any]:
    if phishing_snapshots not in ("all", "latest"):
        raise ValueError("phishing_snapshots must be 'all' or 'latest'")
    if benign_count < 0 or homepage_count < 0:
        raise ValueError("benign_count and homepage_count must be >= 0")
    raw_root, out_dir = Path(raw_root), Path(out_dir)

    phishing_files = {s: find_snapshots(raw_root, s) for s in PHISHING_PARSERS}
    tranco_files = find_snapshots(raw_root, "tranco")
    if not any(phishing_files.values()):
        raise FileNotFoundError("no phishing snapshots found; run python -m src.data.download_datasets")
    if not tranco_files:
        raise FileNotFoundError("no Tranco snapshot found; run python -m src.data.download_datasets")

    rows: dict[tuple[str, str], dict[str, Any]] = {}
    rejected: list[dict[str, str]] = []
    dup: Counter = Counter()
    inputs: dict[str, Any] = {}

    # 1) phishing sources
    for source, parser in PHISHING_PARSERS.items():
        files = phishing_files[source]
        if phishing_snapshots == "latest":
            files = files[-1:]
        skipped: Counter = Counter()
        read = 0
        for path in files:
            for rec in parser(path, read_collected_at(path), skipped):
                read += 1
                _ingest(rec, rows, rejected, dup)
        inputs[source] = {"files": [p.name for p in files], "records_read": read,
                          "skipped": dict(skipped)}

    phishing_regs = {r["registered_domain"] for (lab, _), r in rows.items()
                     if lab == "phishing" and r["registered_domain"]}
    phishing_hosts = {r["host"] for (lab, _), r in rows.items() if lab == "phishing"}

    # 2) Tranco: one streaming pass -> uniform sample + ranks of phishing-hosting domains
    tranco_path = tranco_files[-1]
    skipped = Counter()
    reservoir = Reservoir(benign_count, random.Random(seed))
    tranco_rank: dict[str, int] = {}
    tranco_read = 0
    for rec in parse_tranco(tranco_path, read_collected_at(tranco_path), skipped):
        tranco_read += 1
        key = rec.value.strip().lower().rstrip(".")  # approximate: no IDNA here
        if key in phishing_regs and key not in tranco_rank:
            tranco_rank[key] = int(rec.source_id)
        reservoir.add(rec)
    for rec in sorted(reservoir.items, key=lambda r: int(r.source_id)):
        _ingest(rec, rows, rejected, dup)
    # Homepages of sampled popular domains as benign FULL URLs. Without them, about half
    # of the phishing full URLs are bare homepages ("evil.example/") while almost no
    # benign full URL is, which would teach "a homepage URL means phishing".
    picks = random.Random(seed + 1).sample(reservoir.items,
                                           min(homepage_count, len(reservoir.items)))
    for rec in sorted(picks, key=lambda r: int(r.source_id)):
        _ingest(replace(rec, source="tranco_homepage", input_type="full_url",
                        value=f"https://{rec.value.strip()}/"), rows, rejected, dup)
    inputs["tranco"] = {"files": [tranco_path.name], "records_read": tranco_read,
                        "sampled": len(reservoir.items), "homepages": len(picks),
                        "skipped": dict(skipped)}

    # 2b) Common Crawl: benign FULL URLs (all snapshots; duplicates merge)
    warnings: list[str] = []
    cc_files = find_snapshots(raw_root, "commoncrawl")
    skipped = Counter()
    cc_read = 0
    for path in cc_files:
        for rec in parse_commoncrawl(path, read_collected_at(path), skipped):
            cc_read += 1
            _ingest(rec, rows, rejected, dup)
    inputs["commoncrawl"] = {"files": [p.name for p in cc_files], "records_read": cc_read,
                             "skipped": dict(skipped)}
    if not cc_files:
        warnings.append("no_benign_full_urls: benign data is domain-only, so a full-URL model "
                        "would learn 'has a path means phishing'. Run "
                        "python -m src.data.commoncrawl_sample")
        logger.warning("%s", warnings[-1])

    # 3) conflict flags
    for (label, _), r in rows.items():
        if label == "phishing":
            rank = tranco_rank.get(r["registered_domain"])
            r["tranco_rank"] = rank if rank is not None else ""
            r["host_conflict"] = bool(rank is not None and r["host"] == r["registered_domain"])
        else:
            r["host_conflict"] = r["host"] in phishing_hosts

    # 4) finalize
    final_rows: list[dict[str, Any]] = []
    for (label, canonical), r in sorted(rows.items()):
        sources = sorted(r["sources"])
        if label == "benign":
            quality = "weak_crawl" if "commoncrawl" in sources else "weak_popularity"
        else:
            quality = "community_verified" if "phishtank" in sources else "feed_automated"
        out = {col: r.get(col, "") for col in COLUMNS}
        out.update(
            sample_id=hashlib.sha256(f"{label}|{canonical}".encode()).hexdigest()[:16],
            label_quality=quality, sources="|".join(sources))
        final_rows.append(out)

    phishing = [r for r in final_rows if r["label"] == "phishing"]
    benign = [r for r in final_rows if r["label"] == "benign"]

    def truncation(values: list[int]) -> dict[str, float]:
        n = len(values)
        return {str(limit): round(sum(v > limit for v in values) / n, 6) if n else 0.0
                for limit in TRUNCATION_LENGTHS}

    full_lengths = [len(r["model_string"]) for r in phishing]
    report: dict[str, Any] = {
        "built_at": datetime.now(timezone.utc).isoformat(),
        "seed": seed,
        "benign_count_requested": benign_count,
        "phishing_snapshots": phishing_snapshots,
        "inputs": inputs,
        "rejected": {
            "count": len(rejected),
            "by_reason": dict(Counter(r["reason"] for r in rejected)),
            "by_source": dict(Counter(r["source"] for r in rejected)),
        },
        "duplicates_removed": {"phishing": dup["phishing"], "benign": dup["benign"]},
        "final": {"phishing": len(phishing), "benign": len(benign)},
        "phishing": {
            "by_source": dict(Counter(r["sources"] for r in phishing)),
            "source_overlap": sum("|" in r["sources"] for r in phishing),
            "unique_groups": len({r["group"] for r in phishing}),
            "top_groups": [[g, c] for g, c in Counter(r["group"] for r in phishing).most_common(10)],
            "scheme": dict(Counter(r["scheme"] for r in phishing)),
            "ip_hosts": sum(r["is_ip"] for r in phishing),
            "punycode_hosts": sum(r["has_punycode"] for r in phishing),
            "with_path_or_query": sum(r["has_path_or_query"] for r in phishing),
            "registered_domain_in_tranco": sum(r["tranco_rank"] != "" for r in phishing),
            "host_conflicts": sum(r["host_conflict"] for r in phishing),
        },
        "benign": {
            "by_source": dict(Counter(r["sources"] for r in benign)),
            "by_input_type": dict(Counter(r["input_type"] for r in benign)),
            "with_path_or_query": sum(r["has_path_or_query"] for r in benign),
            "unique_groups": len({r["group"] for r in benign}),
            "host_conflicts": sum(r["host_conflict"] for r in benign),
        },
        "warnings": warnings,
        "lengths": {
            "phishing_full": _pct(full_lengths),
            "benign_full": _pct([len(r["model_string"]) for r in benign
                                 if r["input_type"] == "full_url"]),
            "phishing_host": _pct([len(r["host"]) for r in phishing]),
            "benign_host": _pct([len(r["host"]) for r in benign]),
        },
        "phishing_full_fraction_longer_than": truncation(full_lengths),
    }

    out_dir.mkdir(parents=True, exist_ok=True)
    _write_csv(out_dir / "samples.csv", COLUMNS, final_rows)
    _write_csv(out_dir / "rejected.csv", ["source", "reason", "value"],
               [{**r, "value": _csv_safe(r["value"])} for r in rejected])
    (out_dir / "build_report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build the unified sample table.")
    parser.add_argument("--raw", default="data/raw")
    parser.add_argument("--out", default="data/processed")
    parser.add_argument("--benign-count", type=int, default=200_000)
    parser.add_argument("--homepage-count", type=int, default=20_000)
    parser.add_argument("--seed", type=int, default=13)
    parser.add_argument("--phishing-snapshots", choices=["all", "latest"], default="all")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    try:
        report = build_dataset(args.raw, args.out, benign_count=args.benign_count,
                               homepage_count=args.homepage_count, seed=args.seed,
                               phishing_snapshots=args.phishing_snapshots)
    except FileNotFoundError as exc:
        logger.error("%s", exc)
        return 1
    logger.info("final: %s | rejected: %s | duplicates removed: %s",
                report["final"], report["rejected"]["count"], report["duplicates_removed"])
    logger.info("report written to %s", Path(args.out) / "build_report.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())