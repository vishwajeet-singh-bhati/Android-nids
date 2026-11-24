"""Sample benign FULL URLs (with paths) from the Common Crawl URL index.

Why: Tranco only lists domain names. Training a full-URL model on phishing URLs
with paths versus benign domains without paths teaches the shortcut "has a path
means phishing". This module collects real page URLs from popular sites.

How (no web pages are ever visited, only Common Crawl's own index files):
  1. Stream `cluster.idx`, the master index. Each line describes one compressed
     block of about 3000 index entries and the SURT key of its first entry.
  2. Keep blocks whose first host belongs to a top-N Tranco domain, choose at
     most `max_blocks_per_domain` per domain, then a seeded random subset.
  3. Fetch each chosen block with an HTTP Range request, decompress it, and keep
     entries that are HTTP 200 HTML pages on a top-N Tranco domain, capped per domain.

Domains are compared with PSL *private* suffixes enabled, so a user site such as
`someone.web.app` or `x.blogspot.com` is NOT treated as the popular platform
`web.app` / `blogspot.com`. Those platforms host a lot of phishing.

Labels produced here are weak ("page on a popular domain"), not verified benign.
"""
from __future__ import annotations

import argparse
import csv
import gzip
import hashlib
import io
import json
import logging
import os
import random
import re
import time
import zlib
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterable, Mapping
from urllib.parse import urlsplit

import httpx

from ..preprocessing.url_normalizer import private_registered_domain
from .download_datasets import USER_AGENT_FALLBACK
from .parsers import find_snapshots, parse_tranco

logger = logging.getLogger(__name__)
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)

DATA_BASE = "https://data.commoncrawl.org/"
COLLINFO_URL = "https://index.commoncrawl.org/collinfo.json"
LICENSE_NOTE = ("Common Crawl URL index; see https://commoncrawl.org/terms-of-use. "
                "Only URLs and metadata are used, no page content.")
OUTPUT_COLUMNS = ["url", "timestamp", "registered_domain", "tranco_rank"]

MAX_CLUSTER_BYTES = 400 * 1024 * 1024
MAX_BLOCK_BYTES = 4 * 1024 * 1024
MAX_BLOCK_DECOMPRESSED = 64 * 1024 * 1024
MAX_URL_LENGTH = 2048

_CRAWL_RE = re.compile(r"CC-MAIN-\d{4}-\d{2}")
_INDEX_FILE_RE = re.compile(r"cdx-\d{5}\.gz")


class SampleError(RuntimeError):
    """Sampling failed. Messages never contain secrets (there are none here)."""


class _Retryable(Exception):
    pass


@dataclass(frozen=True, slots=True)
class Block:
    first_host: str
    domain: str        # private-aware registered domain of first_host
    filename: str      # e.g. "cdx-00042.gz"
    offset: int
    length: int


# --------------------------------------------------------------------------- pure helpers
def surt_host(urlkey: str) -> str:
    """'com,example,www)/path' -> 'www.example.com' (port dropped)."""
    head = urlkey.split(")", 1)[0].split(":", 1)[0]
    return ".".join(reversed(head.split(","))).strip(".")


def parse_cluster_line(line: str) -> Block | None:
    """'<surt> <timestamp>\\t<file>\\t<offset>\\t<length>\\t<block-id>' -> Block."""
    parts = line.rstrip("\r\n").split("\t")
    if len(parts) < 4:
        return None
    key = parts[0].split(" ", 1)[0]
    filename, offset, length = parts[1], parts[2], parts[3]
    if not (_INDEX_FILE_RE.fullmatch(filename) and offset.isdigit() and length.isdigit()):
        return None
    host = surt_host(key)
    return Block(host, private_registered_domain(host), filename, int(offset), int(length))


def select_blocks(lines: Iterable[str], allowed: Mapping[str, int], *, num_blocks: int,
                  max_blocks_per_domain: int, rng: random.Random) -> list[Block]:
    """Pick up to num_blocks blocks starting in an allowed domain, spread over domains."""
    by_domain: dict[str, list[Block]] = {}
    for line in lines:
        block = parse_cluster_line(line)
        if block is not None and block.domain in allowed:
            by_domain.setdefault(block.domain, []).append(block)
    domains = sorted(by_domain)
    rng.shuffle(domains)
    chosen: list[Block] = []
    for domain in domains:
        if len(chosen) >= num_blocks:
            break
        blocks = by_domain[domain]
        chosen.extend(rng.sample(blocks, min(max_blocks_per_domain, len(blocks))))
    chosen = chosen[:num_blocks]
    return sorted(chosen, key=lambda b: (b.filename, b.offset))


def cc_timestamp_to_iso(ts: str) -> str:
    """'20261005124020' -> '2026-10-05T12:40:20+00:00'; '' when malformed."""
    try:
        return datetime.strptime(ts, "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc).isoformat()
    except ValueError:
        return ""


def filter_block(text: str, allowed: Mapping[str, int], per_domain: dict[str, int],
                 seen: set[str], max_urls_per_domain: int) -> list[dict[str, str]]:
    """Keep 200/HTML entries on allowed domains. Updates per_domain and seen in place."""
    out: list[dict[str, str]] = []
    for line in text.splitlines():
        parts = line.split(" ", 2)
        if len(parts) != 3:
            continue
        try:
            entry = json.loads(parts[2])
        except ValueError:
            continue
        if not isinstance(entry, dict):
            continue
        url = entry.get("url")
        mime = entry.get("mime-detected") or entry.get("mime") or ""
        if (not isinstance(url, str) or entry.get("status") != "200"
                or "html" not in mime or len(url) > MAX_URL_LENGTH or url in seen):
            continue
        try:
            parts_url = urlsplit(url)
            host = parts_url.hostname or ""
        except ValueError:
            continue
        if parts_url.scheme not in ("http", "https") or parts_url.path.lower() == "/robots.txt":
            continue
        domain = private_registered_domain(host)
        if domain not in allowed or per_domain.get(domain, 0) >= max_urls_per_domain:
            continue
        per_domain[domain] = per_domain.get(domain, 0) + 1
        seen.add(url)
        out.append({"url": url, "timestamp": cc_timestamp_to_iso(parts[1]),
                    "registered_domain": domain, "tranco_rank": str(allowed[domain])})
    return out


def decompress_block(data: bytes) -> str:
    """Decompress one gzip member with a hard output limit (zip-bomb guard)."""
    d = zlib.decompressobj(16 + zlib.MAX_WBITS)
    try:
        raw = d.decompress(data, MAX_BLOCK_DECOMPRESSED)
    except zlib.error as exc:
        raise SampleError("index block is not valid gzip") from exc
    if d.unconsumed_tail:
        raise SampleError("index block decompresses beyond the size limit")
    return raw.decode("utf-8", "replace")


# --------------------------------------------------------------------------- network
def _with_retries(fn: Callable[[], bytes], max_attempts: int, backoff: float,
                  sleep: Callable[[float], None], what: str) -> bytes:
    for attempt in range(1, max_attempts + 1):
        try:
            return fn()
        except _Retryable as exc:
            if attempt == max_attempts:
                raise SampleError(f"{what}: giving up after {attempt} attempts ({exc})") from None
            sleep(backoff * 2 ** (attempt - 1))
    raise AssertionError("unreachable")


def fetch_block(client: httpx.Client, crawl_id: str, block: Block, *, max_attempts: int = 3,
                backoff: float = 2.0, sleep: Callable[[float], None] = time.sleep) -> bytes:
    if block.length <= 0 or block.length > MAX_BLOCK_BYTES:
        raise SampleError("index block has an implausible length")
    url = f"{DATA_BASE}cc-index/collections/{crawl_id}/indexes/{block.filename}"
    headers = {"User-Agent": USER_AGENT_FALLBACK,
               "Range": f"bytes={block.offset}-{block.offset + block.length - 1}"}

    def once() -> bytes:
        try:
            response = client.get(url, headers=headers)
        except httpx.TransportError as exc:
            raise _Retryable(f"network error ({type(exc).__name__})") from None
        if response.status_code == 429 or response.status_code >= 500:
            raise _Retryable(f"HTTP {response.status_code}")
        if response.status_code != 206:
            raise SampleError(f"range request returned HTTP {response.status_code}")
        if len(response.content) != block.length:
            raise _Retryable("short read")
        return response.content

    return _with_retries(once, max_attempts, backoff, sleep, f"block {block.filename}@{block.offset}")


def latest_crawl_id(client: httpx.Client) -> str:
    response = client.get(COLLINFO_URL, headers={"User-Agent": USER_AGENT_FALLBACK})
    if response.status_code != 200:
        raise SampleError(f"collinfo.json returned HTTP {response.status_code}")
    try:
        crawl_id = response.json()[0]["id"]
    except (ValueError, LookupError, TypeError) as exc:
        raise SampleError("collinfo.json has an unexpected format") from exc
    if not isinstance(crawl_id, str) or not _CRAWL_RE.fullmatch(crawl_id):
        raise SampleError("collinfo.json returned an unexpected crawl id")
    return crawl_id


def iter_cluster_lines(client: httpx.Client, crawl_id: str) -> Iterable[str]:
    url = f"{DATA_BASE}cc-index/collections/{crawl_id}/indexes/cluster.idx"
    size = 0
    with client.stream("GET", url, headers={"User-Agent": USER_AGENT_FALLBACK}) as response:
        if response.status_code != 200:
            raise SampleError(f"cluster.idx returned HTTP {response.status_code}")
        for line in response.iter_lines():
            size += len(line) + 1
            if size > MAX_CLUSTER_BYTES:
                raise SampleError("cluster.idx exceeds the size limit")
            yield line


# --------------------------------------------------------------------------- driver
def load_tranco_ranks(path: Path | str, top_n: int) -> dict[str, int]:
    ranks: dict[str, int] = {}
    for rec in parse_tranco(path):
        rank = int(rec.source_id)
        if rank > top_n:
            continue
        domain = rec.value.strip().lower().rstrip(".")
        ranks.setdefault(domain, rank)
    return ranks


def sample_commoncrawl(
    out_root: Path | str,
    tranco_path: Path | str,
    client: httpx.Client,
    *,
    crawl_id: str | None = None,
    top_n: int = 200_000,
    num_blocks: int = 4000,
    max_blocks_per_domain: int = 1,
    max_urls_per_domain: int = 20,
    workers: int = 4,
    seed: int = 13,
    max_failed_fraction: float = 0.2,
    now: datetime | None = None,
    sleep: Callable[[float], None] = time.sleep,
) -> dict[str, object]:
    """Write <out_root>/benign/commoncrawl/commoncrawl_<stamp>.csv.gz plus a manifest."""
    if top_n < 1 or num_blocks < 1 or max_blocks_per_domain < 1 or max_urls_per_domain < 1:
        raise ValueError("top_n, num_blocks and the per-domain caps must be >= 1")
    if not 1 <= workers <= 16:
        raise ValueError("workers must be between 1 and 16")
    now = now or datetime.now(timezone.utc)
    crawl_id = crawl_id or latest_crawl_id(client)
    if not _CRAWL_RE.fullmatch(crawl_id):
        raise ValueError("crawl_id must look like CC-MAIN-YYYY-WW")

    target_dir = Path(out_root) / "benign" / "commoncrawl"
    target_dir.mkdir(parents=True, exist_ok=True)
    final = target_dir / f"commoncrawl_{now.strftime('%Y%m%dT%H%M%SZ')}.csv.gz"
    if final.exists():
        raise FileExistsError(f"{final.name} already exists; refusing to overwrite")

    allowed = load_tranco_ranks(tranco_path, top_n)
    if not allowed:
        raise SampleError("Tranco snapshot produced no domains")
    logger.info("tranco domains allowed: %d; streaming cluster.idx for %s", len(allowed), crawl_id)
    blocks = select_blocks(iter_cluster_lines(client, crawl_id), allowed, num_blocks=num_blocks,
                           max_blocks_per_domain=max_blocks_per_domain, rng=random.Random(seed))
    logger.info("selected %d index blocks; fetching with %d workers", len(blocks), workers)

    def job(block: Block) -> bytes | None:
        try:
            return fetch_block(client, crawl_id, block, sleep=sleep)
        except SampleError as exc:
            logger.warning("%s", exc)
            return None

    rows: list[dict[str, str]] = []
    per_domain: dict[str, int] = {}
    seen: set[str] = set()
    failed = 0
    with ThreadPoolExecutor(max_workers=workers) as pool:
        # map() yields results in input order, so filtering (and the per-domain cap)
        # is deterministic for a given seed regardless of network timing.
        for i, data in enumerate(pool.map(job, blocks), 1):
            if data is None:
                failed += 1
            else:
                try:
                    rows.extend(filter_block(decompress_block(data), allowed, per_domain,
                                             seen, max_urls_per_domain))
                except SampleError as exc:
                    logger.warning("%s", exc)
                    failed += 1
            if i % 250 == 0:
                logger.info("blocks %d/%d, urls %d, failed %d", i, len(blocks), len(rows), failed)

    if blocks and failed / len(blocks) > max_failed_fraction:
        raise SampleError(f"{failed} of {len(blocks)} blocks failed; not writing a partial sample")

    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=OUTPUT_COLUMNS)
    writer.writeheader()
    writer.writerows(rows)
    payload = gzip.compress(buffer.getvalue().encode("utf-8"), mtime=0)
    part = final.with_name(final.name + ".part")
    part.write_bytes(payload)
    os.replace(part, final)

    manifest: dict[str, object] = {
        "source": "commoncrawl",
        "category": "benign",
        "url": f"{DATA_BASE}cc-index/collections/{crawl_id}/indexes/",
        "file": final.name,
        "retrieved_at": now.isoformat(),
        "bytes": len(payload),
        "sha256": hashlib.sha256(payload).hexdigest(),
        "license_note": LICENSE_NOTE,
        "extra": {
            "crawl_id": crawl_id, "tranco_file": Path(tranco_path).name, "top_n": top_n,
            "seed": seed, "blocks_selected": len(blocks), "blocks_failed": failed,
            "max_blocks_per_domain": max_blocks_per_domain,
            "max_urls_per_domain": max_urls_per_domain,
            "urls": len(rows), "domains": len(per_domain),
        },
    }
    final.with_name(final.name + ".manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Sample benign full URLs from Common Crawl.")
    parser.add_argument("--raw", default="data/raw")
    parser.add_argument("--crawl", default=None, help="e.g. CC-MAIN-2026-43 (default: latest)")
    parser.add_argument("--top-n", type=int, default=200_000)
    parser.add_argument("--blocks", type=int, default=4000)
    parser.add_argument("--blocks-per-domain", type=int, default=1)
    parser.add_argument("--urls-per-domain", type=int, default=20)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--seed", type=int, default=13)
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    tranco = find_snapshots(args.raw, "tranco")
    if not tranco:
        logger.error("no Tranco snapshot; run python -m src.data.download_datasets --sources tranco")
        return 1
    try:
        with httpx.Client(timeout=httpx.Timeout(120.0, connect=15.0)) as client:
            manifest = sample_commoncrawl(
                args.raw, tranco[-1], client, crawl_id=args.crawl, top_n=args.top_n,
                num_blocks=args.blocks, max_blocks_per_domain=args.blocks_per_domain,
                max_urls_per_domain=args.urls_per_domain, workers=args.workers, seed=args.seed)
    except (SampleError, FileExistsError, ValueError, httpx.HTTPError) as exc:
        logger.error("%s", exc)
        return 1
    extra = manifest["extra"]
    logger.info("wrote %s: %s urls from %s domains (%s blocks failed)", manifest["file"],
                extra["urls"], extra["domains"], extra["blocks_failed"])  # type: ignore[index]
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
