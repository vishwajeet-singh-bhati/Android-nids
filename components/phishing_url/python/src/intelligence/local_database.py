"""Local threat-intelligence database: known phishing URLs from public feeds.

    python -m src.intelligence.local_database update      # ingest new feed snapshots from data/raw
    python -m src.intelligence.local_database stats
    python -m src.intelligence.local_database lookup "https://example.com/login"
    python -m src.intelligence.local_database lookup example.com --domain

Why local
  Lookups must work offline, take well under a millisecond and never send a
  user's URL anywhere. Feeds are downloaded separately (src.data.download_datasets);
  this module only reads those files, so it makes no network requests at all.

Storage
  One SQLite file (Python's built-in sqlite3: no server, one file, atomic
  updates, fast indexed lookups; it also runs on the Raspberry Pi as is).

Matching (levels are explained in src.intelligence.results)
  * exact_url always applies (scheme and #fragment are ignored, the host is
    normalized like everywhere else in the project).
  * hostname / registered_domain apply only to hosts that are neither popular
    (registered domain in the Tranco top-N) nor URL shorteners: one phishing
    page on docs.google.com or bit.ly must not flag every page there. PSL
    private suffixes are honoured, so evil.github.io is a site of its own.
  This is decided when a URL is ingested, so the edge device needs no Tranco list.

Expiry
  An entry expires ttl_days after the newest snapshot that listed it. Lookups
  ignore expired entries; `update` deletes them. If the newest snapshot is
  older than stale_after_hours, results carry stale=True.

A "no_match" result never means "safe" (see src.intelligence.results).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sqlite3
import threading
import time
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable

from src.data.parsers import (RawRecord, find_snapshots, parse_openphish, parse_phishtank,
                              parse_tranco, read_collected_at)
from src.data.split_dataset import load_redirectors
from src.preprocessing.url_normalizer import (InvalidURLError, NormalizedURL, normalize_url,
                                              private_registered_domain)

from .results import (EXACT_URL, HOSTNAME, MATCH, NO_MATCH, PHISHING_THREAT, REGISTERED_DOMAIN,
                      UNAVAILABLE, IntelMatch, IntelResult)

SCHEMA_VERSION = 1
CONFIG_PATH = Path("config/threat_intel.json")
RAW_DIR = Path("data/raw")
PARSERS = {"phishtank": parse_phishtank, "openphish": parse_openphish}
MAX_IDS = 3
_STAMP_RE = re.compile(r"_(\d{8}T\d{6}Z)")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS snapshots (
    source TEXT NOT NULL, name TEXT NOT NULL, sha256 TEXT NOT NULL,
    retrieved_at TEXT NOT NULL, records INTEGER NOT NULL, ingested_at TEXT NOT NULL,
    PRIMARY KEY (source, name, sha256));
CREATE TABLE IF NOT EXISTS indicators (
    url_key TEXT NOT NULL, host TEXT NOT NULL, site TEXT NOT NULL,
    host_match_ok INTEGER NOT NULL, source TEXT NOT NULL, source_id TEXT NOT NULL,
    first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, expires_at TEXT NOT NULL,
    PRIMARY KEY (url_key, source));
CREATE INDEX IF NOT EXISTS idx_indicators_host ON indicators (host);
CREATE INDEX IF NOT EXISTS idx_indicators_site ON indicators (site);
CREATE INDEX IF NOT EXISTS idx_indicators_expires ON indicators (expires_at);
"""

_UPSERT = """
INSERT INTO indicators (url_key, host, site, host_match_ok, source, source_id,
                        first_seen, last_seen, expires_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (url_key, source) DO UPDATE SET
    first_seen = MIN(first_seen, excluded.first_seen),
    last_seen = MAX(last_seen, excluded.last_seen),
    expires_at = MAX(expires_at, excluded.expires_at),
    source_id = CASE WHEN source_id = '' THEN excluded.source_id ELSE source_id END,
    host_match_ok = excluded.host_match_ok
"""

_AGG = ("SELECT source, COUNT(*), MIN(first_seen), MAX(last_seen), MAX(expires_at), "
        "GROUP_CONCAT(NULLIF(source_id, ''), ' ') FROM indicators WHERE {where} GROUP BY source")


# --------------------------------------------------------------------- time
def _now() -> datetime:
    return datetime.now(timezone.utc)


def _utc(dt: datetime) -> str:
    """Fixed-width UTC text, so string order is time order inside SQLite."""
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_time(text: str | None) -> datetime | None:
    text = (text or "").strip()
    if not text:
        return None
    try:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _snapshot_time(path: Path) -> datetime | None:
    """When we downloaded a snapshot: its manifest, else the timestamp in its name."""
    when = _parse_time(read_collected_at(path))
    if when is not None:
        return when
    m = _STAMP_RE.search(path.name)
    return datetime.strptime(m.group(1), "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc) if m else None


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# --------------------------------------------------------------------- config
@dataclass(frozen=True)
class ThreatIntelConfig:
    database: Path = Path("data/intel/threat_intel.sqlite3")
    ttl_days: dict[str, float] = field(default_factory=lambda: {"phishtank": 7.0, "openphish": 7.0})
    popular_top_n: int = 100_000
    stale_after_hours: float = 48.0
    local_redirectors: Path = Path("config/redirectors_local.txt")

    def __post_init__(self) -> None:
        unknown = set(self.ttl_days) - set(PARSERS)
        if not self.ttl_days or unknown:
            raise ValueError(f"ttl_days must name feeds from {sorted(PARSERS)}")
        if any(not (isinstance(v, (int, float)) and v > 0) for v in self.ttl_days.values()):
            raise ValueError("every ttl_days value must be > 0")
        if not isinstance(self.popular_top_n, int) or self.popular_top_n < 0:
            raise ValueError("popular_top_n must be an integer >= 0")
        if not self.stale_after_hours > 0:
            raise ValueError("stale_after_hours must be > 0")

    @classmethod
    def from_file(cls, path: Path | str = CONFIG_PATH) -> "ThreatIntelConfig":
        path = Path(path)
        if not path.is_file():
            return cls()
        data = json.loads(path.read_text(encoding="utf-8"))
        allowed = {"database", "ttl_days", "popular_top_n", "stale_after_hours", "local_redirectors"}
        if not isinstance(data, dict) or set(data) - allowed:
            raise ValueError(f"{path}: unknown keys {sorted(set(data) - allowed)}")
        default = cls()
        return cls(database=Path(data.get("database", default.database)),
                   ttl_days={k: float(v) for k, v in data.get("ttl_days", default.ttl_days).items()},
                   popular_top_n=data.get("popular_top_n", default.popular_top_n),
                   stale_after_hours=float(data.get("stale_after_hours", default.stale_after_hours)),
                   local_redirectors=Path(data.get("local_redirectors", default.local_redirectors)))


# --------------------------------------------------------------------- host policy
def load_popular(raw_root: Path, top_n: int) -> set[str] | None:
    """Registered domains in the newest Tranco snapshot's top-N; None if there is no snapshot."""
    snaps = find_snapshots(raw_root, "tranco")
    if not snaps:
        return None
    return {rec.value.lower().rstrip(".") for rec in parse_tranco(snaps[-1])
            if int(rec.source_id) <= top_n}


def load_redirector_domains(raw_root: Path, local_list: Path | None) -> set[str]:
    paths: list[Path] = list(find_snapshots(raw_root, "url_shorteners")[-1:])
    if local_list is not None and Path(local_list).is_file():
        paths.append(Path(local_list))
    return load_redirectors(paths)


class HostPolicy:
    """May a listed host be matched beyond its exact URLs?"""

    def __init__(self, popular: set[str] | None, redirectors: set[str]):
        self.popular = popular          # None: no popularity list -> exact URLs only
        self.redirectors = redirectors

    def host_match_ok(self, n: NormalizedURL, site: str) -> bool:
        if self.popular is None:
            return False
        if {n.host, n.registered_domain, site} & self.redirectors:
            return False
        return site not in self.popular


# --------------------------------------------------------------------- shared queries
def _meta(conn: sqlite3.Connection, key: str) -> str | None:
    row = conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
    return row[0] if row else None


def _stats(conn: sqlite3.Connection, now: datetime) -> dict:
    when = _utc(now)
    by_source = dict(conn.execute(
        "SELECT source, COUNT(*) FROM indicators WHERE expires_at > ? GROUP BY source", (when,)))
    total = sum(by_source.values())
    matchable = conn.execute("SELECT COUNT(*) FROM indicators WHERE expires_at > ? AND "
                             "host_match_ok = 1", (when,)).fetchone()[0]
    hosts = conn.execute("SELECT COUNT(DISTINCT host) FROM indicators WHERE expires_at > ?",
                         (when,)).fetchone()[0]
    return {"active_indicators": total, "active_by_source": by_source, "active_hosts": hosts,
            "share_host_matchable": matchable / total if total else None,
            "snapshots_ingested": conn.execute("SELECT COUNT(*) FROM snapshots").fetchone()[0],
            "feeds_updated_at": _meta(conn, "feeds_updated_at")}


# --------------------------------------------------------------------- read side
class _SchemaMismatch(Exception):
    pass


class ThreatIntelDB:
    """Read-only lookups from an in-memory copy of the database file.

    Reading the file directly costs a file lock per query (13 ms per lookup
    measured on Windows); the in-memory copy answers in ~0.2 ms. The copy is
    made with SQLite's backup API (always a consistent snapshot) and reloaded
    when the file changes (checked at most every `refresh_seconds`). If a new
    file is damaged, the last good copy stays in use. Thread-safe; lookup()
    never raises for database problems.
    """

    def __init__(self, path: Path | str, *, stale_after_hours: float = 48.0,
                 refresh_seconds: float = 60.0):
        self.path = Path(path)
        self.stale_after = timedelta(hours=stale_after_hours)
        self.refresh_seconds = refresh_seconds
        self.last_error = ""                  # why the newest reload failed, "" if it did not
        self._conn: sqlite3.Connection | None = None
        self._signature: tuple[int, int] | None = None
        self._checked_at = float("-inf")
        self._lock = threading.Lock()

    @classmethod
    def from_config(cls, config: ThreatIntelConfig, **kwargs) -> "ThreatIntelDB":
        return cls(config.database, stale_after_hours=config.stale_after_hours, **kwargs)

    def _load(self) -> sqlite3.Connection:
        src = sqlite3.connect(self.path.resolve().as_uri() + "?mode=ro", uri=True, timeout=5.0)
        try:
            if _meta(src, "schema_version") != str(SCHEMA_VERSION):
                raise _SchemaMismatch
            mem = sqlite3.connect(":memory:", check_same_thread=False)
            src.backup(mem)
            return mem
        finally:
            src.close()

    def _connect(self) -> sqlite3.Connection:
        tick = time.monotonic()
        if self._conn is not None and tick - self._checked_at < self.refresh_seconds:
            return self._conn
        self._checked_at = tick
        try:
            st = self.path.stat()
        except FileNotFoundError:
            if self._conn is not None:        # file removed: keep serving the last good copy
                self.last_error = "database_missing"
                return self._conn
            raise
        signature = (st.st_mtime_ns, st.st_size)
        if self._conn is not None and signature == self._signature:
            return self._conn
        try:
            fresh = self._load()
        except (sqlite3.Error, _SchemaMismatch) as exc:
            if self._conn is None:
                raise
            self.last_error = type(exc).__name__
            return self._conn
        if self._conn is not None:
            self._conn.close()
        self._conn, self._signature, self.last_error = fresh, signature, ""
        return fresh

    def reload(self) -> None:
        """Check the file now instead of waiting for refresh_seconds."""
        with self._lock:
            self._checked_at = float("-inf")
            self._connect()

    def close(self) -> None:
        with self._lock:
            if self._conn is not None:
                self._conn.close()
            self._conn, self._signature, self._checked_at = None, None, float("-inf")

    def lookup(self, value: str | NormalizedURL, input_type: str = "full_url",
               now: datetime | None = None) -> IntelResult:
        """Raises InvalidURLError for input that cannot be normalized; never for the database."""
        n = value if isinstance(value, NormalizedURL) else normalize_url(value, input_type)
        now = now or _now()
        try:
            with self._lock:
                conn = self._connect()
                matches = _find(conn, n, _utc(now))
                updated = _meta(conn, "feeds_updated_at")
        except FileNotFoundError:
            return IntelResult(UNAVAILABLE, reason="database_missing")
        except _SchemaMismatch:
            return IntelResult(UNAVAILABLE, reason="schema_mismatch")
        except sqlite3.Error as exc:            # damaged file, locked for too long, ...
            self.close()
            return IntelResult(UNAVAILABLE, reason=f"database_error:{type(exc).__name__}")
        updated_at = _parse_time(updated)
        stale = updated_at is None or now - updated_at > self.stale_after
        return IntelResult(MATCH if matches else NO_MATCH, matches, updated, stale)

    def stats(self, now: datetime | None = None) -> dict:
        with self._lock:
            return _stats(self._connect(), now or _now())


def _find(conn: sqlite3.Connection, n: NormalizedURL, when: str) -> tuple[IntelMatch, ...]:
    url_key = n.model_string if n.input_type == "full_url" else ""
    site = "" if n.is_ip else private_registered_domain(n.host)
    queries = []
    if url_key:
        queries.append((EXACT_URL, "url_key = ? AND expires_at > ?", (url_key, when)))
    queries.append((HOSTNAME, "host = ? AND host_match_ok = 1 AND url_key != ? AND expires_at > ?",
                    (n.host, url_key, when)))
    if site:
        queries.append((REGISTERED_DOMAIN,
                        "site = ? AND host != ? AND host_match_ok = 1 AND expires_at > ?",
                        (site, n.host, when)))
    matches = []
    for level, where, params in queries:
        for source, count, first, last, expires, ids in conn.execute(_AGG.format(where=where), params):
            matches.append(IntelMatch(level, source, int(count), first, last, expires,
                                      tuple((ids or "").split()[:MAX_IDS]),
                                      threat_types=(PHISHING_THREAT,)))   # both feeds are phishing-only
    return tuple(matches)


# --------------------------------------------------------------------- write side
class ThreatIntelWriter:
    """Creates / updates the database inside one transaction (all or nothing)."""

    def __init__(self, path: Path | str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path, timeout=30.0)
        self.conn.executescript(_SCHEMA)
        version = _meta(self.conn, "schema_version")
        if version is None:
            self.conn.execute("INSERT INTO meta VALUES ('schema_version', ?)", (str(SCHEMA_VERSION),))
        elif version != str(SCHEMA_VERSION):
            self.conn.close()
            raise RuntimeError(f"{self.path} has schema {version}; delete it and run update again")

    def __enter__(self) -> "ThreatIntelWriter":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if exc_type is None:
            self.conn.commit()
        else:
            self.conn.rollback()
        self.conn.close()

    def has_snapshot(self, source: str, name: str, sha256: str) -> bool:
        return self.conn.execute("SELECT 1 FROM snapshots WHERE source = ? AND name = ? AND sha256 = ?",
                                 (source, name, sha256)).fetchone() is not None

    def ingest(self, source: str, records: Iterable[RawRecord], retrieved: datetime,
               ttl: timedelta, policy: HostPolicy, counts: Counter) -> int:
        rows, last, expires = [], _utc(retrieved), _utc(retrieved + ttl)
        for rec in records:
            try:
                n = normalize_url(rec.value, "full_url")
            except InvalidURLError as exc:
                counts[f"invalid_url:{exc.reason}"] += 1
                continue
            site = "" if n.is_ip else private_registered_domain(n.host)
            reported = _parse_time(rec.first_seen)
            first = _utc(min(reported, retrieved) if reported else retrieved)
            rows.append((n.model_string, n.host, site, int(policy.host_match_ok(n, site)), source,
                         rec.source_id, first, last, expires))
        self.conn.executemany(_UPSERT, rows)
        counts["records"] += len(rows)
        return len(rows)

    def record_snapshot(self, source: str, name: str, sha256: str, retrieved: datetime,
                        records: int, now: datetime) -> None:
        self.conn.execute("INSERT INTO snapshots VALUES (?, ?, ?, ?, ?, ?)",
                          (source, name, sha256, _utc(retrieved), records, _utc(now)))

    def prune(self, now: datetime) -> int:
        return self.conn.execute("DELETE FROM indicators WHERE expires_at <= ?", (_utc(now),)).rowcount

    def finish(self, now: datetime) -> None:
        newest = self.conn.execute("SELECT MAX(retrieved_at) FROM snapshots").fetchone()[0]
        for key, value in (("feeds_updated_at", newest), ("last_update_at", _utc(now))):
            if value is not None:
                self.conn.execute("INSERT OR REPLACE INTO meta VALUES (?, ?)", (key, value))

    def stats(self, now: datetime) -> dict:
        return _stats(self.conn, now)


def update_database(config: ThreatIntelConfig, raw_root: Path | str = RAW_DIR, *,
                    now: datetime | None = None) -> dict:
    """Ingest every feed snapshot not ingested yet, then drop expired entries."""
    raw_root, now = Path(raw_root), now or _now()
    popular = load_popular(raw_root, config.popular_top_n)
    policy = HostPolicy(popular, load_redirector_domains(raw_root, config.local_redirectors))
    warnings = []
    if popular is None:
        warnings.append("no Tranco snapshot: host matching disabled, exact URLs only")
    if not policy.redirectors:
        warnings.append("no URL-shortener list loaded")
    sources = {}
    with ThreatIntelWriter(config.database) as db:
        for source, ttl_days in config.ttl_days.items():
            snaps = find_snapshots(raw_root, source)
            if not snaps:
                warnings.append(f"no {source} snapshots under {raw_root}")
            counts: Counter = Counter()
            for snap in snaps:
                sha = _sha256(snap)
                if db.has_snapshot(source, snap.name, sha):
                    counts["snapshots_already_ingested"] += 1
                    continue
                retrieved = _snapshot_time(snap)
                if retrieved is None:
                    warnings.append(f"{snap.name}: unknown download time, skipped")
                    continue
                skipped: Counter = Counter()
                added = db.ingest(source, PARSERS[source](snap, _utc(retrieved), skipped),
                                  retrieved, timedelta(days=ttl_days), policy, counts)
                counts.update({f"skipped:{k}": v for k, v in skipped.items()})
                db.record_snapshot(source, snap.name, sha, retrieved, added, now)
                counts["snapshots_ingested"] += 1
            sources[source] = dict(counts)
        expired = db.prune(now)
        db.finish(now)
        totals = db.stats(now)
    return {"database": str(config.database), "sources": sources, "expired_removed": expired,
            "popular_domains_loaded": None if popular is None else len(popular),
            "redirector_domains_loaded": len(policy.redirectors), "warnings": warnings, **totals}


# --------------------------------------------------------------------- CLI
def _print_stats(s: dict) -> None:
    share = s["share_host_matchable"]
    print(f"  active entries: {s['active_indicators']} ({s['active_by_source']}) on "
          f"{s['active_hosts']} hosts; host-level matching allowed for "
          f"{'-' if share is None else f'{100 * share:.1f}%'} of them")
    print(f"  feeds updated at: {s['feeds_updated_at']}, snapshots ingested so far: "
          f"{s['snapshots_ingested']}")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--config", type=Path, default=CONFIG_PATH)
    sub = ap.add_subparsers(dest="command", required=True)
    up = sub.add_parser("update", help="ingest new feed snapshots")
    up.add_argument("--raw", type=Path, default=RAW_DIR)
    sub.add_parser("stats", help="show what the database holds")
    lk = sub.add_parser("lookup", help="look one URL or hostname up")
    lk.add_argument("value")
    lk.add_argument("--domain", action="store_true", help="value is a bare hostname")
    args = ap.parse_args(argv)
    config = ThreatIntelConfig.from_file(args.config)

    if args.command == "update":
        r = update_database(config, args.raw)
        print(f"updated {r['database']}")
        for source, counts in r["sources"].items():
            print(f"  {source}: {counts}")
        print(f"  expired entries removed: {r['expired_removed']}; popular domains: "
              f"{r['popular_domains_loaded']}; shortener domains: {r['redirector_domains_loaded']}")
        _print_stats(r)
        for w in r["warnings"]:
            print(f"  WARNING: {w}")
        return 0
    db = ThreatIntelDB.from_config(config)
    if args.command == "stats":
        if not config.database.is_file():
            print(f"{config.database} does not exist: run `update` first")
            return 1
        _print_stats(db.stats())
        return 0
    try:
        result = db.lookup(args.value, "domain" if args.domain else "full_url")
    except InvalidURLError as exc:
        print(f"not a valid {'hostname' if args.domain else 'URL'} ({exc.reason})")
        return 2
    print(json.dumps(result.to_dict(), indent=2))
    if result.status == NO_MATCH:
        print("no_match only means no feed lists it; it is NOT a sign that it is safe.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
