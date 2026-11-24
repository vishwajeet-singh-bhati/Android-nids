import csv
import gzip
import io
import json
import sqlite3
import threading
import zipfile
from datetime import datetime, timedelta, timezone

import pytest

from src.intelligence import local_database
from src.intelligence.local_database import ThreatIntelConfig, ThreatIntelDB, update_database
from src.intelligence.results import (EXACT_URL, HOSTNAME, MATCH, NO_MATCH, REGISTERED_DOMAIN,
                                      UNAVAILABLE)
from src.preprocessing.url_normalizer import InvalidURLError, normalize_url

T0 = datetime(2026, 11, 10, 12, 0, tzinfo=timezone.utc)
LISTED = "http://login-verify.evil-site.xyz/account/update.php?id=1"
LONG = "https://long-path-site.com/" + "a" * 5000
IDN = "https://pаypal.com/signin"            # Cyrillic "а": a look-alike of paypal.com


# ---------------------------------------------------------------- fixture feeds
def _stamp(when):
    return when.strftime("%Y%m%dT%H%M%SZ")


def _manifest(path, when):
    path.with_name(path.name + ".manifest.json").write_text(
        json.dumps({"retrieved_at": when.isoformat()}), encoding="utf-8")


def write_phishtank(raw, when, rows):
    folder = raw / "phishing" / "phishtank"
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / f"phishtank_{_stamp(when)}.csv.gz"
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["phish_id", "url", "phish_detail_url", "submission_time", "verified",
                "verification_time", "online", "target"])
    for pid, url, verified in rows:
        w.writerow([pid, url, "", (when - timedelta(days=1)).isoformat(), verified, "", "yes", "Other"])
    with gzip.open(path, "wt", encoding="utf-8", newline="") as fh:
        fh.write(buf.getvalue())
    _manifest(path, when)


def write_openphish(raw, when, urls):
    folder = raw / "phishing" / "openphish"
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / f"openphish_{_stamp(when)}.txt"
    path.write_text("\n".join(urls) + "\n", encoding="utf-8")
    _manifest(path, when)


def write_reference(raw, tranco, shorteners):
    folder = raw / "benign" / "tranco"
    folder.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(folder / "tranco_20261101T000000Z.csv.zip", "w") as zf:
        zf.writestr("top-1m.csv", "".join(f"{i},{d}\n" for i, d in enumerate(tranco, 1)))
    folder = raw / "reference" / "url_shorteners"
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "url_shorteners_20261101T000000Z.txt").write_text("\n".join(shorteners) + "\n",
                                                               encoding="utf-8")


def build_raw(raw, t0, with_tranco=True):
    write_phishtank(raw, t0, [
        ("1", LISTED, "yes"),
        ("10", LISTED, "yes"),                                  # duplicate in the same feed
        ("2", "https://docs.google.com/forms/d/e/ABC123/viewform", "yes"),
        ("3", "https://evil.github.io/paypal/", "yes"),
        ("4", "https://bit.ly/3abcXYZ", "yes"),
        ("5", "https://unverified-site.com/x", "no"),
        ("6", "http://203.0.113.7/bank/login", "yes"),
        ("7", IDN, "yes"),
        ("8", "not a url at all", "yes"),
        ("9", LONG, "yes"),
        ("11", "https://qr-short.link/abc", "yes"),
    ])
    write_openphish(raw, t0 + timedelta(hours=1),
                    ["https://login-verify.evil-site.xyz/account/update.php?id=1",
                     "https://other.evil-site.xyz/start"])
    if with_tranco:
        write_reference(raw, ["google.com", "github.io", "bit.ly"], ["bit.ly", "qr-short.link"])


def config_for(tmp_path):
    return ThreatIntelConfig(database=tmp_path / "intel" / "intel.sqlite3",
                             local_redirectors=tmp_path / "none.txt")


def _make(tmp_path):
    raw = tmp_path / "raw"
    build_raw(raw, T0)
    cfg = config_for(tmp_path)
    report = update_database(cfg, raw, now=T0 + timedelta(hours=2))
    return ThreatIntelDB.from_config(cfg), report, cfg, raw


@pytest.fixture(scope="module")
def intel(tmp_path_factory):
    """Shared by tests that only read (building a database is slow on Windows)."""
    made = _make(tmp_path_factory.mktemp("intel"))
    yield made
    made[0].close()


@pytest.fixture
def fresh_intel(tmp_path):
    """For tests that change the database."""
    made = _make(tmp_path)
    yield made
    made[0].close()


def at(hours=3):
    return T0 + timedelta(hours=hours)


# ---------------------------------------------------------------- update
def test_update_report_and_is_idempotent(fresh_intel):
    db, report, cfg, raw = fresh_intel
    pt = report["sources"]["phishtank"]
    assert pt["records"] == 9 and pt["snapshots_ingested"] == 1   # 11 rows - unverified - invalid
    assert pt["skipped:not_verified"] == 1 and sum(v for k, v in pt.items() if k.startswith("invalid_url")) == 1
    assert report["sources"]["openphish"]["records"] == 2
    assert report["warnings"] == [] and report["popular_domains_loaded"] == 3
    assert report["active_by_source"] == {"phishtank": 8, "openphish": 2}   # duplicate stored once
    again = update_database(cfg, raw, now=at())
    assert again["sources"]["phishtank"] == {"snapshots_already_ingested": 1}
    assert again["active_indicators"] == report["active_indicators"]
    assert "evil-site" not in json.dumps(report) and "github" not in json.dumps(report)


# ---------------------------------------------------------------- matching
def test_exact_match_ignores_scheme_case_port_and_fragment(intel):
    db = intel[0]
    r = db.lookup("HTTPS://Login-Verify.EVIL-site.xyz:443/account/update.php?id=1#frag", now=at())
    assert r.status == MATCH and r.strongest_level == EXACT_URL
    exact = {m.source: m for m in r.matches if m.level == EXACT_URL}
    assert set(exact) == {"phishtank", "openphish"}             # source attribution
    assert exact["phishtank"].count == 1 and exact["phishtank"].source_ids == ("1",)
    assert r.stale is False and r.feeds_updated_at == "2026-11-10T13:00:00Z"


def test_hostname_and_registered_domain_levels(intel):
    db = intel[0]
    r = db.lookup("https://login-verify.evil-site.xyz/other/page", now=at())
    assert r.strongest_level == HOSTNAME
    r = db.lookup("https://brand-new.evil-site.xyz/", now=at())
    assert r.strongest_level == REGISTERED_DOMAIN
    assert sum(m.count for m in r.matches) == 3                 # 2 listed hosts, 3 rows in all
    assert db.lookup("login-verify.evil-site.xyz", "domain", now=at()).strongest_level == HOSTNAME
    assert db.lookup("evil-site.xyz", "domain", now=at()).strongest_level == REGISTERED_DOMAIN


@pytest.mark.parametrize("listed,other", [
    ("https://docs.google.com/forms/d/e/ABC123/viewform", "https://docs.google.com/forms/d/e/XYZ/viewform"),
    ("https://docs.google.com/forms/d/e/ABC123/viewform", "https://mail.google.com/"),
    ("https://bit.ly/3abcXYZ", "https://bit.ly/zzz"),              # popular and a shortener
    ("https://qr-short.link/abc", "https://qr-short.link/def"),    # shortener only
])
def test_popular_and_shortener_hosts_match_exact_urls_only(intel, listed, other):
    db = intel[0]
    assert db.lookup(listed, now=at()).strongest_level == EXACT_URL
    assert db.lookup(other, now=at()).status == NO_MATCH


def test_private_suffix_tenants_are_separate_sites(intel):
    db = intel[0]
    assert db.lookup("https://evil.github.io/other", now=at()).strongest_level == HOSTNAME
    assert db.lookup("https://nice.github.io/", now=at()).status == NO_MATCH


def test_ip_hosts_unicode_domains_and_long_urls(intel):
    db = intel[0]
    assert db.lookup("http://203.0.113.7/other", now=at()).strongest_level == HOSTNAME
    puny = normalize_url(IDN).canonical
    assert puny.startswith("https://xn--")
    assert db.lookup(IDN, now=at()).strongest_level == EXACT_URL
    assert db.lookup(puny, now=at()).strongest_level == EXACT_URL
    assert db.lookup(LONG, now=at()).strongest_level == EXACT_URL


def test_no_match_is_not_a_safe_verdict(intel):
    r = intel[0].lookup("https://totally-unknown-site.com/", now=at())
    assert r.status == NO_MATCH and r.matches == () and r.strongest_level is None
    assert not hasattr(r, "is_safe") and r.to_dict()["status"] == "no_match"


def test_invalid_input_raises(intel):
    db = intel[0]
    for value, kind in [("", "full_url"), ("javascript:alert(1)", "full_url"), ("a/b", "domain")]:
        with pytest.raises(InvalidURLError):
            db.lookup(value, kind, now=at())


# ---------------------------------------------------------------- expiry / staleness
def test_expiry_staleness_and_pruning(fresh_intel):
    db, _, cfg, raw = fresh_intel
    late = T0 + timedelta(days=6)
    r = db.lookup(LISTED, now=late)
    assert r.status == MATCH and r.stale is True                # feeds are 6 days old
    gone = T0 + timedelta(days=9)                               # past the 7-day TTL
    assert db.lookup(LISTED, now=gone).status == NO_MATCH
    report = update_database(cfg, raw, now=gone)
    assert report["expired_removed"] == 10 and report["active_indicators"] == 0


def test_newer_snapshot_extends_expiry(fresh_intel):
    db, _, cfg, raw = fresh_intel
    write_openphish(raw, T0 + timedelta(days=5), ["https://other.evil-site.xyz/start"])
    update_database(cfg, raw, now=T0 + timedelta(days=5, hours=1))
    db.reload()
    later = T0 + timedelta(days=9)
    assert db.lookup("https://other.evil-site.xyz/start", now=later).strongest_level == EXACT_URL
    # LISTED's own entries expired; its sibling host on the same domain is still listed
    assert db.lookup(LISTED, now=later).strongest_level == REGISTERED_DOMAIN


# ---------------------------------------------------------------- failure handling
def test_reader_picks_up_updates_and_survives_a_damaged_file(fresh_intel):
    _, _, cfg, raw = fresh_intel
    reader = ThreatIntelDB.from_config(cfg, refresh_seconds=0)
    new = "https://new-phish-site.com/a"
    assert reader.lookup(new, now=at()).status == NO_MATCH
    write_openphish(raw, T0 + timedelta(hours=2), [new])
    update_database(cfg, raw, now=at())
    assert reader.lookup(new, now=at()).strongest_level == EXACT_URL   # update picked up
    cfg.database.write_bytes(b"half-copied file " * 1000)
    r = reader.lookup(LISTED, now=at())
    assert r.status == MATCH and reader.last_error                     # last good copy answers
    cfg.database.unlink()
    assert reader.lookup(LISTED, now=at()).status == MATCH and reader.last_error == "database_missing"
    reader.close()
    assert reader.lookup(LISTED, now=at()).status == UNAVAILABLE


def test_without_tranco_only_exact_urls_match(tmp_path):
    raw = tmp_path / "raw"
    build_raw(raw, T0, with_tranco=False)
    cfg = config_for(tmp_path)
    report = update_database(cfg, raw, now=at(2))
    assert any("Tranco" in w for w in report["warnings"])
    db = ThreatIntelDB.from_config(cfg)
    assert db.lookup(LISTED, now=at()).strongest_level == EXACT_URL
    assert db.lookup("https://login-verify.evil-site.xyz/other", now=at()).status == NO_MATCH
    db.close()


def test_unavailable_database_never_raises(tmp_path):
    r = ThreatIntelDB(tmp_path / "missing.sqlite3").lookup(LISTED)
    assert r.status == UNAVAILABLE and r.reason == "database_missing"
    bad = tmp_path / "bad.sqlite3"
    bad.write_bytes(b"this is not a database" * 100)
    r = ThreatIntelDB(bad).lookup(LISTED)
    assert r.status == UNAVAILABLE and r.reason.startswith("database_error")
    old = tmp_path / "old.sqlite3"
    with sqlite3.connect(old) as conn:
        conn.execute("CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        conn.execute("INSERT INTO meta VALUES ('schema_version', '99')")
    conn.close()
    assert ThreatIntelDB(old).lookup(LISTED).reason == "schema_mismatch"


def test_concurrent_lookups(intel):
    db = intel[0]
    errors, results = [], []

    def work():
        try:
            for _ in range(100):
                results.append(db.lookup(LISTED, now=at()).strongest_level)
                results.append(db.lookup("https://nice.github.io/", now=at()).status)
        except Exception as exc:          # pragma: no cover - reported below
            errors.append(exc)

    threads = [threading.Thread(target=work) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors and set(results) == {EXACT_URL, NO_MATCH} and len(results) == 1600


# ---------------------------------------------------------------- config / CLI
def test_config_from_file(tmp_path):
    assert ThreatIntelConfig.from_file(tmp_path / "missing.json") == ThreatIntelConfig()
    path = tmp_path / "c.json"
    path.write_text(json.dumps({"ttl_days": {"phishtank": 3}, "popular_top_n": 10}), encoding="utf-8")
    cfg = ThreatIntelConfig.from_file(path)
    assert cfg.ttl_days == {"phishtank": 3.0} and cfg.popular_top_n == 10
    for bad in [{"nope": 1}, {"ttl_days": {"phishtank": 0}}, {"ttl_days": {"unknown_feed": 1}},
                {"popular_top_n": -1}]:
        path.write_text(json.dumps(bad), encoding="utf-8")
        with pytest.raises(ValueError):
            ThreatIntelConfig.from_file(path)
    shipped = ThreatIntelConfig.from_file()                     # config/threat_intel.json
    assert shipped.popular_top_n == 100_000 and set(shipped.ttl_days) == {"phishtank", "openphish"}


def test_cli(tmp_path, capsys):
    raw = tmp_path / "raw"
    build_raw(raw, datetime.now(timezone.utc) - timedelta(hours=2))   # CLI uses the real clock
    cfg_path = tmp_path / "c.json"
    cfg_path.write_text(json.dumps({"database": str(tmp_path / "db.sqlite3"),
                                    "local_redirectors": str(tmp_path / "none.txt")}), encoding="utf-8")
    base = ["--config", str(cfg_path)]
    assert local_database.main([*base, "stats"]) == 1                # no database yet
    assert local_database.main([*base, "update", "--raw", str(raw)]) == 0
    out = capsys.readouterr().out
    assert "phishtank" in out and "evil-site" not in out             # counts only, no URLs
    assert local_database.main([*base, "stats"]) == 0
    assert local_database.main([*base, "lookup", LISTED]) == 0
    assert '"strongest_level": "exact_url"' in capsys.readouterr().out
    assert local_database.main([*base, "lookup", "unknown-site.com", "--domain"]) == 0
    assert "NOT a sign that it is safe" in capsys.readouterr().out
    assert local_database.main([*base, "lookup", "a/b", "--domain"]) == 2
