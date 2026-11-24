import csv
import gzip
import json
import random
import zipfile

import pytest

from src.data.build_dataset import COLUMNS, Reservoir, _pct, build_dataset

HEADER = "phish_id,url,phish_detail_url,submission_time,verified,verification_time,online,target"


def write_manifest(path, retrieved_at):
    (path.parent / (path.name + ".manifest.json")).write_text(
        json.dumps({"retrieved_at": retrieved_at}), encoding="utf-8")


def write_phishtank(raw, stamp, rows, retrieved_at=None):
    folder = raw / "phishing" / "phishtank"
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / f"phishtank_{stamp}.csv.gz"
    lines = [HEADER] + [
        f'{i},"{url}",https://www.phishtank.com/d?{i},{when},yes,{when},yes,Other'
        for i, (url, when) in enumerate(rows, 1)]
    path.write_bytes(gzip.compress(("\n".join(lines) + "\n").encode()))
    if retrieved_at:
        write_manifest(path, retrieved_at)
    return path


def write_openphish(raw, stamp, lines):
    folder = raw / "phishing" / "openphish"
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / f"openphish_{stamp}.txt"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def write_tranco(raw, stamp, domains):
    folder = raw / "benign" / "tranco"
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / f"tranco_{stamp}.csv.zip"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("top-1m.csv", "".join(f"{i},{d}\n" for i, d in enumerate(domains, 1)))
    return path


def read_rows(out):
    with (out / "samples.csv").open(encoding="utf-8", newline="") as fh:
        return list(csv.DictReader(fh))


@pytest.fixture
def main_raw(tmp_path):
    raw = tmp_path / "raw"
    write_phishtank(raw, "20261112T000000Z", [
        ("https://secure-login.evil-example.com/a/b?x=1", "2026-11-01T10:00:00+00:00"),
        ("HTTP://EVIL-EXAMPLE.com:80/c", "2026-11-02T10:00:00+00:00"),
        ("https://shop.example.org/pay", "2026-11-03T10:00:00+00:00"),
        ("javascript:alert(1)", "2026-11-03T11:00:00+00:00"),
        ("https://example.com/phish", "2026-11-04T10:00:00+00:00"),
    ])
    write_openphish(raw, "20261112T000000Z", [
        "# comment", "", "https://shop.example.org/pay", "http://203.0.113.7/login.php"])
    write_tranco(raw, "20261112T000000Z",
                 ["example.com", "popular.org"] + [f"benign{i}.com" for i in range(3, 21)])
    return raw


def test_end_to_end(tmp_path, main_raw):
    out = tmp_path / "out"
    report = build_dataset(main_raw, out, benign_count=100, homepage_count=0)
    rows = read_rows(out)

    assert report["final"] == {"phishing": 5, "benign": 20}
    assert report["duplicates_removed"]["phishing"] == 1
    assert report["rejected"]["count"] == 1
    assert report["rejected"]["by_reason"] == {"unparseable": 1}
    assert report["rejected"]["by_source"] == {"phishtank": 1}
    assert len(rows) == 25
    assert list(rows[0].keys()) == COLUMNS
    assert all("://" not in r["model_string"] for r in rows)

    by_canon = {r["canonical"]: r for r in rows if r["label"] == "phishing"}
    shop = by_canon["https://shop.example.org/pay"]
    assert shop["sources"] == "openphish|phishtank"
    assert shop["label_quality"] == "community_verified"
    assert shop["first_seen"] == "2026-11-03T10:00:00+00:00"
    assert shop["group"] == "example.org"
    ip = by_canon["http://203.0.113.7/login.php"]
    assert ip["label_quality"] == "feed_automated" and ip["is_ip"] == "True"
    assert ip["group"] == "203.0.113.7"
    assert "http://evil-example.com/c" in by_canon          # case, default port normalized
    conflict = by_canon["https://example.com/phish"]
    assert conflict["tranco_rank"] == "1" and conflict["host_conflict"] == "True"
    assert by_canon["https://shop.example.org/pay"]["host_conflict"] == "False"

    benign = {r["canonical"]: r for r in rows if r["label"] == "benign"}
    assert benign["example.com"]["host_conflict"] == "True"
    assert benign["popular.org"]["host_conflict"] == "False"
    assert benign["popular.org"]["label_quality"] == "weak_popularity"
    assert benign["popular.org"]["tranco_rank"] == "2"

    p = report["phishing"]
    assert p["by_source"] == {"phishtank": 3, "openphish|phishtank": 1, "openphish": 1}
    assert p["source_overlap"] == 1
    assert p["unique_groups"] == 4
    assert p["top_groups"][0] == ["evil-example.com", 2]
    assert p["scheme"] == {"https": 3, "http": 2}
    assert p["ip_hosts"] == 1 and p["with_path_or_query"] == 5
    assert p["registered_domain_in_tranco"] == 1 and p["host_conflicts"] == 1
    assert report["benign"]["host_conflicts"] == 1
    assert report["lengths"]["phishing_full"]["n"] == 5

    text = (out / "build_report.json").read_text(encoding="utf-8")
    assert "secure-login" not in text and "/a/b" not in text   # no raw URLs in the report


def write_commoncrawl(raw, stamp, rows):
    folder = raw / "benign" / "commoncrawl"
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / f"commoncrawl_{stamp}.csv.gz"
    body = "url,timestamp,registered_domain,tranco_rank\n" + "".join(
        f"{u},2026-10-05T12:40:20+00:00,{d},{rank}\n" for u, d, rank in rows)
    path.write_bytes(gzip.compress(body.encode()))
    return path


def test_without_commoncrawl_warns(tmp_path, main_raw):
    report = build_dataset(main_raw, tmp_path / "out", benign_count=100, homepage_count=0)
    assert report["warnings"] and report["warnings"][0].startswith("no_benign_full_urls")
    assert report["benign"]["by_input_type"] == {"domain": 20}


def test_commoncrawl_adds_benign_full_urls(tmp_path, main_raw):
    write_commoncrawl(main_raw, "20261114T000000Z", [
        ("https://popular.org/news/1?id=2", "popular.org", 2),
        ("https://www.example.com/help", "example.com", 1),
        ("https://www.example.com/help", "example.com", 1),       # duplicate
        ("javascript:alert(1)", "x.com", 3),                      # rejected
    ])
    out = tmp_path / "out"
    report = build_dataset(main_raw, out, benign_count=100, homepage_count=0)
    assert report["warnings"] == []
    assert report["inputs"]["commoncrawl"]["records_read"] == 4
    assert report["final"]["benign"] == 22
    assert report["duplicates_removed"]["benign"] == 1
    assert report["benign"]["by_input_type"] == {"domain": 20, "full_url": 2}
    assert report["benign"]["by_source"]["commoncrawl"] == 2
    assert report["benign"]["with_path_or_query"] == 2
    assert report["lengths"]["benign_full"]["n"] == 2
    rows = {r["canonical"]: r for r in read_rows(out) if r["label"] == "benign"}
    news = rows["https://popular.org/news/1?id=2"]
    assert news["label_quality"] == "weak_crawl" and news["input_type"] == "full_url"
    assert news["tranco_rank"] == "2" and news["group"] == "popular.org"
    assert news["first_seen"] == "2026-10-05T12:40:20+00:00"
    assert rows["https://www.example.com/help"]["host_conflict"] == "False"
    assert rows["popular.org"]["label_quality"] == "weak_popularity"


def test_rejected_csv_is_truncated_and_formula_safe(tmp_path):
    raw = tmp_path / "raw"
    write_openphish(raw, "20261112T000000Z", ["=cmd|calc", "http://" + "a" * 300 + " b"])
    write_tranco(raw, "20261112T000000Z", ["example.com"])
    out = tmp_path / "out"
    report = build_dataset(raw, out, benign_count=10)
    assert report["final"]["phishing"] == 0
    assert report["lengths"]["phishing_full"] == {"n": 0}
    with (out / "rejected.csv").open(encoding="utf-8", newline="") as fh:
        rejected = {r["reason"]: r for r in csv.DictReader(fh)}
    assert rejected["invalid_host"]["value"] == "'=cmd|calc"
    assert len(rejected["illegal_characters"]["value"]) == 200


def test_sampling_is_seeded_and_exact_size(tmp_path):
    raw = tmp_path / "raw"
    write_openphish(raw, "20261112T000000Z", ["http://a.example/x"])
    write_tranco(raw, "20261112T000000Z", [f"d{i}.com" for i in range(1, 201)])
    a = build_dataset(raw, tmp_path / "a", benign_count=50, homepage_count=0, seed=7)
    b = build_dataset(raw, tmp_path / "b", benign_count=50, homepage_count=0, seed=7)
    c = build_dataset(raw, tmp_path / "c", benign_count=50, homepage_count=0, seed=8)
    pick = lambda out: sorted(r["canonical"] for r in read_rows(tmp_path / out) if r["label"] == "benign")  # noqa: E731
    assert a["final"]["benign"] == b["final"]["benign"] == c["final"]["benign"] == 50
    assert pick("a") == pick("b")
    assert pick("a") != pick("c")
    ranks = [int(r["tranco_rank"]) for r in read_rows(tmp_path / "a") if r["label"] == "benign"]
    assert all(1 <= r <= 200 for r in ranks) and len(set(ranks)) == 50


def test_snapshot_merging_and_latest_mode(tmp_path):
    raw = tmp_path / "raw"
    t0, t1 = "2026-11-01T00:00:00+00:00", "2026-11-02T00:00:00+00:00"
    seen = "2026-10-30T00:00:00+00:00"
    write_phishtank(raw, "20261101T000000Z",
                    [("https://a.example.net/u0", seen), ("https://a.example.net/u1", seen)], t0)
    write_phishtank(raw, "20261102T000000Z",
                    [("https://a.example.net/u1", seen), ("https://a.example.net/u2", seen)], t1)
    write_tranco(raw, "20261102T000000Z", ["example.com"])

    build_dataset(raw, tmp_path / "all", phishing_snapshots="all")
    rows = {r["canonical"]: r for r in read_rows(tmp_path / "all") if r["label"] == "phishing"}
    assert set(rows) == {"https://a.example.net/u0", "https://a.example.net/u1", "https://a.example.net/u2"}
    assert rows["https://a.example.net/u1"]["first_collected_at"] == t0     # earliest snapshot wins
    assert rows["https://a.example.net/u2"]["first_collected_at"] == t1

    build_dataset(raw, tmp_path / "latest", phishing_snapshots="latest")
    rows = {r["canonical"]: r for r in read_rows(tmp_path / "latest") if r["label"] == "phishing"}
    assert set(rows) == {"https://a.example.net/u1", "https://a.example.net/u2"}
    assert rows["https://a.example.net/u1"]["first_collected_at"] == t1


def test_missing_inputs_and_bad_arguments(tmp_path):
    raw = tmp_path / "raw"
    with pytest.raises(FileNotFoundError):
        build_dataset(raw, tmp_path / "o")
    write_openphish(raw, "20261112T000000Z", ["http://a.example/x"])
    with pytest.raises(FileNotFoundError):          # phishing present, Tranco missing
        build_dataset(raw, tmp_path / "o")
    write_tranco(raw, "20261112T000000Z", ["example.com"])
    with pytest.raises(ValueError):
        build_dataset(raw, tmp_path / "o", phishing_snapshots="newest")
    with pytest.raises(ValueError):
        build_dataset(raw, tmp_path / "o", benign_count=-1)
    with pytest.raises(ValueError):
        build_dataset(raw, tmp_path / "o", homepage_count=-1)


def test_tranco_homepages_become_benign_full_urls(tmp_path, main_raw):
    out = tmp_path / "out"
    report = build_dataset(main_raw, out, benign_count=100, homepage_count=5)
    assert report["inputs"]["tranco"]["homepages"] == 5
    homepages = [r for r in read_rows(out) if r["sources"] == "tranco_homepage"]
    assert len(homepages) == 5
    assert all(r["input_type"] == "full_url" and r["label"] == "benign"
               and r["canonical"].startswith("https://") and r["canonical"].endswith("/")
               and r["model_string"] == r["host"] + "/" for r in homepages)
    again = build_dataset(main_raw, tmp_path / "again", benign_count=100, homepage_count=5)
    assert again["benign"] == report["benign"]   # seeded: same picks


class TestReservoir:
    def test_small_stream_is_kept_entirely(self):
        r = Reservoir(10, random.Random(1))
        for i in range(5):
            r.add(i)
        assert sorted(r.items) == [0, 1, 2, 3, 4]

    def test_size_and_determinism(self):
        def run(seed):
            r = Reservoir(10, random.Random(seed))
            for i in range(1000):
                r.add(i)
            return r.items
        assert len(run(1)) == 10 and run(1) == run(1)

    def test_zero_capacity(self):
        r = Reservoir(0, random.Random(1))
        for i in range(10):
            r.add(i)
        assert r.items == []

    def test_roughly_uniform(self):
        counts = [0] * 100
        rng = random.Random(0)
        for _ in range(2000):
            r = Reservoir(10, rng)
            for i in range(100):
                r.add(i)
            for item in r.items:
                counts[item] += 1
        assert all(100 < c < 300 for c in counts)    # expected 200 each


def test_percentiles():
    assert _pct([]) == {"n": 0}
    stats = _pct(list(range(1, 101)))
    assert stats["n"] == 100 and stats["max"] == 100 and stats["p50"] == pytest.approx(50.5)