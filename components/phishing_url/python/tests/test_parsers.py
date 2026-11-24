import gzip
import json
import zipfile
from collections import Counter

import pytest

from src.data import parsers
from src.data.parsers import (
    find_snapshots,
    parse_commoncrawl,
    parse_openphish,
    parse_phishtank,
    parse_tranco,
    read_collected_at,
)

HEADER = "phish_id,url,phish_detail_url,submission_time,verified,verification_time,online,target"


def write_gz(path, text, encoding="utf-8"):
    path.write_bytes(gzip.compress(text.encode(encoding)))


def test_phishtank_parses_and_counts_skips(tmp_path):
    path = tmp_path / "phishtank_x.csv.gz"
    write_gz(path, "\n".join([
        HEADER,
        "1,http://a.example/x,https://www.phishtank.com/d?1,2026-11-01T00:00:00+00:00,yes,2026-11-01T01:00:00+00:00,yes,Bank",
        "2,http://b.example/y,https://www.phishtank.com/d?2,2026-11-02T00:00:00+00:00,no,,yes,Bank",
        "3,,https://www.phishtank.com/d?3,2026-11-03T00:00:00+00:00,yes,2026-11-03T01:00:00+00:00,yes,Bank",
    ]) + "\n")
    skipped = Counter()
    records = list(parse_phishtank(path, "COLLECTED", skipped))
    assert len(records) == 1
    r = records[0]
    assert (r.source, r.label, r.value, r.input_type) == ("phishtank", "phishing", "http://a.example/x", "full_url")
    assert (r.source_id, r.first_seen, r.collected_at, r.source_file) == (
        "1", "2026-11-01T00:00:00+00:00", "COLLECTED", "phishtank_x.csv.gz")
    assert skipped == {"not_verified": 1, "empty_url": 1}


def test_phishtank_handles_bom(tmp_path):
    path = tmp_path / "p.csv.gz"
    write_gz(path, "\ufeff" + HEADER + "\n1,http://a.example/,d,t,yes,t,yes,x\n")
    assert [r.value for r in parse_phishtank(path)] == ["http://a.example/"]


def test_phishtank_bad_header(tmp_path):
    path = tmp_path / "p.csv.gz"
    write_gz(path, "a,b\n1,2\n")
    with pytest.raises(ValueError):
        list(parse_phishtank(path))


def test_openphish_skips_blank_and_comment_lines(tmp_path):
    path = tmp_path / "o.txt"
    path.write_text("# c\n\n  http://a.example/x  \nhttp://b.example/y\n", encoding="utf-8")
    records = list(parse_openphish(path, "C"))
    assert [r.value for r in records] == ["http://a.example/x", "http://b.example/y"]
    assert all(r.label == "phishing" and r.first_seen == "" and r.collected_at == "C" for r in records)


def make_zip(path, members):
    with zipfile.ZipFile(path, "w") as zf:
        for name, text in members.items():
            zf.writestr(name, text)


def test_tranco_parses_and_counts_malformed(tmp_path):
    path = tmp_path / "t.csv.zip"
    make_zip(path, {"top-1m.csv": "1,google.com\n2,facebook.com\nbadline\nx,foo.com\n3,\n"})
    skipped = Counter()
    records = list(parse_tranco(path, "", skipped))
    assert [(r.source_id, r.value) for r in records] == [("1", "google.com"), ("2", "facebook.com")]
    assert records[0].label == "benign_weak" and records[0].input_type == "domain"
    assert skipped == {"malformed_row": 3}


def test_tranco_requires_exactly_one_csv(tmp_path):
    path = tmp_path / "t.csv.zip"
    make_zip(path, {"a.csv": "1,a.com\n", "b.csv": "1,b.com\n"})
    with pytest.raises(ValueError):
        list(parse_tranco(path))


def test_tranco_size_guard(tmp_path, monkeypatch):
    path = tmp_path / "t.csv.zip"
    make_zip(path, {"top-1m.csv": "1,google.com\n"})
    monkeypatch.setattr(parsers, "MAX_UNCOMPRESSED_BYTES", 5)
    with pytest.raises(ValueError):
        list(parse_tranco(path))


def test_commoncrawl_parses(tmp_path):
    path = tmp_path / "commoncrawl_x.csv.gz"
    write_gz(path, "url,timestamp,registered_domain,tranco_rank\n"
                   "https://example.com/a,2026-10-05T12:40:20+00:00,example.com,7\n"
                   ",2026-10-05T12:40:20+00:00,example.com,7\n")
    skipped = Counter()
    records = list(parse_commoncrawl(path, "C", skipped))
    assert len(records) == 1
    r = records[0]
    assert (r.source, r.label, r.input_type, r.source_id) == ("commoncrawl", "benign_weak", "full_url", "7")
    assert r.first_seen == "2026-10-05T12:40:20+00:00" and r.collected_at == "C"
    assert skipped == {"empty_url": 1}
    write_gz(path, "a,b\n1,2\n")
    with pytest.raises(ValueError):
        list(parse_commoncrawl(path))


def test_find_snapshots_commoncrawl(tmp_path):
    folder = tmp_path / "benign" / "commoncrawl"
    folder.mkdir(parents=True)
    (folder / "commoncrawl_20261114T000000Z.csv.gz").write_bytes(b"x")
    (folder / "commoncrawl_20261114T000000Z.csv.gz.part").write_bytes(b"x")
    assert [p.name for p in find_snapshots(tmp_path, "commoncrawl")] == [
        "commoncrawl_20261114T000000Z.csv.gz"]


def test_read_collected_at(tmp_path):
    data = tmp_path / "d.txt"
    data.write_text("x")
    assert read_collected_at(data) == ""
    (tmp_path / "d.txt.manifest.json").write_text(json.dumps({"retrieved_at": "2026-11-12T00:00:00+00:00"}))
    assert read_collected_at(data) == "2026-11-12T00:00:00+00:00"
    (tmp_path / "d.txt.manifest.json").write_text("{broken")
    assert read_collected_at(data) == ""


def test_find_snapshots_sorted_and_ignores_extras(tmp_path):
    folder = tmp_path / "phishing" / "phishtank"
    folder.mkdir(parents=True)
    for name in ("phishtank_20261102T000000Z.csv.gz", "phishtank_20261101T000000Z.csv.gz",
                 "phishtank_20261103T000000Z.csv.gz.part",
                 "phishtank_20261101T000000Z.csv.gz.manifest.json"):
        (folder / name).write_bytes(b"x")
    names = [p.name for p in find_snapshots(tmp_path, "phishtank")]
    assert names == ["phishtank_20261101T000000Z.csv.gz", "phishtank_20261102T000000Z.csv.gz"]
    assert find_snapshots(tmp_path, "openphish") == []