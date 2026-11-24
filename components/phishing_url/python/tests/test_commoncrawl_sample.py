import csv
import gzip
import io
import json
import random
import zipfile
from datetime import datetime, timezone

import httpx
import pytest

from src.data import commoncrawl_sample as ccs
from src.data.commoncrawl_sample import (
    Block,
    SampleError,
    cc_timestamp_to_iso,
    decompress_block,
    fetch_block,
    filter_block,
    parse_cluster_line,
    private_registered_domain,
    sample_commoncrawl,
    select_blocks,
    surt_host,
)

NOW = datetime(2026, 11, 14, 9, 0, 0, tzinfo=timezone.utc)
CRAWL = "CC-MAIN-2026-43"


def cdx_line(url, status="200", mime="text/html", ts="20261005124020"):
    host = httpx.URL(url).host
    key = ",".join(reversed(host.split("."))) + ")" + (httpx.URL(url).path or "/")
    return f"{key} {ts} " + json.dumps({"url": url, "mime": mime, "mime-detected": mime,
                                       "status": status})


# --------------------------------------------------------------------- helpers
def test_surt_host():
    assert surt_host("com,example,www)/path?x=1") == "www.example.com"
    assert surt_host("105,232,8,104:8081)/robots.txt") == "104.8.232.105"
    assert surt_host("org,commoncrawl)/") == "commoncrawl.org"


def test_private_registered_domain_respects_private_suffixes():
    assert private_registered_domain("www.example.co.uk") == "example.co.uk"
    # user sites on shared platforms are their own "domain", not the platform
    assert private_registered_domain("evil.web.app") == "evil.web.app"
    assert private_registered_domain("someone.github.io") == "someone.github.io"
    assert private_registered_domain("10.0.0.1") == ""
    assert private_registered_domain("localhost") == ""


def test_parse_cluster_line():
    b = parse_cluster_line("com,example,www)/a 20261005124020\tcdx-00012.gz\t500\t250\t7\n")
    assert b == Block("www.example.com", "example.com", "cdx-00012.gz", 500, 250)
    assert parse_cluster_line("garbage") is None
    assert parse_cluster_line("com,x)/ 1\t../etc/passwd\t1\t2\t3") is None   # filename validated
    assert parse_cluster_line("com,x)/ 1\tcdx-00001.gz\t-1\t2\t3") is None


def test_select_blocks_spreads_over_domains_and_is_seeded():
    lines = []
    for d in ("a.com", "b.com", "c.com", "unlisted.com"):
        for i in range(5):
            key = ",".join(reversed(d.split("."))) + f")/{i}"
            lines.append(f"{key} 2026\tcdx-00001.gz\t{len(lines) * 100}\t100\t{len(lines)}")
    allowed = {"a.com": 1, "b.com": 2, "c.com": 3}
    pick = lambda seed, n=10: select_blocks(lines, allowed, num_blocks=n,  # noqa: E731
                                            max_blocks_per_domain=1, rng=random.Random(seed))
    chosen = pick(1)
    assert sorted(b.domain for b in chosen) == ["a.com", "b.com", "c.com"]   # 1 per domain
    assert chosen == sorted(chosen, key=lambda b: (b.filename, b.offset))
    assert pick(1) == pick(1)
    assert len(pick(1, n=2)) == 2
    two = select_blocks(lines, allowed, num_blocks=10, max_blocks_per_domain=2,
                        rng=random.Random(1))
    assert len(two) == 6


def test_filter_block_rules():
    allowed = {"example.com": 5, "web.app": 9}
    text = "\n".join([
        cdx_line("https://www.example.com/a"),
        cdx_line("https://www.example.com/a"),                    # duplicate
        cdx_line("https://www.example.com/b", status="404"),
        cdx_line("https://www.example.com/c.pdf", mime="application/pdf"),
        cdx_line("https://www.example.com/robots.txt"),
        cdx_line("https://www.example.com/d"),
        cdx_line("https://www.example.com/e"),                    # over the cap
        cdx_line("https://evil.web.app/login"),                   # tenant != platform
        cdx_line("https://other.org/x"),
        "not json at all",
        "com,x)/ 2026 [1,2]",
    ])
    per_domain, seen = {}, set()
    rows = filter_block(text, allowed, per_domain, seen, max_urls_per_domain=2)
    assert [r["url"] for r in rows] == ["https://www.example.com/a", "https://www.example.com/d"]
    assert rows[0] == {"url": "https://www.example.com/a", "timestamp": "2026-10-05T12:40:20+00:00",
                       "registered_domain": "example.com", "tranco_rank": "5"}
    assert per_domain == {"example.com": 2}


def test_cc_timestamp():
    assert cc_timestamp_to_iso("20261005124020") == "2026-10-05T12:40:20+00:00"
    assert cc_timestamp_to_iso("bad") == ""


def test_decompress_block_limits(monkeypatch):
    assert decompress_block(gzip.compress(b"hello")) == "hello"
    with pytest.raises(SampleError):
        decompress_block(b"not gzip")
    monkeypatch.setattr(ccs, "MAX_BLOCK_DECOMPRESSED", 10)
    with pytest.raises(SampleError):
        decompress_block(gzip.compress(b"x" * 1000))


# --------------------------------------------------------------------- network
def test_fetch_block_range_and_retries():
    block = Block("h", "example.com", "cdx-00001.gz", 100, 5)
    calls = []

    def handler(request):
        calls.append(request)
        if len(calls) == 1:
            return httpx.Response(503)
        return httpx.Response(206, content=b"12345")

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        assert fetch_block(client, CRAWL, block, sleep=lambda s: None) == b"12345"
    assert calls[-1].headers["range"] == "bytes=100-104"
    assert calls[-1].url.path == f"/cc-index/collections/{CRAWL}/indexes/cdx-00001.gz"


def test_fetch_block_rejects_full_response_and_bad_length():
    block = Block("h", "example.com", "cdx-00001.gz", 0, 5)
    with httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(200, content=b"12345"))) as c:
        with pytest.raises(SampleError):
            fetch_block(c, CRAWL, block, sleep=lambda s: None)
    with httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(206))) as c:
        with pytest.raises(SampleError):
            fetch_block(c, CRAWL, Block("h", "d", "cdx-00001.gz", 0, 10**9), sleep=lambda s: None)


def make_tranco(path, domains):
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("top-1m.csv", "".join(f"{i},{d}\n" for i, d in enumerate(domains, 1)))
    return path


def fake_index(block_texts):
    """Build a fake cdx file made of independent gzip members plus its cluster.idx."""
    data, cluster, offset = b"", [], 0
    for first_key, text in block_texts:
        member = gzip.compress(text.encode())
        cluster.append(f"{first_key} 2026\tcdx-00000.gz\t{offset}\t{len(member)}\t{len(cluster)}")
        data += member
        offset += len(member)
    return data, "\n".join(cluster) + "\n"


def make_handler(data, cluster, broken=False):
    def handler(request):
        path = request.url.path
        if request.url.host == "index.commoncrawl.org":
            return httpx.Response(200, json=[{"id": CRAWL}])
        if path.endswith("/cluster.idx"):
            return httpx.Response(200, content=cluster.encode())
        if path.endswith("/cdx-00000.gz"):
            if broken:
                return httpx.Response(404)
            start, end = (int(x) for x in request.headers["range"][6:].split("-"))
            return httpx.Response(206, content=data[start:end + 1])
        return httpx.Response(404)
    return handler


def test_sample_commoncrawl_end_to_end(tmp_path):
    tranco = make_tranco(tmp_path / "t.csv.zip", ["example.com", "popular.org"])
    data, cluster = fake_index([
        ("com,example)/", "\n".join([cdx_line("https://example.com/"),
                                     cdx_line("https://example.com/about")])),
        ("org,popular)/", cdx_line("https://popular.org/news/1")),
        ("net,unlisted)/", cdx_line("https://unlisted.net/x")),
    ])
    with httpx.Client(transport=httpx.MockTransport(make_handler(data, cluster))) as client:
        manifest = sample_commoncrawl(tmp_path / "raw", tranco, client, num_blocks=10,
                                      workers=2, now=NOW, sleep=lambda s: None)
    out = tmp_path / "raw" / "benign" / "commoncrawl" / "commoncrawl_20261114T090000Z.csv.gz"
    rows = list(csv.DictReader(io.StringIO(gzip.decompress(out.read_bytes()).decode())))
    assert sorted(r["url"] for r in rows) == [
        "https://example.com/", "https://example.com/about", "https://popular.org/news/1"]
    assert manifest["extra"]["crawl_id"] == CRAWL
    assert manifest["extra"]["urls"] == 3 and manifest["extra"]["domains"] == 2
    assert manifest["extra"]["blocks_selected"] == 2
    on_disk = json.loads(out.with_name(out.name + ".manifest.json").read_text())
    assert on_disk == manifest
    assert not list(out.parent.glob("*.part"))

    with httpx.Client(transport=httpx.MockTransport(make_handler(data, cluster))) as client:
        with pytest.raises(FileExistsError):
            sample_commoncrawl(tmp_path / "raw", tranco, client, now=NOW, sleep=lambda s: None)


def test_sample_commoncrawl_refuses_partial_output(tmp_path):
    tranco = make_tranco(tmp_path / "t.csv.zip", ["example.com"])
    data, cluster = fake_index([("com,example)/", cdx_line("https://example.com/"))])
    with httpx.Client(transport=httpx.MockTransport(make_handler(data, cluster, broken=True))) as c:
        with pytest.raises(SampleError):
            sample_commoncrawl(tmp_path / "raw", tranco, c, now=NOW, sleep=lambda s: None)
    assert not list((tmp_path / "raw").rglob("*.csv.gz"))


@pytest.mark.parametrize("kwargs", [{"top_n": 0}, {"num_blocks": 0}, {"workers": 0},
                                    {"workers": 99}, {"crawl_id": "../../etc"}])
def test_sample_commoncrawl_bad_arguments(tmp_path, kwargs):
    tranco = make_tranco(tmp_path / "t.csv.zip", ["example.com"])
    with httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(500))) as c:
        with pytest.raises(ValueError):
            sample_commoncrawl(tmp_path, tranco, c, now=NOW, **{"crawl_id": CRAWL, **kwargs})
