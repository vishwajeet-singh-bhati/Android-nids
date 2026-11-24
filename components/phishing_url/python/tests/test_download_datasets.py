import gzip
import hashlib
import json
from datetime import datetime, timedelta, timezone

import httpx
import pytest

from src.data.download_datasets import (
    SOURCES,
    DownloadError,
    MissingCredentialsError,
    download_source,
)

KEY = "k" * 32  # fake test key
ENV = {"PHISHTANK_APP_KEY": KEY, "PHISHTANK_USERNAME": "tester"}
NOW = datetime(2026, 11, 13, 10, 15, 0, tzinfo=timezone.utc)
GZ = gzip.compress(b"phish_id,url\n1,http://example.test/\n")
ZIP = b"PK\x03\x04" + b"x" * 20


def run(name, handler, tmp_path, env=ENV, now=NOW, **kwargs):
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        return download_source(SOURCES[name], tmp_path, env, client, now=now,
                               sleep=lambda s: None, **kwargs)


def files(tmp_path):
    return [p for p in tmp_path.rglob("*") if p.is_file()]


def test_phishtank_success_and_manifest(tmp_path):
    seen = []

    def handler(request):
        seen.append(request)
        return httpx.Response(200, content=GZ, headers={"etag": '"abc"'})

    manifest = run("phishtank", handler, tmp_path)
    path = tmp_path / "phishing" / "phishtank" / "phishtank_20261113T101500Z.csv.gz"
    assert path.read_bytes() == GZ
    assert manifest["bytes"] == len(GZ)
    assert manifest["sha256"] == hashlib.sha256(GZ).hexdigest()
    assert manifest["etag"] == '"abc"'
    assert manifest["retrieved_at"].startswith("2026-11-13T10:15:00")
    on_disk = json.loads((path.parent / (path.name + ".manifest.json")).read_text())
    assert on_disk == manifest
    assert KEY not in json.dumps(manifest) and "{app_key}" in manifest["url"]
    assert KEY not in "".join(p.name for p in files(tmp_path))
    # the request itself carried the key and the descriptive user agent
    assert seen[0].headers["user-agent"] == "phishtank/tester"
    assert f"/data/{KEY}/online-valid.csv.gz" in seen[0].url.path


@pytest.mark.parametrize("env", [
    {"PHISHTANK_APP_KEY": KEY},
    {"PHISHTANK_USERNAME": "tester"},
    {"PHISHTANK_APP_KEY": "bad key!", "PHISHTANK_USERNAME": "tester"},
    {"PHISHTANK_APP_KEY": KEY, "PHISHTANK_USERNAME": "bad user/"},
])
def test_phishtank_rejects_partial_or_invalid_credentials(tmp_path, env):
    with pytest.raises(MissingCredentialsError):
        run("phishtank", lambda r: httpx.Response(200, content=GZ), tmp_path, env=env)
    assert files(tmp_path) == []


def test_phishtank_works_without_a_key(tmp_path):
    seen = []

    def handler(request):
        seen.append(request)
        return httpx.Response(200, content=GZ)

    manifest = run("phishtank", handler, tmp_path, env={})
    assert seen[0].url.path == "/data/online-valid.csv.gz"
    assert not seen[0].headers["user-agent"].startswith("phishtank/")
    assert manifest["url"] == "https://data.phishtank.com/data/online-valid.csv.gz"


def test_http_error_leaves_no_files_and_leaks_no_key(tmp_path):
    with pytest.raises(DownloadError) as info:
        run("phishtank", lambda r: httpx.Response(404), tmp_path)
    assert KEY not in str(info.value) and "404" in str(info.value)
    assert files(tmp_path) == []


def test_retries_then_succeeds(tmp_path):
    calls = []

    def handler(request):
        calls.append(1)
        return httpx.Response(500) if len(calls) == 1 else httpx.Response(200, content=GZ)

    run("phishtank", handler, tmp_path)
    assert len(calls) == 2 and len(files(tmp_path)) == 2  # data + manifest


def test_retries_exhausted(tmp_path):
    calls = []

    def handler(request):
        calls.append(1)
        return httpx.Response(503)

    with pytest.raises(DownloadError, match="giving up"):
        run("phishtank", handler, tmp_path)
    assert len(calls) == 3 and files(tmp_path) == []


def test_network_error_is_retried_and_leaks_no_key(tmp_path):
    def handler(request):
        raise httpx.ConnectError("boom")

    with pytest.raises(DownloadError) as info:
        run("phishtank", handler, tmp_path)
    assert KEY not in str(info.value) and files(tmp_path) == []


def test_size_cap(tmp_path):
    with pytest.raises(DownloadError, match="exceeds"):
        run("phishtank", lambda r: httpx.Response(200, content=GZ), tmp_path, max_bytes=10)
    assert files(tmp_path) == []


@pytest.mark.parametrize("name,body", [
    ("phishtank", b"<html>rate limited</html>"),
    ("openphish", b"<!DOCTYPE html><html></html>"),
    ("tranco", b"<html>nope</html>"),
])
def test_html_with_200_is_rejected(tmp_path, name, body):
    with pytest.raises(DownloadError, match="unexpected content"):
        run(name, lambda r: httpx.Response(200, content=body), tmp_path)
    assert files(tmp_path) == []


def test_empty_response_rejected(tmp_path):
    with pytest.raises(DownloadError, match="empty"):
        run("phishtank", lambda r: httpx.Response(200, content=b""), tmp_path)


def test_openphish_needs_no_credentials(tmp_path):
    body = b"http://a.example/x\nhttp://b.example/y\n"
    manifest = run("openphish", lambda r: httpx.Response(200, content=body), tmp_path, env={})
    assert (tmp_path / "phishing" / "openphish" / manifest["file"]).read_bytes() == body
    assert "non-commercial" in manifest["license_note"]


def test_tranco_records_list_id(tmp_path):
    def handler(request):
        if request.url.path == "/top-1m-id":
            return httpx.Response(200, text="AB12C\n")
        return httpx.Response(200, content=ZIP)

    manifest = run("tranco", handler, tmp_path, env={})
    assert manifest["extra"]["list_id"] == "AB12C"
    assert (tmp_path / "benign" / "tranco" / manifest["file"]).exists()


@pytest.mark.parametrize("id_response", [httpx.Response(500), httpx.Response(200, text="<html>x</html>")])
def test_tranco_id_failure_does_not_fail_download(tmp_path, id_response):
    def handler(request):
        return id_response if request.url.path == "/top-1m-id" else httpx.Response(200, content=ZIP)

    manifest = run("tranco", handler, tmp_path, env={})
    assert manifest["extra"]["list_id"] is None


def test_history_is_kept_and_same_second_is_refused(tmp_path):
    handler = lambda r: httpx.Response(200, content=GZ)  # noqa: E731
    run("phishtank", handler, tmp_path)
    run("phishtank", handler, tmp_path, now=NOW + timedelta(hours=1))
    assert len([p for p in files(tmp_path) if p.name.endswith(".csv.gz")]) == 2
    with pytest.raises(FileExistsError):
        run("phishtank", handler, tmp_path)