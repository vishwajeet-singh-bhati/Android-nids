"""Download raw phishing/benign datasets with provenance manifests.

Only talks to the feed hosts. It never visits any URL listed inside a feed.
The PhishTank application key is read from the environment and is redacted
from manifests, error messages and logs.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import re
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Mapping

import httpx

logger = logging.getLogger(__name__)
# httpx logs full request URLs at INFO level, which would leak the app key.
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)

USER_AGENT_FALLBACK = "phishing-detector-research/0.1"
MAX_BYTES = 300 * 1024 * 1024
HEAD_BYTES = 16

_KEY_RE = re.compile(r"[A-Za-z0-9_-]{8,128}")
_USER_RE = re.compile(r"[A-Za-z0-9_.-]{1,64}")
_LIST_ID_RE = re.compile(r"[A-Za-z0-9]{1,64}")


class MissingCredentialsError(RuntimeError):
    """Required environment variables are absent or malformed."""


class DownloadError(RuntimeError):
    """A download failed. Messages never contain secrets."""


class _Retryable(Exception):
    pass


@dataclass(frozen=True)
class Source:
    name: str
    category: str                    # "phishing" | "benign"
    url_template: str                # may contain {app_key}; stored redacted
    suffix: str                      # expected file type, e.g. ".csv.gz"
    license_note: str
    requires_env: tuple[str, ...] = ()
    id_url: str | None = None        # optional endpoint returning a citable list ID
    keyless_url: str | None = None   # fallback when no credentials are configured


SOURCES: dict[str, Source] = {
    "phishtank": Source(
        name="phishtank", category="phishing",
        url_template="https://data.phishtank.com/data/{app_key}/online-valid.csv.gz",
        keyless_url="https://data.phishtank.com/data/online-valid.csv.gz",
        suffix=".csv.gz",
        license_note=("PhishTank (Cisco Talos). App key optional; keyless access is limited "
                      "to a few downloads per day. Read the Terms of Use."),
    ),
    "openphish": Source(
        name="openphish", category="phishing",
        url_template="https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt",
        suffix=".txt",
        license_note="OpenPhish Community Feed: non-commercial use only; see https://openphish.com/terms.html",
    ),
    "tranco": Source(
        name="tranco", category="benign",
        url_template="https://tranco-list.eu/top-1m.csv.zip",
        suffix=".csv.zip",
        license_note="Tranco ranking (Le Pochat et al., NDSS 2019); provider licenses listed at tranco-list.eu",
        id_url="https://tranco-list.eu/top-1m-id",
    ),
    "url_shorteners": Source(
        name="url_shorteners", category="reference",
        url_template="https://raw.githubusercontent.com/PeterDaveHello/url-shorteners/master/list",
        suffix=".txt",
        license_note=("PeterDaveHello/url-shorteners, CC BY-SA 4.0. Used only to route opaque "
                      "redirect links, never as a phishing label."),
    ),
}


def build_request(source: Source, env: Mapping[str, str]) -> tuple[str, dict[str, str], str]:
    """Return (url, headers, redacted_url). Only redacted_url may be stored or logged."""
    missing = [name for name in source.requires_env if not env.get(name)]
    if missing:
        raise MissingCredentialsError(f"{source.name}: missing environment variables {missing}")
    headers = {"User-Agent": USER_AGENT_FALLBACK}
    if source.name != "phishtank":
        return source.url_template, headers, source.url_template

    key = env.get("PHISHTANK_APP_KEY", "").strip()
    user = env.get("PHISHTANK_USERNAME", "").strip()
    if not key and not user:
        assert source.keyless_url is not None
        return source.keyless_url, headers, source.keyless_url
    if not (key and user):
        raise MissingCredentialsError(
            "phishtank: set both PHISHTANK_APP_KEY and PHISHTANK_USERNAME, or neither")
    if not _KEY_RE.fullmatch(key):
        raise MissingCredentialsError("phishtank: PHISHTANK_APP_KEY has an invalid format")
    if not _USER_RE.fullmatch(user):
        raise MissingCredentialsError("phishtank: PHISHTANK_USERNAME has an invalid format")
    headers["User-Agent"] = f"phishtank/{user}"
    return source.url_template.format(app_key=key), headers, source.url_template


def _check_content(source: Source, head: bytes) -> None:
    """Reject HTML error pages that arrive with a 200 status."""
    if source.suffix.endswith(".gz"):
        ok = head.startswith(b"\x1f\x8b")
    elif source.suffix.endswith(".zip"):
        ok = head.startswith(b"PK")
    else:
        ok = not head.lstrip().startswith(b"<")
    if not ok:
        raise DownloadError(f"{source.name}: unexpected content (not the expected file type)")


def _cleanup(path: Path) -> None:
    path.unlink(missing_ok=True)


def _fetch_to_file(client: httpx.Client, url: str, headers: dict[str, str],
                   part: Path, source: Source, max_bytes: int) -> dict[str, object]:
    digest = hashlib.sha256()
    size = 0
    head = b""
    try:
        with client.stream("GET", url, headers=headers) as response:
            status = response.status_code
            if status == 429 or status >= 500:
                raise _Retryable(f"HTTP {status}")
            if status != 200:
                raise DownloadError(f"{source.name}: HTTP {status}")
            with part.open("wb") as fh:
                for chunk in response.iter_bytes():
                    if len(head) < HEAD_BYTES:
                        head += chunk[: HEAD_BYTES - len(head)]
                    size += len(chunk)
                    if size > max_bytes:
                        raise DownloadError(f"{source.name}: response exceeds {max_bytes} bytes")
                    digest.update(chunk)
                    fh.write(chunk)
            etag = response.headers.get("etag")
            last_modified = response.headers.get("last-modified")
    except httpx.TransportError as exc:
        # `from None`: never chain the original, whose text could include the URL.
        raise _Retryable(f"network error ({type(exc).__name__})") from None
    if size == 0:
        raise DownloadError(f"{source.name}: empty response")
    _check_content(source, head)
    return {"bytes": size, "sha256": digest.hexdigest(), "etag": etag, "last_modified": last_modified}


def _fetch_list_id(client: httpx.Client, url: str, headers: dict[str, str]) -> str | None:
    """Best-effort fetch of a citable list ID. Never fails the download."""
    try:
        response = client.get(url, headers=headers)
    except httpx.HTTPError:
        return None
    text = response.text.strip() if response.status_code == 200 else ""
    return text if _LIST_ID_RE.fullmatch(text) else None


def download_source(
    source: Source,
    out_root: Path | str,
    env: Mapping[str, str],
    client: httpx.Client,
    *,
    now: datetime | None = None,
    max_bytes: int = MAX_BYTES,
    max_attempts: int = 3,
    backoff_seconds: float = 2.0,
    sleep: Callable[[float], None] = time.sleep,
) -> dict[str, object]:
    """Download one source into <out_root>/<category>/<name>/ and write a manifest."""
    url, headers, redacted_url = build_request(source, env)
    now = now or datetime.now(timezone.utc)
    stamp = now.strftime("%Y%m%dT%H%M%SZ")
    target_dir = Path(out_root) / source.category / source.name
    target_dir.mkdir(parents=True, exist_ok=True)
    final = target_dir / f"{source.name}_{stamp}{source.suffix}"
    if final.exists():
        raise FileExistsError(f"{final.name} already exists; refusing to overwrite")
    part = final.with_name(final.name + ".part")

    info: dict[str, object] | None = None
    for attempt in range(1, max_attempts + 1):
        try:
            info = _fetch_to_file(client, url, headers, part, source, max_bytes)
            break
        except _Retryable as exc:
            _cleanup(part)
            if attempt == max_attempts:
                raise DownloadError(
                    f"{source.name}: giving up after {attempt} attempts ({exc})") from None
            sleep(backoff_seconds * 2 ** (attempt - 1))
        except DownloadError:
            _cleanup(part)
            raise
    assert info is not None
    os.replace(part, final)

    extra: dict[str, object] = {}
    if source.id_url:
        # Fetched separately; the list could in theory roll over in between.
        extra["list_id"] = _fetch_list_id(client, source.id_url, headers)

    manifest: dict[str, object] = {
        "source": source.name,
        "category": source.category,
        "url": redacted_url,                 # never contains the real key
        "file": final.name,
        "retrieved_at": now.isoformat(),
        "http_status": 200,
        **info,
        "license_note": source.license_note,
        "extra": extra,
    }
    final.with_name(final.name + ".manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Download raw datasets with provenance manifests.")
    parser.add_argument("--sources", nargs="+", choices=sorted(SOURCES), default=sorted(SOURCES))
    parser.add_argument("--out", default="data/raw")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    failures = 0
    with httpx.Client(timeout=httpx.Timeout(60.0, connect=15.0), follow_redirects=True) as client:
        for name in args.sources:
            try:
                manifest = download_source(SOURCES[name], Path(args.out), os.environ, client)
            except (MissingCredentialsError, DownloadError, FileExistsError) as exc:
                logger.error("%s", exc)
                failures += 1
                continue
            logger.info("%s: %s bytes, sha256=%s..., file=%s", name, manifest["bytes"],
                        str(manifest["sha256"])[:12], manifest["file"])
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())