"""Optional online lookups: Google Safe Browsing API v5 (hashes.search).

    python -m src.intelligence.safe_browsing expressions "https://a.b.example.com/1/2.html?x=1"
    python -m src.intelligence.safe_browsing check "https://example.com/"      # needs an API key

OFF unless the environment variable SAFE_BROWSING_API_KEY is set. Everything
else in the project works without it.

What is sent (privacy)
  The URL is canonicalized and expanded into up to 30 "host-suffix/path-prefix
  expressions" (e.g. a.b.com/1/2.html, b.com/, ...), exactly as Google
  specifies. Each expression is hashed with SHA-256 and only the first 4 bytes
  of each hash go to Google. The URL, its query string and any tokens in it
  never leave the device. Google returns the full 32-byte hashes of listed
  expressions with those prefixes; the match is decided locally by comparing
  full hashes. Hosts that cannot be on Google's lists (localhost, private IPs,
  names without a public suffix) are never sent.

Rules followed (official pages, read 2026-11-18/20)
  * URL canonicalization and expressions: developers.google.com/safe-browsing/
    reference/URLs.and.Hashing (tested against Google's published examples).
  * hashes.search: 4-byte prefixes, at most 30 per request; empty answer = 200
    with no fullHashes; answers (also empty ones) are cached for cacheDuration.
  * Unknown threat types / attributes: the whole FullHashDetail is ignored.
    CANARY ("should not be used for enforcement") and FRAME_ONLY details are
    not treated as a match for a page.
  * Terms: no warning on Google data older than 30 minutes, so cached
    positive answers live at most 30 minutes. Warnings must say "suspected",
    carry "Advisory provided by Google" (returned as `attribution`) and say that
    accuracy cannot be guaranteed. Non-commercial use only (commercial: Web Risk).
  * The API key goes in the x-goog-api-key header (Google Cloud's recommended
    form, keeping it out of URLs and logs); `api_key_in_header: false` in
    config/safe_browsing.json falls back to the documented ?key= form.
  * Response format: "All of the response bodies are protocol-buffer formatted"
    (v5 overview). JSON is not offered: with a valid key, `$alt=json` is
    refused with 400 "Unsupported Output Format" (live, 2026-11-22). Answers
    are therefore read with a small protobuf reader, built on the field
    numbers in googleapis' safebrowsing/v5/safebrowsing.proto. It was checked
    against Google's real answer for its test page
    testsafebrowsing.appspot.com/s/phishing.html. Refusals keep Google's short
    reason, e.g. "http_400:API_KEY_INVALID".
  * Not implemented: the Global Cache / local hash lists of Real-Time and
    Local List Mode. This client is the plain real-time check with a local cache.

Failure handling: timeouts, one retry for network errors and 5xx, a token-bucket
rate limit, and an exponential back-off after failures (429 Retry-After is
respected). Every failure returns status "unavailable", never "no_match".
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import ipaddress
import json
import math
import os
import re
import threading
import time
from dataclasses import dataclass, fields
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable

import httpx
import idna

from src.preprocessing.url_normalizer import InvalidURLError, NormalizedURL, normalize_url
from src.preprocessing.url_normalizer import public_registered_domain

from .cache import TTLCache
from .results import (EXACT_URL, HARMFUL_APP_THREAT, HOSTNAME, MALWARE_THREAT, MATCH, NO_MATCH,
                      PHISHING_THREAT, REGISTERED_DOMAIN, UNAVAILABLE,
                      UNWANTED_SOFTWARE_THREAT, IntelMatch, IntelResult)

PROVIDER = "google_safe_browsing"
ATTRIBUTION = "Advisory provided by Google"
CONFIG_PATH = Path("config/safe_browsing.json")
MAX_PREFIXES_PER_REQUEST = 30
MAX_POSITIVE_CACHE_SECONDS = 30 * 60           # terms: no warning on data older than 30 minutes
MAX_CACHE_SECONDS = 24 * 3600                   # cap on any cacheDuration (the proto's 24 h limit)
MAX_UNESCAPE_ROUNDS = 1000
THREATS = {"SOCIAL_ENGINEERING": PHISHING_THREAT, "MALWARE": MALWARE_THREAT,
           "UNWANTED_SOFTWARE": UNWANTED_SOFTWARE_THREAT,
           "POTENTIALLY_HARMFUL_APPLICATION": HARMFUL_APP_THREAT}
ATTRIBUTES = {"CANARY", "FRAME_ONLY"}            # both: not a match for a top-level page
_HEX_ESCAPE = re.compile(rb"%([0-9A-Fa-f]{2})")
_SCHEME = re.compile(rb"^([A-Za-z][A-Za-z0-9+.\-]*)://")
_IPV4_PART = re.compile(r"0[xX][0-9a-fA-F]*|0[0-7]*|[1-9][0-9]*")


# --------------------------------------------------------------------- canonicalization
@dataclass(frozen=True)
class CanonicalURL:
    scheme: str
    host: str          # escaped ASCII
    path: str          # escaped, starts with "/"
    query: str | None  # escaped, None if the URL had no "?"
    is_ip: bool

    def __str__(self) -> str:
        return f"{self.scheme}://{self.host}{self.path}" + ("" if self.query is None else f"?{self.query}")


def _unescape_fully(b: bytes) -> bytes:
    for _ in range(MAX_UNESCAPE_ROUNDS):
        new = _HEX_ESCAPE.sub(lambda m: bytes([int(m.group(1), 16)]), b)
        if new == b:
            return b
        b = new
    raise ValueError("too many layers of percent-escaping")


def _escape(b: bytes) -> str:
    return "".join(f"%{c:02X}" if c <= 0x20 or c >= 0x7F or c in (0x23, 0x25) else chr(c) for c in b)


def _ipv4(host: str) -> str | None:
    """inet_aton-style: decimal, octal (0..), hex (0x..), and fewer than four parts."""
    parts = host.split(".")
    if not 1 <= len(parts) <= 4:
        return None
    values = []
    for p in parts:
        if not _IPV4_PART.fullmatch(p):
            return None
        if p[:2] in ("0x", "0X"):
            values.append(int(p[2:] or "0", 16))      # hex; a bare "0x" is 0, as in inet_aton
        elif len(p) > 1:
            values.append(int(p, 8) if p[0] == "0" else int(p))
        else:
            values.append(int(p))
    if any(v > 255 for v in values[:-1]) or values[-1] >= 256 ** (5 - len(values)):
        return None
    number = 0
    for v in values[:-1]:
        number = number * 256 + v
    number = number * 256 ** (5 - len(values)) + values[-1]
    return str(ipaddress.IPv4Address(number))


def _canonical_host(raw: bytes) -> tuple[str, bool]:
    if raw.startswith(b"[") and raw.endswith(b"]"):
        try:
            addr = ipaddress.IPv6Address(raw[1:-1].decode("ascii"))
        except (ValueError, UnicodeDecodeError):
            pass
        else:
            if addr.ipv4_mapped is not None:
                return str(addr.ipv4_mapped), True
            if addr in ipaddress.IPv6Network("64:ff9b::/96"):
                return str(ipaddress.IPv4Address(int(addr) & 0xFFFFFFFF)), True
            return f"[{addr.compressed}]", True
    raw = re.sub(rb"\.{2,}", b".", raw.strip(b"."))
    if any(c >= 0x80 for c in raw):                     # internationalized name -> punycode
        try:
            raw = idna.encode(raw.decode("utf-8"), uts46=True)
        except (UnicodeError, idna.IDNAError):
            pass                                         # not a valid IDN: escape the bytes
    raw = raw.lower()
    if all(c < 0x80 for c in raw):
        ip = _ipv4(raw.decode("ascii"))
        if ip is not None:
            return ip, True
    return _escape(raw), False


def _canonical_path(p: bytes) -> bytes:
    segments = p.split(b"/")[1:] if p.startswith(b"/") else p.split(b"/")
    trailing = p.endswith(b"/") or (segments and segments[-1] in (b".", b".."))
    out: list[bytes] = []
    for s in segments:
        if s in (b"", b"."):
            continue
        if s == b"..":
            if out:
                out.pop()
        else:
            out.append(s)
    return b"/" + b"/".join(out) + (b"/" if out and trailing else b"")


def canonicalize(url: str | bytes) -> CanonicalURL:
    """Google's canonicalization; raises ValueError for input without a host."""
    b = url.encode("utf-8") if isinstance(url, str) else bytes(url)
    b = b.strip().replace(b"\t", b"").replace(b"\r", b"").replace(b"\n", b"")
    b = b.split(b"#", 1)[0]                              # fragment
    b = _unescape_fully(b)
    m = _SCHEME.match(b)
    scheme, rest = (m.group(1).decode("ascii").lower(), b[m.end():]) if m else ("http", b)
    cut = min([i for i in (rest.find(b"/"), rest.find(b"?")) if i >= 0], default=len(rest))
    authority, tail = rest[:cut], rest[cut:]
    authority = authority.rsplit(b"@", 1)[-1]          # drop user:password@
    if authority.startswith(b"["):
        host_raw = authority[:authority.find(b"]") + 1] if b"]" in authority else authority
    else:
        host_raw, colon, port = authority.rpartition(b":")
        if not colon or not (port.isdigit() or port == b""):
            host_raw = authority
    host, is_ip = _canonical_host(host_raw)
    if not host:
        raise ValueError("no host")
    path_raw, q, query_raw = tail.partition(b"?")
    path = _escape(_canonical_path(path_raw or b"/"))
    return CanonicalURL(scheme, host, path, _escape(query_raw) if q else None, is_ip)


# --------------------------------------------------------------------- expressions
def expressions(c: CanonicalURL) -> list[str]:
    """Host-suffix / path-prefix expressions (at most 5 hosts x 6 paths = 30)."""
    hosts = [c.host]
    if not c.is_ip:
        base = public_registered_domain(c.host)
        if base and base != c.host and c.host.endswith("." + base):
            extra = c.host[: -len(base) - 1].split(".")
            suffixes = [base] + [".".join(extra[i:] + [base]) for i in range(len(extra) - 1, 0, -1)]
            hosts += list(reversed(suffixes[:4]))
    paths = ([f"{c.path}?{c.query}"] if c.query is not None else []) + [c.path]
    dirs = c.path.split("/")[1:-1]
    paths += ["/"] + ["/" + "/".join(dirs[:i]) + "/" for i in range(1, min(len(dirs), 3) + 1)]
    out: list[str] = []
    for h in hosts:
        for p in paths:
            e = h + p
            if e not in out:
                out.append(e)
    return out[:MAX_PREFIXES_PER_REQUEST]


def full_hash(expression: str) -> bytes:
    return hashlib.sha256(expression.encode("ascii")).digest()


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")


def _b64decode(text: str) -> bytes:
    text = text.strip()
    return base64.b64decode(text.replace("-", "+").replace("_", "/") + "=" * (-len(text) % 4),
                            validate=True)


# --------------------------------------------------------------------- protobuf answers
# Field numbers from googleapis (read 2026-11-22):
#   google/security/safebrowsing/v5/safebrowsing.proto
#     SearchHashesResponse { repeated FullHash full_hashes = 1; Duration cache_duration = 2; }
#     FullHash { bytes full_hash = 1; repeated FullHashDetail full_hash_details = 2; }
#     FullHashDetail { ThreatType threat_type = 1; repeated ThreatAttribute attributes = 2; }
#   google/protobuf/duration.proto  Duration { int64 seconds = 1; int32 nanos = 2; }
#   google/rpc/status.proto          Status { int32 code = 1; string message = 2; repeated Any details = 3; }
#   google/protobuf/any.proto        Any { string type_url = 1; bytes value = 2; }
#   google/rpc/error_details.proto   ErrorInfo { string reason = 1; ... }
# A read-only wire-format reader for these few messages, instead of the protobuf package.
PROTOBUF_TYPE = "application/x-protobuf"
THREAT_TYPE_NUMBERS = {1: "MALWARE", 2: "SOCIAL_ENGINEERING", 3: "UNWANTED_SOFTWARE",
                       4: "POTENTIALLY_HARMFUL_APPLICATION"}          # 0 = THREAT_TYPE_UNSPECIFIED
ATTRIBUTE_NUMBERS = {1: "CANARY", 2: "FRAME_ONLY"}                    # 0 = THREAT_ATTRIBUTE_UNSPECIFIED
RPC_CODES = {3: "INVALID_ARGUMENT", 5: "NOT_FOUND", 7: "PERMISSION_DENIED", 8: "RESOURCE_EXHAUSTED",
             9: "FAILED_PRECONDITION", 13: "INTERNAL", 14: "UNAVAILABLE", 16: "UNAUTHENTICATED"}  # google/rpc/code.proto


def _varint(buf: bytes, i: int) -> tuple[int, int]:
    value = shift = 0
    while True:
        if i >= len(buf) or shift > 63:
            raise ValueError("truncated or too long varint")
        b = buf[i]
        i += 1
        value |= (b & 0x7F) << shift
        if b < 0x80:
            return value, i
        shift += 7


def _pb_fields(buf: bytes):
    """(field number, wire type, value) for each field of one message. The value is an
    int for varints and bytes otherwise. Callers skip fields they do not know."""
    i = 0
    while i < len(buf):
        key, i = _varint(buf, i)
        number, wire = key >> 3, key & 7
        if number == 0:
            raise ValueError("field number 0")
        if wire == 0:
            value, i = _varint(buf, i)
        elif wire in (1, 5):                                  # fixed64 / fixed32
            size = 8 if wire == 1 else 4
            value, i = buf[i:i + size], i + size
        elif wire == 2:                                       # length-delimited
            size, i = _varint(buf, i)
            value, i = buf[i:i + size], i + size
        else:                                                 # groups: not used by these messages
            raise ValueError(f"unsupported wire type {wire}")
        if i > len(buf):
            raise ValueError("truncated field")
        yield number, wire, value


def _pb_enums(wire: int, value) -> list[int]:
    """A repeated enum field: packed (one run of varints, the proto3 default) or not."""
    if wire == 0:
        return [value]
    if wire != 2:
        raise ValueError("bad wire type for an enum")
    out, i = [], 0
    while i < len(value):
        v, i = _varint(value, i)
        out.append(v)
    return out


def _decode_search_response(buf: bytes):
    """SearchHashesResponse -> ([(full hash, [(threat type, [attribute, ...])])], cache seconds).
    Enum values this client does not know come back as None."""
    full_hashes, ttl = [], 0.0
    for number, wire, value in _pb_fields(buf):
        if number == 1 and wire == 2:                         # FullHash
            h, details = b"", []
            for n2, w2, v2 in _pb_fields(value):
                if n2 == 1 and w2 == 2:
                    h = v2
                elif n2 == 2 and w2 == 2:                     # FullHashDetail
                    threat, attrs = 0, []
                    for n3, w3, v3 in _pb_fields(v2):
                        if n3 == 1 and w3 == 0:
                            threat = v3
                        elif n3 == 2:
                            attrs += _pb_enums(w3, v3)
                    details.append((THREAT_TYPE_NUMBERS.get(threat),
                                    [ATTRIBUTE_NUMBERS.get(a) for a in attrs]))
            full_hashes.append((h, details))
        elif number == 2 and wire == 2:                       # Duration
            seconds = nanos = 0
            for n2, w2, v2 in _pb_fields(value):
                if n2 == 1 and w2 == 0:
                    seconds = v2
                elif n2 == 2 and w2 == 0:
                    nanos = v2
            if seconds >= 2**63 or nanos >= 2**31:            # negative numbers on the wire
                raise ValueError("negative cache duration")
            ttl = seconds + nanos / 1e9
    return full_hashes, ttl


def _status_reasons(buf: bytes) -> list[str | None]:
    """google.rpc.Status (protobuf) -> [ErrorInfo reasons..., canonical code name]."""
    reasons, code = [], 0
    for number, wire, value in _pb_fields(buf):
        if number == 1 and wire == 0:
            code = value
        elif number == 3 and wire == 2:                       # Any
            type_url, payload = b"", b""
            for n2, w2, v2 in _pb_fields(value):
                if n2 == 1 and w2 == 2:
                    type_url = v2
                elif n2 == 2 and w2 == 2:
                    payload = v2
            if type_url.endswith(b"/google.rpc.ErrorInfo"):
                reasons += [v.decode("ascii", "replace") for n, w, v in _pb_fields(payload) if n == 1 and w == 2]
    return reasons + [RPC_CODES.get(code)]


# --------------------------------------------------------------------- config
@dataclass(frozen=True)
class SafeBrowsingConfig:
    api_key_env: str = "SAFE_BROWSING_API_KEY"
    endpoint: str = "https://safebrowsing.googleapis.com/v5/hashes:search"
    api_key_in_header: bool = True
    timeout_seconds: float = 2.0
    retries: int = 1
    retry_delay_seconds: float = 0.2
    max_requests_per_minute: int = 60
    backoff_base_seconds: float = 60.0
    backoff_max_seconds: float = 1800.0
    max_cache_entries: int = 50_000

    def __post_init__(self) -> None:
        if not self.endpoint.startswith("https://"):
            raise ValueError("endpoint must use https")
        if not self.api_key_env or not isinstance(self.api_key_in_header, bool):
            raise ValueError("api_key_env must be set and api_key_in_header must be true/false")
        for name in ("timeout_seconds", "backoff_base_seconds", "backoff_max_seconds"):
            v = getattr(self, name)
            if not (isinstance(v, (int, float)) and math.isfinite(v) and v > 0):
                raise ValueError(f"{name} must be > 0")
        if not (isinstance(self.retries, int) and 0 <= self.retries <= 3):
            raise ValueError("retries must be 0..3")
        if not (isinstance(self.max_requests_per_minute, int) and self.max_requests_per_minute >= 1):
            raise ValueError("max_requests_per_minute must be >= 1")
        if not (isinstance(self.max_cache_entries, int) and self.max_cache_entries >= 1):
            raise ValueError("max_cache_entries must be >= 1")
        if self.retry_delay_seconds < 0:
            raise ValueError("retry_delay_seconds must be >= 0")

    @classmethod
    def from_file(cls, path: Path | str = CONFIG_PATH) -> "SafeBrowsingConfig":
        path = Path(path)
        if not path.is_file():
            return cls()
        data = json.loads(path.read_text(encoding="utf-8"))
        allowed = {f.name for f in fields(cls)}
        if not isinstance(data, dict) or set(data) - allowed:
            raise ValueError(f"{path}: unknown keys {sorted(set(data) - allowed)}")
        return cls(**data)


# --------------------------------------------------------------------- client
class _TokenBucket:
    def __init__(self, per_minute: int, clock: Callable[[], float]):
        self.capacity, self.rate, self.clock = float(per_minute), per_minute / 60.0, clock
        self.tokens, self.last = float(per_minute), clock()

    def take(self) -> bool:
        now = self.clock()
        self.tokens = min(self.capacity, self.tokens + (now - self.last) * self.rate)
        self.last = now
        if self.tokens >= 1.0:
            self.tokens -= 1.0
            return True
        return False


class _RequestFailed(Exception):
    def __init__(self, reason: str, retry_after: float | None = None):
        super().__init__(reason)
        self.reason, self.retry_after = reason, retry_after


def _is_private(n: NormalizedURL) -> bool:
    """Hosts that cannot be on a public blocklist: never sent anywhere."""
    if n.is_ip:
        try:
            ip = ipaddress.ip_address(n.host.strip("[]"))
        except ValueError:
            return True
        return not ip.is_global
    return not n.registered_domain


class SafeBrowsingClient:
    """Thread-safe. check() never raises for network or API problems."""

    name = PROVIDER

    def __init__(self, config: SafeBrowsingConfig | None = None, *, api_key: str | None = None,
                 http: httpx.Client | None = None, clock: Callable[[], float] = time.monotonic,
                 now: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
                 sleep: Callable[[float], None] = time.sleep):
        self.config = config or SafeBrowsingConfig()
        self._key = api_key if api_key is not None else os.environ.get(self.config.api_key_env, "")
        self._http = http or httpx.Client(timeout=self.config.timeout_seconds)
        self._clock, self._now, self._sleep = clock, now, sleep
        self._cache = TTLCache(self.config.max_cache_entries, clock)     # 4-byte prefix -> answer
        self._bucket = _TokenBucket(self.config.max_requests_per_minute, clock)
        self._lock = threading.Lock()
        self._failures, self._blocked_until = 0, float("-inf")
        self.requests_sent = 0

    @property
    def enabled(self) -> bool:
        return bool(self._key)

    def close(self) -> None:
        self._http.close()

    # ------------------------------------------------------------------ public
    def check(self, value: str | NormalizedURL, input_type: str = "full_url") -> IntelResult:
        """Raises InvalidURLError for input that cannot be normalized; never for the API."""
        return self._check(value, input_type, network=True)

    def check_offline(self, value: str | NormalizedURL, input_type: str = "full_url") -> IntelResult | None:
        """Like check(), but never sends a request: the answer from the local prefix
        cache (or for a host that is never sent), or None if Google must be asked."""
        return self._check(value, input_type, network=False)

    def _check(self, value, input_type: str, network: bool) -> IntelResult | None:
        n = value if isinstance(value, NormalizedURL) else normalize_url(value, input_type)
        if not self.enabled:
            return IntelResult(UNAVAILABLE, reason="disabled:no_api_key")
        if _is_private(n):
            return IntelResult(UNAVAILABLE, reason="not_sent:private_or_local_host")
        try:
            canon = canonicalize(n.original if n.input_type == "full_url" else f"http://{n.host}/")
            exprs = expressions(canon)
        except ValueError:
            return IntelResult(UNAVAILABLE, reason="not_sent:not_canonicalizable")
        hashes = {full_hash(e): e for e in exprs}
        prefixes = sorted({h[:4] for h in hashes})

        found, missing = self._from_cache(prefixes, hashes)
        if found:
            return self._result(canon, found)
        if missing and not network:
            return None
        if missing:
            try:
                answer, ttl = self._search(missing)
            except _RequestFailed as exc:
                return IntelResult(UNAVAILABLE, reason=exc.reason)
            self._store(missing, answer, ttl)
            found = [(hashes[h], details, ttl) for h, details in answer.items() if h in hashes]
            found = [(e, d, t) for e, d, t in found if d]
            if found:
                return self._result(canon, [(e, d, min(t, MAX_POSITIVE_CACHE_SECONDS)) for e, d, t in found])
        return IntelResult(NO_MATCH)

    # ------------------------------------------------------------------ cache
    def _from_cache(self, prefixes, hashes):
        found, missing = [], []
        for p in prefixes:
            entry = self._cache.get(p.hex())
            if entry is None:
                missing.append(p)
                continue
            expires_at, answer = entry
            remaining = max(expires_at - self._clock(), 0.0)
            found += [(hashes[h], d, remaining) for h, d in answer.items() if h in hashes and d]
        return found, missing

    def _store(self, prefixes, answer: dict[bytes, tuple], ttl: float) -> None:
        for p in prefixes:
            mine = {h: d for h, d in answer.items() if h[:4] == p}
            # answers with listed hashes: at most 30 minutes (terms); empty answers: cacheDuration
            life = min(ttl, MAX_POSITIVE_CACHE_SECONDS) if mine else ttl
            self._cache.set(p.hex(), (self._clock() + life, mine), life)

    # ------------------------------------------------------------------ network
    def _search(self, prefixes: list[bytes]) -> tuple[dict[bytes, tuple], float]:
        with self._lock:
            if self._clock() < self._blocked_until:
                raise _RequestFailed("backoff_after_errors")
            if not self._bucket.take():
                raise _RequestFailed("rate_limited")
        params = [("hashPrefixes", _b64(p)) for p in prefixes[:MAX_PREFIXES_PER_REQUEST]]
        headers = {}
        if self.config.api_key_in_header:
            headers["x-goog-api-key"] = self._key
        else:
            params.append(("key", self._key))
        try:
            response = self._send(params, headers)
            answer, ttl = self._parse(response)
        except _RequestFailed as exc:
            self._failed(exc.retry_after)
            raise
        with self._lock:
            self._failures = 0
        return answer, ttl

    def _send(self, params, headers) -> httpx.Response:
        attempts = self.config.retries + 1
        for attempt in range(attempts):
            with self._lock:
                self.requests_sent += 1
            try:
                r = self._http.get(self.config.endpoint, params=params, headers=headers,
                                   timeout=self.config.timeout_seconds)
            except httpx.TimeoutException:
                reason = "timeout"
            except httpx.TransportError:
                reason = "network_error"
            else:
                if r.status_code == 200:
                    return r
                if r.status_code == 429:
                    raise _RequestFailed("http_429", _retry_after(r))
                if r.status_code < 500:                   # 400 bad request, 403 bad key: no retry
                    raise _RequestFailed(f"http_{r.status_code}{_google_reason(r)}")
                reason = f"http_{r.status_code}"
            if attempt + 1 < attempts:
                self._sleep(self.config.retry_delay_seconds)
        raise _RequestFailed(reason)

    def _parse(self, r: httpx.Response) -> tuple[dict[bytes, tuple], float]:
        if r.headers.get("content-type", "").split(";")[0].strip().lower() != PROTOBUF_TYPE:
            raise _RequestFailed("bad_response")          # e.g. a Wi-Fi login page
        try:
            full_hashes, ttl = _decode_search_response(r.content)
            answer: dict[bytes, tuple] = {}
            for h, details in full_hashes:
                if len(h) != 32:
                    raise ValueError("full hash is not 32 bytes")
                threats = []
                for threat, attrs in details:
                    if threat is None or None in attrs:
                        continue                          # unknown value: ignore the whole detail
                    if attrs:                             # CANARY / FRAME_ONLY: not for a page
                        continue
                    threats.append(THREATS[threat])
                answer[h] = tuple(sorted(set(answer.get(h, ())) | set(threats)))
        except ValueError as exc:
            raise _RequestFailed("bad_response") from exc
        return answer, min(ttl, MAX_CACHE_SECONDS)

    def _failed(self, retry_after: float | None) -> None:
        with self._lock:
            self._failures += 1
            wait = min(self.config.backoff_base_seconds * 2 ** (self._failures - 1),
                       self.config.backoff_max_seconds)
            if retry_after is not None:
                wait = max(wait, min(retry_after, 24 * 3600))
            self._blocked_until = self._clock() + wait

    # ------------------------------------------------------------------ result
    def _result(self, canon: CanonicalURL, found) -> IntelResult:
        exact = {canon.host + canon.path} | ({f"{canon.host}{canon.path}?{canon.query}"}
                                            if canon.query is not None else set())
        when = self._now()
        by_level: dict[str, list] = {}
        for expr, threats, remaining in found:
            host = expr.split("/", 1)[0]
            level = (EXACT_URL if expr in exact else HOSTNAME if host == canon.host
                     else REGISTERED_DOMAIN)
            by_level.setdefault(level, []).append((threats, remaining))
        stamp = when.strftime("%Y-%m-%dT%H:%M:%SZ")
        matches = tuple(
            IntelMatch(level, PROVIDER, len(items), stamp, stamp,
                       (when + timedelta(seconds=max(r for _, r in items))).strftime("%Y-%m-%dT%H:%M:%SZ"),
                       (), tuple(sorted({t for ts, _ in items for t in ts})), ATTRIBUTION)
            for level, items in sorted(by_level.items(), key=lambda kv: (EXACT_URL, HOSTNAME,
                                                                           REGISTERED_DOMAIN).index(kv[0])))
        return IntelResult(MATCH, matches)

    def stats(self) -> dict:
        with self._lock:
            blocked = max(self._blocked_until - self._clock(), 0.0)
        return {"enabled": self.enabled, "requests_sent": self.requests_sent,
                "consecutive_failures": self._failures, "blocked_for_seconds": blocked,
                "prefix_cache": self._cache.stats()}


_GOOGLE_REASON = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")


def _google_reason(r: httpx.Response) -> str:
    """':API_KEY_INVALID' from Google's error (ErrorInfo reason, else the status code
    name), protobuf or JSON, or ''. Only an upper-case code is kept, never free text,
    so nothing else from the answer (or the request) ends up in results and logs."""
    ctype = r.headers.get("content-type", "").lower()
    try:
        if PROTOBUF_TYPE in ctype:
            candidates = _status_reasons(r.content)
        elif "json" in ctype:
            err = r.json().get("error")
            candidates = [d.get("reason") for d in err.get("details", []) if isinstance(d, dict)]
            candidates.append(err.get("status"))
        else:
            return ""
    except (ValueError, AttributeError, TypeError):
        return ""
    for c in candidates:
        if isinstance(c, str) and _GOOGLE_REASON.match(c):
            return f":{c}"
    return ""


def _retry_after(r: httpx.Response) -> float | None:
    try:
        return float(r.headers.get("retry-after", ""))
    except ValueError:
        return None


# --------------------------------------------------------------------- CLI
def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--config", type=Path, default=CONFIG_PATH)
    sub = ap.add_subparsers(dest="command", required=True)
    ex = sub.add_parser("expressions", help="show what would be hashed (offline)")
    ex.add_argument("url")
    ck = sub.add_parser("check", help="ask Google (needs the API key environment variable)")
    ck.add_argument("value")
    ck.add_argument("--domain", action="store_true")
    args = ap.parse_args(argv)
    config = SafeBrowsingConfig.from_file(args.config)
    if args.command == "expressions":
        try:
            canon = canonicalize(args.url)
        except ValueError as exc:
            print(f"cannot canonicalize: {exc}")
            return 2
        print(f"canonical: {canon}")
        for e in expressions(canon):
            print(f"  {_b64(full_hash(e)[:4]):>8}  {e}")
        print("only the 4-byte prefixes in the left column would be sent")
        return 0
    client = SafeBrowsingClient(config)
    try:
        result = client.check(args.value, "domain" if args.domain else "full_url")
    except InvalidURLError as exc:
        print(f"not a valid {'hostname' if args.domain else 'URL'} ({exc.reason})")
        return 2
    finally:
        client.close()
    print(json.dumps(result.to_dict(), indent=2))
    if result.status == MATCH:
        print(f"Suspected unsafe site. {ATTRIBUTION}. Google cannot guarantee that its "
              "information is comprehensive and error-free.")
    elif result.status == NO_MATCH:
        print("no_match only means Google does not list it; it is NOT a sign that it is safe.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
