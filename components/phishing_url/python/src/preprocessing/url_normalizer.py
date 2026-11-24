"""URL normalization: one canonical form shared by training and inference.

Pure string processing. This module never performs network I/O, so it cannot
be abused for SSRF, and it works offline.
"""
from __future__ import annotations

import ipaddress
import re
import string
from dataclasses import dataclass
from typing import Literal
from urllib.parse import urlsplit

import idna
import tldextract

InputType = Literal["full_url", "domain"]

MAX_RAW_LENGTH = 8192
ALLOWED_SCHEMES = frozenset({"http", "https", "ftp"})
DEFAULT_PORTS = {"http": 80, "https": 443, "ftp": 21}

_SCHEME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.\-]*://")
_PERCENT_RE = re.compile(r"%([0-9A-Fa-f]{2})")
_NON_ASCII_RE = re.compile(r"[^\x00-\x7f]+")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_STRIP_INNER_RE = re.compile(r"[\t\r\n]")
_ASCII_HOST_RE = re.compile(r"[a-z0-9_.-]+")
_UNRESERVED = frozenset(string.ascii_letters + string.digits + "-._~")

# Offline-only: use the bundled Public Suffix List snapshot, never download one.
_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=())
# Same snapshot with PSL *private* suffixes (web.app, github.io, blogspot.com...).
_PRIVATE_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=(), include_psl_private_domains=True)


def private_registered_domain(host: str) -> str:
    """Registered domain with private suffixes honoured.

    'a.b.example.co.uk' -> 'example.co.uk', but 'evil.web.app' -> 'evil.web.app'
    (a tenant of a shared platform is its own site). '' for IPs and bare names.
    """
    ext = _PRIVATE_EXTRACTOR(host)
    return f"{ext.domain}.{ext.suffix}" if ext.domain and ext.suffix else ""


def public_registered_domain(host: str) -> str:
    """Registered domain by the ICANN public suffixes only ('' if unknown).

    'a.b.example.co.uk' -> 'example.co.uk' and 'evil.web.app' -> 'web.app'
    (private suffixes ignored). Used where an external standard says eTLD+1.
    """
    ext = _EXTRACTOR(host)
    return f"{ext.domain}.{ext.suffix}" if ext.domain and ext.suffix else ""


class InvalidURLError(ValueError):
    """Raised for input that cannot be safely normalized.

    `reason` is a short machine-readable code. The message intentionally never
    contains the input, so sensitive URLs do not leak into logs.
    """

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True, slots=True)
class NormalizedURL:
    original: str            # untouched input (redact before logging!)
    input_type: InputType
    scheme: str | None       # None in domain mode
    scheme_inferred: bool    # True if the input had no scheme
    host: str                # lowercase ASCII (punycode) or compressed IP
    host_unicode: str        # human-readable form of the host
    port: int | None         # only if non-default
    path: str                # "" in domain mode, otherwise starts with "/"
    query: str
    has_userinfo: bool       # input contained user[:pass]@
    is_ip: bool
    has_punycode: bool       # any label starts with "xn--"
    subdomain: str
    domain: str
    suffix: str
    registered_domain: str   # "" for IPs / unknown suffixes (e.g. "localhost")
    canonical: str           # scheme://host[:port]/path[?query]
    model_string: str        # canonical without scheme: what the CNN will read


def normalize_url(raw: str, input_type: InputType = "full_url") -> NormalizedURL:
    """Normalize a full URL or a bare hostname. Raises InvalidURLError."""
    if input_type not in ("full_url", "domain"):
        raise ValueError(f"Unknown input_type: {input_type!r}")
    if not isinstance(raw, str):
        raise InvalidURLError("not_a_string")
    text = _clean(raw)
    if input_type == "domain":
        return _normalize_domain(raw, text)
    return _normalize_full(raw, text)


# --------------------------------------------------------------------------
# internals
# --------------------------------------------------------------------------
def _clean(raw: str) -> str:
    if len(raw) > MAX_RAW_LENGTH:
        raise InvalidURLError("too_long")
    # Browsers ignore tabs/newlines anywhere inside a URL; mirror that.
    text = _STRIP_INNER_RE.sub("", raw.strip())
    if not text:
        raise InvalidURLError("empty")
    if " " in text or _CONTROL_RE.search(text):
        raise InvalidURLError("illegal_characters")
    return text


def _backslashes_to_slashes(text: str) -> str:
    """Browsers treat '\\' as '/' before the query/fragment. Mirror that so
    we agree with the browser about where the host ends."""
    match = re.search(r"[?#]", text)
    cut = match.start() if match else len(text)
    return text[:cut].replace("\\", "/") + text[cut:]


def _encode_non_ascii(text: str) -> str:
    return _NON_ASCII_RE.sub(
        lambda m: "".join(f"%{b:02X}" for b in m.group().encode("utf-8", "replace")),
        text,
    )


def _fix_percent(text: str) -> str:
    """Decode %XX of unreserved characters; uppercase hex of the others."""

    def repl(match: re.Match[str]) -> str:
        char = chr(int(match.group(1), 16))
        return char if char in _UNRESERVED else "%" + match.group(1).upper()

    return _PERCENT_RE.sub(repl, text)


def _normalize_component(text: str) -> str:
    return _fix_percent(_encode_non_ascii(text))


def _process_host(hostname: str) -> tuple[str, str, bool]:
    """Return (ascii_host, unicode_host, is_ip)."""
    host = hostname.strip("[]").rstrip(".").lower()
    if not host:
        raise InvalidURLError("no_host")
    if "%" in host:
        raise InvalidURLError("invalid_host")

    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    if ip is not None:
        return str(ip), str(ip), True

    if host.isascii():
        ascii_host = host
    else:
        try:
            ascii_host = idna.encode(host, uts46=True).decode("ascii").lower()
        except UnicodeError as exc:  # idna.IDNAError subclasses UnicodeError
            raise InvalidURLError("idna_failure") from exc

    if (
        not _ASCII_HOST_RE.fullmatch(ascii_host)
        or ".." in ascii_host
        or ascii_host.startswith(".")
    ):
        raise InvalidURLError("invalid_host")

    try:
        unicode_host = idna.decode(ascii_host)
    except UnicodeError:
        unicode_host = ascii_host
    return ascii_host, unicode_host, False


def _split_domain(host: str, is_ip: bool) -> tuple[str, str, str, str]:
    if is_ip:
        return "", "", "", ""
    ext = _EXTRACTOR(host)
    registered = f"{ext.domain}.{ext.suffix}" if ext.domain and ext.suffix else ""
    return ext.subdomain, ext.domain, ext.suffix, registered


def _render_host(host: str) -> str:
    return f"[{host}]" if ":" in host else host


def _normalize_domain(original: str, text: str) -> NormalizedURL:
    if any(ch in text for ch in "/\\?#@"):
        raise InvalidURLError("not_a_hostname")
    host, host_unicode, is_ip = _process_host(text)
    subdomain, domain, suffix, registered = _split_domain(host, is_ip)
    rendered = _render_host(host)
    return NormalizedURL(
        original=original, input_type="domain", scheme=None, scheme_inferred=False,
        host=host, host_unicode=host_unicode, port=None, path="", query="",
        has_userinfo=False, is_ip=is_ip,
        has_punycode=any(l.startswith("xn--") for l in host.split(".")),
        subdomain=subdomain, domain=domain, suffix=suffix, registered_domain=registered,
        canonical=rendered, model_string=rendered,
    )


def _normalize_full(original: str, text: str) -> NormalizedURL:
    text = _backslashes_to_slashes(text)
    scheme_inferred = _SCHEME_RE.match(text) is None
    try:
        parts = urlsplit("//" + text if scheme_inferred else text)
        explicit_port = parts.port
        hostname = parts.hostname
    except ValueError as exc:
        raise InvalidURLError("unparseable") from exc

    scheme = "http" if scheme_inferred else parts.scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        raise InvalidURLError("unsupported_scheme")
    if not hostname:
        raise InvalidURLError("no_host")

    host, host_unicode, is_ip = _process_host(hostname)
    port = explicit_port if explicit_port not in (None, DEFAULT_PORTS[scheme]) else None
    path = _normalize_component(parts.path) or "/"
    query = _normalize_component(parts.query)

    model_string = (
        f"{_render_host(host)}"
        f"{f':{port}' if port is not None else ''}"
        f"{path}"
        f"{f'?{query}' if query else ''}"
    )
    subdomain, domain, suffix, registered = _split_domain(host, is_ip)
    return NormalizedURL(
        original=original, input_type="full_url", scheme=scheme,
        scheme_inferred=scheme_inferred, host=host, host_unicode=host_unicode,
        port=port, path=path, query=query, has_userinfo="@" in parts.netloc,
        is_ip=is_ip,
        has_punycode=any(l.startswith("xn--") for l in host.split(".")),
        subdomain=subdomain, domain=domain, suffix=suffix, registered_domain=registered,
        canonical=f"{scheme}://{model_string}", model_string=model_string,
    )