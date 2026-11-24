"""Make a URL safe to write into a log: no query values, no user:password, no fragment.

    redact_url("https://user:pw@bank.example/reset?token=abc&id=7#top")
    -> "https://bank.example/reset?token=REDACTED&id=REDACTED"

Why: query strings and the user-info part often carry tokens, e-mail addresses
and session IDs, and the spec asks for sensitive query parameters to be redacted
in logs. Parameter *names* are kept when they look like names ("cmd", "id"),
because they help to recognise a phishing kit without exposing anyone's data; a
bare value without "=" (often a token) is not kept. Control characters become
"?", so a URL cannot forge extra log lines. Long results are cut.
Not caught: a secret inside the path itself (e.g. /reset/<token>); the cut limits it.
"""
from __future__ import annotations

import re
from urllib.parse import unquote_plus, urlsplit

MAX_LOG_URL = 200
_NAME = re.compile(r"^[A-Za-z0-9_.\-\[\]]{1,32}$")


def _printable(text: str) -> str:
    return "".join(c if c.isprintable() else "?" for c in text)


def redact_url(raw: object, max_length: int = MAX_LOG_URL) -> str:
    if not isinstance(raw, str):
        return "<not text>"
    try:
        parts = urlsplit(raw.strip())
        port = parts.port
    except ValueError:
        return "<unparseable URL>"
    host = parts.hostname or ""
    if ":" in host:                                   # IPv6 literal
        host = f"[{host}]"
    netloc = host + (f":{port}" if port is not None else "")
    if parts.netloc:
        text = f"{parts.scheme}://{netloc}" if parts.scheme else f"//{netloc}"
    else:
        text = f"{parts.scheme}:" if parts.scheme else ""
    text += parts.path
    if parts.query:
        kept = []
        for segment in parts.query.split("&"):
            if not segment:
                continue
            name, eq, _ = segment.partition("=")
            name = unquote_plus(name)
            # "name=value": keep a plain name; a bare segment (no "=") is a value, so hide it all
            kept.append(f"{name if _NAME.match(name) else 'REDACTED'}=REDACTED" if eq else "REDACTED")
        text += "?" + ("&".join(kept) or "REDACTED")
    if len(text) > max_length:
        text = text[:max_length] + "..."
    return _printable(text)
