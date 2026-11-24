"""Connect the team's SMS scam detector (package `sms_detection`) to this URL detector.

    python -m src.integration.sms_bridge "Your KYC is pending. Update at https://sbi-kyc-verify.in/login" --sender +919876543210
    python -m src.integration.sms_bridge --file messages.json          # [{"text": "...", "sender": "..."}, ...]
    Get-Content msg.txt -Raw | python -m src.integration.sms_bridge    # message from stdin (no quoting trouble)
    python -m src.integration.sms_bridge "..." --api http://127.0.0.1:8123   # ask the running HTTP API instead

Run it from this repository's root (the model and config/ paths are relative). The SMS
package must be importable: `pip install -e <path>/sms-detection --no-deps` (its model
needs scikit-learn 1.9.1, the same version as this project).

What happens to one message
  1. The SMS module scores the text: label, risk band, evidence codes. Its answer is kept unchanged.
  2. The SMS module's own extractor lists the links. It is the same list behind its URL_PRESENT
     code, and its Kotlin twin on the phone uses the same pattern.
  3. tidy_link() removes the sentence's punctuation that the extractor keeps
     ("github.com/login." -> "github.com/login"), then duplicates are dropped and at most
     MAX_LINKS links are checked.
  4. This detector checks the links, either in this process (the model loads here) or
     through POST /predict.
  5. combine(): the link check can only RAISE the message's risk, never lower it.
     * any link PHISHING            -> risk "high", URL_FLAGGED_PHISHING (+ URL_KNOWN_THREAT
                                       when a threat list matched)
     * any link UNCERTAIN           -> risk unchanged, URL_CHECK_UNCERTAIN
     * some links not checked       -> risk unchanged, URL_CHECK_UNAVAILABLE (service down,
       (down, invalid, over the cap)   unparseable link or over the cap). Unavailable never means safe.
     * every link LIKELY_SAFE       -> risk unchanged, URL_NOT_FLAGGED. A clean link does not
                                       make a message safe: "share your OTP, see sbi.co.in" is
                                       still a scam.

Privacy: links are only read as text and are never opened. The output holds no message text,
and links appear only through redact_url (query values, passwords and #fragments are
removed). The HTTP client ignores proxy settings (trust_env=False) and follows no redirects,
so links go only to the API address given. If a Google Safe Browsing key is set, the
detector sends Google only 4-byte hash prefixes, as it does for every caller.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Protocol, Sequence
from urllib.parse import urlsplit

import httpx

from src.utils.redact import redact_url

MODULE_NAME = "sms_url_bridge"
SCHEMA_VERSION = "1.0"
MAX_LINKS = 10                       # links checked per message; real SMS rarely carry more than 2
DEFAULT_API = "http://127.0.0.1:8000"

RISK_ORDER = ("low", "suspicious", "high")      # the SMS module's risk bands
URL_FLAGGED_PHISHING = "URL_FLAGGED_PHISHING"
URL_KNOWN_THREAT = "URL_KNOWN_THREAT"
URL_CHECK_UNCERTAIN = "URL_CHECK_UNCERTAIN"
URL_CHECK_UNAVAILABLE = "URL_CHECK_UNAVAILABLE"
URL_NOT_FLAGGED = "URL_NOT_FLAGGED"

# The SMS module's action codes and display order (sms_detection/policy/action_codes.py).
ACTION_ORDER = ("NO_ACTION", "MARK_AS_SPAM", "DO_NOT_INTERACT", "DO_NOT_CLICK", "DO_NOT_SHARE_OTP",
                "DO_NOT_SHARE_PERSONAL_INFO", "DO_NOT_SEND_MONEY", "VERIFY_BEFORE_ACTING",
                "VERIFY_USING_OFFICIAL_CHANNEL", "REPORT_AS_SCAM")
LOW_BAND_ONLY = frozenset({"NO_ACTION", "MARK_AS_SPAM", "DO_NOT_INTERACT"})
PHISHING_LINK_ACTIONS = ("DO_NOT_CLICK", "VERIFY_USING_OFFICIAL_CHANNEL", "REPORT_AS_SCAM")

_TRAILING = ".,;:!?'\"`*"
_LEADING = "([{<'\"`"
_CLOSERS = {")": "(", "]": "[", "}": "{", ">": "<"}


class CheckUnavailable(RuntimeError):
    """The URL detector could not answer. `reason` is a short code, never a URL."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


class SmsModuleMissing(ImportError):
    pass


class UrlChecker(Protocol):
    def check(self, urls: list[str]) -> list[dict]:
        """One API-shaped result per URL, in order (decision lowercase). Raises CheckUnavailable."""


# ---------------------------------------------------------------- links
def tidy_link(raw: str) -> str | None:
    """Strip what belongs to the sentence, not the link: trailing . , ; : ! ? quotes, and a
    closing bracket that has no opening one inside the link ("(see x.com/a)" -> "x.com/a",
    but "wiki/Python_(language)" keeps its bracket). None if nothing is left."""
    s = str(raw).strip().lstrip(_LEADING)
    while s:
        last = s[-1]
        if last in _TRAILING or (last in _CLOSERS and s.count(last) > s.count(_CLOSERS[last])):
            s = s[:-1]
        else:
            break
    return s or None


def tidy_links(raws: Sequence[str]) -> list[str]:
    return list(dict.fromkeys(t for t in map(tidy_link, raws) if t))


# ---------------------------------------------------------------- the rule
def _ordered(actions) -> list[str]:
    rank = {code: i for i, code in enumerate(ACTION_ORDER)}
    return sorted(dict.fromkeys(actions), key=lambda c: rank.get(c, len(rank)))


def _link_view(url: str, item: Mapping | None) -> dict:
    if item is None:
        return {"display_url": redact_url(url), "decision": None, "risk_score": None, "source": None,
                "reasons": [], "threat_types": [], "pending": [], "error": "not_checked"}
    return {"display_url": redact_url(url), "decision": item.get("decision"),
            "risk_score": item.get("risk_score"), "source": item.get("source"),
            "reasons": list(item.get("reasons") or []), "threat_types": list(item.get("threat_types") or []),
            "pending": list(item.get("pending") or []), "error": item.get("error")}


def combine(sms: Mapping[str, Any], links: Sequence[str], items: Sequence[Mapping] | None, *,
            not_checked: int = 0, error: str | None = None) -> dict:
    """The SMS answer plus the link answers -> one result. `links` are the links that were sent,
    `items` the detector's answers for them (None: the detector was unavailable), `not_checked`
    the links left out (over the cap)."""
    if items is not None and len(items) != len(links):
        raise ValueError("one detector answer per link is required")
    views = [_link_view(u, None if items is None else items[i]) for i, u in enumerate(links)]
    decisions = [v["decision"] for v in views]
    unchecked = not_checked + decisions.count(None)
    phishing = [v for v in views if v["decision"] == "phishing"]

    codes: list[str] = []
    if phishing:
        codes.append(URL_FLAGGED_PHISHING)
        if any(v["source"] == "threat_intel" for v in phishing):
            codes.append(URL_KNOWN_THREAT)
    if "uncertain" in decisions:
        codes.append(URL_CHECK_UNCERTAIN)
    if unchecked:
        codes.append(URL_CHECK_UNAVAILABLE)
    if views and not codes:                              # all checked, all likely_safe
        codes.append(URL_NOT_FLAGGED)

    sms_risk = sms.get("risk_level")
    if sms_risk not in RISK_ORDER:
        raise ValueError(f"unknown SMS risk_level {sms_risk!r}: expected one of {RISK_ORDER}")
    risk = "high" if phishing else sms_risk
    raised = risk != sms_risk
    actions = list(sms.get("recommended_action_codes") or [])
    if phishing:
        actions += PHISHING_LINK_ACTIONS
    if raised:                                           # a high-risk message gets high-risk advice
        actions = [a for a in actions if a not in LOW_BAND_ONLY and a != "VERIFY_BEFORE_ACTING"]
    evidence = [dict(e) for e in sms.get("evidence") or []]
    seen = {e.get("code") for e in evidence}
    evidence += [{"code": c, "present": True} for c in codes if c not in seen]

    found = len(links) + not_checked
    status = ("no_links" if not found else "unavailable" if unchecked == found
              else "partial" if unchecked else "checked")
    return {
        "module": MODULE_NAME, "schema_version": SCHEMA_VERSION,
        "sms": dict(sms),
        "links": {"status": status, "found": found, "checked": found - unchecked, "not_checked": unchecked,
                  "error": error, "complete": not any(v["pending"] for v in views),
                  "model_versions": sorted({i["model_version"] for i in items or [] if i.get("model_version")}),
                  "results": views},
        "combined": {"risk_level": risk, "raised_by_links": raised, "evidence": evidence,
                     "recommended_action_codes": _ordered(actions)},
    }


# ---------------------------------------------------------------- checkers
def _api_item(d: dict) -> dict:
    d = dict(d)
    d["decision"] = d["decision"].lower() if d.get("decision") else None
    return d


class LocalUrlChecker:
    """Runs the detector in this process: same answers as the API, no server needed."""

    def __init__(self, service, *, timeout: float = 15.0, owns_service: bool = False):
        self.service, self.timeout, self._owns = service, timeout, owns_service

    @classmethod
    def from_files(cls, **kwargs) -> "LocalUrlChecker":
        from src.inference.service import InferenceService         # loads torch: only when asked
        return cls(InferenceService.from_files(), owns_service=True, **kwargs)

    def check(self, urls: list[str]) -> list[dict]:
        from src.inference.service import Overloaded, ServiceClosed
        try:
            results = self.service.predict(list(urls), "full_url", timeout=self.timeout)
        except Overloaded:
            raise CheckUnavailable("overloaded") from None
        except ServiceClosed:
            raise CheckUnavailable("closed") from None
        except TimeoutError:
            raise CheckUnavailable("timeout") from None
        return [_api_item(r.to_dict()) for r in results]

    def close(self) -> None:
        if self._owns:
            self.service.close(30)


class HttpUrlChecker:
    """Calls POST /predict of the running API (python -m src.api.app). On 503 it waits for
    Retry-After (at most max_retry_wait seconds) and tries again, `retries` times."""

    def __init__(self, base_url: str = DEFAULT_API, *, timeout: float = 10.0, retries: int = 1,
                 max_retry_wait: float = 5.0, client: httpx.Client | None = None,
                 sleep: Callable[[float], None] = time.sleep):
        parts = urlsplit(base_url)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise ValueError("the API address must look like http://127.0.0.1:8000")
        if retries < 0 or max_retry_wait < 0:
            raise ValueError("retries and max_retry_wait must be >= 0")
        self.retries, self.max_retry_wait, self._sleep = retries, max_retry_wait, sleep
        self._owns = client is None
        self._client = client or httpx.Client(base_url=base_url.rstrip("/"), timeout=timeout,
                                              follow_redirects=False, trust_env=False)

    @staticmethod
    def _retry_after(r: httpx.Response) -> float:
        try:
            return max(0.0, float(r.headers.get("retry-after", "1")))
        except ValueError:
            return 1.0

    def check(self, urls: list[str]) -> list[dict]:
        urls = list(urls)
        for attempt in range(self.retries + 1):
            try:
                r = self._client.post("/predict", json={"urls": urls, "input_type": "full_url"})
            except httpx.TimeoutException:
                raise CheckUnavailable("api_timeout") from None
            except httpx.TransportError:
                raise CheckUnavailable("api_unreachable") from None
            if r.status_code == 503 and attempt < self.retries:
                self._sleep(min(self._retry_after(r), self.max_retry_wait))
                continue
            if r.status_code != 200:
                raise CheckUnavailable(f"api_http_{r.status_code}")
            try:
                items = r.json()["results"]
                if not isinstance(items, list) or len(items) != len(urls) \
                        or not all(isinstance(i, dict) and "decision" in i for i in items):
                    raise ValueError
            except (ValueError, KeyError, TypeError):
                raise CheckUnavailable("api_bad_response") from None
            return items
        raise CheckUnavailable("api_http_503")             # not reached: the loop returns or raises

    def close(self) -> None:
        if self._owns:
            self._client.close()


# ---------------------------------------------------------------- the bridge
def _as_dict(result) -> dict:
    return dict(result) if isinstance(result, Mapping) else result.to_dict()


def load_sms_module(model_dir: str | None = None):
    """(SMS detector, link extractor) from the installed `sms_detection` package."""
    try:
        from sms_detection.predictor import load_detector
        from sms_detection.preprocessing.normalize import normalize_text
    except ImportError as exc:
        raise SmsModuleMissing("the SMS module is not installed: pip install -e <path>/sms-detection "
                               "--no-deps (run from this repository's virtual environment)") from exc
    detector = load_detector(model_dir) if model_dir else load_detector()
    return detector, (lambda text: normalize_text(text).urls)


@dataclass
class SmsBridge:
    sms_detector: Any                              # sms_detection SmsDetector: .predict_sms(text, sender=...)
    url_checker: UrlChecker
    extract_links: Callable[[str], Sequence[str]]  # sms_detection: normalize_text(text).urls
    max_links: int = MAX_LINKS

    @classmethod
    def create(cls, url_checker: UrlChecker, sms_model_dir: str | None = None, **kwargs) -> "SmsBridge":
        detector, extract = load_sms_module(sms_model_dir)
        return cls(detector, url_checker, extract, **kwargs)

    def check(self, text: str, sender: str | None = None, *, known_sender: bool = False) -> dict:
        if not isinstance(text, str):
            raise TypeError("the message must be text")
        sms = _as_dict(self.sms_detector.predict_sms(text, sender=sender, known_sender=known_sender))
        links = tidy_links(self.extract_links(text))
        sent, over_cap = links[:self.max_links], len(links[self.max_links:])
        items, error = None, None
        if sent:
            try:
                items = self.url_checker.check(sent)
            except CheckUnavailable as exc:
                error = exc.reason
        elif not over_cap:
            items = []
        return combine(sms, sent, items, not_checked=over_cap, error=error)


# ---------------------------------------------------------------- command line
def _read_messages(args) -> list[tuple[str, str | None]]:
    if args.file:
        with open(args.file, encoding="utf-8") as fh:
            rows = json.load(fh)
        if not isinstance(rows, list) or not all(isinstance(r, dict) and isinstance(r.get("text"), str)
                                                 for r in rows):
            raise ValueError('--file must hold a JSON list of {"text": "...", "sender": "..."}')
        return [(r["text"], r.get("sender")) for r in rows]
    text = args.text if args.text is not None else sys.stdin.read()
    if not text.strip():
        raise ValueError("no message given (pass it as an argument, with --file, or on stdin)")
    return [(text, args.sender)]


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("text", nargs="?", help="the SMS text (omit to read stdin)")
    ap.add_argument("--sender", help="sender ID or number, e.g. AD-SBIINB")
    ap.add_argument("--file", help='JSON list of {"text": ..., "sender": ...}')
    ap.add_argument("--api", help=f"use the running HTTP API, e.g. {DEFAULT_API}; default: load the model here")
    ap.add_argument("--max-links", type=int, default=MAX_LINKS)
    ap.add_argument("--sms-model-dir", help="the SMS module's artifacts/model (default: its own)")
    args = ap.parse_args(argv)
    if args.max_links < 1:
        ap.error("--max-links must be at least 1")
    try:
        messages = _read_messages(args)
        checker = HttpUrlChecker(args.api) if args.api else None
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    try:
        detector, extract = load_sms_module(args.sms_model_dir)    # before the URL model loads
    except SmsModuleMissing as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    checker = checker or LocalUrlChecker.from_files()
    try:
        bridge = SmsBridge(detector, checker, extract, max_links=args.max_links)
        out = [bridge.check(text, sender) for text, sender in messages]
    finally:
        checker.close()
    print(json.dumps(out[0] if args.file is None else out, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
