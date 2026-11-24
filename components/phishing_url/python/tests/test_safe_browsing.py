import json
import threading
from datetime import datetime, timezone

import httpx
import pytest

from src.intelligence import safe_browsing
from src.intelligence.results import (EXACT_URL, HOSTNAME, MATCH, NO_MATCH, REGISTERED_DOMAIN,
                                      UNAVAILABLE)
from src.intelligence.safe_browsing import (ATTRIBUTION, SafeBrowsingClient, SafeBrowsingConfig,
                                            _b64decode, canonicalize, expressions, full_hash)
from src.preprocessing.url_normalizer import InvalidURLError

NOW = datetime(2026, 11, 20, 12, 0, tzinfo=timezone.utc)
URL = "http://a.b.com/1/2.html?param=1"

# ---------------------------------------------------------------- Google's published examples
# developers.google.com/safe-browsing/v4/urls-hashing (all 33 Canonicalize examples, verbatim)
GOOGLE_CANONICALIZE = [
    ("http://host/%25%32%35", "http://host/%25"),
    ("http://host/%25%32%35%25%32%35", "http://host/%25%25"),
    ("http://host/%2525252525252525", "http://host/%25"),
    ("http://host/asdf%25%32%35asd", "http://host/asdf%25asd"),
    ("http://host/%%%25%32%35asd%%", "http://host/%25%25%25asd%25%25"),
    ("http://www.google.com/", "http://www.google.com/"),
    ("http://%31%36%38%2e%31%38%38%2e%39%39%2e%32%36/%2E%73%65%63%75%72%65/%77%77%77%2E%65%62%61%79%2E%63%6F%6D/",
     "http://168.188.99.26/.secure/www.ebay.com/"),
    ("http://195.127.0.11/uploads/%20%20%20%20/.verify/.eBaysecure=updateuserdataxplimnbqmn-xplmvalidateinfoswqpcmlx=hgplmcx/",
     "http://195.127.0.11/uploads/%20%20%20%20/.verify/.eBaysecure=updateuserdataxplimnbqmn-xplmvalidateinfoswqpcmlx=hgplmcx/"),
    ("http://host%23.com/%257Ea%2521b%2540c%2523d%2524e%25f%255E00%252611%252A22%252833%252944_55%252B",
     "http://host%23.com/~a!b@c%23d$e%25f^00&11*22(33)44_55+"),
    ("http://3279880203/blah", "http://195.127.0.11/blah"),
    ("http://www.google.com/blah/..", "http://www.google.com/"),
    ("www.google.com/", "http://www.google.com/"),
    ("www.google.com", "http://www.google.com/"),
    ("http://www.evil.com/blah#frag", "http://www.evil.com/blah"),
    ("http://www.GOOgle.com/", "http://www.google.com/"),
    ("http://www.google.com.../", "http://www.google.com/"),
    ("http://www.google.com/foo\tbar\rbaz\n2", "http://www.google.com/foobarbaz2"),
    ("http://www.google.com/q?", "http://www.google.com/q?"),
    ("http://www.google.com/q?r?", "http://www.google.com/q?r?"),
    ("http://www.google.com/q?r?s", "http://www.google.com/q?r?s"),
    ("http://evil.com/foo#bar#baz", "http://evil.com/foo"),
    ("http://evil.com/foo;", "http://evil.com/foo;"),
    ("http://evil.com/foo?bar;", "http://evil.com/foo?bar;"),
    (b"http://\x01\x80.com/", "http://%01%80.com/"),
    ("http://notrailingslash.com", "http://notrailingslash.com/"),
    ("http://www.gotaport.com:1234/", "http://www.gotaport.com/"),
    ("  http://www.google.com/  ", "http://www.google.com/"),
    ("http:// leadingspace.com/", "http://%20leadingspace.com/"),
    ("http://%20leadingspace.com/", "http://%20leadingspace.com/"),
    ("%20leadingspace.com/", "http://%20leadingspace.com/"),
    ("https://www.securesite.com/", "https://www.securesite.com/"),
    ("http://host.com/ab%23cd", "http://host.com/ab%23cd"),
    ("http://host.com//twoslashes?more//slashes", "http://host.com/twoslashes?more//slashes"),
]


@pytest.mark.parametrize("raw,expected", GOOGLE_CANONICALIZE)
def test_google_canonicalization_examples(raw, expected):
    assert str(canonicalize(raw)) == expected


@pytest.mark.parametrize("raw,host", [                       # v5 page, IPv6 examples
    ("http://[2001:0db8:0000::1]/", "[2001:db8::1]"),
    ("http://[::ffff:1.2.3.4]/", "1.2.3.4"),
    ("http://[64:ff9b::1.2.3.4]/", "1.2.3.4"),
])
def test_google_ipv6_examples(raw, host):
    assert canonicalize(raw).host == host


@pytest.mark.parametrize("raw,expected", [                   # v5 page, expression examples
    ("http://a.b.com/1/2.html?param=1",
     ["a.b.com/1/2.html?param=1", "a.b.com/1/2.html", "a.b.com/", "a.b.com/1/",
      "b.com/1/2.html?param=1", "b.com/1/2.html", "b.com/", "b.com/1/"]),
    ("http://a.b.c.d.e.f.com/1.html",
     ["a.b.c.d.e.f.com/1.html", "a.b.c.d.e.f.com/", "c.d.e.f.com/1.html", "c.d.e.f.com/",
      "d.e.f.com/1.html", "d.e.f.com/", "e.f.com/1.html", "e.f.com/", "f.com/1.html", "f.com/"]),
    ("http://1.2.3.4/1/", ["1.2.3.4/1/", "1.2.3.4/"]),
    ("http://example.co.uk/1", ["example.co.uk/1", "example.co.uk/"]),
])
def test_google_expression_examples(raw, expected):
    assert expressions(canonicalize(raw)) == expected


@pytest.mark.parametrize("raw,host", [                       # our own cases for the prose rules
    ("http://0x7f.1/", "127.0.0.1"), ("http://0177.0.0.01/", "127.0.0.1"),
    ("http://1.2.3/", "1.2.0.3"), ("http://256.1.1.1/", "256.1.1.1"),
    ("http://08.1.1.1/", "08.1.1.1"), ("http://1.2.3.4.5/", "1.2.3.4.5"),
    ("http://user:pw@www.Example.com:8080/", "www.example.com"),
    ("http://pаypal.com/", "xn--pypal-4ve.com"),
])
def test_host_rules(raw, host):
    assert canonicalize(raw).host == host


def test_at_most_30_expressions_and_path_prefix_rules():
    e = expressions(canonicalize("http://a.b.c.d.e.f.g.com/1/2/3/4/5.html?q=1"))
    assert len(e) == 30 and len(set(e)) == 30
    assert "a.b.c.d.e.f.g.com/1/2/3/" in e and "a.b.c.d.e.f.g.com/1/2/3/4/" not in e
    with pytest.raises(ValueError):
        canonicalize("http:///nohost")


# ---------------------------------------------------------------- protobuf, test side
# Field numbers: googleapis google/security/safebrowsing/v5/safebrowsing.proto
THREAT_NUMBERS = {"THREAT_TYPE_UNSPECIFIED": 0, "MALWARE": 1, "SOCIAL_ENGINEERING": 2,
                  "UNWANTED_SOFTWARE": 3, "POTENTIALLY_HARMFUL_APPLICATION": 4}
ATTRIBUTE_NUMBERS = {"CANARY": 1, "FRAME_ONLY": 2}
UNKNOWN_ENUM = 77                       # a value Google might add later; unknown to the client
PB = {"content-type": "application/x-protobuf"}

# Google's real answer (live API, 2026-11-22; only hash prefixes were sent) for its own
# test page http://testsafebrowsing.appspot.com/s/phishing.html
GOOGLE_TEST_PAGE_ANSWER = bytes.fromhex(
    "0a260a20" "efbd4c3ab44f327eb13ca942ad7c7f0ab47ec260a4d0b8051684a01b2ef35220"
    "12020802" "120308ac02")


def pb_varint(n: int) -> bytes:
    out = bytearray()
    while True:
        byte, n = n & 0x7F, n >> 7
        out.append(byte | (0x80 if n else 0))
        if not n:
            return bytes(out)


def pb(number: int, value) -> bytes:
    """One field: an int becomes a varint field, bytes a length-delimited one."""
    if isinstance(value, int):
        return pb_varint(number << 3) + pb_varint(value)
    return pb_varint(number << 3 | 2) + pb_varint(len(value)) + value


def pb_detail(d: dict, packed: bool = True) -> bytes:
    body = pb(1, THREAT_NUMBERS.get(d["threatType"], UNKNOWN_ENUM))
    attrs = [ATTRIBUTE_NUMBERS.get(a, UNKNOWN_ENUM) for a in d.get("attributes", [])]
    if attrs and packed:
        return body + pb(2, b"".join(pb_varint(a) for a in attrs))
    return body + b"".join(pb(2, a) for a in attrs)


def pb_answer(listed: dict, seconds: int = 300, packed: bool = True) -> bytes:
    """SearchHashesResponse from {full hash: [detail dicts]} and a cache duration."""
    body = b"".join(pb(1, pb(1, h) + b"".join(pb(2, pb_detail(d, packed)) for d in details))
                    for h, details in listed.items())
    return body + pb(2, pb(1, seconds))


# ---------------------------------------------------------------- a fake Google server
class FakeGoogle:
    def __init__(self, listed=None, cache="300s"):
        self.listed = listed or {}          # expression -> list of FullHashDetail dicts
        self.cache = cache
        self.requests: list[httpx.Request] = []
        self.queue: list = []               # canned responses / exceptions, used first

    def handler(self, request):
        self.requests.append(request)
        if self.queue:
            item = self.queue.pop(0)
            if isinstance(item, Exception):
                raise item
            return item
        if "$alt" in request.url.params:                # like the real API (seen 2026-11-22)
            return httpx.Response(400, json={"error": {"code": 400, "status": "INVALID_ARGUMENT",
                                                       "message": "Unsupported Output Format"}})
        prefixes = {_b64decode(v) for v in request.url.params.get_list("hashPrefixes")}
        full = {full_hash(e): d for e, d in self.listed.items() if full_hash(e)[:4] in prefixes}
        return httpx.Response(200, content=pb_answer(full, int(self.cache.rstrip("s"))), headers=PB)


class Clock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t


PHISH = [{"threatType": "SOCIAL_ENGINEERING"}]


def make(fake, **cfg):
    clock = Clock()
    client = SafeBrowsingClient(SafeBrowsingConfig(**cfg), api_key="TESTKEY",
                                http=httpx.Client(transport=httpx.MockTransport(fake.handler)),
                                clock=clock, now=lambda: NOW, sleep=lambda s: None)
    return client, clock


# ---------------------------------------------------------------- what is sent
def test_only_4_byte_prefixes_are_sent_with_the_key_in_a_header():
    fake = FakeGoogle()
    client, _ = make(fake)
    assert client.check(URL).status == NO_MATCH
    (req,) = fake.requests
    sent = req.url.params.get_list("hashPrefixes")
    assert 1 <= len(sent) <= 30 and all(len(_b64decode(p)) == 4 for p in sent)
    assert {_b64decode(p) for p in sent} == {full_hash(e)[:4] for e in expressions(canonicalize(URL))}
    text = str(req.url)
    assert "a.b.com" not in text and "param" not in text and "TESTKEY" not in text
    assert req.headers["x-goog-api-key"] == "TESTKEY" and req.url.host == "safebrowsing.googleapis.com"
    assert "$alt" not in req.url.params           # v5 refuses JSON: 400 "Unsupported Output Format"


def test_key_can_go_in_the_query_instead():
    fake = FakeGoogle()
    client, _ = make(fake, api_key_in_header=False)
    client.check(URL)
    assert fake.requests[0].url.params["key"] == "TESTKEY" and "x-goog-api-key" not in fake.requests[0].headers


@pytest.mark.parametrize("value,kind", [("http://localhost/x", "full_url"), ("http://10.1.2.3/", "full_url"),
                                        ("http://intranet/login", "full_url"), ("http://[::1]/", "full_url"),
                                        ("router.local", "domain")])
def test_private_hosts_are_never_sent(value, kind):
    fake = FakeGoogle()
    client, _ = make(fake)
    r = client.check(value, kind)
    assert r.status == UNAVAILABLE and r.reason.startswith("not_sent") and not fake.requests


def test_disabled_without_a_key(monkeypatch):
    monkeypatch.delenv("SAFE_BROWSING_API_KEY", raising=False)
    fake = FakeGoogle()
    client = SafeBrowsingClient(http=httpx.Client(transport=httpx.MockTransport(fake.handler)))
    r = client.check(URL)
    assert not client.enabled and r.status == UNAVAILABLE and r.reason == "disabled:no_api_key"
    assert not fake.requests
    monkeypatch.setenv("SAFE_BROWSING_API_KEY", "FROMENV")
    assert SafeBrowsingClient().enabled


def test_invalid_input_raises():
    client, _ = make(FakeGoogle())
    with pytest.raises(InvalidURLError):
        client.check("javascript:alert(1)")


# ---------------------------------------------------------------- matching
def test_match_levels_threat_types_and_attribution():
    fake = FakeGoogle({"a.b.com/1/2.html?param=1": PHISH,
                       "a.b.com/1/": [{"threatType": "MALWARE"}],
                       "b.com/": PHISH})
    client, _ = make(fake)
    r = client.check(URL)
    assert r.status == MATCH and r.strongest_level == EXACT_URL
    by_level = {m.level: m for m in r.matches}
    assert set(by_level) == {EXACT_URL, HOSTNAME, REGISTERED_DOMAIN}
    assert by_level[EXACT_URL].threat_types == ("phishing",)
    assert by_level[HOSTNAME].threat_types == ("malware",)
    assert all(m.attribution == ATTRIBUTION and m.source == "google_safe_browsing" for m in r.matches)
    assert "TESTKEY" not in json.dumps(r.to_dict())


def test_domain_mode():
    fake = FakeGoogle({"evil.example.com/": PHISH})
    client, _ = make(fake)
    assert client.check("evil.example.com", "domain").strongest_level == EXACT_URL
    assert client.check("other.example.com", "domain").status == NO_MATCH


@pytest.mark.parametrize("details", [
    [{"threatType": "THREAT_TYPE_UNSPECIFIED"}],
    [{"threatType": "SOMETHING_NEW"}],
    [{"threatType": "SOCIAL_ENGINEERING", "attributes": ["CANARY"]}],
    [{"threatType": "SOCIAL_ENGINEERING", "attributes": ["FRAME_ONLY"]}],
    [{"threatType": "SOCIAL_ENGINEERING", "attributes": ["NEW_ATTRIBUTE"]}],
])
def test_unknown_or_non_enforceable_details_are_ignored(details):
    client, _ = make(FakeGoogle({"a.b.com/1/2.html": details}))
    assert client.check(URL).status == NO_MATCH


def test_googles_real_answer_for_its_test_page():
    hashes, ttl = safe_browsing._decode_search_response(GOOGLE_TEST_PAGE_ANSWER)
    assert hashes == [(full_hash("testsafebrowsing.appspot.com/s/phishing.html"), [("SOCIAL_ENGINEERING", [])])]
    assert ttl == 300
    fake = FakeGoogle()
    fake.queue.append(httpx.Response(200, headers=PB, content=GOOGLE_TEST_PAGE_ANSWER))
    client, _ = make(fake)
    r = client.check("http://testsafebrowsing.appspot.com/s/phishing.html")
    assert r.status == MATCH and r.strongest_level == EXACT_URL and r.matches[0].threat_types == ("phishing",)


def test_decoder_reads_both_enum_encodings_and_skips_unknown_fields():
    h = full_hash("a.b.com/1/2.html")
    detail = pb(1, 2) + pb(2, 1) + pb(9, 5)                 # unpacked CANARY, unknown field 9
    fixed = pb_varint(10 << 3 | 1) + b"\x00" * 8 + pb_varint(11 << 3 | 5) + b"\x00" * 4
    body = pb(1, pb(1, h) + pb(2, detail) + pb(2, pb(1, 1))) + fixed + pb(2, pb(1, 60) + pb(2, 500_000_000))
    hashes, ttl = safe_browsing._decode_search_response(body)
    assert hashes == [(h, [("SOCIAL_ENGINEERING", ["CANARY"]), ("MALWARE", [])])] and ttl == 60.5
    listed = {h: [{"threatType": "MALWARE", "attributes": ["CANARY", "FRAME_ONLY"]}]}
    assert pb_answer(listed, packed=True) != pb_answer(listed, packed=False)
    for packed in (True, False):
        got, _ = safe_browsing._decode_search_response(pb_answer(listed, packed=packed))
        assert got == [(h, [("MALWARE", ["CANARY", "FRAME_ONLY"])])]


# ---------------------------------------------------------------- caching
def test_cache_duration_is_capped_at_24_hours():
    fake = FakeGoogle(cache="9999999s")
    client, clock = make(fake)
    client.check("http://unlisted-site.com/")
    clock.t += 24 * 3600 + 1
    client.check("http://unlisted-site.com/")
    assert len(fake.requests) == 2


def test_answers_are_cached_by_prefix():
    fake = FakeGoogle({"a.b.com/1/2.html": PHISH}, cache="300s")
    client, clock = make(fake)
    assert client.check(URL).status == MATCH
    assert client.check(URL).status == MATCH and len(fake.requests) == 1      # from cache
    assert client.check("http://unlisted-site.com/").status == NO_MATCH
    assert client.check("http://unlisted-site.com/").status == NO_MATCH and len(fake.requests) == 2
    clock.t += 301                                                           # cacheDuration over
    client.check("http://unlisted-site.com/")
    assert len(fake.requests) == 3


def test_check_offline_never_sends():
    fake = FakeGoogle({"a.b.com/1/2.html": PHISH}, cache="300s")
    client, clock = make(fake)
    assert client.check_offline(URL) is None and not fake.requests          # Google would be asked
    assert client.check_offline("http://10.1.2.3/").reason == "not_sent:private_or_local_host"
    assert client.check(URL).status == MATCH and len(fake.requests) == 1
    assert client.check_offline(URL).status == MATCH                        # now from the cache
    client.check("http://unlisted-site.com/")
    assert client.check_offline("http://unlisted-site.com/").status == NO_MATCH
    clock.t += 301                                                          # cacheDuration over
    assert client.check_offline("http://unlisted-site.com/") is None and len(fake.requests) == 2


def test_positive_answers_live_at_most_30_minutes():
    fake = FakeGoogle({"a.b.com/1/2.html": PHISH}, cache="7200s")
    client, clock = make(fake)
    client.check(URL)
    clock.t += 29 * 60
    client.check(URL)
    assert len(fake.requests) == 1
    clock.t += 2 * 60                                                        # 31 minutes old
    assert client.check(URL).status == MATCH and len(fake.requests) == 2
    client.check("http://unlisted-site.com/")
    clock.t += 3600                                                          # negatives: cacheDuration
    client.check("http://unlisted-site.com/")
    assert len(fake.requests) == 3


# ---------------------------------------------------------------- failures
def test_timeouts_are_retried_then_back_off():
    fake = FakeGoogle()
    client, clock = make(fake, retries=1, backoff_base_seconds=60)
    req = httpx.Request("GET", "https://x")
    fake.queue += [httpx.ConnectTimeout("t", request=req), httpx.ReadTimeout("t", request=req)]
    r = client.check(URL)
    assert r.status == UNAVAILABLE and r.reason == "timeout" and len(fake.requests) == 2
    r = client.check("http://another-site.com/")
    assert r.reason == "backoff_after_errors" and len(fake.requests) == 2      # nothing sent
    clock.t += 61
    fake.queue.append(httpx.Response(503))
    fake.queue.append(httpx.Response(503))
    assert client.check(URL).reason == "http_503"
    clock.t += 61                                                            # 2nd failure: 120 s
    assert client.check(URL).reason == "backoff_after_errors"
    clock.t += 60
    assert client.check(URL).status == NO_MATCH                              # recovered
    assert client.stats()["consecutive_failures"] == 0


def test_server_error_then_success():
    fake = FakeGoogle({"a.b.com/1/2.html": PHISH})
    client, _ = make(fake)
    fake.queue.append(httpx.Response(500))
    assert client.check(URL).status == MATCH and len(fake.requests) == 2


@pytest.mark.parametrize("response,reason", [
    (httpx.Response(403, json={"error": "bad key"}), "http_403"),
    # Google's refusal of a wrong key: a protobuf google.rpc.Status with an ErrorInfo
    # (seen live 2026-11-22), or the same as JSON
    (httpx.Response(400, headers=PB, content=pb(1, 3) + pb(2, b"API key not valid.") + pb(3, pb(
        1, b"type.googleapis.com/google.rpc.ErrorInfo") + pb(2, pb(1, b"API_KEY_INVALID") + pb(2, b"googleapis.com")))),
     "http_400:API_KEY_INVALID"),
    (httpx.Response(400, json={"error": {"code": 400, "status": "INVALID_ARGUMENT", "details": [
        {"@type": "type.googleapis.com/google.rpc.ErrorInfo", "reason": "API_KEY_INVALID"}]}}),
     "http_400:API_KEY_INVALID"),
    (httpx.Response(403, headers=PB, content=pb(1, 7) + pb(2, b"denied")), "http_403:PERMISSION_DENIED"),
    (httpx.Response(403, json={"error": {"status": "PERMISSION_DENIED"}}), "http_403:PERMISSION_DENIED"),
    (httpx.Response(403, json={"error": {"status": "key=TESTKEY <b>"}}), "http_403"),   # free text: dropped
    (httpx.Response(400, headers=PB, content=b"\xff\xff"), "http_400"),                   # unreadable
    # broken answers to a request that succeeded
    (httpx.Response(200, json={"fullHashes": [], "cacheDuration": "300s"}), "bad_response"),   # not protobuf
    (httpx.Response(200, text="<html>Wi-Fi login</html>"), "bad_response"),
    (httpx.Response(200, headers=PB, content=pb(1, pb(1, b"\x00" * 4)) + pb(2, pb(1, 1))), "bad_response"),
    (httpx.Response(200, headers=PB, content=pb(2, pb(1, 2**64 - 1))), "bad_response"),       # negative
    (httpx.Response(200, headers=PB, content=GOOGLE_TEST_PAGE_ANSWER[:20]), "bad_response"),  # truncated
    (httpx.Response(200, headers=PB, content=b"\x0b\x0c"), "bad_response"),                  # group wire type
])
def test_client_errors_and_bad_answers_are_not_retried(response, reason):
    fake = FakeGoogle()
    client, _ = make(fake)
    fake.queue.append(response)
    r = client.check(URL)
    assert r.status == UNAVAILABLE and r.reason == reason and len(fake.requests) == 1


def test_429_retry_after_is_respected():
    fake = FakeGoogle()
    client, clock = make(fake, backoff_base_seconds=60)
    fake.queue.append(httpx.Response(429, headers={"Retry-After": "600"}))
    assert client.check(URL).reason == "http_429"
    clock.t += 300
    assert client.check(URL).reason == "backoff_after_errors"
    clock.t += 301
    assert client.check(URL).status == NO_MATCH


def test_rate_limit():
    fake = FakeGoogle()
    client, clock = make(fake, max_requests_per_minute=2)
    assert client.check("http://one-site.com/").status == NO_MATCH
    assert client.check("http://two-site.com/").status == NO_MATCH
    r = client.check("http://three-site.com/")
    assert r.reason == "rate_limited" and len(fake.requests) == 2
    clock.t += 30                                                            # one token back
    assert client.check("http://three-site.com/").status == NO_MATCH


def test_concurrent_checks():
    fake = FakeGoogle({"a.b.com/1/2.html": PHISH})
    client, _ = make(fake, max_requests_per_minute=10_000)
    errors, statuses = [], []

    def work():
        try:
            for i in range(40):
                statuses.append(client.check(URL if i % 2 else f"http://site{i}.com/").status)
        except Exception as exc:                                             # pragma: no cover
            errors.append(exc)

    threads = [threading.Thread(target=work) for _ in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors and set(statuses) == {MATCH, NO_MATCH}


# ---------------------------------------------------------------- config / CLI
def test_config(tmp_path):
    assert SafeBrowsingConfig.from_file() == SafeBrowsingConfig()            # shipped file
    path = tmp_path / "c.json"
    for bad in [{"endpoint": "http://plain-http.example"}, {"retries": 9}, {"nope": 1},
                {"max_requests_per_minute": 0}, {"timeout_seconds": 0}]:
        path.write_text(json.dumps(bad), encoding="utf-8")
        with pytest.raises(ValueError):
            SafeBrowsingConfig.from_file(path)


def test_cli(capsys, monkeypatch):
    monkeypatch.delenv("SAFE_BROWSING_API_KEY", raising=False)
    assert safe_browsing.main(["expressions", URL]) == 0
    out = capsys.readouterr().out
    assert "b.com/1/" in out and "only the 4-byte prefixes" in out
    assert safe_browsing.main(["check", URL]) == 0
    assert "disabled:no_api_key" in capsys.readouterr().out
    assert safe_browsing.main(["check", "a/b", "--domain"]) == 2
