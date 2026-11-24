import dataclasses
import socket

import pytest

from src.preprocessing.url_normalizer import (
    MAX_RAW_LENGTH,
    InvalidURLError,
    normalize_url,
)


class TestBasics:
    def test_lowercases_scheme_and_host_but_not_path(self):
        r = normalize_url("HTTPS://Example.COM/Path?Q=1#frag")
        assert r.scheme == "https"
        assert r.host == "example.com"
        assert r.path == "/Path"
        assert r.query == "Q=1"
        assert r.canonical == "https://example.com/Path?Q=1"
        assert r.model_string == "example.com/Path?Q=1"
        assert "://" not in r.model_string
        assert r.original == "HTTPS://Example.COM/Path?Q=1#frag"

    def test_missing_scheme_is_inferred(self):
        r = normalize_url("example.com/login")
        assert r.scheme == "http"
        assert r.scheme_inferred is True
        assert r.canonical == "http://example.com/login"

    def test_default_port_removed_nondefault_kept(self):
        assert normalize_url("http://example.com:80/").port is None
        r = normalize_url("https://example.com:8443/x")
        assert r.port == 8443
        assert r.model_string == "example.com:8443/x"

    def test_empty_path_becomes_slash(self):
        assert normalize_url("https://example.com").model_string == "example.com/"

    def test_tabs_and_newlines_ignored_like_browsers(self):
        r = normalize_url("http://exam\tple.com/pa\nth")
        assert r.host == "example.com"
        assert r.path == "/path"

    def test_result_is_immutable(self):
        r = normalize_url("https://example.com")
        with pytest.raises(dataclasses.FrozenInstanceError):
            r.host = "evil.example"  # type: ignore[misc]

    def test_long_url_is_accepted(self):
        r = normalize_url("https://example.com/" + "a" * 5000)
        assert len(r.path) == 5001


@pytest.mark.parametrize(
    "a,b",
    [
        ("HTTP://EXAMPLE.com:80", "http://example.com/"),
        ("https://example.com/x#section", "https://example.com/x"),
        ("https://example.com:443/x", "https://example.com/x"),
        ("http://example.com./x", "http://example.com/x"),
        ("https://example.com/%7euser", "https://example.com/~user"),
        ("https://example.com/a%2fb", "https://example.com/a%2Fb"),
    ],
)
def test_equivalent_urls_share_canonical_form(a, b):
    assert normalize_url(a).canonical == normalize_url(b).canonical


class TestSecurityRelevant:
    def test_userinfo_is_dropped_but_flagged(self):
        r = normalize_url("http://user:pw@evil.example/login")
        assert r.has_userinfo is True
        assert r.host == "evil.example"
        assert "pw" not in r.canonical and "user" not in r.canonical

    def test_at_sign_trick_resolves_to_real_host(self):
        r = normalize_url("http://paypal.com@evil.example/login")
        assert r.host == "evil.example"
        assert r.has_userinfo is True

    def test_backslash_matches_browser_behaviour(self):
        r = normalize_url("http://evil.example\\@paypal.com/")
        assert r.host == "evil.example"
        assert r.has_userinfo is False


class TestEncoding:
    def test_percent_normalisation(self):
        r = normalize_url("https://example.com/%7euser/%2fx/%41?a=%3d&b=%7E")
        assert r.path == "/~user/%2Fx/A"
        assert r.query == "a=%3D&b=~"

    def test_non_ascii_path_and_query_are_utf8_percent_encoded(self):
        r = normalize_url("https://example.com/café?q=ü")
        assert r.path == "/caf%C3%A9"
        assert r.query == "q=%C3%BC"


class TestHosts:
    def test_idn_converted_to_punycode(self):
        r = normalize_url("https://münchen.de/")
        assert r.host == "xn--mnchen-3ya.de"
        assert r.host_unicode == "münchen.de"
        assert r.has_punycode is True

    def test_idn_case_insensitive(self):
        assert normalize_url("https://MÜNCHEN.de/").host == "xn--mnchen-3ya.de"

    def test_punycode_input_keeps_unicode_form(self):
        r = normalize_url("http://xn--mnchen-3ya.de")
        assert r.host == "xn--mnchen-3ya.de"
        assert r.host_unicode == "münchen.de"

    def test_ipv4(self):
        r = normalize_url("http://192.168.0.1:8080/admin")
        assert r.is_ip and r.host == "192.168.0.1" and r.port == 8080
        assert r.registered_domain == ""

    def test_ipv6(self):
        r = normalize_url("http://[2001:DB8::1]/x")
        assert r.is_ip and r.host == "2001:db8::1"
        assert r.canonical == "http://[2001:db8::1]/x"

    def test_registered_domain_split(self):
        r = normalize_url("https://forums.news.cnn.com/x")
        assert (r.subdomain, r.domain, r.suffix) == ("forums.news", "cnn", "com")
        assert r.registered_domain == "cnn.com"
        r2 = normalize_url("http://www.bbc.co.uk")
        assert r2.suffix == "co.uk" and r2.registered_domain == "bbc.co.uk"

    def test_localhost_has_no_registered_domain(self):
        r = normalize_url("http://localhost/")
        assert r.host == "localhost" and r.registered_domain == ""


class TestDomainMode:
    def test_basic(self):
        r = normalize_url("Example.COM.", "domain")
        assert r.host == "example.com"
        assert r.scheme is None and r.path == ""
        assert r.canonical == r.model_string == "example.com"

    def test_idn(self):
        assert normalize_url("münchen.de", "domain").host == "xn--mnchen-3ya.de"

    @pytest.mark.parametrize("value", ["example.com/login", "http://example.com",
                                       "user@example.com", "example.com:80"])
    def test_rejects_non_hostnames(self, value):
        with pytest.raises(InvalidURLError):
            normalize_url(value, "domain")


@pytest.mark.parametrize(
    "value,reason",
    [
        ("", "empty"),
        ("   ", "empty"),
        ("http://", "no_host"),
        ("javascript:alert(1)", "unparseable"),
        ("gopher://example.com/", "unsupported_scheme"),
        ("http://exa mple.com/", "illegal_characters"),
        ("http://example.com/\x00", "illegal_characters"),
        ("http://[::1", "unparseable"),
        ("http://example.com:99999/", "unparseable"),
        ("http://a..b.com/", "invalid_host"),
        ("http://exa%6Dple.com/", "invalid_host"),
        ("x" * (MAX_RAW_LENGTH + 1), "too_long"),
    ],
)
def test_invalid_inputs_raise_with_reason(value, reason):
    with pytest.raises(InvalidURLError) as info:
        normalize_url(value)
    assert info.value.reason == reason
    assert value.strip()[:20] not in str(info.value) or reason == "empty"


def test_non_string_input():
    with pytest.raises(InvalidURLError):
        normalize_url(None)  # type: ignore[arg-type]


def test_unknown_input_type():
    with pytest.raises(ValueError, match="input_type"):
        normalize_url("example.com", "nonsense")  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "value",
    [
        "HTTPS://Example.COM:443/A/../b?x=%7e#f",
        "example.com/login",
        "http://user:pw@evil.example:8080/p?q=1",
        "http://[2001:DB8::1]/x",
        "https://münchen.de/café",
    ],
)
def test_normalisation_is_idempotent(value):
    once = normalize_url(value)
    assert normalize_url(once.canonical).canonical == once.canonical


def test_works_without_network(monkeypatch):
    def blocked(*args, **kwargs):
        raise AssertionError("network access attempted")

    monkeypatch.setattr(socket.socket, "connect", blocked)
    monkeypatch.setattr(socket, "getaddrinfo", blocked)
    r = normalize_url("https://forums.news.cnn.com/x")
    assert r.registered_domain == "cnn.com"