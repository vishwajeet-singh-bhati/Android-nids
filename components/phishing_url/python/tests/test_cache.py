import json
import threading

import pytest

from src.intelligence.cache import (CachePolicies, ResultCache, TTLCache, intel_key,
                                    prediction_key)
from src.intelligence.results import MATCH, NO_MATCH, UNAVAILABLE
from src.models.calibration import LIKELY_SAFE, PHISHING, UNCERTAIN
from src.preprocessing.url_normalizer import normalize_url


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t

    def advance(self, seconds):
        self.t += seconds


def url(text, kind="full_url"):
    return normalize_url(text, kind)


# ---------------------------------------------------------------- TTLCache
def test_ttl_expiry_and_overwrite():
    clock = Clock()
    c = TTLCache(10, clock)
    assert c.set("a", 1, 5) and c.get("a") == 1
    clock.advance(4.9)
    assert c.get("a") == 1
    clock.advance(0.1)
    assert c.get("a") is None and c.get("a", "x") == "x"
    c.set("b", 1, 5)
    clock.advance(4)
    c.set("b", 2, 5)                                  # overwrite restarts the TTL
    clock.advance(4)
    assert c.get("b") == 2


@pytest.mark.parametrize("ttl", [0, -1, float("inf"), float("nan"), "10", None])
def test_bad_ttl_stores_nothing(ttl):
    c = TTLCache(10)
    assert c.set("a", 1, ttl) is False and len(c) == 0


def test_lru_eviction_keeps_recently_used():
    c = TTLCache(3, Clock())
    for k in "abc":
        c.set(k, k, 60)
    c.get("a")                                        # a is now the most recent
    c.set("d", "d", 60)
    assert c.get("b") is None and [c.get(k) for k in "acd"] == ["a", "c", "d"]
    assert c.stats()["evictions"] == 1 and len(c) == 3


def test_stats_purge_and_clear():
    clock = Clock()
    c = TTLCache(10, clock)
    c.set("a", 1, 1)
    c.set("b", 1, 100)
    c.get("a")
    c.get("zzz")
    assert c.stats()["hit_rate"] == 0.5
    clock.advance(2)
    assert c.purge_expired() == 1 and len(c) == 1
    c.clear()
    assert len(c) == 0 and TTLCache(1).stats()["hit_rate"] is None
    with pytest.raises(ValueError):
        TTLCache(0)


def test_ttl_cache_is_thread_safe():
    c = TTLCache(50)
    errors = []

    def work(i):
        try:
            for j in range(2000):
                c.set(f"{i}-{j % 80}", j, 60)
                c.get(f"{(i + 1) % 8}-{j % 80}")
        except Exception as exc:                      # pragma: no cover
            errors.append(exc)

    threads = [threading.Thread(target=work, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    s = c.stats()
    assert not errors and len(c) == 50 and s["hits"] + s["misses"] == 16_000


# ---------------------------------------------------------------- keys
def test_keys_are_exact_url_digests_with_model_version():
    a = url("https://Shop.Example.com/a?x=1")
    assert prediction_key(a, "v1") == prediction_key(url("https://shop.example.com:443/a?x=1#f"), "v1")
    others = [url("https://shop.example.com/b?x=1"), url("https://shop.example.com/a?x=2"),
              url("http://shop.example.com/a?x=1"), url("shop.example.com", "domain")]
    assert prediction_key(a, "v1") not in {prediction_key(o, "v1") for o in others}
    assert prediction_key(a, "v1") != prediction_key(a, "v2")
    assert prediction_key(a, "v1") != intel_key(a, "v1")
    key = prediction_key(a, "v1")
    assert len(key) == 64 and "example" not in key           # no readable URL inside
    with pytest.raises(ValueError):
        prediction_key(a, "")
    with pytest.raises(ValueError):
        intel_key(a, "")


def test_unicode_and_long_urls_have_stable_keys():
    idn = url("https://pаypal.com/signin")
    assert prediction_key(idn, "v1") == prediction_key(url(idn.canonical), "v1")
    long_url = url("https://example.com/" + "a" * 6000)
    assert len(prediction_key(long_url, "v1")) == 64


# ---------------------------------------------------------------- policies
def test_likely_safe_answers_expire_sooner():
    clock = Clock()
    cache = ResultCache(CachePolicies(prediction_seconds=3600, likely_safe_seconds=900), clock)
    safe, risky, unsure = url("https://a.example.com/"), url("https://b.example.com/"), url("https://c.example.com/")
    cache.put_prediction(safe, "v1", LIKELY_SAFE, "safe")
    cache.put_prediction(risky, "v1", PHISHING, "phish")
    cache.put_prediction(unsure, "v1", UNCERTAIN, "unsure")
    clock.advance(901)
    assert cache.get_prediction(safe, "v1") is None
    assert cache.get_prediction(risky, "v1") == "phish" and cache.get_prediction(unsure, "v1") == "unsure"
    assert cache.get_prediction(risky, "v2") is None              # new model: no old answers
    with pytest.raises(ValueError):
        cache.put_prediction(safe, "v1", "SAFE", "x")


def test_a_safe_page_never_makes_its_site_safe():
    cache = ResultCache()
    cache.put_prediction(url("https://site.example.com/home"), "v1", LIKELY_SAFE, "safe")
    for other in ("https://site.example.com/login", "https://site.example.com/"):
        assert cache.get_prediction(url(other), "v1") is None
    assert cache.get_prediction(url("site.example.com", "domain"), "v1") is None


def test_intel_policies_and_source_validity():
    clock = Clock()
    cache = ResultCache(CachePolicies(intel_malicious_seconds=600, intel_no_match_seconds=300,
                                      failure_seconds=60), clock)
    m, n, f, short = (url(f"https://{h}.example.com/") for h in ("m", "n", "f", "s"))
    cache.put_intel(m, "feed", MATCH, "match")
    cache.put_intel(n, "feed", NO_MATCH, "none")
    cache.put_intel(f, "feed", UNAVAILABLE, "down")
    cache.put_intel(short, "feed", MATCH, "match", valid_for_seconds=30)   # source says 30 s
    clock.advance(61)
    assert cache.get_intel(f, "feed") is None and cache.get_intel(short, "feed") is None
    assert cache.get_intel(n, "feed") == "none" and cache.get_intel(m, "feed") == "match"
    assert cache.get_intel(m, "other-provider") is None
    clock.advance(240)
    assert cache.get_intel(n, "feed") is None and cache.get_intel(m, "feed") == "match"
    assert cache.put_intel(m, "feed", MATCH, "x", valid_for_seconds=0) is False   # already expired
    with pytest.raises(ValueError):
        cache.put_intel(m, "feed", "safe", "x")
    assert cache.stats()["policies"]["intel_malicious_seconds"] == 600


def test_policies_validation_and_file(tmp_path):
    assert CachePolicies.from_file(tmp_path / "missing.json") == CachePolicies()
    assert CachePolicies.from_file() == CachePolicies()           # shipped config/cache.json
    path = tmp_path / "c.json"
    path.write_text(json.dumps({"failure_seconds": 5, "max_entries": 10}), encoding="utf-8")
    assert CachePolicies.from_file(path).failure_seconds == 5
    for bad in [{"nope": 1}, {"failure_seconds": 0}, {"max_entries": 2.5},
                {"likely_safe_seconds": 7200}, {"prediction_seconds": True}]:
        path.write_text(json.dumps(bad), encoding="utf-8")
        with pytest.raises(ValueError):
            CachePolicies.from_file(path)
