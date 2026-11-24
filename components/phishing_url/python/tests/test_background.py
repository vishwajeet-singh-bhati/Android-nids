import re
import threading
import time

import pytest

from src.intelligence.background import BackgroundChecker
from src.intelligence.cache import CachePolicies, ResultCache
from src.intelligence.results import MATCH, NO_MATCH, PENDING, UNAVAILABLE, IntelResult
from src.intelligence.safe_browsing import ATTRIBUTION
from src.preprocessing.url_normalizer import normalize_url
from tests.test_safe_browsing import PHISH, URL, FakeGoogle, make

A, B = normalize_url("https://site-a.com/login?u=1"), normalize_url("https://site-b.com/")


class FakeProvider:
    name = "fake"

    def __init__(self):
        self.answers = {}                  # what the provider's own cache knows
        self.gate = threading.Event()
        self.gate.set()
        self.calls, self.fail, self.offline_error, self.closed = [], None, None, False

    def check_offline(self, n):
        if self.offline_error:
            raise self.offline_error
        return self.answers.get(n.canonical)

    def check(self, n):
        self.calls.append(n.canonical)
        assert self.gate.wait(5)
        if isinstance(self.fail, Exception):
            raise self.fail
        if self.fail is not None:
            return self.fail
        self.answers[n.canonical] = IntelResult(NO_MATCH)
        return self.answers[n.canonical]

    def stats(self):
        return {"calls": len(self.calls)}

    def close(self):
        self.closed = True


class Clock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t


def test_pending_then_the_answer():
    p = FakeProvider()
    c = BackgroundChecker(p)
    assert c.lookup(A).status == PENDING
    assert c.wait_idle(5)
    assert c.lookup(A).status == NO_MATCH and p.calls == [A.canonical]      # from the provider cache
    s = c.stats()
    assert (s["started"], s["completed"], s["answered_offline"], s["pending"]) == (1, 1, 1, 0)
    assert s["provider"] == {"calls": 1}
    c.close()
    assert p.closed and c.lookup(B).reason == "closed"


def test_never_waits_and_checks_each_url_once():
    p = FakeProvider()
    p.gate.clear()                                     # the "network" hangs
    c = BackgroundChecker(p, max_pending=2)
    start = time.monotonic()
    assert [c.lookup(A).status for _ in range(3)] == [PENDING] * 3
    assert c.lookup(B).status == PENDING
    r = c.lookup(normalize_url("https://site-c.com/"))
    assert (r.status, r.reason) == (UNAVAILABLE, "background_queue_full")
    assert time.monotonic() - start < 1.0
    keys = set(c._in_flight)
    assert all(re.fullmatch(r"[0-9a-f]{64}", k) for k in keys)              # no readable URLs kept
    assert not c.wait_idle(0.05)
    p.gate.set()
    assert c.wait_idle(5)
    assert sorted(p.calls) == sorted([A.canonical, B.canonical])
    assert c.stats()["already_pending"] == 2 and c.stats()["queue_full"] == 1
    c.close()


def test_failures_are_remembered_for_failure_seconds():
    clock = Clock()
    p = FakeProvider()
    p.fail = IntelResult(UNAVAILABLE, reason="timeout")
    c = BackgroundChecker(p, cache=ResultCache(CachePolicies(failure_seconds=60), clock=clock))
    assert c.lookup(A).status == PENDING and c.wait_idle(5)
    r = c.lookup(A)
    assert (r.status, r.reason) == (UNAVAILABLE, "timeout") and len(p.calls) == 1   # not retried yet
    clock.t += 61
    assert c.lookup(A).status == PENDING and c.wait_idle(5) and len(p.calls) == 2
    p.fail = RuntimeError("bug")
    assert c.lookup(B).status == PENDING and c.wait_idle(5)
    assert c.lookup(B).reason == "error:RuntimeError"
    assert c.stats()["failed"] == 3
    p.offline_error = ValueError("broken cache")
    assert c.lookup(A).reason == "error:ValueError"
    c.close()


def test_settings_are_checked():
    for kw in ({"workers": 0}, {"max_pending": 0}, {"workers": True}):
        with pytest.raises(ValueError):
            BackgroundChecker(FakeProvider(), **kw)


def test_with_the_safe_browsing_client():
    fake = FakeGoogle({"a.b.com/1/2.html": PHISH})
    client, _ = make(fake)
    c = BackgroundChecker(client)
    n = normalize_url(URL)
    assert c.lookup(n).status == PENDING and c.wait_idle(5)
    r = c.lookup(n)
    assert r.status == MATCH and r.matches[0].attribution == ATTRIBUTION and len(fake.requests) == 1
    assert c.lookup(normalize_url("http://10.1.2.3/")).reason == "not_sent:private_or_local_host"
    c.close()
