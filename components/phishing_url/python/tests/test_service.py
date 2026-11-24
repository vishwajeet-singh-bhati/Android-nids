import asyncio
import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import pytest

from src.inference.service import (InferenceService, Overloaded, QueueTimeout, ServiceClosed,
                                   ServiceConfig, percentiles)
from tests.test_inference import make_predictor, tiny  # noqa: F401  (module fixture)


class FakePredictor:
    """Answers "<type>:<value>"; `gate` holds the worker inside predict()."""

    def __init__(self):
        self.calls, self.fail, self.closed = [], None, False
        self.gate = threading.Event()
        self.gate.set()
        self.entered = threading.Event()

    def predict(self, values, input_type="full_url"):
        self.calls.append((list(values), input_type))
        self.entered.set()
        assert self.gate.wait(5)
        if self.fail is not None:
            raise self.fail
        return [f"{input_type}:{v}" for v in values]

    def stats(self):
        return {"calls": len(self.calls)}

    def close(self):
        self.closed = True


def blocked_service(**cfg):
    """A service whose worker is busy with a first request ("busy") until gate.set()."""
    fake = FakePredictor()
    fake.gate.clear()
    svc = InferenceService(fake, ServiceConfig(**cfg))
    first = svc.submit(["busy"])
    assert fake.entered.wait(5)
    return svc, fake, first


def test_round_trip_and_input_checks():
    fake = FakePredictor()
    with InferenceService(fake) as svc:
        assert svc.predict(["a", "b"], timeout=5) == ["full_url:a", "full_url:b"]
        assert svc.predict(["x.com"], "domain", timeout=5) == ["domain:x.com"]
        assert svc.submit([]).result(0) == []
        with pytest.raises(TypeError):
            svc.submit("https://example.com/")
        with pytest.raises(ValueError):
            svc.submit(["a"], "email")
        with pytest.raises(ValueError, match="at most"):
            svc.submit(["a"] * 257)
        assert svc.running
    assert not svc.running and not fake.closed                 # not owned: left open
    with pytest.raises(ServiceClosed):
        svc.submit(["a"])


def test_waiting_requests_are_scored_together():
    svc, fake, first = blocked_service()
    futures = [svc.submit([f"u{i}a", f"u{i}b"]) for i in range(5)]
    fake.gate.set()
    assert first.result(5) == ["full_url:busy"]
    assert [f.result(5) for f in futures] == [[f"full_url:u{i}a", f"full_url:u{i}b"] for i in range(5)]
    assert [len(v) for v, _ in fake.calls] == [1, 10]           # one batch for all five
    s = svc.stats()
    assert s["counts"]["batches"] == 2 and s["batch_urls"]["max"] == 10
    assert s["latency_ms"]["window"] == 6 and s["latency_ms"]["p50"] > 0
    svc.close()


def test_batch_limit_types_and_big_requests():
    svc, fake, first = blocked_service(max_batch_urls=4)
    a, b, c = (svc.submit([f"{k}1", f"{k}2", f"{k}3"]) for k in "abc")
    big = svc.submit([f"big{i}" for i in range(6)])
    d = svc.submit(["dom.example"], "domain")
    fake.gate.set()
    for f in (first, a, b, c, big, d):
        f.result(5)
    sizes = [(len(v), t) for v, t in fake.calls]
    assert sizes == [(1, "full_url"), (3, "full_url"), (3, "full_url"), (3, "full_url"),
                     (6, "full_url"), (1, "domain")]               # never split, never over 4 merged
    assert d.result(0) == ["domain:dom.example"]
    svc.close()


def test_mixed_types_in_one_batch_are_scored_separately():
    svc, fake, first = blocked_service()
    u, d = svc.submit(["https://a.com/"]), svc.submit(["a.com"], "domain")
    fake.gate.set()
    assert u.result(5) == ["full_url:https://a.com/"] and d.result(5) == ["domain:a.com"]
    assert [t for _, t in fake.calls[1:]] == ["full_url", "domain"]
    svc.close()


def test_full_queue_refuses_at_once():
    svc, fake, first = blocked_service(max_queue_urls=4, max_urls_per_request=4)
    ok = svc.submit(["a", "b", "c", "d"])
    with pytest.raises(Overloaded):
        svc.submit(["e"])
    assert svc.stats()["counts"]["rejected_overloaded"] == 1 and svc.stats()["queued"]["urls"] == 4
    fake.gate.set()
    assert len(ok.result(5)) == 4
    assert svc.predict(["e"], timeout=5) == ["full_url:e"]       # room again
    svc.close()


def test_stale_and_cancelled_requests_are_not_scored():
    svc, fake, first = blocked_service(queue_timeout_seconds=0.05)
    stale, cancelled = svc.submit(["stale"]), svc.submit(["gone"])
    assert cancelled.cancel()
    time.sleep(0.1)
    fake.gate.set()
    with pytest.raises(QueueTimeout):
        stale.result(5)
    first.result(5)
    svc.close()
    assert all("stale" not in v and "gone" not in v for v, _ in fake.calls)
    counts = svc.stats()["counts"]
    assert (counts["timed_out"], counts["cancelled"]) == (1, 1)


def test_a_failing_batch_fails_only_its_requests():
    fake = FakePredictor()
    svc = InferenceService(fake)
    fake.fail = RuntimeError("boom")
    with pytest.raises(RuntimeError, match="boom"):
        svc.predict(["a"], timeout=5)
    fake.fail = None
    assert svc.predict(["b"], timeout=5) == ["full_url:b"]
    assert svc.stats()["counts"]["failed"] == 1
    svc.close()


def test_close_finishes_queued_requests():
    svc, fake, first = blocked_service()
    queued = svc.submit(["queued"])
    closer = threading.Thread(target=svc.close)
    closer.start()
    time.sleep(0.05)
    with pytest.raises(ServiceClosed):
        svc.submit(["late"])
    fake.gate.set()
    closer.join(5)
    assert queued.result(0) == ["full_url:queued"] and not svc.running


def test_asyncio_callers_are_batched():
    svc, fake, first = blocked_service()

    async def main():
        tasks = [asyncio.ensure_future(svc.predict_async([f"a{i}"])) for i in range(20)]
        await asyncio.sleep(0.05)
        fake.gate.set()
        return await asyncio.gather(*tasks)

    out = asyncio.run(main())
    assert out == [[f"full_url:a{i}"] for i in range(20)]
    assert len(fake.calls) == 2                                  # "busy", then all 20 at once
    svc.close()


def test_config_checks(tmp_path):
    for bad in ({"max_batch_urls": 0}, {"max_wait_ms": -1}, {"queue_timeout_seconds": 0},
                {"max_urls_per_request": 10, "max_queue_urls": 5}, {"online_workers": 1.5},
                {"max_batch_urls": True}):
        with pytest.raises(ValueError):
            ServiceConfig(**bad)
    assert ServiceConfig.from_file(tmp_path / "none.json") == ServiceConfig()
    assert ServiceConfig.from_file("config/inference.json") == ServiceConfig()
    p = tmp_path / "c.json"
    p.write_text(json.dumps({"max_batch_urls": 8, "typo": 1}), encoding="utf-8")
    with pytest.raises(ValueError, match="typo"):
        ServiceConfig.from_file(p)
    assert percentiles([]) == {"p50": None, "p95": None, "p99": None}
    assert percentiles([1, 2, 3, 4])["p50"] == 2.5


def test_concurrent_callers_get_the_same_answers_as_one_caller(tiny):  # noqa: F811
    urls = [f"https://site{i % 23}.example.com/path/{i}?q={i % 5}" for i in range(120)]
    expected = {r.url: (r.decision, r.risk_score) for r in make_predictor(tiny).predict(urls)}
    with InferenceService(make_predictor(tiny), ServiceConfig(max_batch_urls=16)) as svc:
        with ThreadPoolExecutor(8) as pool:
            got = list(pool.map(lambda u: svc.predict([u], timeout=30)[0], urls))
        stats = svc.stats()
    # same decisions; scores equal up to float rounding (batch composition changes the CNN's
    # padded width, and with it the summation order: differences of ~1e-8 were seen)
    assert {r.url: r.decision for r in got} == {u: d for u, (d, _) in expected.items()}
    for r in got:
        assert r.risk_score == pytest.approx(expected[r.url][1], abs=1e-6)
    assert stats["counts"]["completed"] == 120 and stats["counts"]["failed"] == 0
    assert stats["batch_urls"]["max"] <= 16 and stats["predictor"]["cache"] is not None
