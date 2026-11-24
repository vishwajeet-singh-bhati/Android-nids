"""Run a slow online threat-intelligence provider off the request path.

No prediction waits for the network. For each URL, BackgroundChecker.lookup():
  1. answers at once when the provider can do so without the network: from its
     own cache (Google: the answers for 4-byte hash prefixes, kept only as
     long as Google allows), or for a host that is never sent (private IPs,
     localhost);
  2. answers "unavailable" for a URL whose check failed recently. The failure
     is kept for cache.json `failure_seconds` (60 s), so a failing or
     rate-limited API is not hammered;
  3. otherwise queues a background check (one at a time per URL, at most
     `max_pending` in total) and answers "pending". When the check is done
     the provider's cache holds the answer, and the next lookup returns it.
"pending" and "unavailable" never lower the risk (see decision_engine).

The in-flight set holds SHA-256 cache keys, never readable URLs.
"""
from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Protocol

from src.preprocessing.url_normalizer import NormalizedURL

from .cache import ResultCache, intel_key
from .results import PENDING, UNAVAILABLE, IntelResult

DEFAULT_WORKERS = 2
DEFAULT_MAX_PENDING = 1000


class OnlineProvider(Protocol):
    name: str

    def check(self, value: NormalizedURL) -> IntelResult: ...

    def check_offline(self, value: NormalizedURL) -> IntelResult | None: ...

    def stats(self) -> dict: ...

    def close(self) -> None: ...


class BackgroundChecker:
    """Thread-safe. Owns the provider: close() closes it too."""

    def __init__(self, provider: OnlineProvider, *, cache: ResultCache | None = None,
                 workers: int = DEFAULT_WORKERS, max_pending: int = DEFAULT_MAX_PENDING):
        for label, v in (("workers", workers), ("max_pending", max_pending)):
            if isinstance(v, bool) or not isinstance(v, int) or v < 1:
                raise ValueError(f"{label} must be an integer >= 1")
        self.provider, self.name = provider, provider.name
        self.max_pending = max_pending
        self._failures = cache if cache is not None else ResultCache()   # failed checks only
        self._pool = ThreadPoolExecutor(max_workers=workers, thread_name_prefix=f"{self.name}-check")
        self._idle = threading.Condition()
        self._in_flight: set[str] = set()
        self._closed = False
        self.counts = {"answered_offline": 0, "recent_failure": 0, "started": 0, "already_pending": 0,
                       "queue_full": 0, "completed": 0, "failed": 0}

    def lookup(self, n: NormalizedURL) -> IntelResult:
        """Never blocks on the network and never raises."""
        try:
            answer = self.provider.check_offline(n)
        except Exception as exc:                          # a provider bug must not stop predictions
            return IntelResult(UNAVAILABLE, reason=f"error:{type(exc).__name__}")
        if answer is not None:
            return self._count("answered_offline", answer)
        failed = self._failures.get_intel(n, self.name)
        if failed is not None:
            return self._count("recent_failure", failed)
        key = intel_key(n, self.name)
        with self._idle:
            if self._closed:
                return IntelResult(UNAVAILABLE, reason="closed")
            if key in self._in_flight:
                self.counts["already_pending"] += 1
                return IntelResult(PENDING)
            if len(self._in_flight) >= self.max_pending:
                self.counts["queue_full"] += 1
                return IntelResult(UNAVAILABLE, reason="background_queue_full")
            self._in_flight.add(key)
            self.counts["started"] += 1
            try:
                self._pool.submit(self._run, key, n)
            except RuntimeError:                          # the pool was shut down meanwhile
                self._in_flight.discard(key)
                return IntelResult(UNAVAILABLE, reason="closed")
        return IntelResult(PENDING)

    def wait_idle(self, timeout: float | None = None) -> bool:
        """Wait until no check is running; False if the timeout passed first."""
        with self._idle:
            return self._idle.wait_for(lambda: not self._in_flight, timeout)

    def close(self) -> None:
        with self._idle:
            self._closed = True
        self._pool.shutdown(wait=False, cancel_futures=True)
        self.provider.close()

    def stats(self) -> dict:
        with self._idle:
            counts, pending = dict(self.counts), len(self._in_flight)
        return {"pending": pending, "max_pending": self.max_pending, **counts,
                "provider": self.provider.stats()}

    # ------------------------------------------------------------------ internals
    def _count(self, name: str, result: IntelResult) -> IntelResult:
        with self._idle:
            self.counts[name] += 1
        return result

    def _run(self, key: str, n: NormalizedURL) -> None:
        try:
            try:
                result = self.provider.check(n)
            except Exception as exc:
                result = IntelResult(UNAVAILABLE, reason=f"error:{type(exc).__name__}")
            if result.status == UNAVAILABLE:
                self._failures.put_intel(n, self.name, UNAVAILABLE, result)
            with self._idle:
                self.counts["failed" if result.status == UNAVAILABLE else "completed"] += 1
        finally:
            with self._idle:
                self._in_flight.discard(key)
                self._idle.notify_all()
