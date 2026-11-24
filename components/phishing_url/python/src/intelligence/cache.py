"""TTL caches with separate policies, keyed by the exact normalized URL.

Why a cache: a network sees the same links again and again, and each repeat
should not cost a model run or an online lookup. But a cache can also turn an
old answer into a wrong one, so (specification, section 7):

  * Keys are the EXACT normalized URL (scheme, host, port, path, query).
    There is no host- or domain-level entry, so one safe page can never make
    its whole website "safe".
  * Every kind of answer has its own lifetime (CachePolicies):
      prediction       PHISHING / UNCERTAIN model results         1 hour
      likely_safe      LIKELY_SAFE model results (a safe page     15 minutes
                       can be turned malicious later: shorter)
      intel_malicious  confirmed threat-intelligence matches      6 hours, never past
                                                                  the source's own expiry
      intel_no_match   "no feed or provider lists it"             15 minutes
      failure          an online lookup failed                    60 seconds: retry soon,
                                                                  without hammering it
  * Prediction keys include the model version, so a new model never serves
    the previous model's answers.
  * Keys are SHA-256 digests, so the cache holds no readable URLs.
  * Size is bounded: the least recently used entries are evicted first.

Plain Python (no dependencies), thread-safe; times come from a monotonic
clock, so changing the system clock cannot expire or revive entries.
"""
from __future__ import annotations

import hashlib
import json
import math
import threading
import time
from collections import OrderedDict
from dataclasses import asdict, dataclass, fields
from pathlib import Path
from typing import Any, Callable

from src.models.calibration import LIKELY_SAFE, OUTCOMES
from src.preprocessing.url_normalizer import NormalizedURL

from .results import MATCH, NO_MATCH, UNAVAILABLE

CONFIG_PATH = Path("config/cache.json")
_MISSING = object()


# --------------------------------------------------------------------- generic cache
class TTLCache:
    """Bounded LRU cache whose entries each carry their own time-to-live."""

    def __init__(self, max_entries: int, clock: Callable[[], float] = time.monotonic):
        if not isinstance(max_entries, int) or max_entries < 1:
            raise ValueError("max_entries must be an integer >= 1")
        self.max_entries = max_entries
        self._clock = clock
        self._data: OrderedDict[str, tuple[float, Any]] = OrderedDict()
        self._lock = threading.Lock()
        self._hits = self._misses = self._evictions = self._expired = 0

    def get(self, key: str, default: Any = None) -> Any:
        with self._lock:
            item = self._data.get(key, _MISSING)
            if item is _MISSING:
                self._misses += 1
                return default
            expires, value = item
            if self._clock() >= expires:
                del self._data[key]
                self._expired += 1
                self._misses += 1
                return default
            self._data.move_to_end(key)
            self._hits += 1
            return value

    def set(self, key: str, value: Any, ttl_seconds: float) -> bool:
        """Store for ttl_seconds; returns False (and stores nothing) if the TTL is not > 0."""
        if not (isinstance(ttl_seconds, (int, float)) and math.isfinite(ttl_seconds)
                and ttl_seconds > 0):
            return False
        with self._lock:
            self._data[key] = (self._clock() + ttl_seconds, value)
            self._data.move_to_end(key)
            while len(self._data) > self.max_entries:
                self._data.popitem(last=False)
                self._evictions += 1
        return True

    def delete(self, key: str) -> None:
        with self._lock:
            self._data.pop(key, None)

    def clear(self) -> None:
        with self._lock:
            self._data.clear()

    def purge_expired(self) -> int:
        with self._lock:
            now = self._clock()
            dead = [k for k, (expires, _) in self._data.items() if now >= expires]
            for k in dead:
                del self._data[k]
            self._expired += len(dead)
            return len(dead)

    def __len__(self) -> int:
        with self._lock:
            return len(self._data)

    def stats(self) -> dict:
        with self._lock:
            lookups = self._hits + self._misses
            return {"entries": len(self._data), "max_entries": self.max_entries,
                    "hits": self._hits, "misses": self._misses,
                    "hit_rate": self._hits / lookups if lookups else None,
                    "evictions": self._evictions, "expired": self._expired}


# --------------------------------------------------------------------- policies
@dataclass(frozen=True)
class CachePolicies:
    prediction_seconds: float = 3600.0
    likely_safe_seconds: float = 900.0
    intel_malicious_seconds: float = 6 * 3600.0
    intel_no_match_seconds: float = 900.0
    failure_seconds: float = 60.0
    max_entries: int = 100_000

    def __post_init__(self) -> None:
        for f in fields(self):
            v = getattr(self, f.name)
            if isinstance(v, bool) or not isinstance(v, (int, float)) or not math.isfinite(v) or v <= 0:
                raise ValueError(f"{f.name} must be a finite number > 0")
        if not isinstance(self.max_entries, int):
            raise ValueError("max_entries must be an integer")
        if self.likely_safe_seconds > self.prediction_seconds:
            raise ValueError("likely_safe_seconds must not exceed prediction_seconds")

    @classmethod
    def from_file(cls, path: Path | str = CONFIG_PATH) -> "CachePolicies":
        path = Path(path)
        if not path.is_file():
            return cls()
        data = json.loads(path.read_text(encoding="utf-8"))
        allowed = {f.name for f in fields(cls)}
        if not isinstance(data, dict) or set(data) - allowed:
            raise ValueError(f"{path}: unknown keys {sorted(set(data) - allowed)}")
        return cls(**data)

    def to_dict(self) -> dict:
        return asdict(self)


# --------------------------------------------------------------------- keys
def _digest(*parts: str) -> str:
    return hashlib.sha256("\x1f".join(parts).encode("utf-8")).hexdigest()


def prediction_key(n: NormalizedURL, model_version: str) -> str:
    if not model_version:
        raise ValueError("a model version is required for prediction cache keys")
    return _digest("prediction", model_version, n.input_type, n.canonical)


def intel_key(n: NormalizedURL, provider: str) -> str:
    if not provider:
        raise ValueError("a provider name is required for intel cache keys")
    return _digest("intel", provider, n.input_type, n.canonical)


# --------------------------------------------------------------------- facade
class ResultCache:
    """The caches the inference engine and online providers use, one policy per kind."""

    def __init__(self, policies: CachePolicies | None = None,
                 clock: Callable[[], float] = time.monotonic):
        self.policies = policies or CachePolicies()
        self._cache = TTLCache(self.policies.max_entries, clock)

    # model predictions ------------------------------------------------
    def get_prediction(self, n: NormalizedURL, model_version: str) -> Any:
        return self._cache.get(prediction_key(n, model_version))

    def put_prediction(self, n: NormalizedURL, model_version: str, decision: str, value: Any) -> bool:
        if decision not in OUTCOMES:
            raise ValueError(f"decision must be one of {OUTCOMES}")
        ttl = (self.policies.likely_safe_seconds if decision == LIKELY_SAFE
               else self.policies.prediction_seconds)
        return self._cache.set(prediction_key(n, model_version), value, ttl)

    # threat intelligence ------------------------------------------------
    def get_intel(self, n: NormalizedURL, provider: str) -> Any:
        return self._cache.get(intel_key(n, provider))

    def put_intel(self, n: NormalizedURL, provider: str, status: str, value: Any,
                  valid_for_seconds: float | None = None) -> bool:
        """Cache a provider's answer. valid_for_seconds is how long the SOURCE says the
        answer holds (a feed entry's expiry, a provider's cache duration); the cached
        copy never outlives it, nor the policy for its kind."""
        policy = {MATCH: self.policies.intel_malicious_seconds,
                  NO_MATCH: self.policies.intel_no_match_seconds,
                  UNAVAILABLE: self.policies.failure_seconds}
        if status not in policy:
            raise ValueError(f"status must be one of {sorted(policy)}")
        ttl = policy[status] if valid_for_seconds is None else min(policy[status], valid_for_seconds)
        return self._cache.set(intel_key(n, provider), value, ttl)

    # housekeeping -------------------------------------------------------
    def purge_expired(self) -> int:
        return self._cache.purge_expired()

    def clear(self) -> None:
        self._cache.clear()

    def stats(self) -> dict:
        return {**self._cache.stats(), "policies": self.policies.to_dict()}
