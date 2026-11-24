"""Serve many concurrent callers: a bounded queue and micro-batches.

    service = InferenceService.from_files()             # models/full_url + config/*.json
    service.predict(["https://example.com/login"])     # blocking, any thread
    await service.predict_async(urls)                  # from asyncio (the FastAPI app, Phase 6)
    service.stats()                                    # queue, latency, batch sizes, cache, Google
    service.close()                                    # finish queued requests, then stop

Why: the model is fastest when it scores several URLs at once, and PyTorch
already uses every CPU core inside one batch. So one worker thread owns the
model. Callers put requests on a queue; the worker takes everything waiting
(up to max_batch_urls), scores it as one batch, and hands each caller its own
slice. The same URL from several callers is scored once. Batches form by
themselves under load: requests pile up while the previous batch runs. So by
default the worker does not wait for more (max_wait_ms 0). Measured on the
laptop: a 2 ms wait really lasted 16 ms (Windows timer resolution) and only
made things slower; see README, Inference step 2.

Protection (config/inference.json):
  * max_queue_urls: a full queue refuses new requests at once (Overloaded; the
    API answers 503 + Retry-After) instead of letting latency grow without end
  * max_urls_per_request: one caller cannot take the whole queue
  * queue_timeout_seconds: a request that waited longer is answered with
    QueueTimeout and never scored (its caller has most likely given up)
  * a cancelled request (caller went away) is skipped
  * a failing batch fails only its own requests; the worker keeps running
Online lookups (Google) never run on this worker: see src.intelligence.background.
"""
from __future__ import annotations

import asyncio
import json
import math
import threading
import time
from collections import deque
from concurrent.futures import Future
from dataclasses import asdict, dataclass, fields
from pathlib import Path
from typing import Sequence

import numpy as np

from .bundle import MODELS_DIR
from .predict import INPUT_TYPES, PredictionResult, Predictor

CONFIG_PATH = Path("config/inference.json")
STATS_WINDOW = 10_000                     # latencies / batch sizes kept for percentiles


class Overloaded(RuntimeError):
    """The queue is full: try again shortly."""


class ServiceClosed(RuntimeError):
    """The service has been shut down."""


class QueueTimeout(TimeoutError):
    """The request waited in the queue longer than queue_timeout_seconds."""


@dataclass(frozen=True)
class ServiceConfig:
    max_batch_urls: int = 64              # URLs the worker scores together at most
    max_wait_ms: float = 0.0              # how long a batch waits for more requests to join
    max_queue_urls: int = 2048            # queued URLs before new requests are refused
    max_urls_per_request: int = 256
    queue_timeout_seconds: float = 10.0
    model_batch_size: int = 64            # CNN chunk size inside one scoring call
    online_workers: int = 2               # background Google checks running at once
    online_max_pending: int = 1000        # background Google checks queued at most

    def __post_init__(self) -> None:
        for f in fields(self):
            v = getattr(self, f.name)
            if isinstance(v, bool) or not isinstance(v, (int, float)) or not math.isfinite(v):
                raise ValueError(f"{f.name} must be a finite number")
            if f.type in (int, "int") and (not isinstance(v, int) or v < 1):
                raise ValueError(f"{f.name} must be an integer >= 1")
        if self.max_wait_ms < 0 or self.max_wait_ms > 1000:
            raise ValueError("max_wait_ms must be between 0 and 1000")
        if self.queue_timeout_seconds <= 0:
            raise ValueError("queue_timeout_seconds must be > 0")
        if self.max_urls_per_request > self.max_queue_urls:
            raise ValueError("max_urls_per_request must not exceed max_queue_urls")

    @classmethod
    def from_file(cls, path: Path | str = CONFIG_PATH) -> "ServiceConfig":
        path = Path(path)
        if not path.is_file():
            return cls()
        data = json.loads(path.read_text(encoding="utf-8"))
        allowed = {f.name for f in fields(cls)}
        if not isinstance(data, dict) or set(data) - allowed:
            raise ValueError(f"{path}: unknown keys {sorted(set(data) - allowed)}")
        return cls(**data)


def percentiles(values: Sequence[float], qs=(50, 95, 99)) -> dict[str, float | None]:
    if len(values) == 0:
        return {f"p{q}": None for q in qs}
    a = np.asarray(values, dtype=float)
    return {f"p{q}": float(np.percentile(a, q)) for q in qs}


@dataclass
class _Request:
    values: list[str]
    input_type: str
    future: Future
    enqueued: float
    deadline: float


class InferenceService:
    """Thread-safe front of a Predictor: submit from any thread or event loop."""

    def __init__(self, predictor: Predictor, config: ServiceConfig | None = None, *,
                 owns_predictor: bool = False):
        self.predictor, self.config = predictor, config or ServiceConfig()
        self._owns_predictor = owns_predictor
        self._queue: deque[_Request] = deque()
        self._queued_urls = 0
        self._cond = threading.Condition()
        self._closed = False
        self._latency: deque[float] = deque(maxlen=STATS_WINDOW)     # seconds, queued -> answered
        self._batch_urls: deque[int] = deque(maxlen=STATS_WINDOW)
        self.counts = {"requests": 0, "urls": 0, "completed": 0, "rejected_overloaded": 0,
                       "timed_out": 0, "cancelled": 0, "failed": 0, "batches": 0}
        self._worker = threading.Thread(target=self._run, name="inference-worker", daemon=True)
        self._worker.start()

    @classmethod
    def from_files(cls, bundle_dir: Path | str = MODELS_DIR / "full_url", *,
                   service_config: Path | str = CONFIG_PATH,
                   intel_config: Path | str = Path("config/threat_intel.json"),
                   cache_config: Path | str = Path("config/cache.json"),
                   safe_browsing_config: Path | str | None = Path("config/safe_browsing.json"),
                   device: str = "cpu") -> "InferenceService":
        cfg = ServiceConfig.from_file(service_config)
        predictor = Predictor.from_files(bundle_dir, intel_config=intel_config, cache_config=cache_config,
                                         safe_browsing_config=safe_browsing_config, device=device,
                                         batch_size=cfg.model_batch_size,
                                         online_workers=cfg.online_workers,
                                         online_max_pending=cfg.online_max_pending)
        return cls(predictor, cfg, owns_predictor=True)

    # ------------------------------------------------------------------ public
    def submit(self, values: Sequence[str], input_type: str = "full_url") -> Future:
        """Queue a request; the Future gives one PredictionResult per value, in order.
        Raises Overloaded (queue full) or ServiceClosed at once, never later."""
        if isinstance(values, (str, bytes)):
            raise TypeError("submit() expects a list of URLs")
        values = list(values)
        if input_type not in INPUT_TYPES:
            raise ValueError(f"input_type must be one of {INPUT_TYPES}")
        if len(values) > self.config.max_urls_per_request:
            raise ValueError(f"at most {self.config.max_urls_per_request} URLs per request")
        future: Future = Future()
        if not values:
            future.set_result([])
            return future
        now = time.perf_counter()
        with self._cond:
            if self._closed:
                raise ServiceClosed("the inference service is shut down")
            if self._queued_urls + len(values) > self.config.max_queue_urls:
                self.counts["rejected_overloaded"] += 1
                raise Overloaded(f"{self._queued_urls} URLs already queued "
                                 f"(limit {self.config.max_queue_urls})")
            self._queue.append(_Request(values, input_type, future, now,
                                        now + self.config.queue_timeout_seconds))
            self._queued_urls += len(values)
            self.counts["requests"] += 1
            self.counts["urls"] += len(values)
            self._cond.notify()
        return future

    def predict(self, values: Sequence[str], input_type: str = "full_url",
                timeout: float | None = None) -> list[PredictionResult]:
        return self.submit(values, input_type).result(timeout)

    async def predict_async(self, values: Sequence[str], input_type: str = "full_url") -> list[PredictionResult]:
        """Cancelling the awaiting task cancels the request if it is still queued."""
        return await asyncio.wrap_future(self.submit(values, input_type))

    @property
    def running(self) -> bool:
        return self._worker.is_alive() and not self._closed

    def close(self, timeout: float | None = None) -> None:
        """Refuse new requests, finish the queued ones, stop the worker."""
        with self._cond:
            self._closed = True
            self._cond.notify_all()
        self._worker.join(timeout)
        if self._owns_predictor:
            self.predictor.close()

    def __enter__(self) -> "InferenceService":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def stats(self) -> dict:
        with self._cond:
            counts = dict(self.counts)
            latency, batches = list(self._latency), list(self._batch_urls)
            queued = {"requests": len(self._queue), "urls": self._queued_urls}
        lat = {k: (None if v is None else round(v * 1000, 3)) for k, v in percentiles(latency).items()}
        return {"running": self.running, "queued": queued, "counts": counts,
                "latency_ms": {**lat, "window": len(latency)},
                "batch_urls": {"mean": float(np.mean(batches)) if batches else None,
                               "max": max(batches) if batches else None, "window": len(batches)},
                "config": asdict(self.config),
                "predictor": self.predictor.stats() if hasattr(self.predictor, "stats") else None}

    # ------------------------------------------------------------------ worker
    def _run(self) -> None:
        while True:
            batch = self._next_batch()
            if batch is None:
                return
            self._process(batch)

    def _next_batch(self) -> list[_Request] | None:
        cfg = self.config
        with self._cond:
            while not self._queue:
                if self._closed:
                    return None
                self._cond.wait()
            batch = [self._queue.popleft()]
            size = len(batch[0].values)
            until = time.perf_counter() + cfg.max_wait_ms / 1000
            while size < cfg.max_batch_urls:
                if self._queue:
                    if size + len(self._queue[0].values) > cfg.max_batch_urls:
                        break                         # never split a request; it goes next
                    nxt = self._queue.popleft()
                    batch.append(nxt)
                    size += len(nxt.values)
                    continue
                left = until - time.perf_counter()
                if left <= 0 or self._closed:
                    break
                self._cond.wait(left)
            self._queued_urls -= size
        return batch

    def _process(self, batch: list[_Request]) -> None:
        now = time.perf_counter()
        live: dict[str, list[_Request]] = {}
        dropped = {"cancelled": 0, "timed_out": 0}
        for r in batch:
            if not r.future.set_running_or_notify_cancel():
                dropped["cancelled"] += 1
            elif now > r.deadline:
                r.future.set_exception(QueueTimeout(
                    f"waited {now - r.enqueued:.2f} s in the queue (limit {self.config.queue_timeout_seconds} s)"))
                dropped["timed_out"] += 1
            else:
                live.setdefault(r.input_type, []).append(r)
        with self._cond:
            for k, v in dropped.items():
                self.counts[k] += v
        for input_type, reqs in live.items():
            values = [v for r in reqs for v in r.values]
            try:
                out = self.predictor.predict(values, input_type)
            except Exception as exc:                  # fail these requests, keep serving
                for r in reqs:
                    r.future.set_exception(exc)
                with self._cond:
                    self.counts["failed"] += len(reqs)
                continue
            done, start = time.perf_counter(), 0
            for r in reqs:
                r.future.set_result(out[start:start + len(r.values)])
                start += len(r.values)
            with self._cond:
                self.counts["completed"] += len(reqs)
                self.counts["batches"] += 1
                self._batch_urls.append(len(values))
                self._latency.extend(done - r.enqueued for r in reqs)
