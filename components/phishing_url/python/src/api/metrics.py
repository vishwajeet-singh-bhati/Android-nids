"""Counters for GET /metrics, in Prometheus' text format (version 0.0.4).

No client library: a few counters and gauges are enough, and the format is plain
text (prometheus.io/docs/instrumenting/exposition_formats/). Names follow the
Prometheus naming guide: an application prefix (phishing_), base units
(seconds), and _total for counts that only go up. Labels have few values
(endpoint, status code, decision), never URLs.
"""
from __future__ import annotations

import threading
from collections import Counter, defaultdict

CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8"
DECISIONS = ("phishing", "uncertain", "likely_safe", "invalid")
SERVICE_RESULTS = ("completed", "rejected_overloaded", "timed_out", "cancelled", "failed")


def _label(value: str) -> str:
    return str(value).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _num(value) -> str:
    if isinstance(value, bool):
        return "1" if value else "0"
    return str(value) if isinstance(value, int) else repr(float(value))


class Metrics:
    """Thread-safe counters, updated by the app on every request."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.requests: Counter = Counter()               # (endpoint, status code) -> count
        self.seconds_sum: defaultdict = defaultdict(float)  # endpoint -> total seconds
        self.seconds_count: Counter = Counter()          # endpoint -> count
        self.urls: Counter = Counter()                   # decision -> count
        self.cache_hits = 0
        self.pending_answers = 0

    def observe_request(self, endpoint: str, status: int, seconds: float) -> None:
        with self._lock:
            self.requests[(endpoint, str(status))] += 1
            self.seconds_sum[endpoint] += seconds
            self.seconds_count[endpoint] += 1

    def observe_results(self, items: list[dict]) -> None:
        with self._lock:
            for item in items:
                self.urls[item["decision"] or "invalid"] += 1
                self.cache_hits += bool(item["cache_hit"])
                self.pending_answers += bool(item["pending"])

    def render(self, service_stats: dict | None, ready: bool, model_version: str | None) -> str:
        with self._lock:
            requests, sums = dict(self.requests), dict(self.seconds_sum)
            counts, urls = dict(self.seconds_count), dict(self.urls)
            cache_hits, pending = self.cache_hits, self.pending_answers
        out: list[str] = []

        def metric(name: str, kind: str, help_text: str, samples: list[tuple[str, object]]) -> None:
            out.append(f"# HELP {name} {help_text}")
            out.append(f"# TYPE {name} {kind}")
            out.extend(f"{name}{labels} {_num(value)}" for labels, value in samples)

        metric("phishing_ready", "gauge", "1 when the model is loaded and the inference worker runs.",
               [("", ready)])
        metric("phishing_model_info", "gauge", "The loaded model version (value is always 1).",
               [(f'{{model_version="{_label(model_version)}"}}', 1)] if model_version else [])
        metric("phishing_http_requests_total", "counter", "HTTP requests answered, by endpoint and status code.",
               [(f'{{endpoint="{_label(e)}",code="{c}"}}', n) for (e, c), n in sorted(requests.items())])
        out.append("# HELP phishing_http_request_duration_seconds Time to answer HTTP requests, per endpoint.")
        out.append("# TYPE phishing_http_request_duration_seconds summary")
        for e in sorted(counts):
            out.append(f'phishing_http_request_duration_seconds_sum{{endpoint="{_label(e)}"}} {_num(sums[e])}')
            out.append(f'phishing_http_request_duration_seconds_count{{endpoint="{_label(e)}"}} {counts[e]}')
        metric("phishing_urls_total", "counter", "URLs answered by /predict, by decision (invalid = bad input).",
               [(f'{{decision="{d}"}}', urls.get(d, 0)) for d in DECISIONS])
        metric("phishing_cache_hits_total", "counter", "Answers whose model score came from the cache.",
               [("", cache_hits)])
        metric("phishing_pending_answers_total", "counter",
               "Answers given while an online check (Google) was still running.", [("", pending)])
        if service_stats is not None:
            queued = service_stats.get("queued", {})
            metric("phishing_queue_urls", "gauge", "URLs waiting in the inference queue.",
                   [("", queued.get("urls", 0))])
            svc_counts = service_stats.get("counts", {})
            metric("phishing_service_requests_total", "counter", "Inference-service requests, by result.",
                   [(f'{{result="{r}"}}', svc_counts.get(r, 0)) for r in SERVICE_RESULTS])
            metric("phishing_service_batches_total", "counter", "Batches scored by the model worker.",
                   [("", svc_counts.get("batches", 0))])
            latency = service_stats.get("latency_ms", {})
            metric("phishing_service_recent_latency_seconds", "gauge",
                   "Queue-to-answer time over the recent window, by quantile.",
                   [(f'{{quantile="{q}"}}', latency[k] / 1000) for q, k in
                    (("0.5", "p50"), ("0.95", "p95"), ("0.99", "p99")) if latency.get(k) is not None])
        return "\n".join(out) + "\n"
