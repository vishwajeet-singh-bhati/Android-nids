"""Measure inference speed and memory on this machine (laptop now, Raspberry Pi 5 in Phase 5).

    python -m src.inference.benchmark                       # 2,048 validation URLs
    python -m src.inference.benchmark --quick               # short smoke run
    python -m src.inference.benchmark --save-urls data/processed/benchmark_urls.txt
    python -m src.inference.benchmark --urls benchmark_urls.txt --threads 4   # e.g. on the Pi
    python -m src.inference.benchmark --thread-sweep 1,2,4,8   # model alone per thread count first

Everything reported is measured here; nothing is estimated or extrapolated.
  model      runtime.score() alone at batch sizes 1/16/32/64/128: latency per
             batch (P50/P95/P99), time per URL, URLs per second, CPU cores busy
  predictor  the whole path (normalize, cache, model, local threat database,
             decision rules) in calls of 64 URLs: a cold pass with an empty
             cache, then a warm pass over the same URLs (cache hit rate)
  service    C concurrent callers, one URL per request, through the queue and
             micro-batches of InferenceService, no cache (every URL is scored):
             per-request latency P50/P95/P99, requests per second, batch sizes
  memory     resident memory (RSS) at start, after loading and at the peak
  threads    (--thread-sweep) the model alone at batch sizes 1 and 64 for each
             PyTorch thread count: phones mix fast and slow cores, and more
             threads are not always faster
Google Safe Browsing is not called: a benchmark must not depend on the network.
The report goes to reports/benchmark_<machine>_<UTC time>.json. Use the same
URL file on every machine (--save-urls here, --urls there) to compare them.
"""
from __future__ import annotations

import argparse
import ctypes
import json
import math
import platform
import random
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Sequence

import numpy as np
import torch

from src.intelligence.cache import CachePolicies, ResultCache
from src.intelligence.local_database import ThreatIntelConfig, ThreatIntelDB
from src.preprocessing.url_normalizer import InvalidURLError, NormalizedURL, normalize_url

from .bundle import MODELS_DIR, load_bundle
from .machine import machine_info
from .predict import Predictor
from .runtime import ModelRuntime
from .service import InferenceService, ServiceConfig, percentiles

BATCH_SIZES = (1, 16, 32, 64, 128)
CONCURRENCY = (1, 4, 16, 64)
REPORTS_DIR = Path("reports")


# --------------------------------------------------------------------- measuring
def memory() -> dict[str, int | None]:
    """Resident memory now and its peak for this process, in bytes (None if unknown)."""
    if sys.platform.startswith("linux"):
        out: dict[str, int | None] = {"rss": None, "peak_rss": None}
        try:
            with open("/proc/self/status", encoding="ascii") as fh:
                for line in fh:
                    key = {"VmRSS:": "rss", "VmHWM:": "peak_rss"}.get(line.split(":")[0] + ":")
                    if key:
                        out[key] = int(line.split()[1]) * 1024
        except OSError:
            pass
        return out
    if sys.platform == "win32":
        from ctypes import wintypes

        class Counters(ctypes.Structure):
            _fields_ = [("cb", wintypes.DWORD), ("PageFaultCount", wintypes.DWORD),
                        ("PeakWorkingSetSize", ctypes.c_size_t), ("WorkingSetSize", ctypes.c_size_t),
                        ("QuotaPeakPagedPoolUsage", ctypes.c_size_t), ("QuotaPagedPoolUsage", ctypes.c_size_t),
                        ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                        ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                        ("PagefileUsage", ctypes.c_size_t), ("PeakPagefileUsage", ctypes.c_size_t)]
        c = Counters()
        c.cb = ctypes.sizeof(Counters)
        kernel32 = ctypes.WinDLL("kernel32")
        kernel32.GetCurrentProcess.restype = wintypes.HANDLE
        get_info = kernel32.K32GetProcessMemoryInfo
        get_info.argtypes = [wintypes.HANDLE, ctypes.POINTER(Counters), wintypes.DWORD]
        if get_info(kernel32.GetCurrentProcess(), ctypes.byref(c), c.cb):
            return {"rss": int(c.WorkingSetSize), "peak_rss": int(c.PeakWorkingSetSize)}
        return {"rss": None, "peak_rss": None}
    try:                                                      # macOS: peak only, in bytes
        import resource
        return {"rss": None, "peak_rss": int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)}
    except (ImportError, OSError):
        return {"rss": None, "peak_rss": None}


class Meter:
    """Wall time and process CPU time (all threads) over a block."""

    def __enter__(self) -> "Meter":
        self.wall0, self.cpu0 = time.perf_counter(), time.process_time()
        return self

    def __exit__(self, *exc) -> None:
        self.wall = time.perf_counter() - self.wall0
        self.cpu = time.process_time() - self.cpu0

    @property
    def cores_busy(self) -> float:
        """Average CPU cores in use (1.0 = one core fully busy)."""
        return self.cpu / self.wall if self.wall > 0 else 0.0


def _ms(stats: dict[str, float | None]) -> dict[str, float | None]:
    return {k: None if v is None else round(v * 1000, 3) for k, v in stats.items()}


def _cycle(items: Sequence, start: int, size: int) -> list:
    return [items[(start + i) % len(items)] for i in range(size)]


# --------------------------------------------------------------------- cases
def bench_model(runtime: ModelRuntime, urls: Sequence[NormalizedURL], batch_sizes: Sequence[int],
                min_batches: int, max_seconds: float) -> list[dict]:
    out = []
    for b in batch_sizes:
        for k in range(2):                                    # warm-up, not measured
            runtime.score(_cycle(urls, k * b, b))
        target = max(min_batches, math.ceil(len(urls) / b))
        lat: list[float] = []
        with Meter() as m:
            while len(lat) < target and (m.wall0 + max_seconds > time.perf_counter() or len(lat) < 5):
                batch = _cycle(urls, len(lat) * b, b)
                t = time.perf_counter()
                runtime.score(batch)
                lat.append(time.perf_counter() - t)
        mean = float(np.mean(lat))
        out.append({"batch_size": b, "batches": len(lat), "urls": len(lat) * b,
                    "latency_ms": {**_ms(percentiles(lat)), "mean": round(mean * 1000, 3)},
                    "ms_per_url": round(mean * 1000 / b, 4),
                    "urls_per_second": round(len(lat) * b / m.wall, 1),
                    "cpu_cores_busy": round(m.cores_busy, 2)})
    return out


def _pass(predictor: Predictor, urls: Sequence[str], call_size: int) -> dict:
    lat, scored, hits = [], 0, 0
    with Meter() as m:
        for start in range(0, len(urls), call_size):
            t = time.perf_counter()
            results = predictor.predict(urls[start:start + call_size])
            lat.append(time.perf_counter() - t)
            for r in results:
                if r.model_version is not None:              # the model answered (fresh or cached)
                    scored += 1
                    hits += r.cache_hit
    return {"calls": len(lat), "urls": len(urls), "latency_ms_per_call": _ms(percentiles(lat)),
            "urls_per_second": round(len(urls) / m.wall, 1), "cpu_cores_busy": round(m.cores_busy, 2),
            "cache_hit_rate": round(hits / scored, 4) if scored else None}


def bench_predictor(runtime: ModelRuntime, threat_db: ThreatIntelDB | None, urls: Sequence[str],
                    call_size: int = 64) -> dict:
    cache = ResultCache(CachePolicies())
    predictor = Predictor(runtime, threat_db=threat_db, cache=cache)
    cold = _pass(predictor, urls, call_size)
    warm = _pass(predictor, urls, call_size)
    return {"call_size": call_size, "cold": cold, "warm": warm}


def bench_service(runtime: ModelRuntime, threat_db: ThreatIntelDB | None, urls: Sequence[str],
                  concurrency: Sequence[int], requests: int, config: ServiceConfig) -> list[dict]:
    out = []
    for c in concurrency:
        n = max(requests, c)
        work = _cycle(urls, 0, n)
        lat: list[float] = []
        with InferenceService(Predictor(runtime, threat_db=threat_db, cache=None), config) as svc:
            svc.predict(work[:1], timeout=60)                 # warm-up
            def client(share: list[str]) -> list[float]:
                times = []
                for u in share:
                    t = time.perf_counter()
                    svc.predict([u], timeout=60)
                    times.append(time.perf_counter() - t)
                return times
            shares = [work[i::c] for i in range(c)]
            with Meter() as m:
                with ThreadPoolExecutor(c) as pool:
                    for times in pool.map(client, shares):
                        lat.extend(times)
            stats = svc.stats()
        out.append({"concurrency": c, "requests": n, "latency_ms": _ms(percentiles(lat)),
                    "requests_per_second": round(n / m.wall, 1),
                    "mean_batch_urls": None if stats["batch_urls"]["mean"] is None
                    else round(stats["batch_urls"]["mean"], 2),
                    "max_batch_urls": stats["batch_urls"]["max"],
                    "rejected": stats["counts"]["rejected_overloaded"],
                    "cpu_cores_busy": round(m.cores_busy, 2)})
    return out


def bench_threads(runtime: ModelRuntime, urls: Sequence[NormalizedURL], thread_counts: Sequence[int],
                  min_batches: int, max_seconds: float) -> list[dict]:
    """The model alone at batch sizes 1 and 64 for each thread count; restores the setting."""
    before, out = torch.get_num_threads(), []
    try:
        for t in thread_counts:
            torch.set_num_threads(t)
            for x in bench_model(runtime, urls, (1, 64), min_batches, max_seconds):
                out.append({"threads": t, **x})
    finally:
        torch.set_num_threads(before)
    return out


# --------------------------------------------------------------------- driver
def load_urls(path: Path | None, sample: int, seed: int = 0) -> tuple[list[str], str]:
    """URLs from a file (one per line) or a random sample of the validation split."""
    if path is not None:
        lines = Path(path).read_text(encoding="utf-8").splitlines()
        urls = [x.strip() for x in lines if x.strip() and not x.startswith("#")]
        source = f"file:{Path(path).name}"
    else:
        from src.training.data import load_split
        urls = [n.original for n in load_split("full_url", "val").normalized]
        source = "split:full_url/val"
    if not urls:
        raise ValueError("no URLs to benchmark")
    if sample and len(urls) > sample:
        urls = random.Random(seed).sample(urls, sample)
    return urls, source


def run_benchmark(bundle_dir: Path | str, urls: Sequence[str], *, url_source: str = "",
                  intel_config: Path | str | None = Path("config/threat_intel.json"),
                  batch_sizes: Sequence[int] = BATCH_SIZES, concurrency: Sequence[int] = CONCURRENCY,
                  min_batches: int = 30, max_seconds: float = 20.0, service_requests: int = 1000,
                  service_config: ServiceConfig | None = None, threads: int | None = None,
                  thread_sweep: Sequence[int] = (),
                  log: Callable[[str], None] = lambda s: None) -> dict:
    mem_start = memory()
    if threads:
        torch.set_num_threads(threads)
    with Meter() as load:
        bundle = load_bundle(bundle_dir)
        runtime = ModelRuntime(bundle)
    mem_loaded = memory()
    normalized = []
    for u in urls:
        try:
            normalized.append(normalize_url(u))
        except InvalidURLError:
            pass
    if not normalized:
        raise ValueError("none of the URLs normalizes")
    threat_db = None
    if intel_config is not None:
        threat_db = ThreatIntelDB.from_config(ThreatIntelConfig.from_file(intel_config))
    db_status = "not used" if threat_db is None else threat_db.lookup(normalized[0]).status
    config = service_config or ServiceConfig()
    log(f"model loaded in {load.wall:.2f} s; {len(normalized)} URLs; torch threads {torch.get_num_threads()}")
    sweep = []
    if thread_sweep:
        log(f"model alone per thread count {list(thread_sweep)} ...")
        sweep = bench_threads(runtime, normalized, thread_sweep, min_batches, max_seconds)
    log("model alone ...")
    model = bench_model(runtime, normalized, batch_sizes, min_batches, max_seconds)
    log("predictor (cold / warm cache) ...")
    pred = bench_predictor(runtime, threat_db, [n.original for n in normalized])
    log("service (concurrent callers) ...")
    service = bench_service(runtime, threat_db, [n.original for n in normalized], concurrency,
                            service_requests, config)
    mem_end = memory()
    if threat_db is not None:
        threat_db.close()
    bundle_bytes = sum(p.stat().st_size for p in Path(bundle.path).iterdir() if p.is_file())
    return {
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "machine": machine_info(),
        "model_version": runtime.model_version, "bundle_bytes": bundle_bytes,
        "urls": {"count": len(normalized), "source": url_source},
        "threat_db_lookup": db_status,
        "load_seconds": round(load.wall, 3),
        "memory_bytes": {"start_rss": mem_start["rss"], "after_load_rss": mem_loaded["rss"],
                         "end_rss": mem_end["rss"], "peak_rss": mem_end["peak_rss"]},
        "thread_sweep": sweep, "model": model, "predictor": pred, "service": service,
        "service_config": {k: getattr(config, k) for k in ("max_batch_urls", "max_wait_ms",
                                                           "max_queue_urls", "model_batch_size")},
    }


def _mb(v: int | None) -> str:
    return "  n/a" if v is None else f"{v / 2**20:,.0f} MB"


def print_report(r: dict) -> None:
    m = r["machine"]
    print(f"\n{m['system']} {m['machine']}, {m['cpu_count']} CPUs, torch {m['torch']} "
          f"({m['torch_threads']} threads); {r['model_version']}; {r['urls']['count']} URLs "
          f"({r['urls']['source']})")
    if m.get("cores"):
        print("cores: " + ", ".join(f"{n} x {k}" for k, n in m["cores"].items())
              + (f" ({m['board']})" if m.get("board") else ""))
    mem = r["memory_bytes"]
    print(f"load {r['load_seconds']:.2f} s | memory: start {_mb(mem['start_rss'])}, after load "
          f"{_mb(mem['after_load_rss'])}, peak {_mb(mem['peak_rss'])} | bundle {_mb(r['bundle_bytes'])}")
    if r.get("thread_sweep"):
        print("\nthreads, model alone  batch  P50 ms  P95 ms  P99 ms   ms/URL    URLs/s  cores")
        for x in r["thread_sweep"]:
            lat = x["latency_ms"]
            print(f"  {x['threads']:>3} threads        {x['batch_size']:>5} {lat['p50']:>7.2f} {lat['p95']:>7.2f} "
                  f"{lat['p99']:>7.2f} {x['ms_per_url']:>8.3f} {x['urls_per_second']:>9,.0f} "
                  f"{x['cpu_cores_busy']:>6.2f}")
    print("\nmodel alone          batch  P50 ms  P95 ms  P99 ms   ms/URL    URLs/s  cores")
    for x in r["model"]:
        lat = x["latency_ms"]
        print(f"  {x['batches']:>5} batches     {x['batch_size']:>5} {lat['p50']:>7.2f} {lat['p95']:>7.2f} "
              f"{lat['p99']:>7.2f} {x['ms_per_url']:>8.3f} {x['urls_per_second']:>9,.0f} {x['cpu_cores_busy']:>6.2f}")
    p = r["predictor"]
    print(f"\npredictor, calls of {p['call_size']} URLs   P50 ms/call   URLs/s   cache hit rate")
    for name in ("cold", "warm"):
        x = p[name]
        rate = "n/a" if x["cache_hit_rate"] is None else f"{x['cache_hit_rate']:.1%}"
        print(f"  {name:<30} {x['latency_ms_per_call']['p50']:>9.2f} {x['urls_per_second']:>9,.0f}"
              f"   {rate}")
    print("\nservice, 1 URL/request  callers  P50 ms  P95 ms  P99 ms   req/s  mean batch  cores")
    for x in r["service"]:
        lat = x["latency_ms"]
        print(f"  {x['requests']:>6} requests      {x['concurrency']:>5} {lat['p50']:>7.2f} {lat['p95']:>7.2f} "
              f"{lat['p99']:>7.2f} {x['requests_per_second']:>7,.0f} {x['mean_batch_urls'] or 0:>11.1f} "
              f"{x['cpu_cores_busy']:>6.2f}")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--bundle", type=Path, default=MODELS_DIR / "full_url")
    ap.add_argument("--urls", type=Path, default=None, help="one URL per line (default: validation split)")
    ap.add_argument("--sample", type=int, default=2048, help="URLs used (random sample, seed 0)")
    ap.add_argument("--save-urls", type=Path, default=None, help="write the URLs used, for another machine")
    ap.add_argument("--intel-config", type=Path, default=Path("config/threat_intel.json"))
    ap.add_argument("--service-config", type=Path, default=Path("config/inference.json"))
    ap.add_argument("--threads", type=int, default=None, help="torch threads (default: PyTorch's choice)")
    ap.add_argument("--thread-sweep", default="", help="e.g. 1,2,4,8: model alone per thread count")
    ap.add_argument("--batch-sizes", default=",".join(map(str, BATCH_SIZES)))
    ap.add_argument("--concurrency", default=",".join(map(str, CONCURRENCY)))
    ap.add_argument("--service-requests", type=int, default=1000)
    ap.add_argument("--max-seconds", type=float, default=20.0, help="time limit per model batch size")
    ap.add_argument("--quick", action="store_true", help="256 URLs, fewer repeats")
    ap.add_argument("--out", type=Path, default=REPORTS_DIR)
    args = ap.parse_args(argv)
    sample, min_batches, requests = args.sample, 30, args.service_requests
    if args.quick:
        sample, min_batches, requests = min(sample, 256), 5, min(requests, 200)
    urls, source = load_urls(args.urls, sample)
    if args.save_urls is not None:
        args.save_urls.parent.mkdir(parents=True, exist_ok=True)
        args.save_urls.write_text("".join(u + "\n" for u in urls), encoding="utf-8")
        print(f"wrote {len(urls)} URLs to {args.save_urls}")
    report = run_benchmark(args.bundle, urls, url_source=source, intel_config=args.intel_config,
                           batch_sizes=[int(x) for x in args.batch_sizes.split(",")],
                           concurrency=[int(x) for x in args.concurrency.split(",")],
                           min_batches=min_batches, max_seconds=args.max_seconds,
                           service_requests=requests,
                           service_config=ServiceConfig.from_file(args.service_config),
                           threads=args.threads,
                           thread_sweep=[int(x) for x in args.thread_sweep.split(",") if x.strip()],
                           log=lambda s: print(s, flush=True))
    print_report(report)
    args.out.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = args.out / f"benchmark_{platform.machine() or 'unknown'}_{stamp}.json"
    path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"\nreport: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
