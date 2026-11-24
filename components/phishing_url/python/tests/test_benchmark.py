import json

from src.inference import benchmark
from src.inference.benchmark import Meter, load_urls, memory, run_benchmark
from tests.test_inference import tiny  # noqa: F401  (module fixture)

URLS = [f"https://site{i}.example.org/page/{i}?id={i}" for i in range(40)] + ["https://bit.ly/abc", "not a url"]


def test_memory_and_meter():
    m = memory()
    assert set(m) == {"rss", "peak_rss"}
    assert m["peak_rss"] is None or m["peak_rss"] > 0
    with Meter() as t:
        sum(range(100_000))
    assert t.wall > 0 and t.cpu >= 0 and t.cores_busy >= 0


def test_run_benchmark_on_a_tiny_bundle(tiny):  # noqa: F811
    r = run_benchmark(tiny["bundle"].path, URLS, url_source="test", intel_config=None,
                      batch_sizes=(1, 8), concurrency=(1, 4), min_batches=3, max_seconds=2,
                      service_requests=20)
    assert r["urls"]["count"] == 41                              # "not a url" is skipped
    assert [x["batch_size"] for x in r["model"]] == [1, 8]
    for x in r["model"]:
        lat = x["latency_ms"]
        assert x["batches"] >= 3 and x["urls_per_second"] > 0
        assert 0 < lat["p50"] <= lat["p95"] <= lat["p99"]
    assert r["predictor"]["cold"]["cache_hit_rate"] == 0.0
    assert r["predictor"]["warm"]["cache_hit_rate"] == 1.0       # the same URLs again
    assert [x["concurrency"] for x in r["service"]] == [1, 4]
    assert all(x["rejected"] == 0 and x["requests_per_second"] > 0 for x in r["service"])
    assert r["model_version"] == tiny["bundle"].model_version and r["threat_db_lookup"] == "not used"
    json.dumps(r)                                                # the report is plain JSON
    benchmark.print_report(r)


def test_cli_with_a_url_file(tiny, tmp_path, capsys):  # noqa: F811
    src = tmp_path / "urls.txt"
    src.write_text("# comment\n" + "\n".join(URLS) + "\n\n", encoding="utf-8")
    urls, source = load_urls(src, sample=10)
    assert len(urls) == 10 and source == "file:urls.txt"
    saved = tmp_path / "saved.txt"
    assert benchmark.main(["--bundle", str(tiny["bundle"].path), "--urls", str(src), "--quick",
                           "--batch-sizes", "1,4", "--concurrency", "2", "--service-requests", "10",
                           "--save-urls", str(saved), "--out", str(tmp_path / "reports"),
                           "--intel-config", str(tmp_path / "none.json")]) == 0
    out = capsys.readouterr().out
    assert "model alone" in out and "service" in out
    (report,) = (tmp_path / "reports").glob("benchmark_*.json")
    data = json.loads(report.read_text(encoding="utf-8"))
    assert data["urls"]["count"] == len(saved.read_text(encoding="utf-8").splitlines()) - 1  # minus "not a url"
