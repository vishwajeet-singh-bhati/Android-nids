"""HTTP API (src/api): endpoints, limits, errors, logs, metrics, concurrency."""
import json
import logging
import re
from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi.testclient import TestClient

from src.api.app import create_app
from src.api.config import ApiConfig
from src.inference.service import InferenceService, ServiceConfig
from src.utils.redact import redact_url
from tests.test_inference import make_predictor, tiny  # noqa: F401  (module fixture)
from tests.test_service import FakePredictor, blocked_service
from tests.test_threat_intel import LISTED

SMALL = ServiceConfig(max_urls_per_request=8, max_queue_urls=64)


def client_for(factory, **cfg) -> TestClient:
    return TestClient(create_app(factory, ApiConfig(**cfg)))


@pytest.fixture
def api(tiny):  # noqa: F811
    calls = []

    def factory():
        calls.append(1)
        return InferenceService(make_predictor(tiny), SMALL, owns_predictor=True)

    with client_for(factory) as client:          # `with`: runs startup (model load) and shutdown
        client.factory_calls = calls
        yield client


# ---------------------------------------------------------------- /predict
def test_batch_keeps_order_and_marks_bad_input(api):
    urls = ["https://www.news7.org/world/story-7", LISTED, "not a url", "https://bit.ly/unlisted1",
            "HTTPS://WWW.NEWS7.ORG/world/story-7", "https://pаypal.com/signin",      # Cyrillic "а"
            "https://long-site.com/" + "a" * 9000]
    r = api.post("/predict", json={"urls": urls})
    assert r.status_code == 200
    body = r.json()
    res = body["results"]
    assert [x["url"] for x in res] == urls                                          # order kept
    assert (res[1]["decision"], res[1]["source"]) == ("phishing", "threat_intel")
    assert any(m["level"] == "exact_url" for m in res[1]["threat_intel"])
    assert res[2]["decision"] is None and res[2]["error"] == "invalid_input:illegal_characters"
    assert (res[3]["decision"], res[3]["source"], res[3]["risk_score"]) == ("uncertain", "rule", None)
    assert res[0]["risk_score"] == res[4]["risk_score"] is not None                 # duplicates agree
    assert res[5]["decision"] in ("phishing", "uncertain", "likely_safe")            # IDN host is scored
    assert res[6]["error"] == "invalid_input:too_long"
    assert body["request_id"] == r.headers["x-request-id"] and body["model_version"] == res[0]["model_version"]


def test_single_url_and_domain_input(api):
    one = api.post("/predict", json={"urls": ["https://www.news7.org/world/story-7"]}).json()["results"]
    assert len(one) == 1 and one[0]["input_type"] == "full_url"
    assert one[0]["risk_score"] is not None and one[0]["model_version"]
    dom = api.post("/predict", json={"urls": ["news7.org"], "input_type": "domain"}).json()["results"][0]
    # no hostname model yet: threat intelligence only, otherwise UNCERTAIN (spec)
    assert (dom["decision"], dom["source"], dom["risk_score"], dom["input_type"]) == \
        ("uncertain", "rule", None, "domain")


@pytest.mark.parametrize("payload", [
    {"urls": []}, {"urls": "https://a.com/"}, {"urls": [1, 2]}, {}, {"urls": [None]},
    {"urls": ["https://a.com/"], "input_type": "ip"}, {"urls": ["https://a.com/"], "extra": 1}])
def test_malformed_requests_get_422_without_echo(api, payload):
    r = api.post("/predict", json=payload)
    assert r.status_code == 422
    assert all(set(e) == {"loc", "msg", "type"} for e in r.json()["detail"])       # no "input" echoed


def test_invalid_json_and_too_many_urls(api):
    r = api.post("/predict", content=b'{"urls": ["https://a.com/"', headers={"content-type": "application/json"})
    assert r.status_code == 422
    r = api.post("/predict", json={"urls": [f"https://a{i}.com/" for i in range(9)]})
    assert r.status_code == 413 and "at most 8" in r.json()["detail"]


def test_body_size_limit_answers_413_before_reading():
    with client_for(lambda: InferenceService(FakePredictor()), max_body_bytes=1000) as c:
        r = c.post("/predict", json={"urls": ["https://example.com/" + "a" * 2000]})
        assert r.status_code == 413 and "at most 1000 bytes" in r.json()["detail"]
        assert r.headers["x-request-id"]

        def chunks():                                   # no Content-Length: Starlette counts the bytes
            yield b'{"urls": ["https://example.com/'
            for _ in range(10):
                yield b"a" * 200
            yield b'"]}'
        r = c.post("/predict", content=chunks(), headers={"content-type": "application/json"})
        assert r.status_code == 413 and r.json()["detail"]          # JSON either way ("Content Too Large")
        assert c.get("/ready").json()["ready"]          # a predictor without model_version still loads
        assert c.post("/predict", json={"urls": []}).status_code == 422               # small body: parsed


# ---------------------------------------------------------------- overload, timeouts, failures
def test_full_queue_answers_503_with_retry_after():
    svc, fake, first = blocked_service(max_queue_urls=2, max_urls_per_request=2)
    filler = svc.submit(["a", "b"])                     # the queue is now full
    with client_for(lambda: svc, retry_after_seconds=3) as c:
        r = c.post("/predict", json={"urls": ["https://example.com/"]})
        assert r.status_code == 503 and r.headers["retry-after"] == "3"
        assert r.json()["detail"].startswith("overloaded")
        fake.gate.set()
        assert first.result(5) and filler.result(5)


def test_slow_answer_times_out_with_503():
    svc, fake, first = blocked_service()
    with client_for(lambda: svc, request_timeout_seconds=0.2) as c:
        r = c.post("/predict", json={"urls": ["https://example.com/"]})
        assert r.status_code == 503 and "timed out" in r.json()["detail"] and r.headers["retry-after"]
        fake.gate.set()
    assert svc.counts["cancelled"] == 1                 # the abandoned request was never scored


def test_internal_errors_are_not_leaked():
    fake = FakePredictor()
    fake.fail = RuntimeError(r"secret details C:\models\cnn.pt")
    with client_for(lambda: InferenceService(fake)) as c:
        r = c.post("/predict", json={"urls": ["https://example.com/"]})
    assert r.status_code == 500 and r.json() == {"detail": "internal error"}


def test_failed_model_load_keeps_health_but_not_readiness():
    def broken():
        raise FileNotFoundError("models/full_url/version.json not found")
    with client_for(broken) as c:
        assert c.get("/health").json() == {"status": "ok"}
        ready = c.get("/ready")
        assert ready.status_code == 503 and "version.json" in ready.json()["reason"] and ready.headers["retry-after"]
        r = c.post("/predict", json={"urls": ["https://example.com/"]})
        assert r.status_code == 503 and r.json()["detail"].startswith("not ready")
        assert c.get("/model-info").status_code == 503
        assert "phishing_ready 0" in c.get("/metrics").text


def test_shutdown_closes_the_service(tiny):  # noqa: F811
    made = []
    with client_for(lambda: made.append(InferenceService(make_predictor(tiny), owns_predictor=True))
                    or made[-1]) as c:
        assert c.get("/ready").json() == {"ready": True, "model_version": made[0].predictor.model_version,
                                          "reason": None}
    assert not made[0].running


def test_concurrent_requests_share_one_model(api):
    batches = [[f"https://site{i}.example.org/p/{j}" for j in range(3)] for i in range(24)]
    with ThreadPoolExecutor(8) as pool:
        answers = list(pool.map(lambda urls: api.post("/predict", json={"urls": urls}), batches))
    assert all(a.status_code == 200 for a in answers)
    assert [[x["url"] for x in a.json()["results"]] for a in answers] == batches
    alone = api.post("/predict", json={"urls": batches[5]}).json()["results"]
    assert [x["decision"] for x in alone] == [x["decision"] for x in answers[5].json()["results"]]
    assert len(api.factory_calls) == 1                  # loaded once, at startup


# ---------------------------------------------------------------- other endpoints
def test_model_info(api):
    info = api.get("/model-info").json()
    assert info["model_version"] and info["model"]["thresholds"]["phishing_if_p_above"] is not None
    assert info["input_types"] == ["full_url", "domain"] and info["input_types_scored_by_model"] == ["full_url"]
    assert info["limits"]["max_urls_per_request"] == 8 and info["limits"]["max_url_length"] == 8192
    assert info["threat_intel"]["local_feeds"]["active_indicators"] > 0
    assert "stale" in info["threat_intel"]["local_feeds"]
    assert "built_from" not in json.dumps(info) and "artifacts" not in json.dumps(info)   # no internal paths


def test_metrics_are_valid_prometheus_text(api):
    api.post("/predict", json={"urls": [LISTED, "not a url"]})
    r = api.get("/metrics")
    assert r.headers["content-type"].startswith("text/plain; version=0.0.4")
    text = r.text
    assert text.endswith("\n")
    assert 'phishing_http_requests_total{endpoint="/predict",code="200"} 1' in text
    assert 'phishing_urls_total{decision="phishing"} 1' in text and 'phishing_urls_total{decision="invalid"} 1' in text
    assert "phishing_ready 1" in text and "phishing_model_info{model_version=" in text
    sample = re.compile(r'^[a-z_]+(\{[a-z_]+="[^"\n]*"(,[a-z_]+="[^"\n]*")*\})? -?[0-9.e+-]+$')
    for line in text.splitlines():
        assert line.startswith("# HELP ") or line.startswith("# TYPE ") or sample.match(line), line


def test_request_ids_and_docs_switch(tiny):  # noqa: F811
    with client_for(lambda: InferenceService(make_predictor(tiny), owns_predictor=True), docs_enabled=False) as c:
        assert c.get("/health", headers={"X-Request-ID": "nids-42"}).headers["x-request-id"] == "nids-42"
        assert re.fullmatch(r"[0-9a-f]{32}", c.get("/health", headers={"X-Request-ID": "bad id <x>"}).headers["x-request-id"])
        assert c.get("/docs").status_code == 404 and c.get("/openapi.json").status_code == 200


# ---------------------------------------------------------------- logs
def test_logs_hold_no_query_values(api, caplog):
    caplog.set_level(logging.INFO, logger="phishing.api")
    api.post("/predict", json={"urls": [LISTED, "https://www.news7.org/a?token=SECRET123&email=me@x.org"]})
    assert "SECRET123" not in caplog.text and "me@x.org" not in caplog.text and "update.php?id=1" not in caplog.text
    assert "url=http://login-verify.evil-site.xyz/account/update.php?id=REDACTED" in caplog.text
    assert re.search(r"predict id=\w+ type=full_url urls=2 ", caplog.text)


@pytest.mark.parametrize("raw,expected", [
    ("https://user:pw@Bank.example:8443/reset?token=abc&id=7#top",
     "https://bank.example:8443/reset?token=REDACTED&id=REDACTED"),
    ("http://x.com/a?eyJhbGciOiJIUzI1NiJ9&b=1", "http://x.com/a?REDACTED&b=REDACTED"),    # bare value
    ("http://x.com/a?" + "n" * 40 + "=1", "http://x.com/a?REDACTED=REDACTED"),           # odd "name"
    ("example.com/login?email=a@b.c", "example.com/login?email=REDACTED"),
    ("http://[::1]/p?q=1", "http://[::1]/p?q=REDACTED"),
    ("http://evil.com/\x1b[31mred", "http://evil.com/?[31mred"),                        # no terminal codes
    ("http://evil.com/a\r\nFAKE", "http://evil.com/aFAKE"),                             # no forged lines
    ("http://x.com/" + "p" * 300, "http://x.com/" + "p" * 187 + "..."),
    ("http://x.com:99999/", "<unparseable URL>"),
    (12, "<not text>"),
])
def test_redact_url(raw, expected):
    assert redact_url(raw) == expected
    assert "\n" not in redact_url(raw) and "\r" not in redact_url(raw)


def test_api_config_checks(tmp_path):
    assert ApiConfig.from_file(tmp_path / "missing.json") == ApiConfig()
    (tmp_path / "a.json").write_text('{"max_body_bytes": 10, "nope": 1}', encoding="utf-8")
    with pytest.raises(ValueError, match="unknown keys"):
        ApiConfig.from_file(tmp_path / "a.json")
    for bad in ({"max_body_bytes": 0}, {"request_timeout_seconds": -1}, {"docs_enabled": "yes"},
                {"retry_after_seconds": 1.5}):
        with pytest.raises(ValueError):
            ApiConfig(**bad)
    assert ApiConfig.from_file() == ApiConfig()          # the shipped config/api.json = the defaults
