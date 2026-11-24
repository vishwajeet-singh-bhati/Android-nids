"""SMS module -> URL detector bridge (src/integration/sms_bridge.py)."""
import io
import json

import httpx
import pytest
from fastapi.testclient import TestClient

from src.api.app import create_app
from src.api.config import ApiConfig
from src.api.schemas import PredictionItem
from src.inference.service import InferenceService, ServiceConfig
from src.integration import sms_bridge
from src.integration.sms_bridge import (URL_CHECK_UNAVAILABLE, URL_CHECK_UNCERTAIN, URL_FLAGGED_PHISHING,
                                        URL_KNOWN_THREAT, URL_NOT_FLAGGED, CheckUnavailable, HttpUrlChecker,
                                        LocalUrlChecker, SmsBridge, SmsModuleMissing, combine, tidy_link,
                                        tidy_links)
from tests.test_inference import make_predictor, tiny  # noqa: F401  (module fixture)
from tests.test_threat_intel import LISTED

URL_CODES = {URL_FLAGGED_PHISHING, URL_KNOWN_THREAT, URL_CHECK_UNCERTAIN, URL_CHECK_UNAVAILABLE, URL_NOT_FLAGGED}


def sms_result(label="spam", risk="low", actions=("MARK_AS_SPAM", "DO_NOT_INTERACT"), codes=("URL_PRESENT",)):
    """Shaped like sms_detection's SmsDetectionResult.to_dict()."""
    return {"module": "sms_detector", "schema_version": "1.0", "label": label, "risk_level": risk,
            "scores": {"ham": 0.2, "spam": 0.5, "smishing": 0.3},
            "evidence": [{"code": c, "present": True} for c in codes],
            "recommended_action_codes": list(actions), "model_version": "sms-model-0.1",
            "explanation_source": "detector_evidence"}


def item(decision="likely_safe", source="model", pending=(), error=None):
    return {"url": "ignored", "input_type": "full_url", "decision": decision, "risk_score": 0.5,
            "source": source, "model_version": "full_url-test", "cache_hit": False, "reasons": ["r"],
            "threat_types": [], "attributions": [], "threat_intel": [], "pending": list(pending), "error": error}


class FakeSms:
    def __init__(self, result):
        self.result, self.calls = result, []

    def predict_sms(self, text, sender=None, known_sender=False):
        self.calls.append((text, sender, known_sender))
        return dict(self.result)


class FakeChecker:
    def __init__(self, answers=None, fail=None):
        self.answers, self.fail, self.calls, self.closed = answers or {}, fail, [], False

    def check(self, urls):
        self.calls.append(list(urls))
        if self.fail:
            raise CheckUnavailable(self.fail)
        return [self.answers.get(u, item()) for u in urls]

    def close(self):
        self.closed = True


def run(sms, links, checker=None, **kw):
    checker = checker or FakeChecker()
    out = SmsBridge(FakeSms(sms), checker, lambda text: links, **kw).check("message text")
    return out, checker


def codes(out):
    return [e["code"] for e in out["combined"]["evidence"]]


# ---------------------------------------------------------------- tidying links
@pytest.mark.parametrize("raw, want", [
    ("github.com/login.", "github.com/login"),
    ("bit.ly/3xYzAbc,", "bit.ly/3xYzAbc"),
    ("www.indiapost-redelivery.top/pay?id=88213.", "www.indiapost-redelivery.top/pay?id=88213"),
    ("https://en.wikipedia.org/wiki/Python_(language)", "https://en.wikipedia.org/wiki/Python_(language)"),
    ("https://x.com/a)", "https://x.com/a"),
    ("(https://x.com/a)", "https://x.com/a"),
    ('"https://a.com/x"!', "https://a.com/x"),
    ("https://a.com/x?!...", "https://a.com/x"),
    ("https://a.com/", "https://a.com/"),
    ("...", None), ("   ", None),
])
def test_tidy_link(raw, want):
    assert tidy_link(raw) == want


def test_tidy_links_dedupes_after_tidying():
    assert tidy_links(["github.com/login.", "github.com/login", "", "x.in,"]) == ["github.com/login", "x.in"]


# ---------------------------------------------------------------- the combine rule
def test_phishing_link_raises_a_quiet_message_to_high():
    sms = sms_result()
    out, checker = run(sms, ["https://pay-verify.top/login."], FakeChecker({"https://pay-verify.top/login":
                                                                            item("phishing")}))
    assert checker.calls == [["https://pay-verify.top/login"]]                      # tidied before sending
    assert out["sms"] == sms                                                         # SMS answer untouched
    c = out["combined"]
    assert (c["risk_level"], c["raised_by_links"]) == ("high", True)
    assert c["recommended_action_codes"] == ["DO_NOT_CLICK", "VERIFY_USING_OFFICIAL_CHANNEL", "REPORT_AS_SCAM"]
    assert codes(out) == ["URL_PRESENT", URL_FLAGGED_PHISHING]
    assert out["links"]["status"] == "checked" and out["links"]["results"][0]["decision"] == "phishing"


def test_threat_list_match_is_named():
    out, _ = run(sms_result(), ["evil.xyz/a"], FakeChecker({"evil.xyz/a": item("phishing", "threat_intel")}))
    assert codes(out)[1:] == [URL_FLAGGED_PHISHING, URL_KNOWN_THREAT]


def test_raised_suspicious_message_gets_high_risk_advice():
    sms = sms_result("smishing", "suspicious", ("DO_NOT_CLICK", "DO_NOT_SHARE_OTP", "VERIFY_BEFORE_ACTING"))
    out, _ = run(sms, ["a.top/x"], FakeChecker({"a.top/x": item("phishing")}))
    assert out["combined"]["risk_level"] == "high"
    assert out["combined"]["recommended_action_codes"] == [
        "DO_NOT_CLICK", "DO_NOT_SHARE_OTP", "VERIFY_USING_OFFICIAL_CHANNEL", "REPORT_AS_SCAM"]


def test_a_clean_link_never_lowers_the_risk():
    sms = sms_result("smishing", "high", ("DO_NOT_CLICK", "DO_NOT_SHARE_OTP", "REPORT_AS_SCAM"))
    out, _ = run(sms, ["https://www.sbi.co.in/"])
    c = out["combined"]
    assert (c["risk_level"], c["raised_by_links"]) == ("high", False)
    assert c["recommended_action_codes"] == ["DO_NOT_CLICK", "DO_NOT_SHARE_OTP", "REPORT_AS_SCAM"]
    assert codes(out) == ["URL_PRESENT", URL_NOT_FLAGGED]


def test_uncertain_link_changes_nothing_but_is_reported():
    sms = sms_result()
    out, _ = run(sms, ["bit.ly/abc"], FakeChecker({"bit.ly/abc": item("uncertain", "rule")}))
    assert out["combined"]["risk_level"] == "low"
    assert out["combined"]["recommended_action_codes"] == sms["recommended_action_codes"]
    assert codes(out) == ["URL_PRESENT", URL_CHECK_UNCERTAIN]


def test_unavailable_detector_is_never_read_as_safe():
    out, _ = run(sms_result(), ["a.com/x", "b.com/y"], FakeChecker(fail="api_unreachable"))
    links = out["links"]
    assert (links["status"], links["error"], links["checked"], links["not_checked"]) == \
        ("unavailable", "api_unreachable", 0, 2)
    assert all(r["decision"] is None and r["error"] == "not_checked" for r in links["results"])
    assert codes(out) == ["URL_PRESENT", URL_CHECK_UNAVAILABLE]
    assert out["combined"]["risk_level"] == "low"


def test_an_unparseable_link_counts_as_not_checked():
    out, _ = run(sms_result(), ["ok.com/a", "bad"],
                 FakeChecker({"bad": item(None, None, error="invalid_input:no_host")}))
    assert (out["links"]["status"], out["links"]["checked"], out["links"]["not_checked"]) == ("partial", 1, 1)
    assert codes(out) == ["URL_PRESENT", URL_CHECK_UNAVAILABLE]               # not URL_NOT_FLAGGED


def test_links_over_the_cap_are_counted_not_dropped():
    out, checker = run(sms_result(), ["a.com/1", "a.com/2", "a.com/3"], max_links=2)
    assert checker.calls == [["a.com/1", "a.com/2"]]
    assert (out["links"]["found"], out["links"]["checked"], out["links"]["not_checked"]) == (3, 2, 1)
    assert out["links"]["status"] == "partial" and URL_CHECK_UNAVAILABLE in codes(out)


def test_message_without_links_skips_the_detector():
    sms = sms_result("ham", "low", ("NO_ACTION",), ())
    out, checker = run(sms, [])
    assert checker.calls == []
    assert out["links"] == {"status": "no_links", "found": 0, "checked": 0, "not_checked": 0, "error": None,
                            "complete": True, "model_versions": [], "results": []}
    assert out["combined"] == {"risk_level": "low", "raised_by_links": False, "evidence": [],
                               "recommended_action_codes": ["NO_ACTION"]}


def test_pending_online_check_marks_the_answer_incomplete():
    out, _ = run(sms_result(), ["a.com/x"], FakeChecker({"a.com/x": item(pending=["google_safe_browsing"])}))
    assert out["links"]["complete"] is False
    assert out["links"]["model_versions"] == ["full_url-test"]


def test_output_holds_no_message_text_and_no_query_values():
    link = "https://kyc-update.top/verify?phone=9876543210&token=Zx81Qp#frag"
    sms = FakeSms(sms_result())
    out = SmsBridge(sms, FakeChecker(), lambda t: [link]).check("Ramesh, your KYC expires today: " + link)
    dumped = json.dumps(out)
    for secret in ("Ramesh", "9876543210", "Zx81Qp", "frag", "KYC expires"):
        assert secret not in dumped
    assert out["links"]["results"][0]["display_url"] == \
        "https://kyc-update.top/verify?phone=REDACTED&token=REDACTED"


def test_sender_reaches_the_sms_module():
    sms = FakeSms(sms_result())
    SmsBridge(sms, FakeChecker(), lambda t: []).check("hi", "AD-SBIINB", known_sender=True)
    assert sms.calls == [("hi", "AD-SBIINB", True)]
    with pytest.raises(TypeError):
        SmsBridge(sms, FakeChecker(), lambda t: []).check(None)


def test_combine_refuses_inconsistent_input():
    with pytest.raises(ValueError, match="one detector answer per link"):
        combine(sms_result(), ["a.com", "b.com"], [item()])
    with pytest.raises(ValueError, match="unknown SMS risk_level"):
        combine(sms_result(risk="critical"), [], [])


# ---------------------------------------------------------------- HTTP checker
def http_checker(handler, **kw):
    sleeps = []
    client = httpx.Client(base_url="http://api.test", transport=httpx.MockTransport(handler))
    return HttpUrlChecker("http://api.test", client=client, sleep=sleeps.append, **kw), sleeps


def ok_body(urls):
    return {"results": [item() | {"url": u} for u in urls], "model_version": "m", "request_id": "r"}


def test_http_checker_posts_the_links():
    seen = []

    def handler(request):
        seen.append((request.method, request.url.path, json.loads(request.content)))
        return httpx.Response(200, json=ok_body(["a.com/x"]))

    checker, _ = http_checker(handler)
    assert checker.check(["a.com/x"])[0]["url"] == "a.com/x"
    assert seen == [("POST", "/predict", {"urls": ["a.com/x"], "input_type": "full_url"})]


def test_http_checker_waits_once_on_503_with_a_capped_retry_after():
    answers = iter([httpx.Response(503, headers={"retry-after": "30"}), httpx.Response(200, json=ok_body(["a"]))])
    checker, sleeps = http_checker(lambda r: next(answers))
    assert len(checker.check(["a"])) == 1 and sleeps == [5.0]

    checker, sleeps = http_checker(lambda r: httpx.Response(503, headers={"retry-after": "soon"}))
    with pytest.raises(CheckUnavailable) as e:
        checker.check(["a"])
    assert e.value.reason == "api_http_503" and sleeps == [1.0]


@pytest.mark.parametrize("response, reason", [
    (httpx.Response(500, json={"detail": "internal error"}), "api_http_500"),
    (httpx.Response(307, headers={"location": "http://elsewhere.test/predict"}), "api_http_307"),  # not followed
    (httpx.Response(200, content=b"not json"), "api_bad_response"),
    (httpx.Response(200, json={"results": []}), "api_bad_response"),                  # wrong length
    (httpx.Response(200, json={"oops": 1}), "api_bad_response"),
    (httpx.Response(200, json={"results": ["x"]}), "api_bad_response"),
])
def test_http_checker_failures_are_unavailable(response, reason):
    checker, _ = http_checker(lambda r: response)
    with pytest.raises(CheckUnavailable) as e:
        checker.check(["a"])
    assert e.value.reason == reason


@pytest.mark.parametrize("error, reason", [(httpx.ConnectError("refused"), "api_unreachable"),
                                           (httpx.ReadTimeout("slow"), "api_timeout")])
def test_http_checker_network_errors_are_unavailable(error, reason):
    def handler(request):
        raise error

    checker, _ = http_checker(handler)
    with pytest.raises(CheckUnavailable) as e:
        checker.check(["a"])
    assert e.value.reason == reason


def test_http_checker_settings():
    with pytest.raises(ValueError):
        HttpUrlChecker("ftp://127.0.0.1:8000")
    with pytest.raises(ValueError):
        HttpUrlChecker("127.0.0.1:8000")
    with pytest.raises(ValueError):
        HttpUrlChecker(retries=-1)
    checker = HttpUrlChecker("http://127.0.0.1:8123/")
    assert checker._client.trust_env is False and checker._client.follow_redirects is False
    assert str(checker._client.base_url) == "http://127.0.0.1:8123"
    checker.close()


# ---------------------------------------------------------------- with the real detector
SMALL = ServiceConfig(max_urls_per_request=8, max_queue_urls=64)
LINKS = [LISTED + ".", "https://www.news7.org/world/story-7,", "bit.ly/unlisted1"]


def test_through_the_real_http_api(tiny):  # noqa: F811
    factory = lambda: InferenceService(make_predictor(tiny), SMALL, owns_predictor=True)  # noqa: E731
    with TestClient(create_app(factory, ApiConfig())) as client:
        out, _ = run(sms_result(), LINKS, HttpUrlChecker("http://testserver", client=client))
    res = out["links"]["results"]
    assert (res[0]["decision"], res[0]["source"]) == ("phishing", "threat_intel")      # listed, after tidying
    assert (res[2]["decision"], res[2]["source"]) == ("uncertain", "rule")             # link shortener
    assert out["combined"]["risk_level"] == "high"
    assert codes(out)[:3] == ["URL_PRESENT", URL_FLAGGED_PHISHING, URL_KNOWN_THREAT]


def test_in_process_checker_gives_the_api_answers(tiny):  # noqa: F811
    local = LocalUrlChecker(InferenceService(make_predictor(tiny), SMALL, owns_predictor=True), owns_service=True)
    try:
        items = local.check(tidy_links(LINKS))
        out, _ = run(sms_result(), LINKS, local)
    finally:
        local.close()
    assert all(set(i) == set(PredictionItem.model_fields) for i in items)             # same fields as /predict
    assert [i["decision"] for i in items] == [r["decision"] for r in out["links"]["results"]]
    assert items[0]["decision"] == "phishing" and out["combined"]["raised_by_links"] is True


def test_with_the_real_sms_module():
    pytest.importorskip("sms_detection")
    try:
        detector, extract = sms_bridge.load_sms_module()
    except Exception as exc:                          # package present but its model is not built
        pytest.skip(f"SMS model not available: {type(exc).__name__}")
    checker = FakeChecker({"https://sbi-kyc-verify.in/login": item("phishing")})
    bridge = SmsBridge(detector, checker, extract)
    out = bridge.check("Your KYC is pending. Update now at https://sbi-kyc-verify.in/login. "
                       "Or your account will be blocked.", "+919876543210")
    assert checker.calls == [["https://sbi-kyc-verify.in/login"]]
    assert out["sms"]["label"] in ("ham", "spam", "smishing") and out["combined"]["risk_level"] == "high"
    assert "URL_PRESENT" in codes(out) and URL_FLAGGED_PHISHING in codes(out)
    quiet = bridge.check("Your OTP is 482913. Do not share it with anyone.", "AD-HDFCBK")
    assert quiet["links"]["status"] == "no_links" and not URL_CODES & set(codes(quiet))


# ---------------------------------------------------------------- command line
@pytest.fixture
def cli(monkeypatch):
    made = []

    def fake_checker(**kw):
        made.append(FakeChecker({"evil.top/x": item("phishing")}))
        return made[-1]

    monkeypatch.setattr(sms_bridge, "load_sms_module",
                        lambda model_dir=None: (FakeSms(sms_result()), lambda t: [w for w in t.split() if "." in w]))
    monkeypatch.setattr(sms_bridge.LocalUrlChecker, "from_files", staticmethod(fake_checker))
    return made


def test_cli_file_of_messages(cli, tmp_path, capsys):
    f = tmp_path / "messages.json"
    f.write_text(json.dumps([{"text": "pay at evil.top/x.", "sender": "+911234567890"}, {"text": "hello"}]),
                 encoding="utf-8")
    assert sms_bridge.main(["--file", str(f)]) == 0
    out = json.loads(capsys.readouterr().out)
    assert [o["combined"]["risk_level"] for o in out] == ["high", "low"]
    assert cli[0].closed and cli[0].calls == [["evil.top/x"]]


def test_cli_reads_stdin(cli, monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin", io.StringIO("see evil.top/x now"))
    assert sms_bridge.main([]) == 0
    assert json.loads(capsys.readouterr().out)["combined"]["raised_by_links"] is True


@pytest.mark.parametrize("argv, stdin", [([], ""), (["--api", "localhost:8000", "hi"], ""),
                                         (["--file", "does-not-exist.json"], "")])
def test_cli_bad_input_exits_1(cli, monkeypatch, capsys, argv, stdin):
    monkeypatch.setattr("sys.stdin", io.StringIO(stdin))
    assert sms_bridge.main(argv) == 1
    assert capsys.readouterr().err.startswith("error:") and cli == []        # the model never loaded


def test_cli_without_the_sms_module_exits_2_before_loading_the_model(cli, monkeypatch, capsys):
    def missing(model_dir=None):
        raise SmsModuleMissing("the SMS module is not installed")

    monkeypatch.setattr(sms_bridge, "load_sms_module", missing)
    assert sms_bridge.main(["hello"]) == 2
    assert "not installed" in capsys.readouterr().err and cli == []
