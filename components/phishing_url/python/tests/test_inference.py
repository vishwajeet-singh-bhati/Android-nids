import hashlib
import json
import shutil
from datetime import datetime, timedelta, timezone

import numpy as np
import pytest
import torch

from src.inference import bundle as bundle_mod
from src.inference import predict as predict_mod
from src.inference.bundle import BundleError, build_bundle, load_bundle, model_version
from src.inference.decision_engine import MODEL, RULE, THREAT_INTEL, decide
from src.inference.predict import LOCAL_FEEDS, Predictor, is_popular
from src.inference.runtime import ModelRuntime, ModelScores
from src.intelligence.cache import ResultCache
from src.intelligence.local_database import ThreatIntelConfig, ThreatIntelDB, update_database
from src.intelligence.results import (EXACT_URL, HOSTNAME, MATCH, NO_MATCH, PENDING,
                                      REGISTERED_DOMAIN, UNAVAILABLE, IntelMatch, IntelResult)
from src.models.calibration import LIKELY_SAFE, PHISHING, UNCERTAIN, StackCalibrator
from src.models.char_cnn import load_checkpoint
from src.models.ngram_lr import fit_with_c_search
from src.preprocessing.url_normalizer import normalize_url
from src.training.data import load_split
from src.training.train_cnn import predict_logits, to_tensors, train
from tests.test_char_cnn import small
from tests.test_threat_intel import LISTED, build_raw
from tests.test_training import make_rows, write

CANDIDATE = "full_url_hybrid+char_ngram_lr"


def _sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _ensemble_json(path, cnn, ngram, calibrator):
    report = {
        "mode": "full_url", "unit": "website", "budgets": {"max_false_alarm": 0.005, "max_missed": 0.05},
        "fitted_on": {"split": "val"},
        "members": {"full_url_hybrid": {"kind": "char_cnn", "sha256": _sha(cnn)},
                    "char_ngram_lr": {"kind": "char_ngram_lr", "sha256": _sha(ngram)}},
        "candidates": {
            CANDIDATE: {"members": list(calibrator.members), "calibrator": calibrator.to_config(),
                        "crossfit_val": {"pr_auc": 0.9, "roc_auc": 0.95, "ece": 0.01,
                                         "outcomes": {"false_alarm_rate": 0.005}}},
            "broken": {"members": ["full_url_hybrid"], "error": "a weight is not positive"}}}
    path.write_text(json.dumps(report), encoding="utf-8")
    return path


@pytest.fixture(scope="module")
def tiny(tmp_path_factory):
    """A tiny hybrid + n-gram + calibrator, bundled, plus a threat database."""
    root = tmp_path_factory.mktemp("inference")
    splits = root / "splits"
    for split, (start, count) in {"train": (0, 60), "val": (100, 20), "test": (200, 20)}.items():
        write(splits / "full_url" / f"{split}.csv", make_rows(start, count, "full_url"))
    runs = root / "runs"
    train(small(epochs=2, model="hybrid"), splits=splits, run_dir=runs / "full_url_hybrid",
          device="cpu", cache_dir=None, reports_dir=root / "reports")
    tr, va = load_split("full_url", "train", splits), load_split("full_url", "val", splits)
    ngram, _ = fit_with_c_search(tr.texts, tr.y, va.texts, va.y, (1.0,))
    ngram.save(runs / "full_url_ngram" / "model.npz")
    cal = StackCalibrator(("full_url_hybrid", "char_ngram_lr"), (0.6, 0.4), -0.1, 0.8, 0.2)
    cnn, ng = runs / "full_url_hybrid" / "best.pt", runs / "full_url_ngram" / "model.npz"
    ens = _ensemble_json(root / "ensemble.json", cnn, ng, cal)
    redirectors = root / "redirectors.txt"
    redirectors.write_text("bit.ly\nqr-short.link\n", encoding="utf-8")
    b = build_bundle(cnn_checkpoint=cnn, ngram_model=ng, ensemble_json=ens, candidate=CANDIDATE,
                     out_dir=root / "models" / "full_url", redirector_lists=[redirectors],
                     popular_domains=["GitHub.com.", "google.com", "github.io"],
                     popular_source={"top_n": 3, "list": "test"})
    raw = root / "raw"
    build_raw(raw, datetime.now(timezone.utc) - timedelta(hours=1))
    intel_cfg = ThreatIntelConfig(database=root / "intel.sqlite3", local_redirectors=root / "none.txt")
    update_database(intel_cfg, raw)
    return {"root": root, "splits": splits, "bundle": b, "cnn": cnn, "ngram": ng, "ensemble": ens,
            "redirectors": redirectors, "intel_cfg": intel_cfg}


def make_predictor(tiny, **kw):
    runtime = ModelRuntime(tiny["bundle"], batch_size=kw.pop("batch_size", 8))
    return Predictor(runtime, threat_db=ThreatIntelDB.from_config(tiny["intel_cfg"]),
                     cache=kw.pop("cache", ResultCache()), **kw)


# ---------------------------------------------------------------- bundle
def test_bundle_content_and_version(tiny):
    b = load_bundle(tiny["bundle"].path)
    assert b.mode == "full_url" and b.manifest["candidate"] == CANDIDATE
    assert {p.name for p in b.path.iterdir()} == {"cnn.pt", "ngram.npz", "redirectors.txt",
                                                  "popular.txt", "version.json"}
    assert b.redirectors() == {"bit.ly", "qr-short.link"}
    assert b.popular() == {"github.com", "google.com", "github.io"}
    assert b.manifest["popular"] | {"sha256": None} == {"file": "popular.txt", "sha256": None, "count": 3,
                                                       "top_n": 3, "list": "test"}
    hashes = {n: m["sha256"] for n, m in b.manifest["members"].items()}
    assert b.model_version == model_version("full_url", hashes, b.manifest["calibrator"])
    other = dict(b.manifest["calibrator"], bias=0.5)
    assert model_version("full_url", hashes, other) != b.model_version


def test_bundle_refuses_damage(tiny, tmp_path):
    def fresh():
        dst = tmp_path / "b"
        shutil.rmtree(dst, ignore_errors=True)
        shutil.copytree(tiny["bundle"].path, dst)
        return dst

    dst = fresh()
    with (dst / "cnn.pt").open("ab") as fh:
        fh.write(b"x")
    with pytest.raises(BundleError, match="hash"):
        load_bundle(dst)
    dst = fresh()
    (dst / "popular.txt").write_text("evil.example\n", encoding="utf-8")
    with pytest.raises(BundleError, match="hash"):
        load_bundle(dst)
    dst = fresh()
    m = json.loads((dst / "version.json").read_text(encoding="utf-8"))
    m["format_version"] = 1
    (dst / "version.json").write_text(json.dumps(m), encoding="utf-8")
    with pytest.raises(BundleError, match="rebuild"):
        load_bundle(dst)
    dst = fresh()
    (dst / "ngram.npz").unlink()
    with pytest.raises(BundleError, match="missing"):
        load_bundle(dst)
    dst = fresh()
    m = json.loads((dst / "version.json").read_text(encoding="utf-8"))
    m["model_version"] = "full_url-000000000000"
    (dst / "version.json").write_text(json.dumps(m), encoding="utf-8")
    with pytest.raises(BundleError, match="model_version"):
        load_bundle(dst)
    with pytest.raises(BundleError, match="not found"):
        load_bundle(tmp_path / "nothing")


def test_build_refuses_wrong_inputs(tiny, tmp_path):
    kw = dict(cnn_checkpoint=tiny["cnn"], ngram_model=tiny["ngram"], ensemble_json=tiny["ensemble"],
              candidate=CANDIDATE, out_dir=tmp_path / "out", redirector_lists=[tiny["redirectors"]])
    other = tmp_path / "other.pt"
    other.write_bytes(tiny["cnn"].read_bytes() + b"x")
    for change, match in [({"cnn_checkpoint": other}, "hash differs"), ({"candidate": "broken"}, "not usable"),
                          ({"candidate": "nope"}, "no candidate"), ({"redirector_lists": []}, "redirector"),
                          ({"popular_domains": ["bad domain"]}, "not a domain")]:
        with pytest.raises(BundleError, match=match):
            build_bundle(**{**kw, **change})


# ---------------------------------------------------------------- runtime
def test_runtime_matches_the_training_code(tiny):
    val = load_split("full_url", "val", tiny["splits"])
    model, tok, scaler, _ = load_checkpoint(tiny["cnn"])
    cnn = predict_logits(model, to_tensors(val, tok, scaler, torch.device("cpu"), None))
    ng = ModelRuntime(tiny["bundle"])._ngram.logits(val.texts)
    expected = tiny["bundle"].calibrator.probability(np.column_stack([cnn, ng]))
    for batch_size in (1, 7, 64):
        got = ModelRuntime(tiny["bundle"], batch_size=batch_size).score(val.normalized)
        np.testing.assert_allclose(got.probability, expected, atol=1e-6)
        assert set(got.outcome) <= {PHISHING, UNCERTAIN, LIKELY_SAFE}


def test_runtime_input_checks(tiny):
    rt = ModelRuntime(tiny["bundle"])
    assert rt.score([]).probability.shape == (0,)
    with pytest.raises(ValueError):
        rt.score([normalize_url("example.com", "domain")])
    with pytest.raises(ValueError):
        ModelRuntime(tiny["bundle"], batch_size=0)


# ---------------------------------------------------------------- decision engine
def _match(level, threats=("phishing",), source="phishtank", attribution=""):
    return IntelMatch(level, source, 1, "t", "t", "t", (), tuple(threats), attribution)


def _intel(*matches, status=None, **kw):
    return {"feeds": IntelResult(status or (MATCH if matches else NO_MATCH), tuple(matches), **kw)}


def test_threat_intel_phishing_overrides_the_model():
    d = decide(input_type="full_url", model_probability=0.01, model_outcome=LIKELY_SAFE,
               intel=_intel(_match(EXACT_URL)), is_redirector=False)
    assert (d.decision, d.source, d.threat_types) == (PHISHING, THREAT_INTEL, ("phishing",))
    d = decide(input_type="full_url", model_probability=0.01, model_outcome=LIKELY_SAFE,
               intel=_intel(_match(HOSTNAME, source="google_safe_browsing", attribution="Advisory provided by Google")),
               is_redirector=True)
    assert d.decision == PHISHING and d.attributions == ("Advisory provided by Google",)


def test_malware_is_dangerous_but_not_called_phishing():
    d = decide(input_type="full_url", model_probability=0.02, model_outcome=LIKELY_SAFE,
               intel=_intel(_match(EXACT_URL, threats=("malware",))), is_redirector=False)
    assert d.decision == UNCERTAIN and d.source == THREAT_INTEL and any("malware" in r for r in d.reasons)
    d = decide(input_type="full_url", model_probability=0.99, model_outcome=PHISHING,
               intel=_intel(_match(EXACT_URL, threats=("malware",))), is_redirector=False)
    assert d.decision == PHISHING and d.source == MODEL


def test_rules_for_redirectors_missing_models_and_siblings():
    d = decide(input_type="full_url", model_probability=None, model_outcome=None,
               intel=_intel(), is_redirector=True)
    assert (d.decision, d.source) == (UNCERTAIN, RULE) and "hidden" in d.reasons[0]
    d = decide(input_type="domain", model_probability=None, model_outcome=None,
               intel=_intel(), is_redirector=False)
    assert (d.decision, d.source) == (UNCERTAIN, RULE) and "domain-only" in d.reasons[0]
    d = decide(input_type="full_url", model_probability=0.01, model_outcome=LIKELY_SAFE,
               intel=_intel(_match(REGISTERED_DOMAIN)), is_redirector=False)
    assert (d.decision, d.source) == (UNCERTAIN, THREAT_INTEL)
    d = decide(input_type="full_url", model_probability=0.9, model_outcome=PHISHING,
               intel=_intel(_match(REGISTERED_DOMAIN)), is_redirector=False)
    assert (d.decision, d.source) == (PHISHING, MODEL)


def test_popular_website_guard():
    kw = dict(input_type="full_url", is_redirector=False, is_popular=True)
    d = decide(model_probability=0.968, model_outcome=PHISHING, intel=_intel(), **kw)
    assert (d.decision, d.source, d.risk_score) == (UNCERTAIN, RULE, 0.968)
    assert "PHISHING" in d.reasons[0] and "popular website" in d.reasons[1]
    d = decide(model_probability=0.1, model_outcome=LIKELY_SAFE, intel=_intel(), **kw)
    assert (d.decision, d.source) == (LIKELY_SAFE, MODEL)          # untouched: not marked safe by it
    d = decide(model_probability=0.5, model_outcome=UNCERTAIN, intel=_intel(), **kw)
    assert (d.decision, d.source) == (UNCERTAIN, MODEL)
    d = decide(model_probability=0.2, model_outcome=LIKELY_SAFE, intel=_intel(_match(EXACT_URL)), **kw)
    assert (d.decision, d.source) == (PHISHING, THREAT_INTEL)       # a listing still wins


def test_pending_checks_are_no_information():
    intel = {"feeds": IntelResult(NO_MATCH), "google_safe_browsing": IntelResult(PENDING)}
    for outcome in (PHISHING, LIKELY_SAFE):
        d = decide(input_type="full_url", model_probability=0.5, model_outcome=outcome, intel=intel,
                   is_redirector=False)
        assert d.decision == outcome and any("background" in r for r in d.reasons)


def test_no_match_and_unavailable_never_lower_the_risk():
    for intel in (_intel(), _intel(status=UNAVAILABLE, reason="database_missing")):
        d = decide(input_type="full_url", model_probability=0.97, model_outcome=PHISHING,
                   intel=intel, is_redirector=False)
        assert d.decision == PHISHING and any("not evidence of safety" in r for r in d.reasons)
    d = decide(input_type="full_url", model_probability=0.5, model_outcome=UNCERTAIN,
               intel=_intel(status=UNAVAILABLE, reason="database_missing"), is_redirector=False)
    assert d.decision == UNCERTAIN and any("unavailable (database_missing)" in r for r in d.reasons)
    with pytest.raises(ValueError):
        decide(input_type="full_url", model_probability=0.5, model_outcome="SAFE", intel={},
               is_redirector=False)


# ---------------------------------------------------------------- predictor
class CountingRuntime(ModelRuntime):
    calls: list

    def score(self, items):
        self.calls.append(len(items))
        return super().score(items)


def test_predict_end_to_end(tiny):
    rt = CountingRuntime(tiny["bundle"], batch_size=4)
    rt.calls = []
    p = Predictor(rt, threat_db=ThreatIntelDB.from_config(tiny["intel_cfg"]), cache=ResultCache())
    # bit.ly/3abcXYZ is on the test feed (listed -> PHISHING); an unlisted short link is UNCERTAIN
    urls = ["https://www.news7.org/world/story-7", LISTED, "not a url", "https://bit.ly/unlisted1",
            "HTTPS://WWW.NEWS7.ORG/world/story-7", "https://pаypal.com/signin",
            "https://long-site.com/" + "a" * 3000]
    out = p.predict(urls)
    assert [r.url for r in out] == urls                                  # order kept
    assert out[2].error == "invalid_input:illegal_characters" and out[2].decision is None
    assert (out[1].decision, out[1].source) == (PHISHING, THREAT_INTEL)
    assert out[1].threat_intel[0]["source"] in ("phishtank", "openphish")
    assert (out[3].decision, out[3].source, out[3].risk_score) == (UNCERTAIN, RULE, None)
    assert out[0].risk_score == out[4].risk_score and out[0].model_version == rt.model_version
    assert rt.calls == [4]            # news7 (deduplicated), LISTED, IDN, long URL; not bit.ly
    again = p.predict([urls[0]])[0]
    assert again.cache_hit and rt.calls == [4]                           # served from the cache
    listed_short = p.predict_one("https://bit.ly/3abcXYZ")
    assert (listed_short.decision, listed_short.source) == (PHISHING, THREAT_INTEL)
    assert p.predict([]) == []


def _always(p_value):
    def score(items):
        p = np.full(len(items), p_value)
        return ModelScores(p, np.array([PHISHING if p_value >= 0.8 else LIKELY_SAFE] * len(items)), {})
    return score


def test_predict_popular_guard(tiny, monkeypatch):
    p = make_predictor(tiny)
    assert p.popular == {"github.com", "google.com", "github.io"}
    monkeypatch.setattr(p.runtime, "score", _always(0.97))
    login, pages, own_site, google_form = p.predict([
        "https://github.com/login", "https://gist.github.com/x", "https://someone.github.io/login",
        "https://docs.google.com/forms/d/e/ABC123/viewform"])
    assert (login.decision, login.source, login.risk_score) == (UNCERTAIN, RULE, 0.97)
    assert pages.decision == UNCERTAIN                           # any host of the website
    assert (own_site.decision, own_site.source) == (PHISHING, MODEL)   # a user site, not GitHub's
    assert (google_form.decision, google_form.source) == (PHISHING, THREAT_INTEL)  # listed on the feed
    assert not is_popular(normalize_url("http://140.82.112.3/login"), {"140.82.112.3"})
    monkeypatch.setattr(p.runtime, "score", _always(0.01))
    assert p.predict_one("https://github.com/explore").decision == LIKELY_SAFE


class FakeChecker:
    name = "fake_online"

    def __init__(self, result):
        self.result, self.seen = result, []

    def lookup(self, n):
        self.seen.append(n.canonical)
        return self.result

    def wait_idle(self, timeout=None):
        return True

    def stats(self):
        return {"seen": len(self.seen)}

    def close(self):
        self.closed = True


def test_predict_with_online_checks(tiny):
    pending = FakeChecker(IntelResult(PENDING))
    p = make_predictor(tiny, online=[pending])
    r = p.predict_one("https://fresh-site.com/page")
    assert r.pending == ("fake_online",) and r.to_dict()["pending"] == ["fake_online"]
    assert any("background" in x for x in r.reasons) and pending.seen == ["https://fresh-site.com/page"]
    m = IntelMatch(EXACT_URL, "fake_online", 1, "t", "t", "t", (), ("phishing",), "Advisory provided by X")
    listed = make_predictor(tiny, online=[FakeChecker(IntelResult(MATCH, (m,)))])
    r = listed.predict_one("https://fresh-site.com/page")
    assert (r.decision, r.source, r.pending) == (PHISHING, THREAT_INTEL, ())
    assert r.attributions == ("Advisory provided by X",)
    assert listed.stats()["online"] == {"fake_online": {"seen": 1}}
    listed.close()
    with pytest.raises(ValueError, match="unique"):
        make_predictor(tiny, online=[pending, pending])


def test_predict_domain_inputs_and_failures(tiny, monkeypatch):
    p = make_predictor(tiny)
    listed, unknown = p.predict(["login-verify.evil-site.xyz", "unknown-site.com"], "domain")
    assert (listed.decision, listed.source) == (PHISHING, THREAT_INTEL)
    assert (unknown.decision, unknown.source, unknown.model_version) == (UNCERTAIN, RULE, None)
    with pytest.raises(TypeError):
        p.predict("https://example.com/")
    with pytest.raises(ValueError):
        p.predict(["x"], "email")

    def boom(items):
        raise RuntimeError("out of memory")

    monkeypatch.setattr(p.runtime, "score", boom)
    r = p.predict_one("https://fresh-site.com/page")
    assert (r.decision, r.source) == (UNCERTAIN, RULE) and "model error" in r.reasons[0]

    no_db = Predictor(ModelRuntime(tiny["bundle"]), threat_db=ThreatIntelDB(tiny["root"] / "missing.sqlite3"))
    r = no_db.predict_one("https://fresh-site.com/page")
    assert r.decision in (PHISHING, UNCERTAIN, LIKELY_SAFE)
    assert any(f"{LOCAL_FEEDS} unavailable (database_missing)" in x for x in r.reasons)


def test_cli(tiny, capsys, monkeypatch):
    monkeypatch.delenv("SAFE_BROWSING_API_KEY", raising=False)      # never call Google from tests
    cfg = tiny["root"] / "intel.json"
    cfg.write_text(json.dumps({"database": str(tiny["intel_cfg"].database),
                               "local_redirectors": str(tiny["root"] / "none.txt")}), encoding="utf-8")
    base = ["--bundle", str(tiny["bundle"].path), "--intel-config", str(cfg)]
    assert predict_mod.main([LISTED, "https://bit.ly/x", "not a url", *base]) == 0
    out = capsys.readouterr().out
    assert "PHISHING" in out and "UNCERTAIN" in out and "ERROR" in out
    assert "note: google_safe_browsing not used (no API key in SAFE_BROWSING_API_KEY)" in out
    assert predict_mod.main(["unknown-site.com", "--domain", "--json", "--no-online", *base]) == 0
    assert json.loads(capsys.readouterr().out)["decision"] == UNCERTAIN
    assert bundle_mod.main(["verify", str(tiny["bundle"].path)]) == 0
