"""Phone export (src/deploy/mobile_export.py): files, formats, reference answers."""
import hashlib
import json

import numpy as np
import pytest

from src.deploy import mobile_export as mx
from src.models.ngram_lr import NgramLR
from src.preprocessing.url_normalizer import normalize_url
from tests.test_inference import make_predictor, tiny  # noqa: F401  (module fixture)
from tests.test_threat_intel import LISTED


def test_ngram_file_round_trip(tmp_path):
    path = tmp_path / "n.bin"
    mx.write_ngram_bin(path, ["ab", "b.c", "xyz12"], [1.5, 2.25, 3.0], [-0.5, 0.25, 1e-9], -1.75)
    assert mx.read_ngram_bin(path) == (["ab", "b.c", "xyz12"], [1.5, 2.25, 3.0], [-0.5, 0.25, 1e-9], -1.75)
    with pytest.raises(UnicodeEncodeError):
        mx.write_ngram_bin(path, ["é"], [1.0], [1.0], 0.0)
    with pytest.raises(mx.ExportError):
        mx.write_ngram_bin(path, ["ab"], [1.0, 2.0], [1.0], 0.0)
    path.write_bytes(b"NOTRIGHT" + bytes(12))
    with pytest.raises(mx.ExportError):
        mx.read_ngram_bin(path)


def test_written_out_ngram_formula_matches_scikit_learn(tiny):  # noqa: F811
    model = NgramLR.load(tiny["ngram"])
    vocab, idf, coef = model.vectorizer.vocabulary_, model.vectorizer.idf_.tolist(), model.coef.tolist()
    texts = [normalize_url(u).model_string for u in
             ("https://www.news7.org/world/story-7", LISTED, "a.b", "https://x.co/" + "q" * 400)] + ["", "z"]
    for text, want in zip(texts, model.logits(texts)):
        assert mx.ngram_spec_logit(text, vocab, idf, coef, model.intercept) == pytest.approx(want, abs=1e-5)


@pytest.fixture(scope="module")
def exported(tiny, tmp_path_factory):  # noqa: F811
    root = tmp_path_factory.mktemp("export_root")
    (root / "config").mkdir()
    cfg = tiny["intel_cfg"]
    (root / "config" / "threat_intel.json").write_text(json.dumps({
        "database": str(cfg.database), "ttl_days": dict(cfg.ttl_days), "stale_after_hours": 48,
        "local_redirectors": str(cfg.local_redirectors)}), encoding="utf-8")
    urls = root / "urls.txt"
    urls.write_text("https://www.news7.org/world/story-7\nhttps://shop3.com/cart?id=2\n", encoding="utf-8")
    out = mx.build_export(root, out_dir=root / "out", bundle_dir=tiny["bundle"].path, urls_file=urls)
    rows = [json.loads(line) for line in (out / mx.REFERENCE_FILE).read_text(encoding="utf-8").splitlines()]
    return out, rows, json.loads((out / mx.SPEC_FILE).read_text(encoding="utf-8"))


def test_export_folder_and_manifest(exported):
    out, _, spec = exported
    names = {p.name for p in out.iterdir()}
    assert names == {mx.SPEC_FILE, mx.NGRAM_FILE, mx.REFERENCE_FILE, mx.PSL_FILE, mx.MANIFEST_FILE,
                     "redirectors.txt", "popular.txt", "threat_intel.sqlite3"}       # .pte: separate step
    manifest = json.loads((out / mx.MANIFEST_FILE).read_text(encoding="utf-8"))
    assert set(manifest["files"]) == names - {mx.MANIFEST_FILE}
    for name, info in manifest["files"].items():
        assert hashlib.sha256((out / name).read_bytes()).hexdigest() == info["sha256"]
    assert manifest["model_version"] == spec["model_version"]
    psl = (out / mx.PSL_FILE).read_text(encoding="utf-8")
    assert "===BEGIN ICANN DOMAINS===" in psl and "github.io" in psl


def test_spec_holds_what_the_app_needs(exported, tiny):  # noqa: F811
    _, _, spec = exported
    cal = tiny["bundle"].calibrator
    assert spec["calibrator"]["weights"] == list(cal.weights) and spec["calibrator"]["members"] == list(cal.members)
    assert spec["cnn"]["member"] == "full_url_hybrid"
    assert spec["cnn"]["inputs"][0]["shape"] == [1, spec["tokenizer"]["max_length"]]
    assert spec["cnn"]["inputs"][1]["shape"] == [1, len(spec["features"]["names"])]
    assert len(spec["features"]["mean"]) == len(spec["features"]["names"]) == len(spec["features"]["std"])
    assert set(spec["features"]["log1p_then_zscore"]) <= set(spec["features"]["names"])
    assert spec["lists"]["redirectors"]["count"] == 2 and spec["lists"]["popular"]["count"] == 3
    assert "url_key = :model_string" in spec["threat_db"]["queries"]["exact_url"]
    assert spec["reference"]["max_abs_difference"]["ngram_spec_vs_sklearn"] < 1e-5
    assert spec["reference"]["max_abs_difference"]["fixed_256_vs_service"] < 1e-5


def test_ngram_file_matches_the_model(exported, tiny):  # noqa: F811
    out, _, _ = exported
    model = NgramLR.load(tiny["ngram"])
    terms, idf, coef, intercept = mx.read_ngram_bin(out / mx.NGRAM_FILE)
    vocab = model.vectorizer.vocabulary_
    assert terms == sorted(vocab, key=vocab.get)
    assert np.allclose(idf, model.vectorizer.idf_, rtol=0, atol=0) and np.allclose(coef, model.coef, rtol=0, atol=0)
    assert intercept == model.intercept


def test_reference_rows_cover_every_branch(exported, tiny):  # noqa: F811
    _, rows, spec = exported
    by_input = {(r["input"], r["input_type"]): r for r in rows}
    assert len(rows) == 2 + len(mx.EDGE_CASES) + 2 == spec["reference"]["rows"]
    scored = [r for r in rows if "token_ids" in r]
    predictor = make_predictor(tiny)
    try:
        for r in scored:
            assert len(r["features_raw"]) == len(r["features_scaled"]) == len(spec["features"]["names"])
            assert 1 <= len(r["token_ids"]) <= spec["tokenizer"]["max_length"]
            z = sum(w * r["logits"][m] for w, m in zip(spec["calibrator"]["weights"], spec["calibrator"]["members"]))
            assert r["probability"] == pytest.approx(1 / (1 + np.exp(-(z + spec["calibrator"]["bias"]))), abs=1e-12)
            if r["model_used"]:
                assert r["risk_score"] == pytest.approx(predictor.predict_one(r["input"]).risk_score, abs=1e-6)
    finally:
        predictor.close()
    long = next(r for r in rows if r["input"].startswith("https://example.com/aaaa"))
    assert long["truncated"] and len(long["token_ids"]) == spec["tokenizer"]["max_length"]
    assert 2 in long["token_ids"]                                               # the TRUNC marker
    short = by_input[("bit.ly/3xYzAbc", "full_url")]
    assert (short["is_redirector"], short["model_used"], short["decision"], short["risk_score"]) == \
        (True, False, "UNCERTAIN", None)
    gh = by_input[("https://github.com/login", "full_url")]
    assert gh["is_popular"] and gh["decision"] in ("UNCERTAIN", "LIKELY_SAFE")
    assert by_input[("https://someone.github.io/page", "full_url")]["site"] == "someone.github.io"
    assert by_input[("https://sub.example.co.uk/path", "full_url")]["normalized"]["registered_domain"] == "example.co.uk"
    assert by_input[("https://аpple.com/signin", "full_url")]["normalized"]["has_punycode"] is True
    bad = by_input[("not a url", "full_url")]
    assert bad["normalized"] is None and bad["error"] == "invalid_input:illegal_characters"
    dom = by_input[("Example.COM", "domain")]
    assert dom["normalized"]["host"] == "example.com" and "token_ids" not in dom and dom["decision"] == "UNCERTAIN"
    listed = [r for r in rows if r["decision"] == "PHISHING" and r["source"] == "threat_intel"]
    assert {m["level"] for r in listed for m in r["threat_intel"]} >= {"exact_url", "hostname"}


def test_pte_export_matches_pytorch(exported, tiny):  # noqa: F811
    pytest.importorskip("executorch")
    out, _, _ = exported
    report = mx.export_pte(out, tiny["bundle"].path)
    assert report["passed"] and report["outcome_flips"] == 0 and (out / mx.PTE_FILE).stat().st_size > 0


def test_cli_needs_a_folder_for_pte(capsys):
    with pytest.raises(SystemExit):
        mx.main(["pte"])
    assert "needs --dir" in capsys.readouterr().err
