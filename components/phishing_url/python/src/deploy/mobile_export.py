"""Export the link checker for a phone app (Kotlin + ExecuTorch), with reference answers.

    python -m src.deploy.mobile_export                     # -> dist/mobile_<model_version>/ (all but the .pte)
    <export venv>\\python -m src.deploy.mobile_export pte --dir dist/mobile_<model_version>

The second step needs the NIDS app's export pair, executorch==1.5.0 + torch==2.14.1 (its
runtime is executorch-android 1.5.1). Keep that in a separate venv: it must not replace this
project's PyTorch. It adds url_cnn.pte and checks it against the reference answers.

Folder contents
  url_model.json        every number and rule the app needs: tokenizer, feature order, scaler,
                        n-gram settings, calibrator, thresholds, decision rules, lists, threat-list queries
  url_cnn.pte           the char-CNN (+ structural features) for ExecuTorch with XNNPACK:
                        ids int64[1,256] + features float32[1,27] -> logit float32[1]
  ngram_lr.bin          the character n-gram model (format in write_ngram_bin)
  redirectors.txt       link shorteners / QR redirectors (one domain per line)
  popular.txt           popular websites: the model alone may not say PHISHING there
  public_suffix_list.dat the exact Public Suffix List snapshot the Python normaliser uses
  threat_intel.sqlite3  the local threat list (optional, --no-threat-db leaves it out)
  reference.jsonl       one line per test input with every step's value, so each Kotlin step can be
                        checked on its own: normalized parts, token ids, raw and scaled features,
                        both member logits, probability, model outcome, final decision
  pte_selfcheck.json    url_cnn.pte run by ExecuTorch against PyTorch on every reference input
  MANIFEST.json         SHA-256 of every file

Nothing here is secret: no API keys (Google Safe Browsing stays off on the phone), no training data.
"""
from __future__ import annotations

import argparse
import dataclasses
import hashlib
import importlib.metadata
import json
import math
import shutil
import sqlite3
import struct
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

DIST_DIR = Path("dist")
BUNDLE_DIR = Path("models") / "full_url"
URLS_FILE = Path("data/processed/benchmark_urls.txt")
INTEL_CONFIG = Path("config/threat_intel.json")
FORMAT_VERSION = 1
PTE_FILE, NGRAM_FILE, SPEC_FILE, REFERENCE_FILE = "url_cnn.pte", "ngram_lr.bin", "url_model.json", "reference.jsonl"
PSL_FILE, SELFCHECK_FILE, MANIFEST_FILE = "public_suffix_list.dat", "pte_selfcheck.json", "MANIFEST.json"
NGRAM_MAGIC = b"NGRAMLR1"
PTE_TOLERANCE = 1e-4                       # |logit difference| allowed between ExecuTorch and PyTorch

# Inputs that exercise each normaliser / tokenizer / rule branch, on top of the benchmark sample.
EDGE_CASES: tuple[tuple[str, str], ...] = (
    ("HTTPS://WWW.Example.COM:443/Path/?q=1#frag", "full_url"),       # case, default port, fragment
    ("http://user:pass@example.com:8080/a", "full_url"),             # userinfo, other port
    ("example.com", "full_url"),                                      # no scheme, empty path -> "/"
    ("http://192.168.1.10/login", "full_url"),                        # IPv4 host
    ("http://[2001:db8::1]/x", "full_url"),                           # IPv6 host
    ("https://аpple.com/signin", "full_url"),                    # Cyrillic a -> punycode
    ("https://müller.de/über?x=ä", "full_url"),        # non-ASCII host, path, query
    ("https://example.com/a%2fb%7Ec%41", "full_url"),                 # percent fixing
    ("https://example.com\\evil.com\\login", "full_url"),             # backslashes -> slashes
    ("https://example.com./x", "full_url"),                           # trailing dot on the host
    ("https://sub.example.co.uk/path", "full_url"),                   # two-part public suffix
    ("https://someone.github.io/page", "full_url"),                   # private suffix: its own site
    ("https://exa\tmple.com/a\nb", "full_url"),                       # tab / newline are dropped
    ("https://example.com/" + "a" * 300 + "?" + "b" * 50, "full_url"),  # longer than 256: head + tail
    ("bit.ly/3xYzAbc", "full_url"),                                   # link shortener rule
    ("https://github.com/login", "full_url"),                         # popular-website guard
    ("not a url", "full_url"), ("", "full_url"), ("javascript:alert(1)", "full_url"),
    ("http://exa mple.com", "full_url"), ("http://%41.com/", "full_url"), ("ftp://", "full_url"),
    ("Example.COM", "domain"), ("bit.ly", "domain"), ("192.168.0.1", "domain"),
    ("a.b.example.co.uk", "domain"), ("bad/host", "domain"),
)


class ExportError(ValueError):
    pass


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# ---------------------------------------------------------------- n-gram model
def write_ngram_bin(path: Path, terms, idf, coef, intercept: float) -> None:
    """Little-endian: magic "NGRAMLR1", u32 count, f64 intercept, then per term (in index
    order): u8 byte length, the term's ASCII bytes, f64 idf, f64 weight."""
    if not (len(terms) == len(idf) == len(coef)):
        raise ExportError("terms, idf and coef differ in length")
    with path.open("wb") as fh:
        fh.write(NGRAM_MAGIC + struct.pack("<Id", len(terms), float(intercept)))
        for term, i, c in zip(terms, idf, coef):
            raw = str(term).encode("ascii")                       # all terms are ASCII (checked)
            if not 1 <= len(raw) <= 255:
                raise ExportError("n-gram term of unexpected length")
            fh.write(struct.pack("<B", len(raw)) + raw + struct.pack("<dd", float(i), float(c)))


def read_ngram_bin(path: Path) -> tuple[list[str], list[float], list[float], float]:
    data = Path(path).read_bytes()
    if data[:8] != NGRAM_MAGIC:
        raise ExportError("not an n-gram model file")
    count, intercept = struct.unpack_from("<Id", data, 8)
    pos, terms, idf, coef = 20, [], [], []
    for _ in range(count):
        n = data[pos]
        terms.append(data[pos + 1:pos + 1 + n].decode("ascii"))
        i, c = struct.unpack_from("<dd", data, pos + 1 + n)
        idf.append(i)
        coef.append(c)
        pos += 1 + n + 16
    if pos != len(data):
        raise ExportError("n-gram model file has trailing bytes")
    return terms, idf, coef, intercept


def ngram_spec_logit(text: str, index: dict[str, int], idf, coef, intercept: float,
                     ngram_range=(2, 5)) -> float:
    """The n-gram model written out step by step, the way the app must compute it
    (scikit-learn TfidfVectorizer, analyzer="char", sublinear_tf, l2 norm, then the
    logistic-regression weights). Kotlin should follow this function line by line."""
    lo, hi = ngram_range
    counts: Counter = Counter()
    for n in range(lo, min(hi, len(text)) + 1):                 # every substring of length 2..5
        for i in range(len(text) - n + 1):
            j = index.get(text[i:i + n])
            if j is not None:                                     # pieces outside the vocabulary are ignored
                counts[j] += 1
    if not counts:
        return float(intercept)
    weights = {j: (1.0 + math.log(tf)) * idf[j] for j, tf in counts.items()}   # sublinear tf x idf
    norm = math.sqrt(sum(w * w for w in weights.values()))
    return float(intercept) + sum(w / norm * coef[j] for j, w in weights.items())


# ---------------------------------------------------------------- reference answers
def _psl_snapshot() -> Path:
    import tldextract
    path = Path(tldextract.__file__).parent / ".tld_set_snapshot"
    text = path.read_text(encoding="utf-8")
    if "===BEGIN ICANN DOMAINS===" not in text or "===BEGIN PRIVATE DOMAINS===" not in text:
        raise ExportError("tldextract's suffix snapshot is not a Public Suffix List file")
    return path


def _listed_examples(db: Path, now: str) -> list[tuple[str, str]]:
    """One URL listed by the feeds, and another page on the same listed host."""
    if not db.is_file():
        return []
    with sqlite3.connect(f"file:{db.as_posix()}?mode=ro", uri=True) as conn:
        row = conn.execute("SELECT url_key, host FROM indicators WHERE expires_at > ? AND host_match_ok = 1 "
                           "ORDER BY url_key LIMIT 1", (now,)).fetchone()
    if row is None:
        return []
    return [("http://" + row[0], "full_url"), (f"http://{row[1]}/reference-other-page", "full_url")]


def reference_rows(predictor, inputs: list[tuple[str, str]]):
    """Every step's value for each input, from the same code the service runs."""
    import numpy as np
    import torch

    from src.inference.predict import is_popular, is_redirector
    from src.models.char_cnn import load_checkpoint
    from src.models.ngram_lr import NgramLR
    from src.preprocessing.feature_extractor import FeatureExtractor
    from src.preprocessing.url_normalizer import InvalidURLError, normalize_url, private_registered_domain

    runtime = predictor.runtime
    bundle, cal = runtime.bundle, runtime.calibrator
    kinds = {name: bundle.member_kind(name) for name in cal.members}
    cnn_name = next(n for n, k in kinds.items() if k == "char_cnn")
    ngram_name = next(n for n, k in kinds.items() if k == "char_ngram_lr")
    cnn, tokenizer, scaler, _ = load_checkpoint(bundle.member_file(cnn_name))
    ngram = NgramLR.load(bundle.member_file(ngram_name))
    extractor = FeatureExtractor(scaler.feature_names)
    vocab = ngram.vectorizer.vocabulary_
    idf, coef = ngram.vectorizer.idf_.tolist(), ngram.coef.tolist()
    checks = Counter()
    worst = {"ngram_spec_vs_sklearn": 0.0, "fixed_256_vs_service": 0.0}
    rows = []
    for value, input_type in inputs:
        row: dict = {"input": value, "input_type": input_type}
        result = predictor.predict([value], input_type)[0]
        row["decision"] = result.decision
        row["source"] = result.source
        row["risk_score"] = result.risk_score
        row["error"] = result.error
        row["threat_intel"] = [{"level": m["level"], "source": m["source"]} for m in result.threat_intel]
        try:
            n = normalize_url(value, input_type)
        except InvalidURLError as exc:
            row["normalized"] = None
            if result.error != f"invalid_input:{exc.reason}":
                raise ExportError("the service and the normaliser disagree about an invalid input")
            rows.append(row)
            checks["invalid"] += 1
            continue
        row["normalized"] = {k: getattr(n, k) for k in (
            "scheme", "scheme_inferred", "host", "port", "path", "query", "has_userinfo", "is_ip",
            "has_punycode", "subdomain", "domain", "suffix", "registered_domain", "canonical", "model_string")}
        row["site"] = "" if n.is_ip else private_registered_domain(n.host)
        row["is_redirector"] = is_redirector(n, predictor.redirectors)
        row["is_popular"] = is_popular(n, predictor.popular)
        row["model_used"] = input_type == runtime.mode and not row["is_redirector"]
        if input_type != runtime.mode:
            rows.append(row)
            checks["domain"] += 1
            continue
        text = n.model_string
        enc = tokenizer.encode(text)
        raw = extractor.extract(n)
        scaled = scaler.transform(raw)
        with torch.inference_mode():
            cnn_logit = float(cnn(torch.from_numpy(enc.ids[None, :]), torch.from_numpy(scaled[None, :]))[0])
        ngram_logit = float(ngram.logits([text])[0])
        spec = ngram_spec_logit(text, vocab, idf, coef, ngram.intercept)
        worst["ngram_spec_vs_sklearn"] = max(worst["ngram_spec_vs_sklearn"], abs(spec - ngram_logit))
        logits = {cnn_name: cnn_logit, ngram_name: ngram_logit}
        p = float(cal.probability(np.array([[logits[m] for m in cal.members]]))[0])
        service = runtime.score([n])                              # the service's own (trimmed) batch path
        worst["fixed_256_vs_service"] = max(worst["fixed_256_vs_service"], abs(p - float(service.probability[0])))
        row.update({"token_ids": enc.ids[:enc.length].tolist(), "truncated": enc.truncated,
                    "features_raw": [float(x) for x in raw], "features_scaled": [float(x) for x in scaled],
                    "logits": logits, "probability": p, "model_outcome": str(cal.outcome(np.array([p]))[0])})
        if row["model_used"] and result.risk_score is not None and abs(result.risk_score - p) > 1e-6:
            raise ExportError("reference probability differs from the service's answer")
        checks["scored"] += 1
        rows.append(row)
    return rows, dict(checks), worst


# ---------------------------------------------------------------- build
def _spec(predictor, cnn_name: str, scaler, tokenizer, ngram_terms: int, intel_cfg, reference_time: str,
          psl_note: str) -> dict:
    from src.inference import decision_engine
    from src.preprocessing import url_normalizer as un
    from src.preprocessing.feature_extractor import LOG_SCALED_FEATURES

    runtime = predictor.runtime
    bundle, cal = runtime.bundle, runtime.calibrator
    names = list(scaler.feature_names)
    return {
        "format_version": FORMAT_VERSION, "model_version": bundle.model_version, "mode": bundle.mode,
        "reference_time": reference_time,
        "validation_crossfit": bundle.manifest.get("validation_crossfit"),
        "normalizer": {
            "source": "src/preprocessing/url_normalizer.py (follow it exactly; reference.jsonl checks each part)",
            "max_raw_length": un.MAX_RAW_LENGTH, "allowed_schemes": sorted(un.ALLOWED_SCHEMES),
            "default_ports": un.DEFAULT_PORTS, "scheme_when_missing": "http",
            "unreserved_percent_decoded": "A-Z a-z 0-9 - . _ ~",
            "idna": "UTS #46, non-transitional (Python idna 3.x, uts46=True)",
            "public_suffix_list": psl_note,
            "registered_domain": "ICANN section only", "site": "ICANN + PRIVATE sections",
            "model_string_is_ascii": True},
        "tokenizer": {**tokenizer.to_config(), "vocab_size": tokenizer.vocab_size,
                      "head_length": tokenizer.head_length},
        "features": {"names": names, "log1p_then_zscore": [n for n in names if n in LOG_SCALED_FEATURES],
                     "mean": scaler.mean.tolist(), "std": scaler.std.tolist(),
                     "source": "src/preprocessing/feature_extractor.py compute_features"},
        "cnn": {"file": PTE_FILE, "member": cnn_name,
                "inputs": [{"name": "ids", "dtype": "int64", "shape": [1, tokenizer.max_length],
                            "note": "token ids, right-padded with 0 (padding is masked: exact)"},
                           {"name": "features", "dtype": "float32", "shape": [1, len(names)],
                            "note": "scaled features, in `features.names` order"}],
                "output": {"dtype": "float32", "shape": [1], "meaning": "logit of phishing"}},
        "ngram": {"file": NGRAM_FILE, "terms": ngram_terms, "analyzer": "char", "ngram_range": [2, 5],
                  "lowercase": False, "sublinear_tf": True, "norm": "l2",
                  "formula": "src/deploy/mobile_export.py ngram_spec_logit"},
        "calibrator": {**cal.to_config(),
                       "formula": "p = sigmoid(sum(weights[i] * logit[members[i]]) + bias)",
                       "outcome": "PHISHING if p > t_phishing; LIKELY_SAFE if p < t_safe; else UNCERTAIN"},
        "lists": {"redirectors": {"file": "redirectors.txt", "count": len(predictor.redirectors),
                                  "matches_when": "host, registered_domain or site is in the list"},
                  "popular": {"file": "popular.txt", "count": len(predictor.popular),
                              "matches_when": "site is in the list (never for IP hosts)"}},
        "decision_rules": decision_engine.__doc__,
        "threat_db": {"file": "threat_intel.sqlite3", "schema_version": 1,
                      "time_format": "%Y-%m-%dT%H:%M:%SZ (UTC; text order is time order)",
                      "stale_after_hours": intel_cfg.stale_after_hours, "ttl_days": dict(intel_cfg.ttl_days),
                      "queries": {
                          "exact_url": "SELECT ... FROM indicators WHERE url_key = :model_string AND expires_at > :now",
                          "hostname": "... WHERE host = :host AND host_match_ok = 1 AND url_key != :model_string "
                                      "AND expires_at > :now",
                          "registered_domain": "... WHERE site = :site AND host != :host AND host_match_ok = 1 "
                                               "AND expires_at > :now"},
                      "note": "full_url input: all three; domain input: url_key is '' so only hostname and "
                              "registered_domain. Every match is phishing. No match is never evidence of safety."},
    }


def build_export(root: Path | str = ".", *, out_dir: Path | str | None = None, bundle_dir=BUNDLE_DIR,
                 urls_file=URLS_FILE, threat_db: bool = True, now: datetime | None = None) -> Path:
    from src.inference.predict import Predictor
    from src.inference.runtime import ModelRuntime
    from src.intelligence.cache import ResultCache
    from src.intelligence.local_database import ThreatIntelConfig, ThreatIntelDB
    from src.models.char_cnn import load_checkpoint
    from src.models.ngram_lr import NgramLR
    from src.inference.parity import read_urls

    root = Path(root).resolve()
    runtime = ModelRuntime(root / bundle_dir)
    bundle, cal = runtime.bundle, runtime.calibrator
    intel_cfg = ThreatIntelConfig.from_file(root / INTEL_CONFIG)
    db_path = Path(intel_cfg.database) if Path(intel_cfg.database).is_absolute() else root / intel_cfg.database
    intel_cfg = dataclasses.replace(intel_cfg, database=db_path)
    predictor = Predictor(runtime, threat_db=ThreatIntelDB.from_config(intel_cfg) if threat_db else None,
                          cache=ResultCache())
    now = now or datetime.now(timezone.utc)
    reference_time = now.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    out = root / (out_dir or DIST_DIR / f"mobile_{bundle.model_version}")
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)
    try:
        kinds = {name: bundle.member_kind(name) for name in cal.members}
        cnn_name = next(n for n, k in kinds.items() if k == "char_cnn")
        _, tokenizer, scaler, _ = load_checkpoint(bundle.member_file(cnn_name))
        ngram = NgramLR.load(bundle.member_file(next(n for n, k in kinds.items() if k == "char_ngram_lr")))
        vocab = ngram.vectorizer.vocabulary_
        terms = sorted(vocab, key=vocab.get)
        if not all(t.isascii() for t in terms):
            raise ExportError("n-gram vocabulary is not ASCII")
        write_ngram_bin(out / NGRAM_FILE, terms, ngram.vectorizer.idf_, ngram.coef, ngram.intercept)
        for name in ("redirectors.txt", "popular.txt"):
            shutil.copyfile(bundle.path / name, out / name)
        psl = _psl_snapshot()
        shutil.copyfile(psl, out / PSL_FILE)
        if threat_db:
            if not db_path.is_file():
                raise ExportError(f"{db_path} not found: build it, or pass --no-threat-db")
            with sqlite3.connect(f"file:{db_path.as_posix()}?mode=ro", uri=True) as src, \
                    sqlite3.connect(out / "threat_intel.sqlite3") as dst:
                src.backup(dst)                                   # consistent copy even if in use
        inputs = [(u, "full_url") for u in read_urls(root / urls_file)] + list(EDGE_CASES)
        inputs += _listed_examples(db_path, reference_time) if threat_db else []
        rows, checks, worst = reference_rows(predictor, inputs)
        with (out / REFERENCE_FILE).open("w", encoding="utf-8", newline="\n") as fh:
            for row in rows:
                fh.write(json.dumps(row, ensure_ascii=False) + "\n")
        import tldextract
        spec = _spec(predictor, cnn_name, scaler, tokenizer, len(terms), intel_cfg, reference_time,
                     f"{PSL_FILE}: tldextract {tldextract.__version__} bundled snapshot")
        spec["reference"] = {"file": REFERENCE_FILE, "rows": len(rows), **checks,
                             "max_abs_difference": worst, "threat_db_included": threat_db,
                             "decisions": dict(Counter(r["decision"] or "invalid" for r in rows))}
        (out / SPEC_FILE).write_text(json.dumps(spec, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        write_manifest(out)
    finally:
        predictor.close()
    return out


def write_manifest(out: Path) -> dict:
    files = {p.name: {"sha256": _sha256(p), "bytes": p.stat().st_size}
             for p in sorted(out.iterdir()) if p.is_file() and p.name != MANIFEST_FILE}
    manifest = {"model_version": json.loads((out / SPEC_FILE).read_text(encoding="utf-8"))["model_version"]
                if (out / SPEC_FILE).is_file() else None, "files": files}
    (out / MANIFEST_FILE).write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest


# ---------------------------------------------------------------- ExecuTorch (separate venv)
def export_pte(out: Path | str, bundle_dir: Path | str = BUNDLE_DIR) -> dict:
    """Write url_cnn.pte (XNNPACK) and check it on every scored reference row."""
    import torch
    from executorch.backends.xnnpack.partition.xnnpack_partitioner import XnnpackPartitioner
    from executorch.backends.xnnpack.utils.configs import get_transform_passes
    from executorch.exir import to_edge_transform_and_lower
    from executorch.runtime import Runtime

    from src.models.char_cnn import load_checkpoint

    out = Path(out)
    spec = json.loads((out / SPEC_FILE).read_text(encoding="utf-8"))
    version = json.loads((Path(bundle_dir) / "version.json").read_text(encoding="utf-8"))
    if version["model_version"] != spec["model_version"]:
        raise ExportError("the bundle is not the one this folder was exported from")
    member = spec["cnn"]["member"]
    cnn_file = Path(bundle_dir) / version["members"][member]["file"]
    if _sha256(cnn_file) != version["members"][member]["sha256"]:
        raise ExportError("the CNN file does not match its recorded hash")
    model, tokenizer, scaler, _ = load_checkpoint(cnn_file)
    length, width = spec["tokenizer"]["max_length"], len(spec["features"]["names"])
    example = (torch.zeros(1, length, dtype=torch.int64), torch.zeros(1, width, dtype=torch.float32))
    program = to_edge_transform_and_lower(torch.export.export(model.eval(), example),
                                          partitioner=[XnnpackPartitioner()],
                                          transform_passes=get_transform_passes()).to_executorch()
    (out / PTE_FILE).write_bytes(program.buffer)

    method = Runtime.get().load_program(str(out / PTE_FILE)).load_method("forward")
    weights, bias = spec["calibrator"]["weights"], spec["calibrator"]["bias"]
    members, t_hi, t_lo = spec["calibrator"]["members"], spec["calibrator"]["t_phishing"], spec["calibrator"]["t_safe"]
    worst_logit = worst_p = 0.0
    flips, checked = [], 0
    with (out / REFERENCE_FILE).open(encoding="utf-8") as fh:
        for line in fh:
            row = json.loads(line)
            if "token_ids" not in row:
                continue
            ids = torch.zeros(1, length, dtype=torch.int64)
            ids[0, :len(row["token_ids"])] = torch.tensor(row["token_ids"], dtype=torch.int64)
            feats = torch.tensor([row["features_scaled"]], dtype=torch.float32)
            logit = float(method.execute([ids, feats])[0].reshape(-1)[0])
            logits = dict(row["logits"], **{member: logit})
            z = sum(w * logits[m] for w, m in zip(weights, members)) + bias
            p = 1.0 / (1.0 + math.exp(-z)) if z >= 0 else math.exp(z) / (1.0 + math.exp(z))
            outcome = "PHISHING" if p > t_hi else "LIKELY_SAFE" if p < t_lo else "UNCERTAIN"
            worst_logit = max(worst_logit, abs(logit - row["logits"][member]))
            worst_p = max(worst_p, abs(p - row["probability"]))
            if outcome != row["model_outcome"]:
                flips.append(row["input"][:80])
            checked += 1
    report = {"file": PTE_FILE, "bytes": (out / PTE_FILE).stat().st_size,
              "executorch": importlib.metadata.version("executorch"),
              "torch": str(torch.__version__), "backend": "XNNPACK", "rows_checked": checked,
              "max_abs_logit_difference": worst_logit, "max_abs_probability_difference": worst_p,
              "outcome_flips": len(flips), "flipped_inputs": flips[:20], "tolerance": PTE_TOLERANCE,
              "passed": checked > 0 and worst_logit <= PTE_TOLERANCE and not flips}
    (out / SELFCHECK_FILE).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    write_manifest(out)
    return report


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("command", nargs="?", choices=("build", "pte"), default="build")
    ap.add_argument("--dir", type=Path, help="output folder (pte: the folder `build` wrote)")
    ap.add_argument("--bundle", type=Path, default=BUNDLE_DIR)
    ap.add_argument("--urls", type=Path, default=URLS_FILE)
    ap.add_argument("--no-threat-db", action="store_true")
    args = ap.parse_args(argv)
    if args.command == "pte":
        if args.dir is None:
            ap.error("pte needs --dir (the folder `build` wrote)")
        report = export_pte(args.dir, args.bundle)
        print(json.dumps({k: v for k, v in report.items() if k != "flipped_inputs"}, indent=2))
        return 0 if report["passed"] else 1
    out = build_export(".", out_dir=args.dir, bundle_dir=args.bundle, urls_file=args.urls,
                       threat_db=not args.no_threat_db)
    spec = json.loads((out / SPEC_FILE).read_text(encoding="utf-8"))
    print(f"wrote {out}")
    print(json.dumps(spec["reference"], indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
