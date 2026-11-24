"""Check authored scenarios against local corpora without clustering reference pairs."""
from collections import Counter, defaultdict
import csv
import hashlib
import json
from pathlib import Path
import sys

import pandas as pd

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
from sms_detection.preprocessing.normalize import normalize_text
from sms_detection.data.deduplicate import _template_skeleton, _shingles, _jaccard

HERE = Path(__file__).resolve().parent

def main():
    suite = json.loads((HERE / "challenge.json").read_text(encoding="utf-8"))
    rows = suite["cases"]
    assert hashlib.sha256(json.dumps(rows, ensure_ascii=False, sort_keys=True).encode()).hexdigest() == suite["rows_sha256"]
    with (HERE / "challenge.csv").open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    refs = {}
    for split in ("train", "val", "test", "external"):
        p = ROOT / f"data/processed/{split}.csv"
        if p.exists(): refs[split] = pd.read_csv(p, usecols=["text"])["text"].dropna().astype(str).tolist()
    refs["legacy_handmade"] = pd.read_csv(ROOT / "experiments/mobilebert/handmade_dataset/smishing_dataset.csv")["Message"].astype(str).tolist()
    refs["indian_binary"] = pd.read_csv(ROOT / "data/indian/india_spam_sms.csv")["text"].dropna().astype(str).tolist()
    checks = {}
    for source, texts in refs.items():
        normalized = [normalize_text(t).normalized.lower() for t in texts]
        exact = set(normalized)
        templates = {_template_skeleton(t) for t in normalized}
        shingles = [_shingles(t) for t in normalized]
        inverted = defaultdict(set)
        for i, words in enumerate(shingles):
            for word in words: inverted[word].add(i)
        matches = []
        for row in rows:
            q = normalize_text(row["text"]).normalized.lower()
            qwords = _shingles(q)
            candidates = set()
            for word in qwords: candidates.update(inverted.get(word, ()))
            near = any(min(len(qwords), len(shingles[i])) / max(len(qwords), len(shingles[i])) >= .8
                       and _jaccard(qwords, shingles[i]) >= .8 for i in candidates)
            is_exact = q in exact
            is_template = _template_skeleton(q) in templates
            if is_exact or is_template or near:
                matches.append({"id": row["id"], "exact": is_exact, "template": is_template, "near_jaccard_0_8": near})
        checks[source] = {"reference_rows": len(texts), "overlap_rows": len(matches),
                         "overlap_scenarios": len({r["id"].rsplit("-", 1)[0] for r in matches}), "matches": matches}
        print(source, len(texts), len(matches), flush=True)
    report = {"suite_sha256": suite["rows_sha256"], "rows": len(rows),
              "semantic_scenarios": len({r["scenario_id"] for r in rows}),
              "labels": dict(Counter(r["label"] for r in rows)),
              "languages": dict(Counter(r["language"] for r in rows)),
              "method": "Normalized exact, template skeleton, and exhaustive query-to-reference trigram Jaccard >=0.8; references never compared to one another",
              "sources": checks, "not_blind": True,
              "limitation": "No overlap removal: this is an authored regression challenge; exact/simple phrase overlaps remain transparently flagged. Semantic or contextual similarity below this check may remain."}
    out = ROOT / "artifacts/reports/automation_review"
    out.mkdir(parents=True, exist_ok=True)
    (out / "suite_audit.json").write_text(json.dumps(report, indent=2), encoding="utf-8")

if __name__ == "__main__": main()
