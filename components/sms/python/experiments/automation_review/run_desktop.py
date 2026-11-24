"""Automated Kotlin + frozen Python PTE cascade comparison. No manual SMS needed."""
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

import pandas as pd
import numpy as np

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
from sms_detection.preprocessing.normalize import normalize_text
from sms_detection.data.indian_sms import check_leakage, load_benchmark, load_reference_splits

HERE = Path(__file__).resolve().parent
PRIVATE = ROOT / "data/indian/automation_v1"
REPORT = ROOT / "artifacts/reports/automation_review"

def b64(s): return base64.b64encode(str(s).encode("utf-8")).decode("ascii") if s else "-"
def sha(p): return hashlib.sha256(Path(p).read_bytes()).hexdigest()

def metrics(frame):
    f = frame.copy()
    for col in ("routed", "attention", "financial"):
        f[col] = f[col].astype(str).str.lower().eq("true")
    if "any_attention" in f:
        f["any_attention"] = f.any_attention.astype(str).str.lower().eq("true")
    known = f.label.isin(["ham", "spam", "smishing"])
    smish = f.label.eq("smishing")
    safe = f.label.isin(["ham", "spam"])
    warn = f.final_risk.ne("low")
    exact_tp = int((smish & f.final_label.eq("smishing")).sum())
    exact_fp = int((safe & f.final_label.eq("smishing")).sum())
    warning_tp = int((smish & warn).sum())
    warning_fp = int((safe & warn).sum())
    def div(a, b): return a / b if b else None
    slices = {}
    for language, group in f.groupby("language"):
        pos = group.label.eq("smishing")
        neg = group.label.isin(["ham", "spam"])
        slices[str(language)] = {"rows": len(group), "scams": int(pos.sum()),
            "scams_warned": int((pos & group.final_risk.ne("low")).sum()),
            "non_scams": int(neg.sum()), "non_scams_warned": int((neg & group.final_risk.ne("low")).sum())}
    return {"rows": len(f), "semantic_scenarios": int(f.scenario_id.nunique()),
        "exact_label_accuracy_known": div(int((known & f.label.eq(f.final_label)).sum()), int(known.sum())),
        "smishing_support": int(smish.sum()), "smishing_label_correct": exact_tp,
        "smishing_label_recall": div(exact_tp, int(smish.sum())),
        "smishing_label_precision": div(exact_tp, exact_tp + exact_fp),
        "scams_warned": warning_tp, "scams_attention": int((smish & f.attention).sum()),
        "scams_financial_attention": int((smish & f.financial).sum()),
        "scams_any_attention": int((smish & f.get("any_attention", f.attention)).sum()),
        "non_scams_any_attention": int((safe & f.get("any_attention", f.attention)).sum()),
        "raw_tier1_scams_warned": int((smish & f.get("tier1_risk", f.final_risk).ne("low")).sum()),
        "raw_tier1_ham_warned": int((f.label.eq("ham") & f.get("tier1_risk", f.final_risk).ne("low")).sum()),
        "warning_recall": div(warning_tp, int(smish.sum())),
        "warning_precision": div(warning_tp, warning_tp + warning_fp),
        "ham_support": int(f.label.eq("ham").sum()), "ham_warned": int((f.label.eq("ham") & warn).sum()),
        "ham_attention": int((f.label.eq("ham") & f.attention).sum()),
        "spam_support": int(f.label.eq("spam").sum()), "spam_warned": int((f.label.eq("spam") & warn).sum()),
        "spam_to_smishing": int((f.label.eq("spam") & f.final_label.eq("smishing")).sum()),
        "tier1_only": int((~f.routed).sum()), "tier2_called": int(f.routed.sum()),
        "tier2_call_rate": float(f.routed.mean()), "routing_reasons": f.routing_reason.value_counts().to_dict(),
        "uncertain_support": int(f.label.eq("uncertain").sum()),
        "uncertain_reviewed": int((f.label.eq("uncertain") & warn).sum()), "language_slices": slices,
        "failures": f.loc[(smish & ~warn) | (safe & warn), ["id", "label", "family", "language", "final_label", "final_risk", "routing_reason"]].to_dict("records")}

def binary_control_metrics(result):
    """Source spam can include fraud: never count it as a confirmed fraud negative."""
    for field in ("smishing_label_precision", "smishing_label_recall", "warning_precision", "warning_recall", "exact_label_accuracy_known", "non_scams_any_attention"):
        result[field] = None
    result["fraud_ground_truth_available"] = False
    result["failures"] = [r for r in result["failures"] if r["label"] == "ham"]
    for group in result["language_slices"].values():
        group["non_scams"] = result["ham_support"]
        group["non_scams_warned"] = result["ham_warned"]
        group["source_spam_warned_not_confirmed_false_positives"] = result["spam_warned"]
    return result

def main():
    PRIVATE.mkdir(parents=True, exist_ok=True)
    REPORT.mkdir(parents=True, exist_ok=True)
    challenge = json.loads((HERE / "challenge.json").read_text(encoding="utf-8"))
    cases = [{**r, "dataset": "synthetic_challenge"} for r in challenge["cases"]]
    for row in pd.read_csv(ROOT / "experiments/mobilebert/handmade_dataset/smishing_dataset.csv").itertuples():
        cases.append({"id": f"handmade-{row.ID}", "text": row.Message, "sender": "", "label": "smishing",
            "language": "en", "family": row.Category, "scenario_id": f"handmade-{row.ID}", "dataset": "legacy_handmade"})
    for row in pd.read_csv(ROOT / "data/processed/test.csv").itertuples():
        cases.append({"id": f"legacy-{row.message_id}", "text": row.text, "sender": "", "label": row.label,
            "language": "source_labelled", "family": "legacy", "scenario_id": row.split_group, "dataset": "legacy_test"})
    indian = load_benchmark(ROOT / "data/indian/india_spam_sms.csv")
    refs = {k: v for k, v in load_reference_splits(ROOT / "data/processed").items() if k in {"train", "val"}}
    indian, leakage = check_leakage(indian, refs, near_duplicate=True)
    for i, row in enumerate(indian.itertuples()):
        cases.append({"id": f"indian-{i}", "text": row.text, "sender": row.sender or "", "label": row.label,
            "language": "not_individually_annotated", "family": "binary_control", "scenario_id": row.group_id or f"indian-{i}", "dataset": "indian_binary_control"})
    all_cases = pd.DataFrame(cases)
    assert all_cases.id.is_unique
    (PRIVATE / "cases.json").write_text(json.dumps(cases, ensure_ascii=False), encoding="utf-8")
    inputs = PRIVATE / "inputs.tsv"
    inputs.write_text("\n".join("\t".join([r['id'], b64(r['text']), b64(r.get('sender', ''))]) for r in cases) + "\n", encoding="utf-8")
    java = Path(os.environ["LOCALAPPDATA"]) / "Temp/opencode/bharat_tools/jdk17/jdk-17.0.21+9/bin/java.exe"
    model = ROOT / "artifacts/model/portable/portable_model.json"
    def kotlin(mode, source, out):
        jar = ROOT / f"tier1-kotlin/build/{'baseline' if mode == 'baseline' else 'candidate'}-batch.jar"
        subprocess.run([str(java), "-jar", str(jar), "--batch", str(model), str(source), str(out), mode], check=True)
    routed = set()
    for mode in ("baseline", "candidate"):
        out = PRIVATE / f"{mode}_route.tsv"
        kotlin(mode, inputs, out)
        table = pd.read_csv(out, sep="\t")
        routed |= set(table.loc[table.routed.astype(str).str.lower().eq("true"), "id"])
    keys, unique = {}, {}
    for row in cases:
        if row["id"] in routed:
            normalized = normalize_text(row["text"]).model_text
            key = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
            keys[row["id"]] = key
            unique[key] = {"key": key, "normalized": normalized}
    neural_input = PRIVATE / "neural_inputs.json"
    neural_output = PRIVATE / "neural_outputs.jsonl"
    neural_input.write_text(json.dumps(list(unique.values()), ensure_ascii=False), encoding="utf-8")
    # Resume only the exact normalized input cache for the same frozen model.
    cache_stamp = PRIVATE / "neural_cache_stamp.json"
    stamp = {"pte_sha256": sha(ROOT / "experiments/mobilebert/qat/artifacts/ptq_int8_b1.pte"), "input_sha256": sha(neural_input)}
    cached = cache_stamp.exists() and neural_output.exists() and json.loads(cache_stamp.read_text()) == stamp
    if not cached:
        subprocess.run([str(ROOT / "experiments/mobilebert/.venv/Scripts/python.exe"), str(HERE / "run_pte_worker.py"), str(neural_input), str(neural_output)], check=True)
        cache_stamp.write_text(json.dumps(stamp), encoding="utf-8")
    neural = {r["key"]: r for r in map(json.loads, neural_output.read_text(encoding="utf-8").splitlines())}
    assert set(neural) == set(unique)
    full = PRIVATE / "inputs_with_neural.tsv"
    with full.open("w", encoding="utf-8") as handle:
        for row in cases:
            scores = neural[keys[row["id"]]]["scores"] if row["id"] in keys else ["-", "-", "-"]
            handle.write("\t".join([row["id"], b64(row["text"]), b64(row.get("sender", "")), *map(str, scores)]) + "\n")
    report = {"challenge_sha256": challenge["rows_sha256"], "pte_sha256": stamp["pte_sha256"],
        "portable_sha256": sha(model), "research_date": "2026-11-12", "engine": "Kotlin/JVM core + Windows ExecuTorch 1.6.0 PTE",
        "on_phone": False, "weights_retrained": False, "indian_leakage": leakage,
        "total_cases": len(cases), "unique_neural_inputs": len(unique), "datasets": {},
        "limitations": challenge["limitations"] + ["Old test/handmade/Indian sources are previously inspected regression controls", "Indian binary source cannot measure smishing precision or recall", "Desktop diagnostic timing is not phone latency/battery", "No test-driven changes were made after running the frozen suite"]}
    for mode in ("baseline", "candidate"):
        out = REPORT / f"{mode}_predictions.tsv"
        kotlin(mode, full, out)
        frame = all_cases.drop(columns=["text", "sender"]).merge(pd.read_csv(out, sep="\t"), on="id", validate="one_to_one")
        for name, group in frame.groupby("dataset"):
            result = metrics(group)
            if name == "indian_binary_control":
                result = binary_control_metrics(result)
            report["datasets"].setdefault(name, {})[mode] = result
        frame.to_csv(REPORT / f"{mode}_text_free_results.csv", index=False)
    (REPORT / "comparison.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    for name, results in report["datasets"].items():
        print(name, json.dumps({m: {k: v for k, v in r.items() if k in {"rows", "tier2_called", "smishing_support", "scams_warned", "ham_warned", "spam_warned", "smishing_label_correct"}} for m, r in results.items()}), flush=True)

if __name__ == "__main__": main()
