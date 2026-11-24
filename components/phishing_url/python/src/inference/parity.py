"""Same model, same answers on another machine? (x86 laptop vs Arm phone / Pi)

    python -m src.inference.parity save  --urls data/processed/benchmark_urls.txt   # reference machine
    python -m src.inference.parity check --urls benchmark_urls.txt                  # the device

`save` scores the URLs with the bundle in fixed batches of 64 and writes
reports/parity_<model_version>.json: the scores and decisions in URL order,
plus a SHA-256 of the URL list (the URLs themselves are not copied).
`check` scores the same URLs the same way on this machine and compares:
  * max / mean difference of P(phishing), and of each member's logit
  * decisions that differ (expected: none, unless a score sits right on a
    threshold; such a case is listed with its distance to the threshold)
Different CPUs and math libraries add up numbers in a different order, so
tiny differences (around 1e-6) are normal. It passes when every decision is
the same and P(phishing) differs by at most --tolerance (default 1e-4).
Exit code 0 = pass, 1 = fail. The result goes to reports/parity_check_<machine>_<time>.json.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import platform
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence

import numpy as np

from src.preprocessing.url_normalizer import normalize_url

from .bundle import MODELS_DIR
from .machine import machine_info
from .runtime import ModelRuntime

BATCH = 64
REPORTS_DIR = Path("reports")
DEFAULT_TOLERANCE = 1e-4


def read_urls(path: Path | str) -> list[str]:
    lines = Path(path).read_text(encoding="utf-8").splitlines()
    return [x.strip() for x in lines if x.strip() and not x.startswith("#")]


def urls_digest(urls: Sequence[str]) -> str:
    return hashlib.sha256("\n".join(urls).encode("utf-8")).hexdigest()


def score(runtime: ModelRuntime, urls: Sequence[str]) -> dict:
    """Scores in URL order, batches of BATCH (the same batching on every machine)."""
    normalized = [normalize_url(u) for u in urls]
    prob, outcome, logits = [], [], {name: [] for name in runtime.calibrator.members}
    for start in range(0, len(normalized), BATCH):
        s = runtime.score(normalized[start:start + BATCH])
        prob += [float(p) for p in s.probability]
        outcome += [str(o) for o in s.outcome]
        for name in logits:
            logits[name] += [float(v) for v in s.member_logits[name]]
    return {"probability": prob, "outcome": outcome, "member_logits": logits}


def save(runtime: ModelRuntime, urls: Sequence[str]) -> dict:
    return {"kind": "parity_reference", "model_version": runtime.model_version,
            "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "machine": machine_info(), "batch": BATCH, "count": len(urls),
            "urls_sha256": urls_digest(urls), **score(runtime, urls)}


def compare(reference: dict, runtime: ModelRuntime, urls: Sequence[str],
            tolerance: float = DEFAULT_TOLERANCE) -> dict:
    problems = []
    if reference["model_version"] != runtime.model_version:
        problems.append(f"model version differs: reference {reference['model_version']}, "
                        f"here {runtime.model_version}")
    if reference["urls_sha256"] != urls_digest(urls):
        problems.append("the URL list is not the one the reference was made with")
    if problems:
        return {"passed": False, "problems": problems}
    got = score(runtime, urls)
    ref_p, p = np.array(reference["probability"]), np.array(got["probability"])
    dp = np.abs(ref_p - p)
    t_phishing, t_safe = runtime.calibrator.t_phishing, runtime.calibrator.t_safe
    flips = [{"index": i, "reference": reference["outcome"][i], "here": got["outcome"][i],
              "reference_p": float(ref_p[i]), "here_p": float(p[i]),
              "distance_to_threshold": float(min(abs(ref_p[i] - t_phishing), abs(ref_p[i] - t_safe)))}
             for i in range(len(urls)) if reference["outcome"][i] != got["outcome"][i]]
    members = {}
    for name, ref_logits in reference["member_logits"].items():
        d = np.abs(np.array(ref_logits) - np.array(got["member_logits"][name]))
        members[name] = {"max_abs_diff": float(d.max()), "mean_abs_diff": float(d.mean())}
    if flips:
        problems.append(f"{len(flips)} decision(s) differ")
    if dp.max() > tolerance:
        problems.append(f"P(phishing) differs by up to {dp.max():.2e} (tolerance {tolerance:.0e})")
    return {"passed": not problems, "problems": problems, "count": len(urls), "tolerance": tolerance,
            "probability": {"max_abs_diff": float(dp.max()), "mean_abs_diff": float(dp.mean()),
                            "identical": int((dp == 0).sum())},
            "member_logits": members, "decision_flips": flips,
            "outcome_counts": {o: got["outcome"].count(o) for o in sorted(set(got["outcome"]))}}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("command", choices=("save", "check"))
    ap.add_argument("--urls", type=Path, required=True)
    ap.add_argument("--bundle", type=Path, default=MODELS_DIR / "full_url")
    ap.add_argument("--reference", type=Path, default=None,
                    help="default: reports/parity_<model_version>.json")
    ap.add_argument("--tolerance", type=float, default=DEFAULT_TOLERANCE)
    ap.add_argument("--out", type=Path, default=REPORTS_DIR)
    args = ap.parse_args(argv)
    runtime = ModelRuntime(args.bundle)
    urls = read_urls(args.urls)
    reference_path = args.reference or args.out / f"parity_{runtime.model_version}.json"
    args.out.mkdir(parents=True, exist_ok=True)
    if args.command == "save":
        reference_path.write_text(json.dumps(save(runtime, urls)) + "\n", encoding="utf-8")
        print(f"saved scores of {len(urls)} URLs for {runtime.model_version} to {reference_path}")
        return 0
    reference = json.loads(reference_path.read_text(encoding="utf-8"))
    result = compare(reference, runtime, urls, args.tolerance)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    report = {"kind": "parity_check", "created_at": stamp, "model_version": runtime.model_version,
              "machine": machine_info(), "reference_machine": reference.get("machine"), **result}
    path = args.out / f"parity_check_{platform.machine() or 'unknown'}_{stamp}.json"
    path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    ref_m, m = reference.get("machine", {}), report["machine"]
    print(f"reference: {ref_m.get('system')} {ref_m.get('machine')}, torch {ref_m.get('torch')}")
    print(f"here:      {m['system']} {m['machine']}, torch {m['torch']}")
    if "probability" in result:
        pr = result["probability"]
        print(f"{result['count']} URLs: P(phishing) max diff {pr['max_abs_diff']:.2e}, "
              f"mean {pr['mean_abs_diff']:.2e}, identical {pr['identical']}; "
              f"decisions that differ: {len(result['decision_flips'])}")
        for name, d in result["member_logits"].items():
            print(f"  {name}: logit max diff {d['max_abs_diff']:.2e}")
    print("PASS" if result["passed"] else "FAIL: " + "; ".join(result["problems"]))
    print(f"report: {path}")
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
