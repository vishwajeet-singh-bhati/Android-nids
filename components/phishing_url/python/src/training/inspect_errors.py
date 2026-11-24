"""Where do a calibrated run's mistakes come from?

    python -m src.training.inspect_errors --run artifacts/runs/full_url_hybrid
    python -m src.training.inspect_errors --run artifacts/runs/full_url_hybrid --with-test

Uses the frozen calibrator in <run>/calibration.json (run src.training.calibrate
first). Safe URLs come in groups of up to ~21 per website, so mistakes are also
counted per website: 60 false alarms from 3 websites is a very different
problem from 60 false alarms spread over 60 websites.

Validation: lists the safe websites with the highest scores (host + path only;
query strings are never printed) so a human can judge whether they are real
mistakes or mislabelled "safe" data. Test: aggregate counts only, so the test
split stays an exam and is never used to tune anything.

Nothing is written to disk.
"""
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

import numpy as np

from src.models.calibration import LIKELY_SAFE, PHISHING, Calibrator, classify
from src.models.char_cnn import load_checkpoint

from .data import CACHE_DIR, SPLITS_DIR, SplitData, file_sha256, load_split, split_path
from .train_cnn import predict_logits, resolve_device, to_tensors

N_BOOT = 2000


def _site_bootstrap(hits: np.ndarray, sizes: np.ndarray, n_boot: int, seed: int) -> list[float]:
    """95% range of hits.sum()/sizes.sum() when whole websites are resampled."""
    rng = np.random.default_rng(seed)
    rates = np.empty(n_boot)
    for start in range(0, n_boot, 250):                  # chunks keep memory small
        idx = rng.integers(0, len(sizes), size=(min(250, n_boot - start), len(sizes)))
        rates[start:start + len(idx)] = hits[idx].sum(1) / sizes[idx].sum(1)
    return [float(np.percentile(rates, 2.5)), float(np.percentile(rates, 97.5))]


def _per_site(mask: np.ndarray, hit: np.ndarray, groups: np.ndarray, n_boot: int, seed: int) -> dict:
    sites, inv = np.unique(groups[mask], return_inverse=True)
    sizes = np.bincount(inv, minlength=len(sites))
    hits = np.bincount(inv, weights=hit[mask].astype(float), minlength=len(sites)).astype(int)
    n, k = int(sizes.sum()), int(hits.sum())
    out = {"urls": k, "of_urls": n, "rate": k / n, "sites": int((hits > 0).sum()),
           "of_sites": len(sites), "largest_site_urls": int(hits.max()) if k else 0,
           "site_bootstrap_95": _site_bootstrap(hits, sizes, n_boot, seed) if n_boot else None}
    if k:
        j = int(hits.argmax())
        rest = n - int(sizes[j])
        out["rate_without_largest_site"] = (k - int(hits[j])) / rest if rest else None
    return out


def site_errors(p, y, groups, t_phishing: float, t_safe: float, *, n_boot: int = N_BOOT,
                seed: int = 0) -> dict:
    """False alarms (safe -> PHISHING) and misses (phishing -> LIKELY_SAFE), per URL and per site."""
    out = classify(np.asarray(p, dtype=np.float64), t_phishing, t_safe)
    y, groups = np.asarray(y), np.asarray(groups, dtype=object)
    return {"false_alarm": _per_site(y == 0, out == PHISHING, groups, n_boot, seed),
            "missed": _per_site(y == 1, out == LIKELY_SAFE, groups, n_boot, seed)}


def _extra_columns(data: SplitData, splits: Path) -> dict[str, dict]:
    with split_path(data.mode, data.split, splits).open(encoding="utf-8", newline="") as fh:
        return {r["sample_id"]: {"sources": r.get("sources", ""), "tranco_rank": r.get("tranco_rank", "")}
                for r in csv.DictReader(fh)}


def top_safe_sites(data: SplitData, p: np.ndarray, t_phishing: float, splits: Path,
                   n: int = 15) -> list[dict]:
    """Safe websites ordered by their highest score. Examples show host + path only."""
    extra = _extra_columns(data, splits)
    best: dict[str, dict] = {}
    for i in np.flatnonzero(data.y == 0):
        site = data.groups[i]
        entry = best.setdefault(site, {"site": site, "urls": 0, "flagged": 0, "max_p": -1.0})
        entry["urls"] += 1
        entry["flagged"] += int(p[i] > t_phishing)
        if p[i] > entry["max_p"]:
            norm = data.normalized[i]
            info = extra.get(data.sample_ids[i], {})
            entry.update(max_p=float(p[i]), example=f"{norm.host}{norm.path}"[:70],
                         sources=info.get("sources", ""), tranco_rank=info.get("tranco_rank", ""))
    return sorted(best.values(), key=lambda e: -e["max_p"])[:n]


def inspect_run(run_dir: Path, *, splits: Path = SPLITS_DIR, with_test: bool = False,
                device: str = "auto", cache_dir: Path | None = CACHE_DIR, top: int = 15,
                n_boot: int = N_BOOT) -> dict:
    run_dir = Path(run_dir)
    cal_path, ckpt_path = run_dir / "calibration.json", run_dir / "best.pt"
    if not cal_path.exists():
        raise FileNotFoundError(f"{cal_path} not found: run src.training.calibrate first")
    saved = json.loads(cal_path.read_text(encoding="utf-8"))
    if saved["checkpoint_sha256"] != file_sha256(ckpt_path):
        raise ValueError("best.pt changed since calibration: run src.training.calibrate again")
    cal = Calibrator.from_config(saved["calibrator"])
    dev = resolve_device(device)
    model, tokenizer, scaler, meta = load_checkpoint(ckpt_path, map_location=dev)
    model.to(dev)

    def score(split: str) -> tuple[SplitData, np.ndarray]:
        data = load_split(meta["mode"], split, splits)
        expected = meta["data_sha256"].get(split) if split == "val" else saved.get("test", {}).get("sha256")
        if expected and data.file_sha256 != expected:
            raise ValueError(f"the {split} split changed since this run was trained/calibrated")
        return data, cal.probability(predict_logits(model, to_tensors(data, tokenizer, scaler, dev, cache_dir)))

    val, p = score("val")
    report = {"run": run_dir.name, "mode": meta["mode"], "budgets": saved["budgets"],
              "unit": saved.get("unit", "url"),
              "thresholds": {"t_phishing": cal.t_phishing, "t_safe": cal.t_safe},
              "val": {"errors": site_errors(p, val.y, val.groups, cal.t_phishing, cal.t_safe,
                                            n_boot=n_boot),
                      "top_safe_sites": top_safe_sites(val, p, cal.t_phishing, splits, top)}}
    if with_test:
        test, p = score("test")
        report["test"] = {"errors": site_errors(p, test.y, test.groups, cal.t_phishing, cal.t_safe,
                                                n_boot=n_boot)}   # aggregates only
    return report


# --------------------------------------------------------------------- printing
def _pct(v) -> str:
    return "-" if v is None else f"{100 * v:.2f}%"


def print_report(r: dict) -> None:
    t = r["thresholds"]
    print(f"run {r['run']} ({r['mode']}): PHISHING if p > {t['t_phishing']:.4f}, "
          f"LIKELY_SAFE if p < {t['t_safe']:.4f} (budgets {_pct(r['budgets']['max_false_alarm'])} "
          f"false alarm, {_pct(r['budgets']['max_missed'])} missed, "
          f"{'every website counts once' if r.get('unit') == 'website' else 'per URL'})")
    for split in ("val", "test"):
        if split not in r:
            continue
        fa, ms = r[split]["errors"]["false_alarm"], r[split]["errors"]["missed"]
        print(f"  [{split}] false alarms: {fa['urls']} of {fa['of_urls']} safe URLs ({_pct(fa['rate'])}) "
              f"from {fa['sites']} of {fa['of_sites']} safe websites")
        if fa["urls"]:
            print(f"  [{split}]   the worst website gives {fa['largest_site_urls']} of them; without it "
                  f"the rate is {_pct(fa.get('rate_without_largest_site'))}")
        if fa["site_bootstrap_95"]:
            lo, hi = fa["site_bootstrap_95"]
            print(f"  [{split}]   if other websites had been drawn: roughly {_pct(lo)} to {_pct(hi)}")
        print(f"  [{split}] missed (phishing called LIKELY_SAFE): {ms['urls']} of {ms['of_urls']} "
              f"({_pct(ms['rate'])}) from {ms['sites']} of {ms['of_sites']} phishing websites")
    print("  [val] safe websites with the highest scores (host + path only):")
    print("    max p   flagged  source        tranco  example")
    for e in r["val"]["top_safe_sites"]:
        print(f"    {e['max_p']:.4f}  {e['flagged']:>3}/{e['urls']:<3}  {e['sources'][:12]:<12}  "
              f"{str(e['tranco_rank'] or '-'):>6}  {e['example']}")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--run", type=Path, required=True, help="calibrated run directory")
    ap.add_argument("--splits", type=Path, default=SPLITS_DIR)
    ap.add_argument("--device", choices=("auto", "cpu", "cuda"), default="auto")
    ap.add_argument("--top", type=int, default=15, help="how many safe websites to list")
    ap.add_argument("--with-test", action="store_true", help="add test aggregates (no URLs)")
    args = ap.parse_args(argv)
    print_report(inspect_run(args.run, splits=args.splits, with_test=args.with_test,
                             device=args.device, cache_dir=CACHE_DIR, top=args.top))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
