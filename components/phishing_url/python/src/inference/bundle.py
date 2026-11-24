"""A model bundle: one folder with everything inference needs, checked by hash.

    python -m src.inference.bundle build        # from artifacts/runs -> models/full_url
    python -m src.inference.bundle build --popular-top-n 10000
    python -m src.inference.bundle verify models/full_url

Contents of models/<mode>/
  cnn.pt           the char-CNN / hybrid checkpoint (weights, tokenizer, feature scaler)
  ngram.npz        the character n-gram model (plain arrays, no pickle)
  redirectors.txt  URL-shortener / QR-redirector domains (their links hide the destination)
  popular.txt      the most popular websites (Tranco top-N, default 1,000): the model
                   alone may not call a page there PHISHING (decision_engine rule 4)
  version.json     model version, calibrator + thresholds, SHA-256 of every file,
                   validation numbers, data hashes and library versions

The model version is derived from the content (member hashes + calibrator), so
the same model always has the same version and any change gives a new one.
Prediction caches use it in their keys. Copy the whole folder to deploy.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import platform
import shutil
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from src.data.parsers import find_snapshots, parse_tranco
from src.data.split_dataset import load_redirectors
from src.models.calibration import StackCalibrator

FORMAT_VERSION = 2                                   # 2: popular.txt added
MODELS_DIR = Path("models")
FILES = {"char_cnn": "cnn.pt", "char_ngram_lr": "ngram.npz"}
REDIRECTORS_FILE = "redirectors.txt"
POPULAR_FILE = "popular.txt"
DEFAULT_POPULAR_TOP_N = 1000


class BundleError(ValueError):
    """The bundle is missing, incomplete, or a file does not match its recorded hash."""


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def model_version(mode: str, member_hashes: dict[str, str], calibrator: dict) -> str:
    blob = json.dumps({"members": member_hashes, "calibrator": calibrator}, sort_keys=True)
    return f"{mode}-{hashlib.sha256(blob.encode()).hexdigest()[:12]}"


@dataclass(frozen=True)
class Bundle:
    path: Path
    manifest: dict

    @property
    def mode(self) -> str:
        return self.manifest["mode"]

    @property
    def model_version(self) -> str:
        return self.manifest["model_version"]

    @property
    def calibrator(self) -> StackCalibrator:
        return StackCalibrator.from_config(self.manifest["calibrator"])

    def member_file(self, name: str) -> Path:
        return self.path / self.manifest["members"][name]["file"]

    def member_kind(self, name: str) -> str:
        return self.manifest["members"][name]["kind"]

    def redirectors(self) -> set[str]:
        return load_redirectors([self.path / REDIRECTORS_FILE])

    def popular(self) -> set[str]:
        """Websites (registered domains) where the model alone may not say PHISHING."""
        text = (self.path / self.manifest["popular"]["file"]).read_text(encoding="utf-8")
        return {line.strip() for line in text.splitlines() if line.strip()}


def _clean_domains(domains) -> list[str]:
    out = set()
    for d in domains:
        d = str(d).strip().lower().rstrip(".")
        if not d or any(c.isspace() for c in d) or "/" in d:
            raise BundleError(f"not a domain name: {d!r}")
        out.add(d)
    return sorted(out)


def build_bundle(*, cnn_checkpoint: Path, ngram_model: Path, ensemble_json: Path, candidate: str,
                 out_dir: Path, redirector_lists: list[Path], popular_domains=(),
                 popular_source: dict | None = None, now: datetime | None = None) -> Bundle:
    """Copy the chosen candidate's members into out_dir and write version.json.

    popular_domains: registered domains where the model alone may not say PHISHING
    (empty: no guard). popular_source records where they came from (list, top_n).
    """
    report = json.loads(Path(ensemble_json).read_text(encoding="utf-8"))
    cand = report.get("candidates", {}).get(candidate)
    if cand is None:
        raise BundleError(f"{ensemble_json} has no candidate {candidate!r} "
                          f"(have {sorted(report.get('candidates', {}))})")
    if "error" in cand:
        raise BundleError(f"candidate {candidate!r} is not usable: {cand['error']}")
    calibrator = StackCalibrator.from_config(cand["calibrator"])
    sources = {"char_cnn": Path(cnn_checkpoint), "char_ngram_lr": Path(ngram_model)}
    members = {}
    for name in calibrator.members:
        info = report["members"].get(name)
        if info is None or info["kind"] not in FILES:
            raise BundleError(f"member {name!r} is not described in {ensemble_json}")
        src = sources[info["kind"]]
        digest = _sha256(src)
        if digest != info["sha256"]:
            raise BundleError(f"{src} is not the file the calibrator was fitted for (hash differs)")
        members[name] = {"kind": info["kind"], "file": FILES[info["kind"]], "sha256": digest,
                         "source": src.as_posix()}
    redirectors = load_redirectors(redirector_lists)
    if not redirectors:
        raise BundleError("no redirector domains loaded: links that hide their target would be scored")
    popular = _clean_domains(popular_domains)

    out_dir = Path(out_dir)
    tmp = out_dir.with_name(out_dir.name + ".part")
    shutil.rmtree(tmp, ignore_errors=True)
    tmp.mkdir(parents=True)
    for name, m in members.items():
        shutil.copyfile(m["source"], tmp / m["file"])
    (tmp / REDIRECTORS_FILE).write_text("\n".join(sorted(redirectors)) + "\n", encoding="utf-8")
    (tmp / POPULAR_FILE).write_text("".join(d + "\n" for d in popular), encoding="utf-8")

    import numpy, sklearn, torch                             # versions for the record only
    hashes = {name: m["sha256"] for name, m in members.items()}
    manifest = {
        "format_version": FORMAT_VERSION, "mode": report["mode"],
        "model_version": model_version(report["mode"], hashes, calibrator.to_config()),
        "created_at": (now or datetime.now(timezone.utc)).isoformat(timespec="seconds"),
        "candidate": candidate,
        "members": {n: {k: v for k, v in m.items() if k != "source"} for n, m in members.items()},
        "calibrator": calibrator.to_config(),
        "budgets": report.get("budgets"), "unit": report.get("unit"),
        "validation_crossfit": {k: cand["crossfit_val"].get(k) for k in ("pr_auc", "roc_auc", "ece")}
        | {"outcomes": {k: cand["crossfit_val"]["outcomes"].get(k)
                        for k in ("false_alarm_rate", "phishing_caught_rate", "missed_rate",
                                  "projected_by_phishing_base_rate")}},
        "fitted_on": report.get("fitted_on"),
        "redirectors": {"file": REDIRECTORS_FILE, "sha256": _sha256(tmp / REDIRECTORS_FILE),
                        "count": len(redirectors)},
        "popular": {"file": POPULAR_FILE, "sha256": _sha256(tmp / POPULAR_FILE),
                    "count": len(popular), "top_n": 0, **(popular_source or {})},
        "built_from": {"ensemble": Path(ensemble_json).as_posix(),
                       **{n: m["source"] for n, m in members.items()}},
        "versions": {"python": platform.python_version(), "torch": str(torch.__version__),
                     "sklearn": sklearn.__version__, "numpy": numpy.__version__},
    }
    (tmp / "version.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    shutil.rmtree(out_dir, ignore_errors=True)
    tmp.rename(out_dir)
    return load_bundle(out_dir)


def load_bundle(path: Path | str) -> Bundle:
    """Read version.json and check every file against its recorded SHA-256."""
    path = Path(path)
    manifest_path = path / "version.json"
    if not manifest_path.is_file():
        raise BundleError(f"{manifest_path} not found: run `python -m src.inference.bundle build`")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise BundleError(f"{manifest_path} is not valid JSON") from exc
    if manifest.get("format_version") != FORMAT_VERSION:
        raise BundleError(f"bundle format {manifest.get('format_version')} is not {FORMAT_VERSION}: "
                          "rebuild it with `python -m src.inference.bundle build`")
    calibrator = StackCalibrator.from_config(manifest["calibrator"])
    if set(calibrator.members) != set(manifest["members"]):
        raise BundleError("calibrator members do not match the bundled members")
    checks = [(m["file"], m["sha256"]) for m in manifest["members"].values()]
    for extra in ("redirectors", "popular"):
        checks.append((manifest[extra]["file"], manifest[extra]["sha256"]))
    for name, digest in checks:
        f = path / name
        if not f.is_file():
            raise BundleError(f"{f} is missing")
        if _sha256(f) != digest:
            raise BundleError(f"{f} does not match its recorded hash (damaged or replaced)")
    hashes = {n: m["sha256"] for n, m in manifest["members"].items()}
    if model_version(manifest["mode"], hashes, manifest["calibrator"]) != manifest["model_version"]:
        raise BundleError("model_version does not match the bundle content")
    return Bundle(path, manifest)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="command", required=True)
    b = sub.add_parser("build", help="assemble a bundle from training artifacts")
    b.add_argument("--cnn-run", type=Path, default=Path("artifacts/runs/full_url_hybrid"))
    b.add_argument("--ngram", type=Path, default=Path("artifacts/runs/full_url_ngram/model.npz"))
    b.add_argument("--ensemble", type=Path, default=None,
                   help="default: artifacts/runs/<cnn run>_ensemble/ensemble.json")
    b.add_argument("--candidate", default=None, help="default: <cnn run>+char_ngram_lr")
    b.add_argument("--out", type=Path, default=None, help="default: models/<mode>")
    b.add_argument("--raw", type=Path, default=Path("data/raw"))
    b.add_argument("--local-redirectors", type=Path, default=Path("config/redirectors_local.txt"))
    b.add_argument("--popular-top-n", type=int, default=DEFAULT_POPULAR_TOP_N,
                   help="popular-website guard: newest Tranco top-N (0 = no guard)")
    v = sub.add_parser("verify", help="check a bundle's files against version.json")
    v.add_argument("path", type=Path, nargs="?", default=MODELS_DIR / "full_url")
    args = ap.parse_args(argv)
    if args.command == "verify":
        bundle = load_bundle(args.path)
        print(f"OK {bundle.path}: {bundle.model_version} ({bundle.manifest['candidate']})")
        return 0
    run = args.cnn_run
    ensemble = args.ensemble or run.parent / f"{run.name}_ensemble" / "ensemble.json"
    mode = json.loads(ensemble.read_text(encoding="utf-8"))["mode"]
    lists = list(find_snapshots(args.raw, "url_shorteners")[-1:])
    if args.local_redirectors.is_file():
        lists.append(args.local_redirectors)
    if args.popular_top_n < 0:
        ap.error("--popular-top-n must be >= 0")
    popular, source = set(), {"top_n": 0}
    if args.popular_top_n > 0:
        snaps = find_snapshots(args.raw, "tranco")
        if not snaps:
            ap.error("no Tranco snapshot for the popular-website guard: run "
                     "'python -m src.data.download_datasets --sources tranco' or pass --popular-top-n 0")
        popular = {rec.value for rec in parse_tranco(snaps[-1]) if int(rec.source_id) <= args.popular_top_n}
        source = {"top_n": args.popular_top_n, "list": snaps[-1].name}
    bundle = build_bundle(cnn_checkpoint=run / "best.pt", ngram_model=args.ngram,
                          ensemble_json=ensemble,
                          candidate=args.candidate or f"{run.name}+char_ngram_lr",
                          out_dir=args.out or MODELS_DIR / mode, redirector_lists=lists,
                          popular_domains=popular, popular_source=source)
    m = bundle.manifest
    print(f"built {bundle.path}: model_version {m['model_version']} ({m['candidate']}), "
          f"{m['redirectors']['count']} redirector domains, popular-website guard on "
          f"{m['popular']['count']} websites (Tranco top {m['popular']['top_n']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
