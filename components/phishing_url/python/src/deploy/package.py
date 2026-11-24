"""Pack everything a test device needs into one zip: no secrets, no training data.

    python -m src.deploy.package                  # -> dist/phishing_device_<model_version>.zip
    python -m src.deploy.package --no-threat-db   # smaller, without the local threat database

Contents
  src/, tests/                       the code and its tests (run the tests on the device)
  config/*.json, config/*.txt        settings (no keys: keys only ever come from the environment)
  models/full_url/                   the model bundle (checked by hash when loaded)
  data/intel/threat_intel.sqlite3    the local threat database (optional)
  data/processed/benchmark_urls.txt  the benchmark URL sample
  reports/parity_<version>.json      this machine's scores, for `src.inference.parity check`
  requirements-device.txt, DEVICE_README.txt
  MANIFEST.json                      SHA-256 of every file above
Refused: .env*, *.key, *.pem, *.p12, *.pfx, secret(s).* / credential(s).*, files over 50 MB.
Skipped: __pycache__, *.pyc.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import zipfile
from datetime import datetime, timezone
from pathlib import Path

# No numpy / torch imports at module level: `verify` must work with plain Python,
# before anything is installed on the device.
BUNDLE_DIR = Path("models") / "full_url"
DIST_DIR = Path("dist")
URLS_FILE = Path("data/processed/benchmark_urls.txt")
THREAT_DB = Path("data/intel/threat_intel.sqlite3")
MAX_FILE_BYTES = 50 * 2**20
SECRET_NAMES = re.compile(r"^\.env(\..*)?$|\.(key|pem|p12|pfx)$|^(secrets?|credentials?)(\..*)?$", re.I)

REQUIREMENTS = """\
# Runtime + tests on a test device. Install PyTorch FIRST, CPU build:
#   pip install torch --index-url https://download.pytorch.org/whl/cpu
# (since PyTorch 2.11 a plain `pip install torch` on aarch64 Linux fetches the CUDA build)
numpy>=2.0
scikit-learn>=1.5
tldextract>=5.1
idna>=3.6
httpx>=0.27
pytest>=8.0
# HTTP API (python -m src.api.app) and its tests
fastapi>=0.162
starlette>=1.10
uvicorn>=0.54
pydantic>=2.14
"""

DEVICE_README = """\
Phishing detector: test package for an Arm device ({model_version})

Inside the Linux environment (Debian in Termux via proot-distro, or a Raspberry Pi):

  python3 -m zipfile -e phishing_device_{model_version}.zip ~/phishing
  cd ~/phishing
  python3 -m src.deploy.package verify      (every file arrived intact?)
  python3 -m venv ~/venv
  . ~/venv/bin/activate
  pip install torch=={torch} --index-url https://download.pytorch.org/whl/cpu
      (if that version is not found: pip install torch --index-url https://download.pytorch.org/whl/cpu)
  pip install -r requirements-device.txt

  python -m src.inference.bundle verify
  python -m pytest -q
  python -m src.inference.parity check --urls data/processed/benchmark_urls.txt
  python -m src.inference.benchmark --urls data/processed/benchmark_urls.txt --quick --thread-sweep 1,2,4,8
  python -m src.inference.benchmark --urls data/processed/benchmark_urls.txt --thread-sweep 1,2,4,8
  python -m src.inference.predict "https://github.com/login" "https://en.wikipedia.org/wiki/Phishing"

Send back the printed output and the reports/*.json files written here.
No API key is needed or wanted on this device: Google Safe Browsing is skipped without one.
"""


class PackageError(ValueError):
    pass


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _code_files(root: Path, folder: str) -> list[Path]:
    return sorted(p for p in (root / folder).rglob("*")
                  if p.is_file() and "__pycache__" not in p.parts and p.suffix != ".pyc")


def _git_commit(root: Path) -> str | None:
    try:
        out = subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=root, capture_output=True,
                             text=True, timeout=10)
        dirty = subprocess.run(["git", "status", "--porcelain"], cwd=root, capture_output=True,
                               text=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return None
    if out.returncode != 0:
        return None
    return out.stdout.strip() + ("+uncommitted" if dirty.stdout.strip() else "")


def collect(root: Path, *, bundle_dir: Path, urls_file: Path, parity_file: Path,
            threat_db: Path | None) -> list[tuple[Path, str]]:
    """(source path, path inside the zip) for every file to pack."""
    items = [(p, p.relative_to(root).as_posix()) for folder in ("src", "tests")
             for p in _code_files(root, folder)]
    items += [(p, f"config/{p.name}") for p in sorted((root / "config").glob("*"))
              if p.is_file() and p.suffix in (".json", ".txt")]
    items += [(p, f"models/{bundle_dir.name}/{p.name}") for p in sorted(bundle_dir.iterdir()) if p.is_file()]
    items.append((urls_file, URLS_FILE.as_posix()))
    items.append((parity_file, f"reports/{parity_file.name}"))
    if threat_db is not None:
        items.append((threat_db, THREAT_DB.as_posix()))
    for src, name in items:
        if SECRET_NAMES.search(src.name):
            raise PackageError(f"refusing to pack {name}: it looks like a secret")
        if src.stat().st_size > MAX_FILE_BYTES:
            raise PackageError(f"refusing to pack {name}: larger than {MAX_FILE_BYTES // 2**20} MB")
    return items


def build_package(root: Path | str = ".", *, bundle_dir: Path | str = BUNDLE_DIR,
                  urls_file: Path | str = URLS_FILE, parity_file: Path | str | None = None,
                  threat_db: Path | str | None = THREAT_DB, out_dir: Path | str = DIST_DIR,
                  now: datetime | None = None) -> Path:
    from src.inference.bundle import load_bundle
    root = Path(root).resolve()
    bundle = load_bundle(root / bundle_dir)                       # refuses a damaged bundle
    urls_file = root / urls_file
    if not urls_file.is_file():
        raise PackageError(f"{urls_file} not found: run `python -m src.inference.benchmark "
                           f"--save-urls {URLS_FILE.as_posix()}` first")
    parity_file = root / (parity_file or Path("reports") / f"parity_{bundle.model_version}.json")
    if not parity_file.is_file():
        raise PackageError(f"{parity_file} not found: run `python -m src.inference.parity save "
                           f"--urls {URLS_FILE.as_posix()}` first")
    reference = json.loads(parity_file.read_text(encoding="utf-8"))
    from src.inference.parity import read_urls, urls_digest
    if reference.get("model_version") != bundle.model_version:
        raise PackageError(f"{parity_file} is for {reference.get('model_version')}, not {bundle.model_version}")
    if reference.get("urls_sha256") != urls_digest(read_urls(urls_file)):
        raise PackageError(f"{parity_file} was made with a different URL list than {urls_file}")
    db = None
    if threat_db is not None:
        db = root / threat_db
        if not db.is_file():
            raise PackageError(f"{db} not found: build it, or pass --no-threat-db")
    items = collect(root, bundle_dir=bundle.path, urls_file=urls_file, parity_file=parity_file, threat_db=db)

    import torch
    torch_version = str(torch.__version__).split("+")[0]
    extra = {"requirements-device.txt": REQUIREMENTS,
             "DEVICE_README.txt": DEVICE_README.format(model_version=bundle.model_version, torch=torch_version)}
    manifest = {
        "model_version": bundle.model_version,
        "created_at": (now or datetime.now(timezone.utc)).isoformat(timespec="seconds"),
        "git_commit": _git_commit(root), "reference_torch": torch_version,
        "threat_db_included": db is not None,
        "files": {name: {"sha256": _sha256(src), "bytes": src.stat().st_size} for src, name in items},
    }
    out_dir = root / out_dir
    out_dir.mkdir(parents=True, exist_ok=True)
    target = out_dir / f"phishing_device_{bundle.model_version}.zip"
    tmp = target.with_name(target.name + ".part")
    with zipfile.ZipFile(tmp, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for src, name in items:
            zf.write(src, name)
        for name, text in extra.items():
            zf.writestr(name, text)
        zf.writestr("MANIFEST.json", json.dumps(manifest, indent=2) + "\n")
    tmp.replace(target)
    return target


def verify_package(root: Path | str = ".") -> list[str]:
    """On the device, after unzipping: files whose SHA-256 differs from MANIFEST.json."""
    root = Path(root)
    manifest = json.loads((root / "MANIFEST.json").read_text(encoding="utf-8"))
    return [name for name, info in manifest["files"].items()
            if not (root / name).is_file() or _sha256(root / name) != info["sha256"]]


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("command", nargs="?", choices=("build", "verify"), default="build")
    ap.add_argument("--bundle", type=Path, default=BUNDLE_DIR)
    ap.add_argument("--urls", type=Path, default=URLS_FILE)
    ap.add_argument("--no-threat-db", action="store_true")
    ap.add_argument("--out", type=Path, default=DIST_DIR)
    args = ap.parse_args(argv)
    if args.command == "verify":
        bad = verify_package(".")
        print("OK: every file matches MANIFEST.json" if not bad else f"DAMAGED or missing: {bad}")
        return 0 if not bad else 1
    path = build_package(".", bundle_dir=args.bundle, urls_file=args.urls,
                         threat_db=None if args.no_threat_db else THREAT_DB, out_dir=args.out)
    with zipfile.ZipFile(path) as zf:
        count = len(zf.namelist())
    print(f"built {path} ({path.stat().st_size / 2**20:.1f} MB, {count} files)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
