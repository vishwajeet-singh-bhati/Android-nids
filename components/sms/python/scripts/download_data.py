"""Download the public SMS datasets used by the audit.

Raw files are written under ``data/raw/`` and are intentionally excluded from
Git. A manifest records URL, license, download time, size and SHA-256 so every
derived table can be traced back to an immutable source.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests

from sms_detection.config import RAW_DIR, SOURCE_LICENSES

UCI_URL = "https://archive.ics.uci.edu/static/public/228/sms+spam+collection.zip"
MENDELEY_API = "https://data.mendeley.com/api/datasets/f45bkkt8pr/files"
MENDELEY_LANDING = "https://data.mendeley.com/datasets/f45bkkt8pr/1"
NCSU_BASE = "https://raw.githubusercontent.com/wspr-ncsu/sms-phishing/main"
NCSU_FILES = ["README.md", "LICENSE", "phishing_messages.csv", "phishing_campaigns.csv"]
HINGLISH_BASE = "https://huggingface.co/datasets/bolewara/hinglish-scam-text-dataset/resolve/main"
HINGLISH_FILES = ["README.md", "data.json"]
INDIA_SPAM_BASE = "https://raw.githubusercontent.com/junioralive/india-spam-sms-classification/main"
INDIA_SPAM_FILES = ["dataset/spam_ham_india.csv", "LICENSE", "README.md"]


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def download(url: str, destination: Path, *, force: bool = False, timeout: int = 120) -> Path:
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists() and not force:
        print(f"[skip] {destination} ({destination.stat().st_size:,} bytes)")
        return destination
    print(f"[get ] {url}")
    with requests.get(url, stream=True, timeout=timeout) as response:
        response.raise_for_status()
        temporary = destination.with_suffix(destination.suffix + ".part")
        with temporary.open("wb") as handle:
            for chunk in response.iter_content(chunk_size=1024 * 256):
                if chunk:
                    handle.write(chunk)
        temporary.replace(destination)
    print(f"[ok  ] {destination} ({destination.stat().st_size:,} bytes)")
    return destination


def extract_zip(path: Path, destination: Path, *, force: bool = False) -> None:
    marker = destination / ".extracted"
    if marker.exists() and not force:
        print(f"[skip] extracted {destination}")
        return
    destination.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path) as archive:
        archive.extractall(destination)
    marker.write_text(datetime.now(timezone.utc).isoformat(), encoding="utf-8")
    print(f"[ok  ] extracted {path.name} -> {destination}")


def record_entry(
    manifest: dict[str, Any],
    *,
    dataset: str,
    url: str,
    path: Path,
    license_text: str,
    note: str = "",
) -> None:
    entry = {
        "dataset": dataset,
        "url": url,
        "path": str(path.relative_to(RAW_DIR.parent.parent)).replace("\\", "/"),
        "license": license_text,
        "downloaded_utc": datetime.now(timezone.utc).isoformat(),
        "size_bytes": path.stat().st_size,
        "sha256": sha256(path),
        "note": note,
    }
    manifest.setdefault("files", []).append(entry)
    print(f"[hash] {path.name}: {entry['sha256']}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Download SMS scam datasets")
    parser.add_argument("--force", action="store_true")
    parser.add_argument(
        "--skip-large",
        action="store_true",
        help="Skip the optional NCSU external-test corpus",
    )
    args = parser.parse_args(argv)

    RAW_DIR.mkdir(parents=True, exist_ok=True)
    manifest: dict[str, Any] = {
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "project": "Bharat AI 2026 SMS scam detection module",
        "notes": "Raw files are not redistributed by this repository. Re-check licenses at use.",
        "files": [],
    }

    # 1. UCI SMS Spam Collection -------------------------------------------------
    uci_zip = RAW_DIR / "uci" / "sms_spam_collection.zip"
    download(UCI_URL, uci_zip, force=args.force)
    record_entry(
        manifest,
        dataset="uci_sms_spam",
        url=UCI_URL,
        path=uci_zip,
        license_text=SOURCE_LICENSES["uci_sms_spam"],
        note="Classic 5,574-message ham/spam benchmark; old UK/Singapore-oriented corpus.",
    )
    extract_zip(uci_zip, RAW_DIR / "uci", force=args.force)

    # 2. Mishra & Soni LSDST-2022 ------------------------------------------------
    files = requests.get(MENDELEY_API, timeout=120).json()
    dataset_zip = next((item for item in files if item["filename"] == "Dataset_5971.zip"), None)
    if dataset_zip is None:
        raise RuntimeError("Dataset_5971.zip not found in Mendeley file listing")
    lsdst_zip = RAW_DIR / "lsdst_2022" / "Dataset_5971.zip"
    download(dataset_zip["content_details"]["download_url"], lsdst_zip, force=args.force)
    expected = dataset_zip["content_details"].get("sha256_hash")
    if expected and sha256(lsdst_zip) != expected:
        raise RuntimeError("LSDST-2022 checksum mismatch")
    record_entry(
        manifest,
        dataset="lsdst_2022",
        url=MENDELEY_LANDING,
        path=lsdst_zip,
        license_text=SOURCE_LICENSES["lsdst_2022"],
        note="5,971 messages: 4,844 ham / 489 spam / 638 smishing; labels partly image-derived.",
    )
    extract_zip(lsdst_zip, RAW_DIR / "lsdst_2022", force=args.force)

    # 3. Hinglish seed corpus ----------------------------------------------------
    for name in HINGLISH_FILES:
        path = RAW_DIR / "hinglish_scam" / name
        download(f"{HINGLISH_BASE}/{name}", path, force=args.force)
        record_entry(
            manifest,
            dataset="hinglish_scam",
            url=f"{HINGLISH_BASE}/{name}",
            path=path,
            license_text=SOURCE_LICENSES["hinglish_scam"],
            note="3,787 rows, mostly UCI-derived; only 63 hand-written Hinglish rows.",
        )

    # 4. Kaggle India Spam SMS collection (binary evaluation source) -------------
    for name in INDIA_SPAM_FILES:
        path = RAW_DIR / "india_spam_sms" / Path(name).name
        download(f"{INDIA_SPAM_BASE}/{name}", path, force=args.force)
        record_entry(
            manifest,
            dataset="india_spam_sms",
            url=f"{INDIA_SPAM_BASE}/{name}",
            path=path,
            license_text=SOURCE_LICENSES["india_spam_sms"],
            note=(
                "2,267 real-world Indian telecom SMS; binary ham/spam labels; "
                "no smishing labels. Evaluation-only external source."
            ),
        )

    # 5. NCSU SMS phishing (optional external test) ------------------------------
    if not args.skip_large:
        for name in NCSU_FILES:
            path = RAW_DIR / "ncsu_sms_phishing" / name
            download(f"{NCSU_BASE}/{name}", path, force=args.force, timeout=300)
            record_entry(
                manifest,
                dataset="ncsu_sms_phishing",
                url=f"{NCSU_BASE}/{name}",
                path=path,
                license_text=SOURCE_LICENSES["ncsu_sms_phishing"],
                note="Phishing-only corpus with campaign metadata; verify data provenance before redistribution.",
            )

    manifest_path = RAW_DIR / "source_manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"\nManifest: {manifest_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
