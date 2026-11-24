"""Load the leakage-safe splits written by src.data.split_dataset.

Every row is re-normalized with the same normalizer the live service uses and
checked against the stored `model_string`, so training and serving can never
silently see URLs differently. Structural features are expensive to compute
(tldextract), so they are cached on disk, keyed by the CSV's content hash and
the feature list.
"""
from __future__ import annotations

import csv
import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Sequence

import numpy as np

from src.preprocessing.feature_extractor import FORMAT_VERSION as FEATURE_FORMAT
from src.preprocessing.feature_extractor import FeatureExtractor
from src.preprocessing.url_normalizer import InvalidURLError, NormalizedURL, normalize_url

SPLITS_DIR = Path("data/processed/splits")
CACHE_DIR = Path("data/processed/cache")
MODES = ("full_url", "domain")
SPLITS = ("train", "val", "test", "test_future")
# full_url rows are re-normalized from `canonical` (keeps the scheme);
# domain rows from the bare host in `model_string`.
_SOURCE_COLUMN = {"full_url": "canonical", "domain": "model_string"}
_REQUIRED = {"sample_id", "y", "model_string", "canonical", "host", "group"}


class DataMismatchError(ValueError):
    """The stored model_string no longer matches the current normalizer."""


@dataclass
class SplitData:
    mode: str
    split: str
    sample_ids: list[str]
    texts: list[str]                   # model_string: what the char models read
    y: np.ndarray                      # int64, 1 = phishing
    groups: list[str]
    normalized: list[NormalizedURL] = field(repr=False)
    file_sha256: str = ""

    def __len__(self) -> int:
        return len(self.texts)

    def slices(self) -> dict[str, np.ndarray]:
        """Boolean masks for slice-wise evaluation (shortcut checks)."""
        if self.mode == "full_url":
            homepage = np.array([n.path in ("", "/") and not n.query for n in self.normalized])
            www = np.array([n.host.startswith("www.") for n in self.normalized])
            return {"all": np.ones(len(self), bool), "homepage_only": homepage,
                    "with_path_or_query": ~homepage, "www_host": www, "non_www_host": ~www}
        sub = np.array([bool(n.subdomain) and n.subdomain != "www" for n in self.normalized])
        return {"all": np.ones(len(self), bool), "with_subdomain": sub, "bare_domain": ~sub}


def file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def split_path(mode: str, split: str, root: Path = SPLITS_DIR) -> Path:
    if mode not in MODES:
        raise ValueError(f"mode must be one of {MODES}")
    if split not in SPLITS:
        raise ValueError(f"split must be one of {SPLITS}")
    return Path(root) / mode / f"{split}.csv"


def load_split(mode: str, split: str, root: Path = SPLITS_DIR) -> SplitData:
    path = split_path(mode, split, root)
    if not path.exists():
        raise FileNotFoundError(f"{path} not found: run `python -m src.data.split_dataset` first")
    input_type = "full_url" if mode == "full_url" else "domain"
    source = _SOURCE_COLUMN[mode]
    ids, texts, ys, groups, norms = [], [], [], [], []
    with path.open(encoding="utf-8", newline="") as fh:
        reader = csv.DictReader(fh)
        missing = _REQUIRED - set(reader.fieldnames or ())
        if missing:
            raise ValueError(f"{path}: missing columns {sorted(missing)}")
        for line, row in enumerate(reader, start=2):
            if row["y"] not in ("0", "1"):
                raise ValueError(f"{path}:{line}: y must be 0 or 1")
            try:
                n = normalize_url(row[source], input_type)
            except InvalidURLError as exc:
                raise DataMismatchError(f"{path}:{line}: no longer normalizes ({exc})") from exc
            if n.model_string != row["model_string"]:
                raise DataMismatchError(
                    f"{path}:{line}: normalizer output changed; rebuild the dataset")
            ids.append(row["sample_id"])
            texts.append(row["model_string"])
            ys.append(int(row["y"]))
            groups.append(row["group"])
            norms.append(n)
    if not texts:
        raise ValueError(f"{path} is empty")
    return SplitData(mode, split, ids, texts, np.asarray(ys, dtype=np.int64), groups, norms,
                     file_sha256(path))


def load_features(data: SplitData, feature_names: Sequence[str] | None = None,
                  cache_dir: Path | None = CACHE_DIR) -> np.ndarray:
    """RAW (unscaled) structural features, cached by file hash + feature list."""
    extractor = FeatureExtractor(feature_names)
    key = hashlib.sha256(json.dumps(
        [FEATURE_FORMAT, data.file_sha256, list(extractor.feature_names)]).encode()).hexdigest()[:20]
    cache = None if cache_dir is None else Path(cache_dir) / f"{data.mode}_{data.split}_{key}.npy"
    if cache is not None and cache.exists():
        arr = np.load(cache, allow_pickle=False)
        if arr.shape == (len(data), len(extractor.feature_names)):
            return arr
    arr = extractor.extract_batch(data.normalized)
    if cache is not None:
        cache.parent.mkdir(parents=True, exist_ok=True)
        tmp = cache.with_suffix(".part.npy")
        np.save(tmp, arr, allow_pickle=False)
        tmp.replace(cache)
    return arr
