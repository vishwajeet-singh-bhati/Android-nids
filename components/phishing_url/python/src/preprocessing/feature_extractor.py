"""Structural URL features and a leakage-safe scaler.

Everything is computed from a NormalizedURL: no network access and no keyword
lists. The extractor outputs raw numbers; FeatureScaler applies log1p to the
heavy-tailed count/length columns and then z-score standardization, using
statistics fitted on the TRAINING split only.
"""
from __future__ import annotations

import hashlib
import json
import math
from collections import Counter
from pathlib import Path
from typing import Any, Sequence

import numpy as np

from .url_normalizer import NormalizedURL

FORMAT_VERSION = 1
SCALER_TYPE = "log1p_zscore"

ALL_FEATURE_NAMES: tuple[str, ...] = (
    # lengths and counts (heavy-tailed -> log1p before standardizing)
    "url_length", "host_length", "path_length", "query_length",
    "registered_domain_length", "num_host_labels", "num_subdomain_labels",
    "num_dots", "num_digits", "num_special_chars", "host_hyphens",
    "longest_host_label", "num_underscores", "num_percent_encoded",
    "num_query_params", "path_depth", "longest_path_segment",
    # ratios and entropies (bounded -> only standardized)
    "digit_ratio", "special_char_ratio", "host_digit_ratio",
    "entropy_url", "entropy_host", "entropy_path_query",
    # binary indicators
    "is_ip_host", "has_punycode", "has_userinfo", "has_nondefault_port",
    # dataset-artifact risk (scheme): computed but excluded by default
    "is_https", "scheme_inferred",
)

LOG_SCALED_FEATURES = frozenset({
    "url_length", "host_length", "path_length", "query_length",
    "registered_domain_length", "num_host_labels", "num_subdomain_labels",
    "num_dots", "num_digits", "num_special_chars", "host_hyphens",
    "longest_host_label", "num_underscores", "num_percent_encoded",
    "num_query_params", "path_depth", "longest_path_segment",
})

ARTIFACT_RISK_FEATURES = frozenset({"is_https", "scheme_inferred"})

DEFAULT_FEATURE_NAMES: tuple[str, ...] = tuple(
    name for name in ALL_FEATURE_NAMES if name not in ARTIFACT_RISK_FEATURES
)


def shannon_entropy(text: str) -> float:
    """Shannon entropy of the character distribution, in bits."""
    if not text:
        return 0.0
    total = len(text)
    entropy = -sum((c / total) * math.log2(c / total) for c in Counter(text).values())
    return max(0.0, entropy)


def _ratio(numerator: float, denominator: float) -> float:
    return numerator / denominator if denominator else 0.0


def compute_features(n: NormalizedURL) -> dict[str, float]:
    """Compute every feature for one URL, keyed by name."""
    if not isinstance(n, NormalizedURL):
        raise TypeError("compute_features expects a NormalizedURL")

    s = n.model_string
    length = len(s)
    host = n.host
    labels = [] if n.is_ip else host.split(".")

    digits = sum(ch.isdigit() for ch in s)
    alnum = sum(ch.isascii() and ch.isalnum() for ch in s)
    special = length - alnum
    host_digits = sum(ch.isdigit() for ch in host)

    segments = [seg for seg in n.path.split("/") if seg]
    path_query = n.path + (f"?{n.query}" if n.query else "")

    values: dict[str, float] = {
        "url_length": length,
        "host_length": len(host),
        "path_length": len(n.path),
        "query_length": len(n.query),
        "registered_domain_length": len(n.registered_domain),
        "num_host_labels": len(labels),
        "num_subdomain_labels": len(n.subdomain.split(".")) if n.subdomain else 0,
        "num_dots": s.count("."),
        "num_digits": digits,
        "num_special_chars": special,
        "host_hyphens": host.count("-"),
        "longest_host_label": max((len(l) for l in labels), default=0),
        "num_underscores": s.count("_"),
        "num_percent_encoded": s.count("%"),
        "num_query_params": sum(1 for part in n.query.split("&") if part),
        "path_depth": len(segments),
        "longest_path_segment": max((len(seg) for seg in segments), default=0),
        "digit_ratio": _ratio(digits, length),
        "special_char_ratio": _ratio(special, length),
        "host_digit_ratio": _ratio(host_digits, len(host)),
        "entropy_url": shannon_entropy(s),
        "entropy_host": shannon_entropy(host),
        "entropy_path_query": shannon_entropy(path_query),
        "is_ip_host": float(n.is_ip),
        "has_punycode": float(n.has_punycode),
        "has_userinfo": float(n.has_userinfo),
        "has_nondefault_port": float(n.port is not None),
        "is_https": float(n.scheme == "https"),
        "scheme_inferred": float(n.scheme_inferred),
    }
    return {name: float(values[name]) for name in ALL_FEATURE_NAMES}


def _validate_names(names: Sequence[str]) -> tuple[str, ...]:
    names = tuple(names)
    if not names:
        raise ValueError("feature_names must not be empty")
    if len(set(names)) != len(names):
        raise ValueError("feature_names contains duplicates")
    unknown = [n for n in names if n not in ALL_FEATURE_NAMES]
    if unknown:
        raise ValueError(f"unknown feature names: {unknown}")
    return names


class FeatureExtractor:
    def __init__(self, feature_names: Sequence[str] | None = None) -> None:
        self.feature_names = _validate_names(
            DEFAULT_FEATURE_NAMES if feature_names is None else feature_names
        )

    def extract(self, n: NormalizedURL) -> np.ndarray:
        values = compute_features(n)
        return np.fromiter((values[name] for name in self.feature_names),
                           dtype=np.float32, count=len(self.feature_names))

    def extract_batch(self, items: Sequence[NormalizedURL]) -> np.ndarray:
        out = np.zeros((len(items), len(self.feature_names)), dtype=np.float32)
        for row, item in enumerate(items):
            out[row] = self.extract(item)
        return out


class FeatureScaler:
    """log1p on count/length columns, then (x - mean) / std per column."""

    def __init__(self, feature_names: Sequence[str], mean: Sequence[float],
                 std: Sequence[float]) -> None:
        self.feature_names = _validate_names(feature_names)
        self.mean = np.asarray(mean, dtype=np.float64)
        self.std = np.asarray(std, dtype=np.float64)
        d = len(self.feature_names)
        if self.mean.shape != (d,) or self.std.shape != (d,):
            raise ValueError("mean/std must be 1-D arrays matching feature_names")
        if not (np.isfinite(self.mean).all() and np.isfinite(self.std).all()):
            raise ValueError("mean/std must be finite")
        if (self.std <= 0).any():
            raise ValueError("std must be strictly positive")
        self._log_mask = np.array([n in LOG_SCALED_FEATURES for n in self.feature_names])

    # ---------------------------------------------------------------- core
    @staticmethod
    def _log_transform(names: Sequence[str], arr: np.ndarray) -> np.ndarray:
        mask = np.array([n in LOG_SCALED_FEATURES for n in names])
        arr = arr.copy()
        if mask.any():
            if (arr[:, mask] < 0).any():
                raise ValueError("count/length features must be non-negative")
            arr[:, mask] = np.log1p(arr[:, mask])
        return arr

    @classmethod
    def fit(cls, feature_names: Sequence[str], raw: np.ndarray) -> "FeatureScaler":
        """Fit on RAW training features. Never call this with val/test data."""
        names = _validate_names(feature_names)
        arr = np.asarray(raw, dtype=np.float64)
        if arr.ndim != 2 or arr.shape[0] == 0 or arr.shape[1] != len(names):
            raise ValueError("raw must be a non-empty 2-D array with one column per feature")
        if not np.isfinite(arr).all():
            raise ValueError("raw contains NaN or infinity")
        transformed = cls._log_transform(names, arr)
        mean = transformed.mean(axis=0)
        std = transformed.std(axis=0)
        std = np.where(std < 1e-8, 1.0, std)  # constant column -> maps to 0, no NaN
        return cls(names, mean, std)

    def transform(self, raw: np.ndarray) -> np.ndarray:
        arr = np.asarray(raw, dtype=np.float64)
        single = arr.ndim == 1
        if single:
            arr = arr[None, :]
        if arr.ndim != 2 or arr.shape[1] != len(self.feature_names):
            raise ValueError("raw has the wrong shape for this scaler")
        if not np.isfinite(arr).all():
            raise ValueError("raw contains NaN or infinity")
        out = ((self._log_transform(self.feature_names, arr) - self.mean) / self.std)
        out = out.astype(np.float32)
        return out[0] if single else out

    # ------------------------------------------------------- serialization
    def to_config(self) -> dict[str, Any]:
        return {
            "format_version": FORMAT_VERSION,
            "type": SCALER_TYPE,
            "feature_names": list(self.feature_names),
            "mean": self.mean.tolist(),
            "std": self.std.tolist(),
        }

    def fingerprint(self) -> str:
        canonical = json.dumps(self.to_config(), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("ascii")).hexdigest()

    @classmethod
    def from_config(cls, config: dict[str, Any]) -> "FeatureScaler":
        if not isinstance(config, dict):
            raise ValueError("scaler config must be a JSON object")
        missing = {"format_version", "type", "feature_names", "mean", "std"} - config.keys()
        if missing:
            raise ValueError(f"scaler config missing keys: {sorted(missing)}")
        if config["format_version"] != FORMAT_VERSION:
            raise ValueError(f"unsupported scaler format_version: {config['format_version']!r}")
        if config["type"] != SCALER_TYPE:
            raise ValueError(f"unsupported scaler type: {config['type']!r}")
        try:
            return cls(config["feature_names"], config["mean"], config["std"])
        except (TypeError, ValueError) as exc:
            raise ValueError(f"invalid scaler config: {exc}") from exc

    def save(self, path: str | Path) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.to_config(), indent=2) + "\n", encoding="utf-8")

    @classmethod
    def load(cls, path: str | Path) -> "FeatureScaler":
        try:
            config = json.loads(Path(path).read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ValueError("scaler file is not valid JSON") from exc
        return cls.from_config(config)