"""Load a model bundle and score normalized URLs on the CPU (or a given device).

The scoring path mirrors training exactly: the model reads `model_string`,
the hybrid's structural features come from the same FeatureExtractor and the
scaler fitted on the training split, the n-gram model reads the same text,
and the stacked calibrator turns the member logits into P(phishing) and the
PHISHING / UNCERTAIN / LIKELY_SAFE outcome. tests/test_inference.py checks
that this gives the same numbers as the training code.
"""
from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Sequence

import numpy as np
import torch

from src.models.char_cnn import load_checkpoint
from src.models.ngram_lr import NgramLR
from src.preprocessing.feature_extractor import FeatureExtractor
from src.preprocessing.url_normalizer import NormalizedURL

from .bundle import Bundle, BundleError, load_bundle

DEFAULT_BATCH_SIZE = 64


@dataclass(frozen=True)
class ModelScores:
    probability: np.ndarray            # calibrated P(phishing), float64
    outcome: np.ndarray                # PHISHING / UNCERTAIN / LIKELY_SAFE per row
    member_logits: dict[str, np.ndarray]


class ModelRuntime:
    """Thread-safe scorer for one bundle. Only inputs of the bundle's mode are accepted."""

    def __init__(self, bundle: Bundle | str, device: str = "cpu", batch_size: int = DEFAULT_BATCH_SIZE):
        self.bundle = bundle if isinstance(bundle, Bundle) else load_bundle(bundle)
        if not isinstance(batch_size, int) or batch_size < 1:
            raise ValueError("batch_size must be an integer >= 1")
        self.batch_size = batch_size
        self.device = torch.device(device)
        self.calibrator = self.bundle.calibrator
        self._cnn = self._ngram = None
        self._tokenizer = self._scaler = self._extractor = None
        for name in self.calibrator.members:
            kind, path = self.bundle.member_kind(name), self.bundle.member_file(name)
            if kind == "char_cnn":
                model, self._tokenizer, self._scaler, meta = load_checkpoint(path, map_location=self.device)
                if meta["mode"] != self.bundle.mode:
                    raise BundleError("checkpoint mode does not match the bundle")
                self._cnn = model.to(self.device).eval()
                if self._scaler is not None:
                    self._extractor = FeatureExtractor(self._scaler.feature_names)
            elif kind == "char_ngram_lr":
                self._ngram = NgramLR.load(path)
            else:
                raise BundleError(f"unknown member kind {kind!r}")
        self._lock = threading.Lock()

    @property
    def mode(self) -> str:
        return self.bundle.mode

    @property
    def model_version(self) -> str:
        return self.bundle.model_version

    def score(self, items: Sequence[NormalizedURL]) -> ModelScores:
        if not items:
            empty = np.zeros(0)
            return ModelScores(empty, np.zeros(0, dtype="<U11"), {})
        expected = "domain" if self.mode == "domain" else "full_url"
        if any(n.input_type != expected for n in items):
            raise ValueError(f"this bundle scores {expected!r} inputs only")
        texts = [n.model_string for n in items]
        logits: dict[str, np.ndarray] = {}
        for name in self.calibrator.members:
            kind = self.bundle.member_kind(name)
            logits[name] = self._cnn_logits(items, texts) if kind == "char_cnn" else self._ngram.logits(texts)
        x = np.column_stack([logits[name] for name in self.calibrator.members])
        p = self.calibrator.probability(x)
        return ModelScores(p, self.calibrator.outcome(p), logits)

    def _cnn_logits(self, items: Sequence[NormalizedURL], texts: list[str]) -> np.ndarray:
        enc = self._tokenizer.encode_batch(texts)
        feats = (None if self._scaler is None
                 else self._scaler.transform(self._extractor.extract_batch(list(items))))
        out = []
        with self._lock, torch.inference_mode():
            for start in range(0, len(texts), self.batch_size):
                stop = start + self.batch_size
                width = max(int(enc.lengths[start:stop].max()), 1)   # masking makes the trim exact
                ids = torch.from_numpy(enc.ids[start:stop, :width]).to(self.device)
                f = None if feats is None else torch.from_numpy(feats[start:stop]).to(self.device)
                out.append(self._cnn(ids, f).float().cpu())
        return torch.cat(out).double().numpy()
