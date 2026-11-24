"""Export the sparse linear model for future Kotlin/Android inference.

scikit-learn models cannot be loaded directly by ExecuTorch. The plan therefore
calls for exporting the vocabulary, IDF values, coefficients and intercepts and
re-implementing vectorization + linear inference on-device. This module provides
that export and a pure-Python reference implementation so parity can be tested
before any Kotlin work begins.
"""

from __future__ import annotations

import json
import math
import re
from collections import Counter
from pathlib import Path
from typing import Iterable, Sequence

import numpy as np
from scipy.special import softmax

from ..config import LABELS
from ..preprocessing.indicators import FEATURE_NAMES, analyze_text, feature_vector
from ..preprocessing.normalize import normalize_text
from .classifier import SmsClassifier

WORD_TOKEN_RE = re.compile(r"(?u)\b\w+\b")
WHITESPACE_RE = re.compile(r"\s\s+")


def export_portable_model(model: SmsClassifier, output_dir: str | Path) -> Path:
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    if model.classifier is None:
        raise RuntimeError("model is not fitted")

    word = _vectorizer_payload(model.word_vectorizer, analyzer="word")
    char = _vectorizer_payload(model.char_vectorizer, analyzer="char_wb")
    indicator_size = len(FEATURE_NAMES) if model.config.use_indicators else 0
    block_sizes = [len(word["vocabulary"]), len(char["vocabulary"]), indicator_size]
    if sum(block_sizes) != model.classifier.coef_.shape[1]:
        raise RuntimeError(
            f"feature block mismatch: {block_sizes} vs {model.classifier.coef_.shape}"
        )

    # Reorder coefficient rows to the project's canonical label order.
    order = [model.classes_.index(label) for label in LABELS]
    coefficients = model.classifier.coef_[order]
    intercepts = model.classifier.intercept_[order]

    payload = {
        "format": "sms-linear-v1",
        "description": "Portable TF-IDF + Logistic Regression export for Kotlin parity work.",
        "labels": list(LABELS),
        "temperature": float(model.temperature),
        "feature_blocks": {
            "word": word,
            "char_wb": char,
            "indicators": {
                "feature_names": list(FEATURE_NAMES) if model.config.use_indicators else [],
            },
            "block_sizes": block_sizes,
        },
        "coefficients": coefficients.tolist(),
        "intercepts": intercepts.tolist(),
        "notes": [
            "Preprocessing and indicator feature order must match the Python implementation.",
            "URLs/emails/phones are masked by normalize_text before vectorization.",
            "Apply softmax(logits / temperature) to obtain calibrated probabilities.",
        ],
    }
    path = output_dir / "portable_model.json"
    path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    (output_dir / "README.md").write_text(_readme(payload), encoding="utf-8")
    return path


def _vectorizer_payload(vectorizer, *, analyzer: str) -> dict:
    if vectorizer is None:
        return {
            "analyzer": analyzer,
            "ngram_range": [1, 1],
            "vocabulary": {},
            "idf": [],
            "sublinear_tf": True,
            "lowercase": False,
            "token_pattern": WORD_TOKEN_RE.pattern,
        }
    return {
        "analyzer": analyzer,
        "ngram_range": list(vectorizer.ngram_range),
        "vocabulary": {str(term): int(index) for term, index in vectorizer.vocabulary_.items()},
        "idf": vectorizer.idf_.tolist(),
        "sublinear_tf": bool(vectorizer.sublinear_tf),
        "lowercase": bool(vectorizer.lowercase),
        "token_pattern": vectorizer.token_pattern,
    }


def _readme(payload: dict) -> str:
    sizes = payload["feature_blocks"]["block_sizes"]
    return f"""# Portable linear model

This directory contains `portable_model.json`, a runtime-neutral export of the
TF-IDF + Logistic Regression baseline. It is intended for the Android/Kotlin
phase, where scikit-learn is unavailable and ExecuTorch is not appropriate for a
sparse linear model.

## Contents

- Word and character n-gram vocabularies with fitted IDF values.
- Indicator feature names and block order.
- Coefficients (one row per label, in `ham`, `spam`, `smishing` order) and intercepts.
- One temperature value for calibration.

Feature block sizes: word={sizes[0]}, char_wb={sizes[1]}, indicators={sizes[2]}.

## Required on-device behaviour

1. Reimplement `normalize_text` exactly, including URL/email/phone masking and
   leetspeak handling.
2. Build word 1–2 grams and `char_wb` 3–5 grams from the normalized model text.
3. Apply sublinear term frequency, multiply by the exported IDF vector and L2
   normalize each block.
4. Append the deterministic indicator features in the exported order.
5. Compute `logits = coefficients @ features + intercepts`, then
   `softmax(logits / temperature)`.

Do not silently update these weights. Bundle them with a version and checksum,
and verify predictions against `SmsClassifier` before release.

`PortableLinearClassifier` in `src/sms_detection/models/export.py` is the Python
reference implementation used by the parity test.
"""


class PortableLinearClassifier:
    """Pure-Python reference for the exported model (no scikit-learn)."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        payload = json.loads(self.path.read_text(encoding="utf-8"))
        if payload.get("format") != "sms-linear-v1":
            raise ValueError("unsupported portable model format")
        self.payload = payload
        self.labels: tuple[str, ...] = tuple(payload["labels"])
        self.temperature = float(payload["temperature"])
        blocks = payload["feature_blocks"]
        self.word = blocks["word"]
        self.char = blocks["char_wb"]
        self.indicator_names = blocks["indicators"]["feature_names"]
        self.block_sizes = blocks["block_sizes"]
        self.coefficients = np.asarray(payload["coefficients"], dtype=float)
        self.intercepts = np.asarray(payload["intercepts"], dtype=float)
        self._word_vocab = {term: int(index) for term, index in self.word["vocabulary"].items()}
        self._char_vocab = {term: int(index) for term, index in self.char["vocabulary"].items()}
        self._word_idf = np.asarray(self.word["idf"], dtype=float)
        self._char_idf = np.asarray(self.char["idf"], dtype=float)

    def vectorize(self, text: str, sender: str | None = None) -> np.ndarray:
        normalized = normalize_text(text)
        indicator = analyze_text(text, normalized=normalized, sender=sender)
        word_vector = _tfidf_vector(
            _word_ngrams(normalized.model_text, tuple(self.word["ngram_range"])),
            self._word_vocab,
            self._word_idf,
            sublinear_tf=bool(self.word["sublinear_tf"]),
        )
        char_vector = _tfidf_vector(
            _char_wb_ngrams(normalized.model_text, tuple(self.char["ngram_range"])),
            self._char_vocab,
            self._char_idf,
            sublinear_tf=bool(self.char["sublinear_tf"]),
        )
        indicator_vector = (
            np.asarray(feature_vector(indicator), dtype=float)
            if self.indicator_names
            else np.zeros(0, dtype=float)
        )
        return np.concatenate([word_vector, char_vector, indicator_vector])

    def decision_function(self, text: str, sender: str | None = None) -> np.ndarray:
        return self.coefficients @ self.vectorize(text, sender=sender) + self.intercepts

    def predict_proba(self, text: str, sender: str | None = None) -> dict[str, float]:
        logits = self.decision_function(text, sender=sender)
        probabilities = softmax(logits / self.temperature)
        return {label: float(probabilities[i]) for i, label in enumerate(self.labels)}

    def predict(self, text: str, sender: str | None = None) -> str:
        probabilities = self.predict_proba(text, sender=sender)
        return max(probabilities, key=probabilities.get)


def _word_ngrams(text: str, ngram_range: tuple[int, int]) -> Iterable[str]:
    tokens = WORD_TOKEN_RE.findall(text)
    min_n, max_n = ngram_range
    for n in range(min_n, max_n + 1):
        for index in range(len(tokens) - n + 1):
            yield " ".join(tokens[index : index + n])


def _char_wb_ngrams(text: str, ngram_range: tuple[int, int]) -> Iterable[str]:
    """Match sklearn's char_wb analyzer for normalized single-space text."""

    text = WHITESPACE_RE.sub(" ", text)
    min_n, max_n = ngram_range
    for word in text.split():
        padded = " " + word + " "
        length = len(padded)
        for n in range(min_n, max_n + 1):
            offset = 0
            yield padded[offset : offset + n]
            while offset + n < length:
                offset += 1
                yield padded[offset : offset + n]
            if offset == 0:
                break


def _tfidf_vector(
    ngrams: Iterable[str],
    vocabulary: dict[str, int],
    idf: np.ndarray,
    *,
    sublinear_tf: bool,
) -> np.ndarray:
    counts: Counter[int] = Counter()
    for ngram in ngrams:
        index = vocabulary.get(ngram)
        if index is not None:
            counts[index] += 1
    vector = np.zeros(len(vocabulary), dtype=float)
    for index, count in counts.items():
        value = float(count)
        if sublinear_tf and value > 0:
            value = 1.0 + math.log(value)
        vector[index] = value * float(idf[index])
    norm = float(np.linalg.norm(vector))
    if norm > 0:
        vector /= norm
    return vector


def parity_check(
    model: SmsClassifier,
    portable: PortableLinearClassifier,
    texts: Sequence[str],
    *,
    tolerance: float = 1e-6,
) -> dict:
    """Compare sklearn and portable probabilities; raise on mismatch."""

    matrix = np.asarray([portable.vectorize(text) for text in texts])
    logits = matrix @ model.classifier.coef_.T + model.classifier.intercept_
    order = [model.classes_.index(label) for label in LABELS]
    sklearn_logits = logits[:, order]
    portable_logits = np.asarray([portable.decision_function(text) for text in texts])
    max_logit_diff = float(np.max(np.abs(sklearn_logits - portable_logits))) if len(texts) else 0.0
    if max_logit_diff > tolerance:
        raise AssertionError(f"portable logit mismatch: {max_logit_diff} > {tolerance}")
    return {"texts": len(texts), "max_logit_difference": max_logit_diff}
