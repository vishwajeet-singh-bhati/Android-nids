"""Sparse TF-IDF + Logistic Regression baseline.

This is intentionally a compact, auditable model rather than a transformer. It
combines word n-grams, character n-grams (for obfuscation/spelling variation)
and optional deterministic SMS indicators. The wrapper keeps preprocessing and
model together so inference cannot silently drift from training.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterable, Sequence

import joblib
import numpy as np
from scipy import sparse
from scipy.special import softmax
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression

from ..config import LABELS, RANDOM_STATE
from ..preprocessing.indicators import (
    FEATURE_NAMES,
    IndicatorResult,
    analyze_text,
    feature_vector,
)
from ..preprocessing.normalize import NormalizedText, normalize_text


@dataclass
class ClassifierConfig:
    use_word: bool = True
    use_char: bool = True
    use_indicators: bool = True
    word_ngram: tuple[int, int] = (1, 2)
    char_ngram: tuple[int, int] = (3, 5)
    max_features_word: int = 30_000
    max_features_char: int = 50_000
    min_df: int = 2
    max_df: float = 0.95
    C: float = 1.0
    class_weight: str | None = "balanced"
    max_iter: int = 2_000
    random_state: int = RANDOM_STATE

    def to_dict(self) -> dict:
        return asdict(self)


class SmsClassifier:
    """Self-contained sparse classifier with deterministic inference."""

    def __init__(self, config: ClassifierConfig | None = None) -> None:
        self.config = config or ClassifierConfig()
        self.word_vectorizer: TfidfVectorizer | None = None
        self.char_vectorizer: TfidfVectorizer | None = None
        self.classifier: LogisticRegression | None = None
        self.classes_: tuple[str, ...] = LABELS
        self.temperature: float = 1.0
        self.metadata: dict = {}

    # ------------------------------------------------------------------
    # Training
    # ------------------------------------------------------------------
    def fit(
        self,
        raw_texts: Sequence[str],
        y: Sequence[str],
        *,
        normalized: Sequence[NormalizedText] | None = None,
        indicators: Sequence[IndicatorResult] | None = None,
        senders: Sequence[str | None] | None = None,
    ) -> "SmsClassifier":
        if len(raw_texts) != len(y):
            raise ValueError("raw_texts and y must have the same length")
        if not raw_texts:
            raise ValueError("cannot train on an empty dataset")

        norms, inds = self._prepare(raw_texts, normalized, indicators, senders)
        model_texts = [item.model_text for item in norms]

        blocks: list[sparse.csr_matrix] = []
        if self.config.use_word:
            self.word_vectorizer = TfidfVectorizer(
                analyzer="word",
                ngram_range=self.config.word_ngram,
                min_df=self.config.min_df,
                max_df=self.config.max_df,
                max_features=self.config.max_features_word,
                sublinear_tf=True,
                lowercase=False,
                token_pattern=r"(?u)\b\w+\b",
            )
            blocks.append(self.word_vectorizer.fit_transform(model_texts).tocsr())
        if self.config.use_char:
            self.char_vectorizer = TfidfVectorizer(
                analyzer="char_wb",
                ngram_range=self.config.char_ngram,
                min_df=self.config.min_df,
                max_df=self.config.max_df,
                max_features=self.config.max_features_char,
                sublinear_tf=True,
                lowercase=False,
            )
            blocks.append(self.char_vectorizer.fit_transform(model_texts).tocsr())
        if self.config.use_indicators:
            blocks.append(_indicator_matrix(inds))

        if not blocks:
            raise ValueError("at least one feature block must be enabled")
        X = sparse.hstack(blocks, format="csr") if len(blocks) > 1 else blocks[0]

        self.classifier = LogisticRegression(
            C=self.config.C,
            class_weight=self.config.class_weight,
            max_iter=self.config.max_iter,
            solver="lbfgs",
            random_state=self.config.random_state,
        )
        self.classifier.fit(X, list(y))
        self.classes_ = tuple(self.classifier.classes_)
        return self

    # ------------------------------------------------------------------
    # Inference
    # ------------------------------------------------------------------
    def predict_proba(
        self,
        raw_texts: Sequence[str],
        *,
        normalized: Sequence[NormalizedText] | None = None,
        indicators: Sequence[IndicatorResult] | None = None,
        senders: Sequence[str | None] | None = None,
    ) -> np.ndarray:
        X = self.transform(
            raw_texts, normalized=normalized, indicators=indicators, senders=senders
        )
        if self.classifier is None:
            raise RuntimeError("classifier is not fitted")
        if self.temperature != 1.0:
            logits = self._decision_function(X)
            return softmax(logits / self.temperature, axis=1)
        raw = self.classifier.predict_proba(X)
        return self._reorder(raw)

    def predict(
        self,
        raw_texts: Sequence[str],
        *,
        normalized: Sequence[NormalizedText] | None = None,
        indicators: Sequence[IndicatorResult] | None = None,
        senders: Sequence[str | None] | None = None,
    ) -> list[str]:
        probabilities = self.predict_proba(
            raw_texts, normalized=normalized, indicators=indicators, senders=senders
        )
        return [LABELS[index] for index in probabilities.argmax(axis=1)]

    def decision_function(
        self,
        raw_texts: Sequence[str],
        *,
        normalized: Sequence[NormalizedText] | None = None,
        indicators: Sequence[IndicatorResult] | None = None,
        senders: Sequence[str | None] | None = None,
    ) -> np.ndarray:
        X = self.transform(
            raw_texts, normalized=normalized, indicators=indicators, senders=senders
        )
        return self._decision_function(X)

    def transform(
        self,
        raw_texts: Sequence[str],
        *,
        normalized: Sequence[NormalizedText] | None = None,
        indicators: Sequence[IndicatorResult] | None = None,
        senders: Sequence[str | None] | None = None,
    ) -> sparse.csr_matrix:
        if self.classifier is None:
            raise RuntimeError("classifier is not fitted")
        norms, inds = self._prepare(raw_texts, normalized, indicators, senders)
        model_texts = [item.model_text for item in norms]
        blocks: list[sparse.csr_matrix] = []
        if self.word_vectorizer is not None:
            blocks.append(self.word_vectorizer.transform(model_texts).tocsr())
        if self.char_vectorizer is not None:
            blocks.append(self.char_vectorizer.transform(model_texts).tocsr())
        if self.config.use_indicators:
            blocks.append(_indicator_matrix(inds))
        if not blocks:
            raise RuntimeError("no feature block is available")
        return sparse.hstack(blocks, format="csr") if len(blocks) > 1 else blocks[0]

    def _decision_function(self, X: sparse.csr_matrix) -> np.ndarray:
        if self.classifier is None:
            raise RuntimeError("classifier is not fitted")
        logits = self.classifier.decision_function(X)
        if logits.ndim == 1:
            logits = np.column_stack([-logits, logits])
        return logits[:, [self.classes_.index(label) for label in LABELS]]

    def _reorder(self, probabilities: np.ndarray) -> np.ndarray:
        return probabilities[:, [self.classes_.index(label) for label in LABELS]]

    # ------------------------------------------------------------------
    # Persistence and introspection
    # ------------------------------------------------------------------
    def set_temperature(self, temperature: float) -> None:
        if temperature <= 0:
            raise ValueError("temperature must be positive")
        self.temperature = float(temperature)

    def save(self, path: str | Path) -> Path:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self, path)
        return path

    @classmethod
    def load(cls, path: str | Path) -> "SmsClassifier":
        model = joblib.load(path)
        if not isinstance(model, cls):
            raise TypeError(f"artifact is not a {cls.__name__}")
        return model

    @property
    def feature_count(self) -> int:
        total = 0
        if self.word_vectorizer is not None:
            total += len(self.word_vectorizer.vocabulary_)
        if self.char_vectorizer is not None:
            total += len(self.char_vectorizer.vocabulary_)
        if self.config.use_indicators:
            total += len(FEATURE_NAMES)
        return total

    def summary(self) -> dict:
        return {
            "config": self.config.to_dict(),
            "classes": list(self.classes_),
            "temperature": self.temperature,
            "feature_count": self.feature_count,
            "word_features": len(self.word_vectorizer.vocabulary_)
            if self.word_vectorizer is not None
            else 0,
            "char_features": len(self.char_vectorizer.vocabulary_)
            if self.char_vectorizer is not None
            else 0,
            "indicator_features": len(FEATURE_NAMES)
            if self.config.use_indicators
            else 0,
            "metadata": dict(self.metadata),
        }

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _prepare(
        self,
        raw_texts: Sequence[str],
        normalized: Sequence[NormalizedText] | None,
        indicators: Sequence[IndicatorResult] | None,
        senders: Sequence[str | None] | None,
    ) -> tuple[list[NormalizedText], list[IndicatorResult]]:
        if normalized is None:
            norms = [normalize_text(text) for text in raw_texts]
        else:
            if len(normalized) != len(raw_texts):
                raise ValueError("normalized and raw_texts must have the same length")
            norms = list(normalized)
        if indicators is None:
            inds = [
                analyze_text(
                    text,
                    normalized=norm,
                    sender=(senders[i] if senders else None),
                )
                for i, (text, norm) in enumerate(zip(raw_texts, norms))
            ]
        else:
            if len(indicators) != len(raw_texts):
                raise ValueError("indicators and raw_texts must have the same length")
            inds = list(indicators)
        return norms, inds


def _indicator_matrix(results: Sequence[IndicatorResult]) -> sparse.csr_matrix:
    values = np.asarray([feature_vector(result) for result in results], dtype=np.float32)
    if values.ndim != 2:
        values = values.reshape(len(results), -1)
    return sparse.csr_matrix(values)
