"""Character n-gram TF-IDF + logistic regression, saved without pickle.

The same model as the `char_ngram_lr` baseline. It is saved as one .npz file of
plain arrays (n-gram strings, idf, weights) plus JSON metadata and is loaded
with allow_pickle=False, so opening a model file can never run code.
"""
from __future__ import annotations

import json
import math
import os
from pathlib import Path
from typing import Any, Sequence

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score

FORMAT_VERSION = 1
MODEL_TYPE = "char_ngram_lr"
VECTORIZER = {"analyzer": "char", "ngram_range": (2, 5), "min_df": 3, "max_features": 300_000,
              "sublinear_tf": True, "lowercase": False}


def _vectorizer(**extra) -> TfidfVectorizer:
    return TfidfVectorizer(**VECTORIZER, dtype=np.float32, **extra)


def _lr(c: float) -> LogisticRegression:
    return LogisticRegression(C=c, solver="liblinear", max_iter=1000)


class NgramLR:
    def __init__(self, vectorizer: TfidfVectorizer, coef, intercept: float, meta: dict | None = None):
        self.vectorizer = vectorizer
        self.coef = np.asarray(coef, dtype=np.float64).ravel()
        self.intercept = float(intercept)
        self.meta: dict[str, Any] = dict(meta or {})
        if len(self.coef) != len(vectorizer.vocabulary_) or not np.isfinite(self.coef).all() \
                or not math.isfinite(self.intercept):
            raise ValueError("weights do not match the vocabulary or are not finite")

    @property
    def vocabulary_size(self) -> int:
        return len(self.coef)

    @classmethod
    def from_sklearn(cls, vectorizer: TfidfVectorizer, model: LogisticRegression,
                     meta: dict | None = None) -> "NgramLR":
        return cls(vectorizer, model.coef_, model.intercept_[0], {"C": float(model.C), **(meta or {})})

    def logits(self, texts: Sequence[str]) -> np.ndarray:
        """Log-odds of phishing (the same as LogisticRegression.decision_function)."""
        return np.asarray(self.vectorizer.transform(texts) @ self.coef, dtype=np.float64) + self.intercept

    # ------------------------------------------------------- serialization
    def save(self, path: str | Path) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        vocab = self.vectorizer.vocabulary_
        terms = np.array(sorted(vocab, key=vocab.get))
        meta = {"format_version": FORMAT_VERSION, "model_type": MODEL_TYPE,
                "vectorizer": {**VECTORIZER, "ngram_range": list(VECTORIZER["ngram_range"])},
                **self.meta}
        tmp = path.with_name(path.name + ".part")
        with tmp.open("wb") as fh:
            np.savez(fh, terms=terms, idf=np.asarray(self.vectorizer.idf_, dtype=np.float64),
                     coef=self.coef, intercept=np.array([self.intercept]),
                     meta=np.array(json.dumps(meta)))
        os.replace(tmp, path)

    @classmethod
    def load(cls, path: str | Path) -> "NgramLR":
        with np.load(Path(path), allow_pickle=False) as z:
            meta = json.loads(str(z["meta"]))
            if meta.get("format_version") != FORMAT_VERSION or meta.get("model_type") != MODEL_TYPE:
                raise ValueError("unsupported n-gram model format/type")
            saved = dict(meta["vectorizer"], ngram_range=tuple(meta["vectorizer"]["ngram_range"]))
            if saved != VECTORIZER:
                raise ValueError("n-gram model was saved with different vectorizer settings")
            terms, idf = z["terms"].tolist(), z["idf"]
            if len(set(terms)) != len(terms) or len(idf) != len(terms):
                raise ValueError("corrupt n-gram vocabulary")
            vec = _vectorizer(vocabulary={t: i for i, t in enumerate(terms)})
            vec.idf_ = idf
            meta = {k: v for k, v in meta.items()
                    if k not in ("format_version", "model_type", "vectorizer")}
            return cls(vec, z["coef"], float(z["intercept"][0]), meta)


def fit_with_c_search(train_texts, train_y, val_texts, val_y, c_grid) -> tuple[NgramLR, dict]:
    """Fit the vectorizer on train, pick C by validation PR-AUC, refit with the best C."""
    vec = _vectorizer()
    x_train = vec.fit_transform(train_texts)
    x_val = vec.transform(val_texts)
    search = {}
    for c in c_grid:
        m = _lr(c).fit(x_train, train_y)
        search[str(c)] = float(average_precision_score(val_y, m.predict_proba(x_val)[:, 1]))
    best_c = float(max(search, key=search.get))
    model = _lr(best_c).fit(x_train, train_y)
    return NgramLR.from_sklearn(vec, model, {"val_pr_auc_by_C": search}), search
