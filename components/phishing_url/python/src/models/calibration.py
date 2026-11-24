"""Probability calibration + the three-outcome decision for the CNN's logit.

    p = sigmoid(a * logit + b)              Platt scaling, a > 0 (keeps the ranking)
    PHISHING     if p >  t_phishing
    LIKELY_SAFE  if p <  t_safe
    UNCERTAIN    otherwise (t_safe <= p <= t_phishing)

Plain NumPy, so the edge runtime can use it without PyTorch. The decision
engine adds further rules later (redirectors -> UNCERTAIN, threat intel); the
absence of a threat-intel match never turns UNCERTAIN into LIKELY_SAFE.
"""
from __future__ import annotations

import json
import math
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np

FORMAT_VERSION = 1
CALIBRATOR_TYPE = "platt_three_outcome"
PHISHING, UNCERTAIN, LIKELY_SAFE = "PHISHING", "UNCERTAIN", "LIKELY_SAFE"
OUTCOMES = (PHISHING, UNCERTAIN, LIKELY_SAFE)


def sigmoid(z) -> np.ndarray:
    """Numerically stable logistic function (no overflow warnings)."""
    z = np.asarray(z, dtype=np.float64)
    out = np.empty_like(z)
    pos = z >= 0
    out[pos] = 1.0 / (1.0 + np.exp(-z[pos]))
    ez = np.exp(z[~pos])
    out[~pos] = ez / (1.0 + ez)
    return out


def classify(probability, t_phishing: float, t_safe: float) -> np.ndarray:
    p = np.asarray(probability, dtype=np.float64)
    return np.where(p > t_phishing, PHISHING, np.where(p < t_safe, LIKELY_SAFE, UNCERTAIN))


@dataclass(frozen=True)
class Calibrator:
    a: float
    b: float
    t_phishing: float
    t_safe: float

    def __post_init__(self) -> None:
        values = (self.a, self.b, self.t_phishing, self.t_safe)
        if not all(isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v)
                   for v in values):
            raise ValueError("calibrator values must be finite numbers")
        if self.a <= 0:
            raise ValueError("slope a must be > 0 (calibration must keep the ranking)")
        if not 0.0 <= self.t_safe <= self.t_phishing <= 1.0:
            raise ValueError("thresholds must satisfy 0 <= t_safe <= t_phishing <= 1")

    def probability(self, logits) -> np.ndarray:
        return sigmoid(self.a * np.asarray(logits, dtype=np.float64) + self.b)

    def outcome(self, probability) -> np.ndarray:
        return classify(probability, self.t_phishing, self.t_safe)

    # ------------------------------------------------------- serialization
    def to_config(self) -> dict[str, Any]:
        return {"format_version": FORMAT_VERSION, "type": CALIBRATOR_TYPE,
                "a": float(self.a), "b": float(self.b),
                "t_phishing": float(self.t_phishing), "t_safe": float(self.t_safe)}

    @classmethod
    def from_config(cls, config: dict[str, Any]) -> "Calibrator":
        if not isinstance(config, dict):
            raise ValueError("calibrator config must be a JSON object")
        missing = {"format_version", "type", "a", "b", "t_phishing", "t_safe"} - config.keys()
        if missing:
            raise ValueError(f"calibrator config missing keys: {sorted(missing)}")
        if config["format_version"] != FORMAT_VERSION or config["type"] != CALIBRATOR_TYPE:
            raise ValueError("unsupported calibrator format/type")
        return cls(config["a"], config["b"], config["t_phishing"], config["t_safe"])

    def save(self, path: str | Path) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.to_config(), indent=2) + "\n", encoding="utf-8")

    @classmethod
    def load(cls, path: str | Path) -> "Calibrator":
        try:
            config = json.loads(Path(path).read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ValueError("calibrator file is not valid JSON") from exc
        return cls.from_config(config)


STACK_TYPE = "stacked_three_outcome"


@dataclass(frozen=True)
class StackCalibrator:
    """p = sigmoid(w1*logit_1 + ... + wk*logit_k + bias) over named member models.

    With one member this is Platt scaling; with several it combines models.
    Every weight must be > 0, so each member can only push in its own direction.
    """
    members: tuple[str, ...]
    weights: tuple[float, ...]
    bias: float
    t_phishing: float
    t_safe: float

    def __post_init__(self) -> None:
        object.__setattr__(self, "members", tuple(self.members))
        object.__setattr__(self, "weights", tuple(self.weights))
        if not self.members or len(self.members) != len(self.weights):
            raise ValueError("need one weight per member and at least one member")
        if len(set(self.members)) != len(self.members) or not all(
                isinstance(m, str) and m for m in self.members):
            raise ValueError("member names must be unique, non-empty strings")
        values = (*self.weights, self.bias, self.t_phishing, self.t_safe)
        if not all(isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v)
                   for v in values):
            raise ValueError("calibrator values must be finite numbers")
        if min(self.weights) <= 0:
            raise ValueError("every member weight must be > 0")
        if not 0.0 <= self.t_safe <= self.t_phishing <= 1.0:
            raise ValueError("thresholds must satisfy 0 <= t_safe <= t_phishing <= 1")

    def probability(self, logits) -> np.ndarray:
        """logits: shape (n, k) in member order, or (n,) when there is one member."""
        x = np.asarray(logits, dtype=np.float64)
        if x.ndim == 1:
            x = x[:, None]
        if x.ndim != 2 or x.shape[1] != len(self.weights):
            raise ValueError(f"expected logits of shape (n, {len(self.weights)})")
        return sigmoid(x @ np.asarray(self.weights) + self.bias)

    def outcome(self, probability) -> np.ndarray:
        return classify(probability, self.t_phishing, self.t_safe)

    def to_config(self) -> dict[str, Any]:
        return {"format_version": FORMAT_VERSION, "type": STACK_TYPE,
                "members": list(self.members), "weights": [float(w) for w in self.weights],
                "bias": float(self.bias), "t_phishing": float(self.t_phishing),
                "t_safe": float(self.t_safe)}

    @classmethod
    def from_config(cls, config: dict[str, Any]) -> "StackCalibrator":
        if not isinstance(config, dict):
            raise ValueError("calibrator config must be a JSON object")
        missing = {"format_version", "type", "members", "weights", "bias", "t_phishing",
                   "t_safe"} - config.keys()
        if missing:
            raise ValueError(f"calibrator config missing keys: {sorted(missing)}")
        if config["format_version"] != FORMAT_VERSION or config["type"] != STACK_TYPE:
            raise ValueError("unsupported calibrator format/type")
        if not isinstance(config["members"], list) or not isinstance(config["weights"], list):
            raise ValueError("members and weights must be lists")
        return cls(tuple(config["members"]), tuple(config["weights"]), config["bias"],
                   config["t_phishing"], config["t_safe"])
