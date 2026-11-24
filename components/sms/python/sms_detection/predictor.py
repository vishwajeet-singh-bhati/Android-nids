"""Local inference facade.

The host app (or the Llama explanation layer) calls this module. No network
access is used and the returned contract never contains the SMS body.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Sequence

import numpy as np

from .config import (
    DEFAULT_EVIDENCE_FREE_HIGH,
    DEFAULT_HIGH_THRESHOLD,
    DEFAULT_SUSPICIOUS_THRESHOLD,
    MODEL_DIR,
    MODEL_VERSION,
    POLICY_VERSION,
)
from .interface.schema import SmsDetectionResult
from .models.classifier import SmsClassifier
from .policy.risk_fusion import RiskPolicy
from .preprocessing.indicators import analyze_text
from .preprocessing.normalize import normalize_text


class DetectorNotReady(RuntimeError):
    """Raised when no trained artifact is available."""


class SmsDetector:
    """Loads a trained artifact and produces an auditable detection result."""

    def __init__(
        self,
        classifier: SmsClassifier,
        *,
        policy: RiskPolicy | None = None,
        model_version: str = MODEL_VERSION,
        metadata: dict | None = None,
    ) -> None:
        self.classifier = classifier
        self.policy = policy or RiskPolicy()
        self.model_version = model_version
        self.metadata = metadata or {}

    @classmethod
    def from_artifact(cls, model_dir: str | Path = MODEL_DIR) -> "SmsDetector":
        model_dir = Path(model_dir)
        model_path = model_dir / "model.joblib"
        metadata_path = model_dir / "metadata.json"
        if not model_path.exists():
            raise DetectorNotReady(
                f"No model artifact at {model_path}. Run the data pipeline and training first."
            )
        classifier = SmsClassifier.load(model_path)
        metadata: dict = {}
        if metadata_path.exists():
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        thresholds = metadata.get("thresholds", {})
        policy = RiskPolicy(
            high_threshold=float(thresholds.get("high", DEFAULT_HIGH_THRESHOLD)),
            suspicious_threshold=float(
                thresholds.get("suspicious", DEFAULT_SUSPICIOUS_THRESHOLD)
            ),
            evidence_free_high_threshold=float(
                thresholds.get(
                    "evidence_free_high", DEFAULT_EVIDENCE_FREE_HIGH
                )
            ),
            cost_fn=float(metadata.get("costs", {}).get("fn", 10.0)),
            cost_fp=float(metadata.get("costs", {}).get("fp", 1.0)),
            # Weights metadata records the historical policy; current code
            # implements the current policy independently of those weights.
            policy_version=POLICY_VERSION,
        )
        return cls(
            classifier,
            policy=policy,
            model_version=metadata.get("model_version", MODEL_VERSION),
            metadata=metadata,
        )

    def predict_sms(
        self,
        message: str,
        sender: str | None = None,
        *,
        known_sender: bool = False,
    ) -> SmsDetectionResult:
        normalized = normalize_text(message)
        indicators = analyze_text(
            message,
            normalized=normalized,
            sender=sender,
            known_sender=known_sender,
        )
        probabilities = self.classifier.predict_proba(
            [message],
            normalized=[normalized],
            indicators=[indicators],
        )[0]
        scores = {
            label: float(probabilities[index])
            for index, label in enumerate(("ham", "spam", "smishing"))
        }
        assessment = self.policy.assess(scores, indicators)
        return SmsDetectionResult(
            label=assessment.label,
            risk_level=assessment.risk_level,
            scores=assessment.scores,
            evidence=assessment.evidence,
            recommended_action_codes=assessment.recommended_action_codes,
            model_version=self.model_version,
            explanation_source="detector_evidence",
        )

    # The name used in the implementation plan.
    predict = predict_sms

    def predict_batch(
        self,
        messages: Sequence[str],
        senders: Sequence[str | None] | None = None,
    ) -> list[SmsDetectionResult]:
        if senders is not None and len(senders) != len(messages):
            raise ValueError("senders and messages must have the same length")
        return [
            self.predict_sms(message, senders[i] if senders else None)
            for i, message in enumerate(messages)
        ]

    def artifact_summary(self) -> dict:
        return {
            "model_version": self.model_version,
            "policy_version": self.policy.policy_version,
            "thresholds": {
                "high": self.policy.high_threshold,
                "suspicious": self.policy.suspicious_threshold,
                "evidence_free_high": self.policy.evidence_free_high_threshold,
            },
            "classifier": self.classifier.summary(),
            "metadata": self.metadata,
        }


def load_detector(model_dir: str | Path = MODEL_DIR) -> SmsDetector:
    return SmsDetector.from_artifact(model_dir)
