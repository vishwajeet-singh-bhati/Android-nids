import json
from pathlib import Path

import numpy as np
import pytest

from sms_detection.config import MODEL_DIR
from sms_detection.predictor import SmsDetector, load_detector
from sms_detection.policy.risk_fusion import RiskPolicy


class DummyClassifier:
    def __init__(self, probabilities: tuple[float, float, float]) -> None:
        self.probabilities = np.asarray([probabilities], dtype=float)
        self.last_kwargs = None

    def predict_proba(self, raw_texts, **kwargs):
        self.last_kwargs = kwargs
        return self.probabilities

    def summary(self):
        return {"dummy": True}


def test_predictor_returns_text_free_contract():
    classifier = DummyClassifier((0.05, 0.05, 0.90))
    detector = SmsDetector(
        classifier,
        policy=RiskPolicy(
            high_threshold=0.385,
            suspicious_threshold=0.10,
            evidence_free_high_threshold=0.80,
        ),
    )
    raw_message = (
        "Your account has been reset. Login with your username and password at "
        "https://evil.example/account"
    )
    result = detector.predict_sms(raw_message)
    payload = json.loads(result.to_json())

    assert result.label == "smishing"
    assert result.risk_level == "high"
    assert "URL_PRESENT" in [item.code for item in result.evidence]
    assert "evil.example" not in result.to_json()
    assert raw_message not in result.to_json()
    assert "message" not in payload
    assert payload["schema_version"] == "1.0"
    assert classifier.last_kwargs is not None


def test_predict_batch_length_mismatch_raises():
    detector = SmsDetector(DummyClassifier((0.5, 0.3, 0.2)))

    with pytest.raises(ValueError):
        detector.predict_batch(["a", "b"], senders=["sender"])


@pytest.mark.skipif(
    not (Path(MODEL_DIR) / "model.joblib").exists(),
    reason="trained artifact is not present",
)
def test_trained_artifact_handles_benign_and_phishing_examples():
    detector = load_detector(MODEL_DIR)

    benign = detector.predict_sms(
        "Bank notification: Salary ₹45,000 credited to your account on 01 Aug. "
        "Balance: ₹52,300."
    )
    phishing = detector.predict_sms(
        "Your KYC is pending. Update now at https://sbi-kyc-verify.in or your "
        "account will be blocked."
    )

    assert benign.label == "ham"
    assert benign.risk_level == "low"
    assert phishing.label == "smishing"
    assert phishing.risk_level == "high"
