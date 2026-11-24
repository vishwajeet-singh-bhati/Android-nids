import json

import numpy as np

from sms_detection.models.classifier import ClassifierConfig, SmsClassifier
from sms_detection.models.export import (
    PortableLinearClassifier,
    export_portable_model,
    parity_check,
)


def fitted_model() -> SmsClassifier:
    texts = [
        "Your OTP is 482913. Do not share it with anyone.",
        "Your OTP is 771234. Do not share it with anyone.",
        "Your salary has been credited to your account today.",
        "Your salary has been credited to your account today.",
        "Congratulations, you won a free gift voucher. Claim it now.",
        "Congratulations, you won a free gift voucher. Claim it now.",
        "Your account has been blocked. Verify at https://evil.example/login.",
        "Your account has been blocked. Verify at https://evil.example/login.",
        "Your KYC is pending. Update at https://evil.example/kyc.",
        "Your KYC is pending. Update at https://evil.example/kyc.",
    ]
    labels = [
        "ham",
        "ham",
        "ham",
        "ham",
        "spam",
        "spam",
        "smishing",
        "smishing",
        "smishing",
        "smishing",
    ]
    config = ClassifierConfig(
        use_word=True,
        use_char=True,
        use_indicators=True,
        word_ngram=(1, 2),
        char_ngram=(2, 4),
        max_features_word=1000,
        max_features_char=5000,
        min_df=1,
        max_df=1.0,
        max_iter=500,
    )
    return SmsClassifier(config).fit(texts, labels)


def test_portable_export_matches_sklearn(tmp_path):
    model = fitted_model()
    path = export_portable_model(model, tmp_path)
    portable = PortableLinearClassifier(path)

    assert path.name == "portable_model.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["labels"] == ["ham", "spam", "smishing"]
    assert payload["feature_blocks"]["block_sizes"][2] > 0

    texts = [
        "Your OTP is 999999. Do not share it.",
        "You won a free voucher. Click now.",
        "Your KYC is pending. Update at https://evil.example/kyc.",
    ]
    result = parity_check(model, portable, texts)
    assert result["texts"] == len(texts)
    assert result["max_logit_difference"] <= 1e-6

    probabilities = portable.predict_proba(texts[0])
    assert set(probabilities) == {"ham", "spam", "smishing"}
    assert abs(sum(probabilities.values()) - 1.0) <= 1e-9
    assert portable.predict(texts[0]) in probabilities


def test_portable_export_uses_canonical_label_order(tmp_path):
    model = fitted_model()
    path = export_portable_model(model, tmp_path)
    portable = PortableLinearClassifier(path)

    assert portable.labels == ("ham", "spam", "smishing")
    assert np.asarray(portable.coefficients).shape[0] == 3
    assert np.asarray(portable.intercepts).shape[0] == 3
