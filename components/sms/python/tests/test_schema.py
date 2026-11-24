import json

import pytest

from sms_detection.interface.schema import (
    EvidenceItem,
    SchemaError,
    SmsDetectionResult,
    json_schema,
    write_json_schema,
)


def valid_result() -> SmsDetectionResult:
    return SmsDetectionResult(
        label="smishing",
        risk_level="high",
        scores={"ham": 0.05, "spam": 0.05, "smishing": 0.90},
        evidence=[
            EvidenceItem("URL_PRESENT"),
            EvidenceItem("OTP_REQUEST"),
        ],
        recommended_action_codes=["DO_NOT_CLICK", "DO_NOT_SHARE_OTP"],
    )


def test_result_round_trip_is_text_free():
    result = valid_result()
    payload = result.to_dict()
    encoded = result.to_json()

    assert payload["label"] == "smishing"
    assert payload["risk_level"] == "high"
    assert "OTP_REQUEST" in encoded  # stable evidence code, not a message body
    assert "message" not in payload
    assert "raw" not in payload
    assert "scores" in payload

    restored = SmsDetectionResult.from_dict(payload)
    assert restored.label == result.label
    assert restored.risk_level == result.risk_level
    assert [item.code for item in restored.evidence] == [
        "URL_PRESENT",
        "OTP_REQUEST",
    ]


def test_schema_has_no_message_body_field():
    schema = json_schema()

    assert schema["type"] == "object"
    assert "message" not in schema["properties"]
    assert "raw" not in schema["properties"]
    assert {"label", "risk_level", "scores", "evidence"} <= set(schema["required"])
    assert schema["properties"]["scores"]["additionalProperties"] is False


def test_invalid_label_is_rejected():
    with pytest.raises(SchemaError):
        SmsDetectionResult(
            label="phishing",
            risk_level="high",
            scores={"ham": 0.2, "spam": 0.3, "smishing": 0.5},
        )


def test_invalid_score_total_is_rejected():
    with pytest.raises(SchemaError):
        SmsDetectionResult(
            label="ham",
            risk_level="low",
            scores={"ham": 0.2, "spam": 0.2, "smishing": 0.2},
        )


def test_duplicate_evidence_is_rejected():
    with pytest.raises(SchemaError):
        SmsDetectionResult(
            label="ham",
            risk_level="low",
            scores={"ham": 1.0, "spam": 0.0, "smishing": 0.0},
            evidence=[EvidenceItem("URL_PRESENT"), EvidenceItem("URL_PRESENT")],
        )


def test_invalid_action_code_is_rejected():
    with pytest.raises(SchemaError):
        SmsDetectionResult(
            label="ham",
            risk_level="low",
            scores={"ham": 1.0, "spam": 0.0, "smishing": 0.0},
            recommended_action_codes=["click the link"],
        )


def test_write_schema(tmp_path):
    path = write_json_schema(tmp_path / "schema.json")
    payload = json.loads(path.read_text(encoding="utf-8"))

    assert payload["title"] == "SMS detection result"
    assert payload["properties"]["explanation_source"]["const"] == "detector_evidence"
