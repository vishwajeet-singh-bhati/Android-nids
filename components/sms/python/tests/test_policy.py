from sms_detection.policy.risk_fusion import (
    RiskPolicy,
    rule_based_classify,
)
from sms_detection.preprocessing import indicators as ind
from sms_detection.preprocessing.indicators import analyze_text


def policy() -> RiskPolicy:
    return RiskPolicy(
        high_threshold=0.385,
        suspicious_threshold=0.10,
        evidence_free_high_threshold=0.80,
    )


def scores(smishing: float) -> dict[str, float]:
    remaining = 1.0 - smishing
    return {"ham": remaining * 0.5, "spam": remaining * 0.5, "smishing": smishing}


def test_routine_transaction_is_hard_guarded_even_with_high_model_score():
    indicator = analyze_text(
        "Your EMI of ₹8,400 for car loan has been auto-debited successfully."
    )
    assessment = policy().assess(scores(0.95), indicator)

    assert assessment.label == "ham"
    assert assessment.risk_level == "low"
    assert assessment.recommended_action_codes == ["NO_ACTION"]


def test_account_access_lure_escalates_with_safe_action_codes():
    indicator = analyze_text(
        "Your account has been reset. Login with your username and password at "
        "https://evil.example"
    )
    assessment = policy().assess(scores(0.20), indicator)

    assert assessment.label == "smishing"
    assert assessment.risk_level == "high"
    assert "DO_NOT_CLICK" in assessment.recommended_action_codes
    assert "DO_NOT_SHARE_OTP" in assessment.recommended_action_codes
    assert "DO_NOT_SHARE_PERSONAL_INFO" in assessment.recommended_action_codes
    assert "REPORT_AS_SCAM" in assessment.recommended_action_codes


def test_weak_model_score_with_only_a_link_is_suspicious_not_high():
    indicator = analyze_text(
        "You have registered Shijo as Payee. Log in at icicibank.com and enter URN "
        "to confirm. Beware of frauds."
    )
    assessment = policy().assess(scores(0.56), indicator)

    assert assessment.label == "smishing"
    assert assessment.risk_level == "suspicious"
    assert "VERIFY_BEFORE_ACTING" in assessment.recommended_action_codes


def test_very_high_model_score_can_stand_without_evidence():
    indicator = analyze_text("Please review the attached statement.")
    assessment = policy().assess(scores(0.90), indicator)

    assert assessment.risk_level == "high"
    assert assessment.label == "smishing"


def test_rules_do_not_call_a_normal_delivery_message_smishing():
    normal = analyze_text(
        "Your parcel from Amazon has been delivered. Thank you for shopping."
    )
    scam = analyze_text(
        "Your parcel is held at customs. Pay the delivery fee at "
        "https://evil.example/parcel"
    )

    assert rule_based_classify(normal).label == "ham"
    assert rule_based_classify(scam).label == "smishing"


def test_official_security_alert_with_benign_phrasing_is_not_high():
    indicator = analyze_text(
        "Your account has been reset. If this was not you, visit "
        "https://bank.example/security"
    )
    assessment = policy().assess(scores(0.30), indicator)

    assert assessment.risk_level != "high"


def test_actions_are_bounded_to_safe_codes():
    indicator = analyze_text(
        "Urgent! Your KYC is pending. Update at https://evil.example or your account "
        "will be blocked."
    )
    assessment = policy().assess(scores(0.77), indicator)

    assert assessment.label == "smishing"
    assert assessment.risk_level == "high"
    forbidden = {"CLICK_LINK", "DELETE_MESSAGE", "AUTO_BLOCK", "SEND_REPLY"}
    assert forbidden.isdisjoint(assessment.recommended_action_codes)
    assert ind.ACCOUNT_THREAT in indicator.codes
    assert ind.KYC_LANGUAGE in indicator.codes


def test_service_pattern_requests_review_without_overriding_model():
    indicator = analyze_text(
        "Tata Sky/Play: Your DTH connection will be deactivated at midnight. "
        "Recharge at https://evil.example/dth"
    )
    assessment = policy().assess(scores(0.05), indicator)

    assert ind.DTH_UTILITY_THREAT in indicator.codes
    assert assessment.label == "ham"
    assert assessment.risk_level == "suspicious"
    assert "DO_NOT_CLICK" in assessment.recommended_action_codes
    assert "REPORT_AS_SCAM" not in assessment.recommended_action_codes


def test_ordinary_promotion_is_quiet_despite_nonzero_smishing_score():
    indicator = analyze_text("Sale ends today! Get 50% off shoes at https://shop.example")
    assessment = policy().assess({"ham": 0.2, "spam": 0.6, "smishing": 0.2}, indicator)
    assert assessment.label == "spam"
    assert assessment.risk_level == "low"
    assert assessment.recommended_action_codes == ["MARK_AS_SPAM", "DO_NOT_INTERACT"]


def test_weak_smishing_score_does_not_interrupt_ham():
    assessment = policy().assess(
        {"ham": 0.7, "spam": 0.15, "smishing": 0.15},
        analyze_text("Your statement is ready."),
    )
    assert assessment.label == "ham"
    assert assessment.risk_level == "low"


def test_bill_pressure_and_link_are_review_evidence_not_proof_of_fraud():
    assessment = policy().assess(
        {"ham": 0.6, "spam": 0.3, "smishing": 0.1},
        analyze_text("Your electricity bill is overdue. Pay now at https://utility.example/pay to avoid disconnection."),
    )
    assert assessment.label == "ham"
    assert assessment.risk_level == "suspicious"
    assert "REPORT_AS_SCAM" not in assessment.recommended_action_codes


def test_normal_telecom_recharge_is_not_escalated():
    indicator = analyze_text("Your Jio recharge of Rs. 299 was successful.")
    assessment = policy().assess(scores(0.05), indicator)

    assert ind.TELECOM_LURE not in indicator.codes
    assert assessment.label == "ham"
