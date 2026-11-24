from sms_detection.preprocessing import indicators as ind
from sms_detection.preprocessing.indicators import (
    FEATURE_NAMES,
    analyze_text,
    feature_vector,
)


def codes(text: str) -> set[str]:
    return analyze_text(text).codes


def test_otp_request_positive_and_negated():
    positive = analyze_text("Your OTP is 482913. Share it with our agent immediately.")
    negative = analyze_text("Your OTP is 482913. Do not share it with anyone.")

    assert ind.OTP_REQUEST in positive.codes
    assert ind.OTP_REQUEST not in negative.codes


def test_credential_request_requires_request_context():
    positive = analyze_text("Please share your password and PIN to verify your account.")
    negative = analyze_text("Your password is stored securely. We never ask you to share it.")

    assert ind.CREDENTIAL_REQUEST in positive.codes
    assert ind.CREDENTIAL_REQUEST not in negative.codes


def test_account_access_lure_requires_link_and_supports_obfuscation():
    lure = analyze_text(
        "Your account has been reset. Login with your username and password at "
        "https://evil.example/account"
    )
    obfuscated = analyze_text(
        "New KTRC L0gin [ https://campaign.invalid/path ] Username:Rom88 P***word:R66888"
    )

    assert ind.ACCOUNT_ACCESS_LURE in lure.codes
    assert ind.ACCOUNT_ACCESS_LURE in obfuscated.codes


def test_account_alert_phrasing_is_suppressed():
    result = analyze_text(
        "Your account has been reset. If this was not you, visit "
        "https://bank.example/security"
    )

    assert ind.ACCOUNT_ACCESS_LURE not in result.codes


def test_routine_transaction_guard_and_link_override():
    benign = analyze_text(
        "Your EMI of ₹8,400 for car loan has been auto-debited successfully."
    )
    linked = analyze_text(
        "Your EMI of ₹8,400 has been auto-debited. Click https://evil.example to dispute."
    )

    assert benign.flags[ind.BENIGN_TRANSACTIONAL] is True
    assert ind.URL_PRESENT not in benign.codes
    assert linked.flags[ind.BENIGN_TRANSACTIONAL] is False
    assert ind.URL_PRESENT in linked.codes


def test_delivery_guard_and_delivery_fee_scam():
    benign = analyze_text(
        "Your order from Flipkart has been delivered today. Track ID: FD31289045."
    )
    scam = analyze_text(
        "Your parcel is held at customs. Pay the delivery fee at "
        "https://evil.example/parcel"
    )

    assert benign.flags[ind.BENIGN_DELIVERY] is True
    assert ind.BENIGN_DELIVERY not in benign.codes
    assert benign.flags[ind.OBFUSCATED_TEXT] is False
    assert scam.flags[ind.BENIGN_DELIVERY] is False
    assert ind.DELIVERY_BAIT in scam.codes
    assert ind.PAYMENT_REQUEST in scam.codes


def test_payment_request_negation_and_success_are_not_demands():
    negated = analyze_text("There is no processing fee. Your parcel is ready.")
    success = analyze_text("Payment successful. Thank you for paying your electricity bill.")

    assert negated.flags[ind.PAYMENT_REQUEST] is False
    assert success.flags[ind.PAYMENT_REQUEST] is False


def test_evidence_and_feature_vector_are_well_formed():
    result = analyze_text(
        "Urgent! Your KYC is pending. Update at https://evil.example or your account "
        "will be blocked."
    )

    assert len(feature_vector(result)) == len(FEATURE_NAMES)
    assert result.has(ind.URL_PRESENT)
    assert result.has(ind.KYC_LANGUAGE)
    assert result.has(ind.ACCOUNT_THREAT)
    assert ind.ACCOUNT_ACCESS_LURE in result.codes
    assert all(item.present for item in result.items)
    assert len({item.code for item in result.items}) == len(result.items)


def test_guard_flags_are_internal_not_public_evidence():
    result = analyze_text("Your salary has been credited to your account today.")

    assert result.flags[ind.BENIGN_TRANSACTIONAL] is True
    assert ind.BENIGN_TRANSACTIONAL not in ind.EVIDENCE_CODES
    assert ind.BENIGN_TRANSACTIONAL not in result.codes


def test_sender_mismatch_is_detected_when_brand_claim_uses_phone_sender():
    result = analyze_text(
        "SBI: Your account is blocked. Verify at https://evil.example",
        sender="+919876543210",
    )

    assert ind.IMPERSONATION in result.codes
    assert ind.SENDER_CLAIM_MISMATCH in result.codes


def test_dlt_sender_mismatch_covers_kyc_and_account_threats():
    kyc = analyze_text(
        "Your KYC is pending. Update at https://evil.example",
        sender="+919876543210",
    )
    bare_mobile = analyze_text(
        "SBI: Your account is blocked. Verify at https://evil.example",
        sender="9876543210",
    )
    threat = analyze_text(
        "Your electricity connection will be disconnected. Pay at "
        "https://evil.example",
        sender="+919876543210",
    )
    benign = analyze_text(
        "Your KYC is pending. Visit your bank branch to update it."
    )

    assert ind.SENDER_CLAIM_MISMATCH in kyc.codes
    assert ind.SENDER_CLAIM_MISMATCH in bare_mobile.codes
    assert ind.SENDER_CLAIM_MISMATCH in threat.codes
    assert ind.SENDER_CLAIM_MISMATCH not in benign.codes


def test_dth_utility_threat_requires_provider_and_disruption():
    positive = analyze_text(
        "Tata Sky/Play: Your DTH connection will be deactivated at midnight. "
        "Recharge at https://evil.example/dth"
    )
    benign = analyze_text("Your DTH recharge was successful. Thank you.")
    outage = analyze_text("The electricity just went out here.")

    assert ind.DTH_UTILITY_THREAT in positive.codes
    assert ind.DTH_UTILITY_THREAT not in benign.codes
    assert ind.DTH_UTILITY_THREAT not in outage.codes


def test_task_scam_requires_task_earning_and_channel():
    positive = analyze_text(
        "Google Maps Reviewer needed! Get paid Rs. 150 per review you write. "
        "Add us on WhatsApp: https://wa.me/919000000001"
    )
    benign = analyze_text("We received your survey response. Thank you for your feedback.")

    assert ind.TASK_SCAM in positive.codes
    assert ind.TASK_SCAM not in benign.codes


def test_telecom_lure_requires_telecom_context_and_unrealistic_offer():
    positive = analyze_text(
        "Jio/Vi user! Special offer: Get 100GB data + unlimited calls at just "
        "INR 494/month. Activate now: https://vi-offer.example"
    )
    benign = analyze_text("Your Jio recharge of Rs. 299 was successful.")
    generic_offer = analyze_text(
        "Jio Welcome Offer: recharge today at https://jio.example/offer"
    )

    assert ind.TELECOM_LURE in positive.codes
    assert ind.TELECOM_LURE not in benign.codes
    assert ind.TELECOM_LURE not in generic_offer.codes


def test_document_harvesting_requires_url_document_request_and_risk():
    positive = analyze_text(
        "DigiLocker: Your uploaded documents are corrupted. Re-upload your "
        "Class 10/12 marksheets and Aadhaar: https://evil.example/reupload"
    )
    benign = analyze_text("Please upload your KYC documents at the bank branch.")

    assert ind.DATA_HARVESTING in positive.codes
    assert ind.DATA_HARVESTING not in benign.codes


def test_high_demand_gadget_scam_requires_scarcity_and_payment():
    positive = analyze_text(
        "Reliance Digital: Pre-book Sony PlayStation 5 at 50% discount. Only 5 "
        "units left! Book for Rs. 5000: https://evil.example/ps5"
    )
    benign = analyze_text("The new iPhone 15 is available on Flipkart.")
    normal_sale = analyze_text(
        "iPhone 15 at 10% discount. Pay Rs. 79,900 at "
        "https://shop.example/iphone"
    )

    assert ind.HIGH_DEMAND_GADGET_SCAM in positive.codes
    assert ind.HIGH_DEMAND_GADGET_SCAM not in benign.codes
    assert ind.HIGH_DEMAND_GADGET_SCAM not in normal_sale.codes


def test_apk_download_lure_requires_apk_or_patch_context():
    positive = analyze_text(
        "Apollo Hospitals: Download the detailed report here: "
        "https://evil.example/report.apk"
    )
    benign = analyze_text(
        "Download our app from https://play.google.com/store/apps/details?id=example"
    )

    assert ind.APK_DOWNLOAD_LURE in positive.codes
    assert ind.APK_DOWNLOAD_LURE not in benign.codes


def test_delivery_update_lure_requires_a_delivery_problem_and_link():
    positive = analyze_text(
        "Amazon: We could not deliver your package today. Reschedule delivery "
        "here: https://evil.example/reschedule"
    )
    benign = analyze_text(
        "Your parcel from Amazon has been delivered. Thank you for shopping."
    )

    assert ind.DELIVERY_UPDATE_LURE in positive.codes
    assert ind.DELIVERY_UPDATE_LURE not in benign.codes


def test_service_interruption_lure_requires_interruption_and_recovery_action():
    positive = analyze_text(
        "Google: Your storage is full! Your Gmail account will stop receiving "
        "emails tomorrow. Upgrade storage for free: https://evil.example/storage"
    )
    benign = analyze_text("Your electricity bill is due tomorrow.")

    assert ind.SERVICE_INTERRUPTION_LURE in positive.codes
    assert ind.SERVICE_INTERRUPTION_LURE not in benign.codes
