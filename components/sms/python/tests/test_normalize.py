from sms_detection.preprocessing.normalize import model_text_for, normalize_text


def test_raw_text_is_preserved_and_entities_are_masked():
    raw = (
        "Pay ₹500 at https://evil.example/path or call 9876543210 "
        "or email help@evil.example"
    )
    normalized = normalize_text(raw)

    assert normalized.raw == raw
    assert normalized.normalized != raw
    assert "https://evil.example/path" not in normalized.normalized
    assert "9876543210" not in normalized.normalized
    assert "help@evil.example" not in normalized.normalized
    assert "url_present" in normalized.normalized
    assert "phone_present" in normalized.normalized
    assert "email_present" in normalized.normalized
    assert normalized.urls == ("https://evil.example/path",)
    assert normalized.phones == ("9876543210",)
    assert normalized.emails == ("help@evil.example",)


def test_leetspeak_security_words_are_normalized():
    normalized = normalize_text("New KTRC L0gin Username:Rom88 P***word:R66888")

    assert "login" in normalized.model_text
    assert normalized.flags["leetspeak"] is True
    assert normalized.flags["obfuscated"] is True


def test_tracking_ids_are_not_treated_as_obfuscation():
    normalized = normalize_text("Your order from Flipkart has been delivered. Track ID: FD31289045.")

    assert "fd31289045" in normalized.model_text
    assert normalized.flags["leetspeak"] is False
    assert normalized.flags["obfuscated"] is False


def test_unicode_obfuscation_is_detected_but_removed_from_model_copy():
    zero_width = normalize_text("Your ban\u200bk account is blocked")
    fullwidth = normalize_text("Your ＯＴＰ code is 123456")

    assert zero_width.flags["zero_width"] is True
    assert "\u200b" not in zero_width.normalized
    assert fullwidth.flags["fullwidth"] is True
    assert "OTP" in fullwidth.normalized


def test_model_text_helper_is_text_free_of_entities():
    text = model_text_for("Visit https://example.com or call 9876543210")

    assert "example.com" not in text
    assert "9876543210" not in text
    assert "url_present" in text
    assert "phone_present" in text


def test_amounts_and_short_codes_survive_normalization():
    normalized = normalize_text("EMI of Rs 8,400 debited; OTP 482913")

    assert "8,400" in normalized.normalized
    assert "482913" in normalized.model_text
