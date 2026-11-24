"""Deterministic SMS security indicators and evidence codes.

Indicators are deliberately conservative and context-aware. A single keyword is
never enough to call a message malicious; request verbs are checked near
credential/OTP nouns and negations such as "do not share your OTP" are ignored.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Iterable

from ..interface.schema import EvidenceItem
from .normalize import NormalizedText, normalize_text

# Stable evidence codes. Keep these values machine-readable and append-only.
URL_PRESENT = "URL_PRESENT"
EMAIL_PRESENT = "EMAIL_PRESENT"
PHONE_PRESENT = "PHONE_PRESENT"
LONG_DIGIT_STRING = "LONG_DIGIT_STRING"
URGENCY_LANGUAGE = "URGENCY_LANGUAGE"
ACCOUNT_THREAT = "ACCOUNT_THREAT"
CREDENTIAL_REQUEST = "CREDENTIAL_REQUEST"
OTP_REQUEST = "OTP_REQUEST"
PAYMENT_REQUEST = "PAYMENT_REQUEST"
PRIZE_OR_REWARD_BAIT = "PRIZE_OR_REWARD_BAIT"
LOAN_OR_INVESTMENT_BAIT = "LOAN_OR_INVESTMENT_BAIT"
DELIVERY_BAIT = "DELIVERY_BAIT"
IMPERSONATION = "IMPERSONATION"
PROMOTIONAL_CONTENT = "PROMOTIONAL_CONTENT"
THREAT_OF_ACTION = "THREAT_OF_ACTION"
REFUND_BAIT = "REFUND_BAIT"
JOB_OFFER_BAIT = "JOB_OFFER_BAIT"
KYC_LANGUAGE = "KYC_LANGUAGE"
ACCOUNT_ACCESS_LURE = "ACCOUNT_ACCESS_LURE"
# Internal guard flag: suppresses risk for routine bank/UPI transaction alerts.
# It is not emitted as user-facing evidence because it is not a threat finding.
BENIGN_TRANSACTIONAL = "BENIGN_TRANSACTIONAL"
BENIGN_DELIVERY = "BENIGN_DELIVERY"
SENDER_ID_UNVERIFIED = "SENDER_ID_UNVERIFIED"
SENDER_CLAIM_MISMATCH = "SENDER_CLAIM_MISMATCH"
OBFUSCATED_TEXT = "OBFUSCATED_TEXT"
MULTIPLE_SOCIAL_ENGINEERING_CUES = "MULTIPLE_SOCIAL_ENGINEERING_CUES"
DTH_UTILITY_THREAT = "DTH_UTILITY_THREAT"
TASK_SCAM = "TASK_SCAM"
TELECOM_LURE = "TELECOM_LURE"
DATA_HARVESTING = "DATA_HARVESTING"
HIGH_DEMAND_GADGET_SCAM = "HIGH_DEMAND_GADGET_SCAM"
APK_DOWNLOAD_LURE = "APK_DOWNLOAD_LURE"
DELIVERY_UPDATE_LURE = "DELIVERY_UPDATE_LURE"
SERVICE_INTERRUPTION_LURE = "SERVICE_INTERRUPTION_LURE"

EVIDENCE_CODES = (
    URL_PRESENT,
    EMAIL_PRESENT,
    PHONE_PRESENT,
    LONG_DIGIT_STRING,
    URGENCY_LANGUAGE,
    ACCOUNT_THREAT,
    CREDENTIAL_REQUEST,
    OTP_REQUEST,
    PAYMENT_REQUEST,
    PRIZE_OR_REWARD_BAIT,
    LOAN_OR_INVESTMENT_BAIT,
    DELIVERY_BAIT,
    IMPERSONATION,
    PROMOTIONAL_CONTENT,
    THREAT_OF_ACTION,
    REFUND_BAIT,
    JOB_OFFER_BAIT,
    KYC_LANGUAGE,
    ACCOUNT_ACCESS_LURE,
    SENDER_ID_UNVERIFIED,
    SENDER_CLAIM_MISMATCH,
    OBFUSCATED_TEXT,
    MULTIPLE_SOCIAL_ENGINEERING_CUES,
    DTH_UTILITY_THREAT,
    TASK_SCAM,
    TELECOM_LURE,
    DATA_HARVESTING,
    HIGH_DEMAND_GADGET_SCAM,
    APK_DOWNLOAD_LURE,
    DELIVERY_UPDATE_LURE,
    SERVICE_INTERRUPTION_LURE,
)

STRENGTH = {
    OTP_REQUEST: "critical",
    CREDENTIAL_REQUEST: "critical",
    PAYMENT_REQUEST: "strong",
    ACCOUNT_THREAT: "strong",
    PRIZE_OR_REWARD_BAIT: "strong",
    THREAT_OF_ACTION: "strong",
    LOAN_OR_INVESTMENT_BAIT: "medium",
    IMPERSONATION: "medium",
    URGENCY_LANGUAGE: "medium",
    KYC_LANGUAGE: "medium",
    DELIVERY_BAIT: "medium",
    REFUND_BAIT: "medium",
    JOB_OFFER_BAIT: "medium",
    ACCOUNT_ACCESS_LURE: "strong",
    PROMOTIONAL_CONTENT: "weak",
    URL_PRESENT: "weak",
    EMAIL_PRESENT: "weak",
    PHONE_PRESENT: "weak",
    LONG_DIGIT_STRING: "weak",
    SENDER_ID_UNVERIFIED: "weak",
    SENDER_CLAIM_MISMATCH: "medium",
    OBFUSCATED_TEXT: "medium",
    MULTIPLE_SOCIAL_ENGINEERING_CUES: "strong",
    DTH_UTILITY_THREAT: "strong",
    TASK_SCAM: "strong",
    TELECOM_LURE: "strong",
    DATA_HARVESTING: "strong",
    HIGH_DEMAND_GADGET_SCAM: "strong",
    APK_DOWNLOAD_LURE: "strong",
    DELIVERY_UPDATE_LURE: "strong",
    SERVICE_INTERRUPTION_LURE: "strong",
}

STRONG_CODES = {
    OTP_REQUEST,
    CREDENTIAL_REQUEST,
    PAYMENT_REQUEST,
    ACCOUNT_THREAT,
    PRIZE_OR_REWARD_BAIT,
    THREAT_OF_ACTION,
    ACCOUNT_ACCESS_LURE,
    DTH_UTILITY_THREAT,
    TASK_SCAM,
    TELECOM_LURE,
    DATA_HARVESTING,
    HIGH_DEMAND_GADGET_SCAM,
    APK_DOWNLOAD_LURE,
    DELIVERY_UPDATE_LURE,
    SERVICE_INTERRUPTION_LURE,
}

CRITICAL_CODES = {OTP_REQUEST, CREDENTIAL_REQUEST}

# ---------------------------------------------------------------------------
# Pattern definitions
# ---------------------------------------------------------------------------

URGENCY_RE = re.compile(
    r"""(?ix)
    \b(?:
        urgent(?:ly)?
        |immediate(?:ly)?
        |right\s+now
        |asap
        |hurry
        |last\s+chance
        |final\s+(?:notice|warning|reminder)
        |expir(?:es?|ing|y)\s+(?:today|soon|in\s+\d+)
        |within\s+\d+\s*(?:hours?|hrs?|minutes?|mins?|days?)
        |today\s+itself
        |act\s+now
        |limited\s+time
        |before\s+it(?:'s|\s+is)\s+too\s+late
        |time\s+is\s+running\s+out
    )\b
    """
)

ACCOUNT_THREAT_RE = re.compile(
    r"""(?ix)
    \b(?:
        block(?:ed|ing)?
        |suspend(?:ed|ing)?
        |deactivat(?:ed|ion|ing)
        |frozen|freeze|frozen\s+account
        |closed|closure
        |terminat(?:ed|ion)
        |expired?
        |disconnect(?:ed|ion)?
        |service\s+(?:will\s+be\s+)?(?:stopped|disconnected|suspended)
        |kyc\s+(?:expired|pending|update|verification|failed)
        |account\s+(?:will\s+be|has\s+been|is)\s+(?:blocked|suspended|closed|frozen|deactivated)
        |sim\s+(?:will\s+be|is)\s+(?:blocked|deactivated|disconnected)
        |profile\s+(?:will\s+be\s+)?(?:blocked|suspended)
    )\b
    """
)

THREAT_OF_ACTION_RE = re.compile(
    r"""(?ix)
    \b(?:
        legal\s+action
        |police\s+(?:case|complaint)
        |fir\b
        |penalty
        |fine\s+of
        |case\s+(?:has\s+been\s+)?filed
        |arrest
        |court\s+(?:case|notice)
        |non[- ]?bailable
        |recovery\s+notice
    )\b
    """
)

KYC_RE = re.compile(
    r"""(?ix)
    \b(?:kyc|know\s+your\s+customer|re[- ]?kyc|video\s+kyc|pan\s+card|aadhaar|aadhar)\b
    """
)

PRIZE_RE = re.compile(
    r"""(?ix)
    \b(?:
        won\b|winner|prize|lottery|lucky\s+draw|jackpot
        |reward|cashback|voucher|scratch\s+card
        |claim\s+(?:your|now|reward|prize)
        |free\s+(?:gift|recharge|data|voucher|hamper)
        |you\s+have\s+been\s+selected
        |selected\s+(?:as\s+)?(?:a\s+)?winner
    )\b
    """
)

PROMOTIONAL_RE = re.compile(
    r"""(?ix)
    \b(?:
        offer|discount|sale|deal|buy\s+\d|get\s+\d+\s*%\s*off
        |subscribe|unsubscribe|limited\s+offer|free\s+trial
        |shop\s+now|order\s+now|new\s+arrivals?
        |plan\s+starting|recharge|top[- ]?up
        |exclusive\s+offer|best\s+price|save\s+\d+
    )\b
    """
)

LOAN_INVESTMENT_RE = re.compile(
    r"""(?ix)
    \b(?:
        loan\s+(?:approved|offer|available|free|fast|instant|without|bina)
        |pre[- ]?approved
        |instant\s+loan
        |credit\s+limit
        |investment
        |guaranteed\s+returns?
        |double\s+your\s+money
        |trading\s+(?:tips?|course)
        |stock\s+tips?
        |mutual\s+fund
        |earn\s+(?:rs\.?|inr|₹|\$|£|€|usd|gbp)?\s*\d+
        |work\s+from\s+home
        |part[- ]?time\s+job
        |daily\s+(?:income|payment|payout)
        |monthly\s+income
        |no\s+experience\s+required
        |no\s+documents?|bina\s+(?:documents?|guarantor)|guarantor
    )\b
    """
)

DELIVERY_RE = re.compile(
    r"""(?ix)
    \b(?:
        parcel|courier|delivery|shipment|customs
        |address\s+(?:confirmation|update|verification)
        |india\s+post|dtdc|bluedart|delhivery|fedex|dhl|ekart
        |package\s+(?:is\s+)?(?:held|stuck|waiting)
        |consignment
    )\b
    """
)

IMPERSONATION_RE = re.compile(
    r"""(?ix)
    \b(?:
        sbi|state\s+bank|hdfc|icici|axis\s+bank|kotak|yes\s+bank
        |paytm|phonepe|google\s+pay|gpay|bhim
        |amazon|flipkart|netflix|swiggy|zomato
        |income\s+tax|gst|rbi|reserve\s+bank|uidai|trai
        |govt|government|police|cbi|customs|epfo|lic
        |india\s+post|irctc|electricity\s+board
    )\b
    """
)

REFUND_RE = re.compile(
    r"""(?ix)
    \b(?:refund|reversal|money\s+back|failed\s+transaction|compensation|reimburse(?:ment)?)\b
    """
)

JOB_RE = re.compile(
    r"""(?ix)
    \b(?:
        work\s+from\s+home|part[- ]?time|daily\s+(?:income|payment)
        |earn\s+(?:rs\.?|inr|₹)?\s*\d+|hiring|vacancy
        |salary\s+(?:up\s+to|per\s+(?:month|annum)|\d)
        |job\s+offer|no\s+experience|simple\s+typing\s+job
    )\b
    """
)

DTH_UTILITY_PROVIDER_RE = re.compile(
    r"""(?ix)
    \b(?:
        dth|dish\s*tv|tata\s*(?:sky|play)|airtel\s*dth
        |videocon(?:\s*d2h)?|sun\s*direct
        |electricity(?:\s*(?:bill|connection|board))?
        |power\s*(?:bill|connection)|water\s*(?:bill|connection)
        |piped\s*gas|gas\s*(?:connection|bill)|broadband|landline
    )\b
    """
)

SERVICE_DISRUPTION_RE = re.compile(
    r"""(?ix)
    \b(?:
        disconnect(?:ed|ion)?|cut\s*off|suspend(?:ed|ing|ion)?
        |deactivat(?:e|ed|ion)|block(?:ed|ing)?
        |halt(?:ed|ing)?|stop(?:ped|ping)?|expir(?:e[sd]?|ing|y)
    )\b
    """
)

TASK_ACTIVITY_RE = re.compile(
    r"""(?ix)
    \b(?:
        lik(?:e|ing)|comment(?:ing)?|sharing|share
        |rating|review(?:er|ing|s|ed)?|survey(?:s)?
        |data\s*entry|captcha(?:s)?|typing
        |watch(?:ing)?\s+(?:videos?|ads?|advertisements?)
        |simple\s+tasks?|micro\s*tasks?
    )\b
    """
)

TASK_EARNING_RE = re.compile(
    r"""(?ix)
    \b(?:earn(?:ing)?(?:\s+money)?|get\s+paid|paid|get|receive|make)\b
    .{0,60}?
    (?:\b(?:rs\.?|inr|₹|\$)\s*\d+
       |\b\d+\s*(?:per|/)\s*(?:day|review|task|like|post|hour))
    """
)

REMOTE_CHANNEL_RE = re.compile(
    r"""(?ix)\b(?:telegram|t\.me|whatsapp|wa\.me|instagram|facebook|social\s+media)\b"""
)

TELECOM_CONTEXT_RE = re.compile(
    r"""(?ix)
    \b(?:
        jio|airtel|vodafone|vi\b|bsnl|sim|4g|5g
        |data\s*(?:plan|pack|balance)|recharge
        |unlimited\s*calls?|mobile\s+number
    )\b
    """
)

TELECOM_UNREALISTIC_RE = re.compile(
    r"""(?ix)
    \b(?:
        (?:50|75|100|150|200)\s*gb
        |(?:rs\.?|inr|₹)\s*[1-9]\s*recharge
        |data\s*pack\s*free
        |free\s*(?:5g|recharge|data|sim|plan)
        |unlimited\s*(?:5g|data)\s*offer
        |just\s*(?:rs\.?|inr|₹)\s*\d{1,3}
    )\b
    """
)

DOCUMENT_NOUN_RE = re.compile(
    r"""(?ix)
    \b(?:
        aadhaar|aadhar|pan(?:\s+card)?|marksheet|mark\s*sheet
        |class\s*(?:10|12)|documents?|digilocker
        |driving\s+licen[cs]e|passport|voter\s*id
        |identity\s+proof|bank\s+details
    )\b
    """
)

DOCUMENT_ACTION_RE = re.compile(
    r"""(?ix)\b(?:re-?upload|upload|share|submit|send|verify|update|complete|provide)\b"""
)

DOCUMENT_RISK_RE = re.compile(
    r"""(?ix)\b(?:corrupt(?:ed)?|expired?|mismatch|pending|failed|blocked?|invalid|hold|re-?verify|re-?upload)\b"""
)

GADGET_RE = re.compile(
    r"""(?ix)
    \b(?:
        iphone|ipad|macbook|playstation(?:\s*5)?|ps5|xbox
        |nintendo\s*switch|graphics\s*card|gpu|samsung\s*galaxy
        |oneplus|google\s*pixel
    )\b
    """
)

GADGET_SCARCITY_RE = re.compile(
    r"""(?ix)
    \b(?:
        pre-?book|pre-?order|only\s+\d+\s+units?
        |limited\s+(?:stock|units?)|50%\s*(?:off|discount)
        |discount|sale
    )\b
    """
)

GADGET_COMMITMENT_RE = re.compile(
    r"""(?ix)
    \b(?:
        book\s+for|pre-?book|pre-?order|token|advance|deposit
    )\b
    """
)

APK_URL_RE = re.compile(r"(?ix)\.apk(?:$|[/?#])")
APK_MENTION_RE = re.compile(r"(?ix)\b(?:apk|patch\s+configuration|configuration\s+app)\b")

DELIVERY_PROBLEM_RE = re.compile(
    r"""(?ix)
    \b(?:
        could\s+not\s+deliver|couldn'?t\s+deliver|failed\s+delivery
        |delivery\s+failed|missed\s+delivery|not\s+delivered
        |address\s+(?:is\s+)?incomplete|address\s+(?:confirmation|verification)
        |return(?:ed)?\s+to\s+sender|avoid\s+return
        |import\s+duty|customs\s+duty|pending\s+duty
        |reschedule\s+delivery|update\s+(?:delivery\s+)?(?:address|location|coordinates)
    )\b
    """
)

SERVICE_INTERRUPTION_RE = re.compile(
    r"""(?ix)
    \b(?:
        storage\s+(?:is\s+)?full
        |will\s+(?:stop\s+receiving|stop\s+working|be\s+(?:stopped|halted|disconnected|deactivated|suspended))
        |service\s+(?:will\s+be\s+)?(?:stopped|halted|interrupted|disrupted|disconnected|deactivated|suspended)
        |account\s+(?:will\s+be\s+)?(?:stopped|suspended|blocked|deactivated)
    )\b
    """
)

SERVICE_RECOVERY_ACTION_RE = re.compile(
    r"""(?ix)\b(?:upgrade|renew|verify|update|pay|continue|restore|reactivate|click|download)\b"""
)

TRANSACTION_RE = re.compile(
    r"""(?ix)
    \b(?:
        auto[- ]?debit(?:ed)?|debited|credited|withdrawn|deposited|refilled
        |transaction\s+(?:was\s+)?successful
        |payment\s+(?:was\s+)?successful|payment\s+received
        |amount\s+(?:debited|credited)
        |account\s+(?:debited|credited)
    )\b
    """
)

CALL_ACTION_RE = re.compile(r"(?ix)\b(?:call|dial|contact)\b")

DELIVERY_SUCCESS_RE = re.compile(
    r"""(?ix)
    \b(?:
        (?:order|parcel|package|shipment|consignment).{0,40}(?:delivered|arrived)
        |(?:delivered|arrived)\s+today
        |out\s+for\s+delivery
    )\b
    """
)

ACCOUNT_ACCESS_ACTION_RE = re.compile(
    r"""(?ix)
    \b(?:
        account\s+(?:has\s+been|is|was|will\s+be)?\s*
            (?:reset|locked|restricted|limited|suspended|frozen|flagged|compromised|blocked|on\s+hold)
        |(?:reset|unlock|restore|reactivate|verify|confirm|secure)\s+
            (?:your\s+)?(?:account|login|profile|identity)
        |new\s+(?:login|sign[- ]?in)
        |unusual\s+(?:login|activity)
        |account\s+(?:information|details)\s+(?:now|immediately)
    )\b
    """
)

ACCOUNT_ACCESS_CREDENTIAL_RE = re.compile(
    r"""(?ix)
    \b(?:
        username|user\s*name|password|p\W{0,3}word|passcode
        |login\s*code|access\s*code|credential|login\s+details
        |security\s+code
    )\b
    """
)

ACCOUNT_ACCESS_CONTEXT_RE = re.compile(
    r"""(?ix)
    \b(?:account|login|log\s*in|sign\s*in|bank|access|reset|verify|confirm|secure|unlock|code)\b
    """
)

ACCOUNT_ALERT_SUPPRESS_RE = re.compile(
    r"""(?ix)
    \b(?:
        if\s+(?:this\s+)?(?:wasn'?t|was\s+not)\s+you
        |did\s+not\s+request|didn'?t\s+request
        |no\s+action\s+(?:is\s+)?(?:needed|required)
    )\b
    """
)

CREDENTIAL_NOUN_RE = re.compile(
    r"""(?ix)
    \b(?:
        password|passcode|pin\b|cvv|card\s+number|account\s+number
        |aadhaar|aadhar|pan\b|username|login|credentials
        |net\s?banking|upi\s+pin|mpin|debit\s+card|credit\s+card
        |security\s+code
    )\b
    """
)

OTP_NOUN_RE = re.compile(
    r"""(?ix)
    \b(?:otp|one[- ]time\s+password|verification\s+code|auth(?:entication)?\s+code|security\s+code)\b
    """
)

REQUEST_VERB_RE = re.compile(
    r"""(?ix)
    \b(?:share|send|provide|enter|submit|confirm|verify|update|tell|give|forward|reply\s+with|type|fill)\b
    """
)

PAYMENT_ACTION_RE = re.compile(
    r"""(?ix)
    \b(?:pay|payment|transfer|remit|deposit|send\s+money|scan|clear|settle)\b
    """
)

PAYMENT_TARGET_RE = re.compile(
    r"""(?ix)
    (?:rs\.?|inr|₹|\$|£|€|usd|gbp|eur|\bmoney\b|\bamount\b|\bfee\b|\bcharge\b|\bupi\b|\bqr\b|\baccount\b|\bnumber\b|\bwallet\b|\bpayee\b)
    """
)

PAYMENT_FEE_RE = re.compile(
    r"""(?ix)
    \b(?:
        processing|registration|security|clearance|customs|delivery|handling
        |service|activation|verification|documentation|starter|training|membership|subscription
    )\s+(?:fee|charge|amount|payment|cost|kit)\b
    |\b(?:registration|processing|security|clearance|customs|delivery|handling|activation|verification|documentation)
       \s+(?:₹|rs\.?|inr|\$|£|€|usd|gbp|eur)\s*[\d,]+
    """
)

PAYMENT_IMPERATIVE_RE = re.compile(
    r"""(?ix)
    \b(?:
        pay\s+now|make\s+(?:a\s+)?payment|complete\s+(?:the\s+)?payment
        |please\s+pay|kindly\s+pay|pay\s+(?:the\s+)?(?:fee|amount|money)
        |transfer\s+(?:the\s+)?(?:amount|money|rs|inr)
        |send\s+(?:the\s+)?(?:amount|money|rs|inr)
        |scan\s+(?:the\s+)?qr
        |deposit\s+(?:the\s+)?(?:amount|money|fee)
    )\b
    """
)

PAYMENT_SUCCESS_RE = re.compile(
    r"""(?ix)
    \b(?:payment\s+(?:was\s+)?successful|payment\s+received|has\s+been\s+(?:debited|credited)|transaction\s+(?:was\s+)?successful|amount\s+(?:debited|credited))\b
    """
)

NEGATION_RE = re.compile(
    r"""(?ix)
    \b(?:do\s+not|don't|never|not|no\s+need\s+to|we\s+never\s+ask\s+you\s+to|will\s+never\s+ask)\b
    """
)

# Keep "no processing fee" from being read as a demand without treating every
# occurrence of "no" as a global negation cue.
PAYMENT_NEGATION_RE = re.compile(
    r"""(?ix)
    \b(?:no|without|zero)\s+(?:\w+\s+){0,2}(?:fee|charge|payment|cost)s?\b
    """
)

CURRENCY_RE = re.compile(r"(?ix)(?:₹|rs\.?|inr|\$|usd|£|gbp|€|eur)\s?\d")
AMOUNT_RE = re.compile(r"(?ix)(?:₹|rs\.?|inr|\$|usd|£|gbp|€|eur)\s?[\d,]+(?:\.\d+)?")


@dataclass(frozen=True)
class IndicatorResult:
    """All deterministic findings for one SMS.

    ``items`` only contains present evidence. ``flags`` includes every code
    (present or not) so models and tests can inspect the full feature vector.
    """

    normalized: NormalizedText
    items: tuple[EvidenceItem, ...]
    flags: dict[str, bool]
    features: dict[str, float] = field(default_factory=dict)

    @property
    def codes(self) -> set[str]:
        return {item.code for item in self.items}

    def has(self, code: str) -> bool:
        return bool(self.flags.get(code, False))

    def strong_cue_count(self) -> int:
        return sum(1 for code in STRONG_CODES if self.flags.get(code, False))

    def to_evidence(self) -> list[EvidenceItem]:
        return list(self.items)

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence": [item.to_dict() for item in self.items],
            "flags": dict(self.flags),
            "features": dict(self.features),
        }


def analyze_text(
    raw_text: str,
    *,
    normalized: NormalizedText | None = None,
    sender: str | None = None,
    known_sender: bool = False,
) -> IndicatorResult:
    """Extract deterministic indicators from one message.

    ``known_sender`` must only be set by the host app based on an explicit local
    contact/allow-list decision. Unknown senders are a weak signal, not proof.
    """

    norm = normalized if normalized is not None else normalize_text(raw_text)
    text = norm.normalized
    lower = text.lower()
    # Leetspeak is undone in model_text, so account/password lures survive
    # obfuscation such as "L0gin" and "P***word".
    access_text = norm.model_text.lower()

    flags: dict[str, bool] = {code: False for code in EVIDENCE_CODES}

    flags[URL_PRESENT] = bool(norm.urls)
    flags[EMAIL_PRESENT] = bool(norm.emails)
    flags[PHONE_PRESENT] = bool(norm.phones)
    flags[LONG_DIGIT_STRING] = bool(norm.flags.get("long_digit_string", False))
    flags[OBFUSCATED_TEXT] = bool(norm.flags.get("obfuscated", False))

    flags[URGENCY_LANGUAGE] = bool(URGENCY_RE.search(lower))
    flags[ACCOUNT_THREAT] = bool(ACCOUNT_THREAT_RE.search(lower))
    flags[THREAT_OF_ACTION] = bool(THREAT_OF_ACTION_RE.search(lower))
    flags[KYC_LANGUAGE] = bool(KYC_RE.search(lower))
    flags[PRIZE_OR_REWARD_BAIT] = bool(PRIZE_RE.search(lower))
    flags[PROMOTIONAL_CONTENT] = bool(PROMOTIONAL_RE.search(lower))
    flags[LOAN_OR_INVESTMENT_BAIT] = bool(LOAN_INVESTMENT_RE.search(lower))
    flags[DELIVERY_BAIT] = bool(DELIVERY_RE.search(lower))
    flags[IMPERSONATION] = bool(IMPERSONATION_RE.search(lower))
    flags[REFUND_BAIT] = bool(REFUND_RE.search(lower))
    flags[JOB_OFFER_BAIT] = bool(JOB_RE.search(lower))

    account_access = bool(
        ACCOUNT_ACCESS_ACTION_RE.search(access_text)
        or (
            ACCOUNT_ACCESS_CREDENTIAL_RE.search(access_text)
            and ACCOUNT_ACCESS_CONTEXT_RE.search(access_text)
        )
    )
    flags[ACCOUNT_ACCESS_LURE] = bool(
        flags[URL_PRESENT]
        and account_access
        and not ACCOUNT_ALERT_SUPPRESS_RE.search(lower)
    )

    flags[CREDENTIAL_REQUEST] = _request_context(
        access_text, REQUEST_VERB_RE, CREDENTIAL_NOUN_RE, window=60
    )
    flags[OTP_REQUEST] = _request_context(
        access_text, REQUEST_VERB_RE, OTP_NOUN_RE, window=40
    )
    flags[PAYMENT_REQUEST] = _payment_request(lower)

    dth_utility = bool(
        DTH_UTILITY_PROVIDER_RE.search(lower)
        and SERVICE_DISRUPTION_RE.search(lower)
        and (
            flags[URL_PRESENT]
            or flags[PAYMENT_REQUEST]
            or flags[URGENCY_LANGUAGE]
        )
    )
    task_scam = bool(
        TASK_ACTIVITY_RE.search(lower)
        and TASK_EARNING_RE.search(lower)
        and (flags[URL_PRESENT] or REMOTE_CHANNEL_RE.search(lower))
    )
    apk_download = bool(
        flags[URL_PRESENT]
        and (
            any(APK_URL_RE.search(url) for url in norm.urls)
            or APK_MENTION_RE.search(lower)
        )
    )
    telecom_lure = bool(
        flags[URL_PRESENT]
        and TELECOM_CONTEXT_RE.search(lower)
        and (apk_download or TELECOM_UNREALISTIC_RE.search(lower))
    )
    data_harvesting = bool(
        flags[URL_PRESENT]
        and DOCUMENT_NOUN_RE.search(lower)
        and DOCUMENT_ACTION_RE.search(lower)
        and DOCUMENT_RISK_RE.search(lower)
    )
    high_demand_gadget = bool(
        flags[URL_PRESENT]
        and GADGET_RE.search(lower)
        and GADGET_SCARCITY_RE.search(lower)
        and GADGET_COMMITMENT_RE.search(lower)
    )
    flags[DTH_UTILITY_THREAT] = dth_utility
    flags[TASK_SCAM] = task_scam
    flags[TELECOM_LURE] = telecom_lure
    flags[DATA_HARVESTING] = data_harvesting
    flags[HIGH_DEMAND_GADGET_SCAM] = high_demand_gadget
    flags[APK_DOWNLOAD_LURE] = apk_download
    flags[DELIVERY_UPDATE_LURE] = bool(
        flags[URL_PRESENT]
        and flags[DELIVERY_BAIT]
        and DELIVERY_PROBLEM_RE.search(lower)
    )
    flags[SERVICE_INTERRUPTION_LURE] = bool(
        flags[URL_PRESENT]
        and SERVICE_INTERRUPTION_RE.search(lower)
        and SERVICE_RECOVERY_ACTION_RE.search(lower)
    )

    benign_blockers = (
        URL_PRESENT,
        OTP_REQUEST,
        CREDENTIAL_REQUEST,
        ACCOUNT_ACCESS_LURE,
        ACCOUNT_THREAT,
        THREAT_OF_ACTION,
        PAYMENT_REQUEST,
        PRIZE_OR_REWARD_BAIT,
        LOAN_OR_INVESTMENT_BAIT,
        DELIVERY_BAIT,
        JOB_OFFER_BAIT,
        KYC_LANGUAGE,
        URGENCY_LANGUAGE,
        PROMOTIONAL_CONTENT,
        DTH_UTILITY_THREAT,
        TASK_SCAM,
        TELECOM_LURE,
        DATA_HARVESTING,
        HIGH_DEMAND_GADGET_SCAM,
        APK_DOWNLOAD_LURE,
        DELIVERY_UPDATE_LURE,
        SERVICE_INTERRUPTION_LURE,
    )
    flags[BENIGN_TRANSACTIONAL] = bool(
        TRANSACTION_RE.search(lower)
        and not any(flags.get(code, False) for code in benign_blockers)
        and not (flags[PHONE_PRESENT] and CALL_ACTION_RE.search(lower))
    )

    delivery_blockers = tuple(
        code for code in benign_blockers if code != DELIVERY_BAIT
    ) + (REFUND_BAIT,)
    flags[BENIGN_DELIVERY] = bool(
        DELIVERY_SUCCESS_RE.search(lower)
        and not any(flags.get(code, False) for code in delivery_blockers)
        and not (flags[PHONE_PRESENT] and CALL_ACTION_RE.search(lower))
    )

    _sender_flags(flags, sender=sender, known_sender=known_sender, text=lower)

    strong_count = sum(1 for code in STRONG_CODES if flags[code])
    flags[MULTIPLE_SOCIAL_ENGINEERING_CUES] = strong_count >= 2 or (
        strong_count >= 1
        and (flags[URL_PRESENT] or flags[URGENCY_LANGUAGE])
        and (flags[ACCOUNT_THREAT] or flags[IMPERSONATION] or flags[PROMOTIONAL_CONTENT])
    )

    items = tuple(
        EvidenceItem(code=code, present=True)
        for code in EVIDENCE_CODES
        if flags[code]
    )
    features = _feature_dict(norm, flags)
    return IndicatorResult(normalized=norm, items=items, flags=flags, features=features)


def _request_context(
    text: str,
    verb_re: re.Pattern[str],
    noun_re: re.Pattern[str],
    *,
    window: int,
) -> bool:
    """Return True when a non-negated request verb is near a sensitive noun."""

    verbs = list(verb_re.finditer(text))
    for verb in verbs:
        if _is_negated(text, verb.start()):
            continue
        tail = text[verb.end() : verb.end() + window]
        if noun_re.search(tail):
            return True

    # Handle "OTP share karo" / "PIN bhejo" style ordering and noun-first SMS.
    for noun in noun_re.finditer(text):
        tail = text[noun.end() : noun.end() + window]
        for verb in verb_re.finditer(tail):
            absolute = noun.end() + verb.start()
            if not _is_negated(text, absolute):
                return True
    return False


def _is_negated(text: str, position: int, window: int = 32) -> bool:
    prefix = text[max(0, position - window) : position]
    return bool(NEGATION_RE.search(prefix))


def _payment_request(text: str) -> bool:
    if PAYMENT_SUCCESS_RE.search(text) and not re.search(
        r"(?i)\b(?:please|kindly|now|click|scan|transfer|send|deposit|pay)\b", text
    ):
        return False

    if PAYMENT_NEGATION_RE.search(text):
        # "no processing fee" / "there is no fee" should not be a payment demand.
        return False

    if PAYMENT_IMPERATIVE_RE.search(text) or PAYMENT_FEE_RE.search(text):
        match = PAYMENT_FEE_RE.search(text) or PAYMENT_IMPERATIVE_RE.search(text)
        if match and _is_negated(text, match.start()):
            return False
        return True

    # Action verb followed by a payment target (amount, UPI, QR, account).
    for verb in PAYMENT_ACTION_RE.finditer(text):
        if _is_negated(text, verb.start()):
            continue
        tail = text[verb.end() : verb.end() + 60]
        if PAYMENT_TARGET_RE.search(tail):
            return True
    return False


def _sender_flags(
    flags: dict[str, bool],
    *,
    sender: str | None,
    known_sender: bool,
    text: str,
) -> None:
    if not sender:
        return
    sender = str(sender).strip()
    if not sender:
        return
    transactional = bool(
        re.fullmatch(r"[A-Z]{2}-[A-Z0-9]{3,}", sender)
        or re.fullmatch(r"[A-Z]{5,9}", sender)
        or re.fullmatch(r"\d{5,6}", sender)
    )
    if not known_sender and not transactional:
        flags[SENDER_ID_UNVERIFIED] = True
    normalized_sender = re.sub(r"[\s-]", "", sender)
    if (
        flags[IMPERSONATION]
        or flags[KYC_LANGUAGE]
        or flags[ACCOUNT_THREAT]
    ) and re.fullmatch(r"\+?(?:91)?[6-9]\d{9}", normalized_sender):
        flags[SENDER_CLAIM_MISMATCH] = True


# ---------------------------------------------------------------------------
# Model feature vector (E3)
# ---------------------------------------------------------------------------

NUMERIC_FEATURE_NAMES = (
    "text_length",
    "token_count",
    "digit_count",
    "digit_ratio",
    "uppercase_ratio",
    "punctuation_count",
    "exclamation_count",
    "question_count",
    "url_count",
    "phone_count",
    "email_count",
    "has_currency",
    "has_amount",
    "is_short",
    "benign_transactional",
)

FEATURE_NAMES: tuple[str, ...] = tuple(f"ind:{code}" for code in EVIDENCE_CODES) + NUMERIC_FEATURE_NAMES


def _feature_dict(norm: NormalizedText, flags: dict[str, bool]) -> dict[str, float]:
    text = norm.normalized
    tokens = text.split()
    letters = [ch for ch in text if ch.isalpha()]
    digits = [ch for ch in text if ch.isdigit()]
    punctuation = [ch for ch in text if not ch.isalnum() and not ch.isspace()]
    features: dict[str, float] = {}
    for code in EVIDENCE_CODES:
        features[f"ind:{code}"] = float(flags.get(code, False))
    features.update(
        {
            "text_length": float(len(text)),
            "token_count": float(len(tokens)),
            "digit_count": float(len(digits)),
            "digit_ratio": float(len(digits) / max(1, len(text))),
            "uppercase_ratio": float(
                sum(1 for ch in letters if ch.isupper()) / max(1, len(letters))
            ),
            "punctuation_count": float(len(punctuation)),
            "exclamation_count": float(text.count("!")),
            "question_count": float(text.count("?")),
            "url_count": float(len(norm.urls)),
            "phone_count": float(len(norm.phones)),
            "email_count": float(len(norm.emails)),
            "has_currency": float(bool(CURRENCY_RE.search(text))),
            "has_amount": float(bool(AMOUNT_RE.search(text))),
            "is_short": float(len(text) < 30),
            "benign_transactional": float(flags.get(BENIGN_TRANSACTIONAL, False)),
        }
    )
    return features


def feature_vector(result: IndicatorResult) -> list[float]:
    return [float(result.features.get(name, 0.0)) for name in FEATURE_NAMES]


def feature_matrix(results: Iterable[IndicatorResult]) -> list[list[float]]:
    return [feature_vector(result) for result in results]


def present_codes(result: IndicatorResult) -> list[str]:
    return [code for code in EVIDENCE_CODES if result.flags.get(code, False)]
