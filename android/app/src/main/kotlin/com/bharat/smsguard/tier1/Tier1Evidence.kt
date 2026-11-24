package com.bharat.smsguard.tier1

import java.util.Locale

/**
 * Kotlin port of the Tier-1 evidence needed by the eight hardening rules and
 * the TRAI/DLT sender-claim check. Existing policy/model fusion is deliberately
 * not included here; that belongs in a later parity stage.
 */
object Codes {
    const val URL_PRESENT = "URL_PRESENT"
    const val EMAIL_PRESENT = "EMAIL_PRESENT"
    const val PHONE_PRESENT = "PHONE_PRESENT"
    const val LONG_DIGIT_STRING = "LONG_DIGIT_STRING"
    const val URGENCY_LANGUAGE = "URGENCY_LANGUAGE"
    const val ACCOUNT_THREAT = "ACCOUNT_THREAT"
    const val CREDENTIAL_REQUEST = "CREDENTIAL_REQUEST"
    const val OTP_REQUEST = "OTP_REQUEST"
    const val PAYMENT_REQUEST = "PAYMENT_REQUEST"
    const val PRIZE_OR_REWARD_BAIT = "PRIZE_OR_REWARD_BAIT"
    const val LOAN_OR_INVESTMENT_BAIT = "LOAN_OR_INVESTMENT_BAIT"
    const val DELIVERY_BAIT = "DELIVERY_BAIT"
    const val IMPERSONATION = "IMPERSONATION"
    const val PROMOTIONAL_CONTENT = "PROMOTIONAL_CONTENT"
    const val THREAT_OF_ACTION = "THREAT_OF_ACTION"
    const val REFUND_BAIT = "REFUND_BAIT"
    const val JOB_OFFER_BAIT = "JOB_OFFER_BAIT"
    const val KYC_LANGUAGE = "KYC_LANGUAGE"
    const val ACCOUNT_ACCESS_LURE = "ACCOUNT_ACCESS_LURE"
    const val BENIGN_TRANSACTIONAL = "BENIGN_TRANSACTIONAL"
    const val BENIGN_DELIVERY = "BENIGN_DELIVERY"
    const val SENDER_ID_UNVERIFIED = "SENDER_ID_UNVERIFIED"
    const val OBFUSCATED_TEXT = "OBFUSCATED_TEXT"
    const val MULTIPLE_SOCIAL_ENGINEERING_CUES = "MULTIPLE_SOCIAL_ENGINEERING_CUES"
    const val SENDER_CLAIM_MISMATCH = "SENDER_CLAIM_MISMATCH"

    const val DTH_UTILITY_THREAT = "DTH_UTILITY_THREAT"
    const val TASK_SCAM = "TASK_SCAM"
    const val TELECOM_LURE = "TELECOM_LURE"
    const val DATA_HARVESTING = "DATA_HARVESTING"
    const val HIGH_DEMAND_GADGET_SCAM = "HIGH_DEMAND_GADGET_SCAM"
    const val APK_DOWNLOAD_LURE = "APK_DOWNLOAD_LURE"
    const val DELIVERY_UPDATE_LURE = "DELIVERY_UPDATE_LURE"
    const val SERVICE_INTERRUPTION_LURE = "SERVICE_INTERRUPTION_LURE"

    val NEW_HARDENING_CODES = listOf(
        DTH_UTILITY_THREAT,
        TASK_SCAM,
        TELECOM_LURE,
        DATA_HARVESTING,
        HIGH_DEMAND_GADGET_SCAM,
        APK_DOWNLOAD_LURE,
        DELIVERY_UPDATE_LURE,
        SERVICE_INTERRUPTION_LURE,
    )

    val EVIDENCE_CODES = listOf(
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

    val STRONG_CODES = setOf(
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
    )
}

data class Tier1EvidenceResult(
    val normalized: NormalizedSms,
    val flags: Map<String, Boolean>,
    /** The eight new hardening codes that fired, in stable Python order. */
    val newCodes: List<String>,
) {
    fun has(code: String): Boolean = flags[code] == true

    fun strongCueCount(): Int = Codes.STRONG_CODES.count { has(it) }

    fun presentCodes(): List<String> = Codes.EVIDENCE_CODES.filter { has(it) }

    val dltSenderMismatch: Boolean
        get() = has(Codes.SENDER_CLAIM_MISMATCH)
}

object Tier1Evidence {
    // Existing signals needed by the new context gates or by the DLT check.
    private val URGENCY_RE = regex(
        """
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
        """,
    )

    private val ACCOUNT_THREAT_RE = regex(
        """
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
        """,
    )

    private val THREAT_OF_ACTION_RE = regex(
        """
        \b(?:
            legal\s+action
            |police\s+(?:case|complaint)
            |fir\b
            |penalty
            |fine\s+of
            |case\s+(?:has\s+been\s+)?filed
            |arrest
            |court\s+(?:case|notice)
            |non[-\x20]?bailable
            |recovery\s+notice
        )\b
        """,
    )

    private val PRIZE_RE = regex(
        """
        \b(?:
            won\b|winner|prize|lottery|lucky\s+draw|jackpot
            |reward|cashback|voucher|scratch\s+card
            |claim\s+(?:your|now|reward|prize)
            |free\s+(?:gift|recharge|data|voucher|hamper)
            |you\s+have\s+been\s+selected
            |selected\s+(?:as\s+)?(?:a\s+)?winner
        )\b
        """,
    )

    private val PROMOTIONAL_RE = regex(
        """
        \b(?:
            offer|discount|sale|deal|buy\s+\d|get\s+\d+\s*%\s*off
            |subscribe|unsubscribe|limited\s+offer|free\s+trial
            |shop\s+now|order\s+now|new\s+arrivals?
            |plan\s+starting|recharge|top[-\x20]?up
            |exclusive\s+offer|best\s+price|save\s+\d+
        )\b
        """,
    )

    private val LOAN_INVESTMENT_RE = regex(
        """
        \b(?:
            loan\s+(?:approved|offer|available|free|fast|instant|without|bina)
            |pre[-\x20]?approved
            |instant\s+loan
            |credit\s+limit
            |investment
            |guaranteed\s+returns?
            |double\s+your\s+money
            |trading\s+(?:tips?|course)
            |stock\s+tips?
            |mutual\s+fund
            |earn\s+(?:rs\.?|inr|₹|\${'$'}|£|€|usd|gbp)?\s*\d+
            |work\s+from\s+home
            |part[-\x20]?time\s+job
            |daily\s+(?:income|payment|payout)
            |monthly\s+income
            |no\s+experience\s+required
            |no\s+documents?|bina\s+(?:documents?|guarantor)|guarantor
        )\b
        """,
    )

    private val REFUND_RE = regex(
        """\b(?:refund|reversal|money\s+back|failed\s+transaction|compensation|reimburse(?:ment)?)\b""",
    )

    private val JOB_RE = regex(
        """
        \b(?:
            work\s+from\s+home|part[-\x20]?time|daily\s+(?:income|payment)
            |earn\s+(?:rs\.?|inr|₹)?\s*\d+|hiring|vacancy
            |salary\s+(?:up\s+to|per\s+(?:month|annum)|\d)
            |job\s+offer|no\s+experience|simple\s+typing\s+job
        )\b
        """,
    )

    private val KYC_RE = regex(
        """\b(?:kyc|know\s+your\s+customer|re[-\x20]?kyc|video\s+kyc|pan\s+card|aadhaar|aadhar)\b""",
    )

    private val DELIVERY_RE = regex(
        """
        \b(?:
            parcel|courier|delivery|shipment|customs
            |address\s+(?:confirmation|update|verification)
            |india\s+post|dtdc|bluedart|delhivery|fedex|dhl|ekart
            |package\s+(?:is\s+)?(?:held|stuck|waiting)
            |consignment
        )\b
        """,
    )

    private val IMPERSONATION_RE = regex(
        """
        \b(?:
            sbi|state\s+bank|hdfc|icici|axis\s+bank|kotak|yes\s+bank
            |paytm|phonepe|google\s+pay|gpay|bhim
            |amazon|flipkart|netflix|swiggy|zomato
            |income\s+tax|gst|rbi|reserve\s+bank|uidai|trai
            |govt|government|police|cbi|customs|epfo|lic
            |india\s+post|irctc|electricity\s+board
        )\b
        """,
    )

    private val ACCOUNT_ACCESS_ACTION_RE = regex(
        """
        \b(?:
            account\s+(?:has\s+been|is|was|will\s+be)?\s*
                (?:reset|locked|restricted|limited|suspended|frozen|flagged|compromised|blocked|on\s+hold)
            |(?:reset|unlock|restore|reactivate|verify|confirm|secure)\s+
                (?:your\s+)?(?:account|login|profile|identity)
            |new\s+(?:login|sign[-\x20]?in)
            |unusual\s+(?:login|activity)
            |account\s+(?:information|details)\s+(?:now|immediately)
        )\b
        """,
    )

    private val ACCOUNT_ACCESS_CREDENTIAL_RE = regex(
        """
        \b(?:
            username|user\s*name|password|p\W{0,3}word|passcode
            |login\s*code|access\s*code|credential|login\s+details
            |security\s+code
        )\b
        """,
    )

    private val ACCOUNT_ACCESS_CONTEXT_RE = regex(
        """\b(?:account|login|log\s*in|sign\s*in|bank|access|reset|verify|confirm|secure|unlock|code)\b""",
    )

    private val ACCOUNT_ALERT_SUPPRESS_RE = regex(
        """
        \b(?:
            if\s+(?:this\s+)?(?:wasn'?t|was\s+not)\s+you
            |did\s+not\s+request|didn'?t\s+request
            |no\s+action\s+(?:is\s+)?(?:needed|required)
        )\b
        """,
    )

    private val CREDENTIAL_NOUN_RE = regex(
        """
        \b(?:
            password|passcode|pin\b|cvv|card\s+number|account\s+number
            |aadhaar|aadhar|pan\b|username|login|credentials
            |net\s?banking|upi\s+pin|mpin|debit\s+card|credit\s+card
            |security\s+code
        )\b
        """,
    )

    private val OTP_NOUN_RE = regex(
        """\b(?:otp|one[- ]time\s+password|verification\s+code|auth(?:entication)?\s+code|security\s+code)\b""",
    )

    private val REQUEST_VERB_RE = regex(
        """\b(?:share|send|provide|enter|submit|confirm|verify|update|tell|give|forward|reply\s+with|type|fill)\b""",
    )

    private val DTH_PROVIDER_RE = regex(
        """
        \b(?:
            dth|dish\s*tv|tata\s*(?:sky|play)|airtel\s*dth
            |videocon(?:\s*d2h)?|sun\s*direct
            |electricity(?:\s*(?:bill|connection|board))?
            |power\s*(?:bill|connection)|water\s*(?:bill|connection)
            |piped\s*gas|gas\s*(?:connection|bill)|broadband|landline
        )\b
        """,
    )

    private val SERVICE_DISRUPTION_RE = regex(
        """
        \b(?:
            disconnect(?:ed|ion)?|cut\s*off|suspend(?:ed|ing|ion)?
            |deactivat(?:e|ed|ion)|block(?:ed|ing)?
            |halt(?:ed|ing)?|stop(?:ped|ping)?|expir(?:e[sd]?|ing|y)
        )\b
        """,
    )

    private val TASK_ACTIVITY_RE = regex(
        """
        \b(?:
            lik(?:e|ing)|comment(?:ing)?|sharing|share
            |rating|review(?:er|ing|s|ed)?|survey(?:s)?
            |data\s*entry|captcha(?:s)?|typing
            |watch(?:ing)?\s+(?:videos?|ads?|advertisements?)
            |simple\s+tasks?|micro\s*tasks?
        )\b
        """,
    )

    private val TASK_EARNING_RE = regex(
        """
        \b(?:earn(?:ing)?(?:\s+money)?|get\s+paid|paid|get|receive|make)\b
        .{0,60}?
        (?:\b(?:rs\.?|inr|₹|\${'$'})\s*\d+
           |\b\d+\s*(?:per|/)\s*(?:day|review|task|like|post|hour))
        """,
    )

    private val REMOTE_CHANNEL_RE = regex(
        """\b(?:telegram|t\.me|whatsapp|wa\.me|instagram|facebook|social\s+media)\b""",
    )

    private val TELECOM_CONTEXT_RE = regex(
        """
        \b(?:
            jio|airtel|vodafone|vi\b|bsnl|sim|4g|5g
            |data\s*(?:plan|pack|balance)|recharge
            |unlimited\s*calls?|mobile\s+number
        )\b
        """,
    )

    private val TELECOM_UNREALISTIC_RE = regex(
        """
        \b(?:
            (?:50|75|100|150|200)\s*gb
            |(?:rs\.?|inr|₹)\s*[1-9]\s*recharge
            |data\s*pack\s*free
            |free\s*(?:5g|recharge|data|sim|plan)
            |unlimited\s*(?:5g|data)\s*offer
            |just\s*(?:rs\.?|inr|₹)\s*\d{1,3}
        )\b
        """,
    )

    private val DOCUMENT_NOUN_RE = regex(
        """
        \b(?:
            aadhaar|aadhar|pan(?:\s+card)?|marksheet|mark\s*sheet
            |class\s*(?:10|12)|documents?|digilocker
            |driving\s+licen[cs]e|passport|voter\s*id
            |identity\s+proof|bank\s+details
        )\b
        """,
    )

    private val DOCUMENT_ACTION_RE = regex(
        """\b(?:re-?upload|upload|share|submit|send|verify|update|complete|provide)\b""",
    )

    private val DOCUMENT_RISK_RE = regex(
        """\b(?:corrupt(?:ed)?|expired?|mismatch|pending|failed|blocked?|invalid|hold|re-?verify|re-?upload)\b""",
    )

    private val GADGET_RE = regex(
        """
        \b(?:
            iphone|ipad|macbook|playstation(?:\s*5)?|ps5|xbox
            |nintendo\s*switch|graphics\s*card|gpu|samsung\s*galaxy
            |oneplus|google\s*pixel
        )\b
        """,
    )

    private val GADGET_SCARCITY_RE = regex(
        """
        \b(?:
            pre-?book|pre-?order|only\s+\d+\s+units?
            |limited\s+(?:stock|units?)|50%\s*(?:off|discount)
            |discount|sale
        )\b
        """,
    )

    private val GADGET_COMMITMENT_RE = regex(
        """\b(?:book\s+for|pre-?book|pre-?order|token|advance|deposit)\b""",
    )

    private val APK_URL_RE = regex("""\.apk(?:[/?]|\#|\z)""")
    private val APK_MENTION_RE = regex("""\b(?:apk|patch\s+configuration|configuration\s+app)\b""")

    private val DELIVERY_PROBLEM_RE = regex(
        """
        \b(?:
            could\s+not\s+deliver|couldn'?t\s+deliver|failed\s+delivery
            |delivery\s+failed|missed\s+delivery|not\s+delivered
            |address\s+(?:is\s+)?incomplete|address\s+(?:confirmation|verification)
            |return(?:ed)?\s+to\s+sender|avoid\s+return
            |import\s+duty|customs\s+duty|pending\s+duty
            |reschedule\s+delivery|update\s+(?:delivery\s+)?(?:address|location|coordinates)
        )\b
        """,
    )

    private val SERVICE_INTERRUPTION_RE = regex(
        """
        \b(?:
            storage\s+(?:is\s+)?full
            |will\s+(?:stop\s+receiving|stop\s+working|be\s+(?:stopped|halted|disconnected|deactivated|suspended))
            |service\s+(?:will\s+be\s+)?(?:stopped|halted|interrupted|disrupted|disconnected|deactivated|suspended)
            |account\s+(?:will\s+be\s+)?(?:stopped|suspended|blocked|deactivated)
        )\b
        """,
    )

    private val SERVICE_RECOVERY_ACTION_RE = regex(
        """\b(?:upgrade|renew|verify|update|pay|continue|restore|reactivate|click|download)\b""",
    )

    private val PAYMENT_ACTION_RE = regex(
        """\b(?:pay|payment|transfer|remit|deposit|send\s+money|scan|clear|settle)\b""",
    )

    private val PAYMENT_TARGET_RE = regex(
        """
        (?:rs\.?|inr|₹|\${'$'}|£|€|usd|gbp|eur|\bmoney\b|\bamount\b|\bfee\b|\bcharge\b|\bupi\b|\bqr\b|\baccount\b|\bnumber\b|\bwallet\b|\bpayee\b)
        """,
    )

    private val PAYMENT_FEE_RE = regex(
        """
        \b(?:
            processing|registration|security|clearance|customs|delivery|handling
            |service|activation|verification|documentation|starter|training|membership|subscription
        )\s+(?:fee|charge|amount|payment|cost|kit)\b
        |\b(?:registration|processing|security|clearance|customs|delivery|handling|activation|verification|documentation)
           \s+(?:₹|rs\.?|inr|\${'$'}|£|€|usd|gbp|eur)\s*[\d,]+
        """,
    )

    private val PAYMENT_IMPERATIVE_RE = regex(
        """
        \b(?:
            pay\s+now|make\s+(?:a\s+)?payment|complete\s+(?:the\s+)?payment
            |please\s+pay|kindly\s+pay|pay\s+(?:the\s+)?(?:fee|amount|money)
            |transfer\s+(?:the\s+)?(?:amount|money|rs|inr)
            |send\s+(?:the\s+)?(?:amount|money|rs|inr)
            |scan\s+(?:the\s+)?qr
            |deposit\s+(?:the\s+)?(?:amount|money|fee)
        )\b
        """,
    )

    private val PAYMENT_SUCCESS_RE = regex(
        """\b(?:payment\s+(?:was\s+)?successful|payment\s+received|has\s+been\s+(?:debited|credited)|transaction\s+(?:was\s+)?successful|amount\s+(?:debited|credited))\b""",
    )

    private val PAYMENT_SUCCESS_HINT_RE = regex(
        """\b(?:please|kindly|now|click|scan|transfer|send|deposit|pay)\b""",
    )

    private val NEGATION_RE = regex(
        """\b(?:do\s+not|don't|never|not|no\s+need\s+to|we\s+never\s+ask\s+you\s+to|will\s+never\s+ask)\b""",
    )

    private val PAYMENT_NEGATION_RE = regex(
        """\b(?:no|without|zero)\s+(?:\w+\s+){0,2}(?:fee|charge|payment|cost)s?\b""",
    )

    private val TRANSACTION_RE = regex(
        """
        \b(?:
            auto[-\x20]?debit(?:ed)?|debited|credited|withdrawn|deposited|refilled
            |transaction\s+(?:was\s+)?successful
            |payment\s+(?:was\s+)?successful|payment\s+received
            |amount\s+(?:debited|credited)
            |account\s+(?:debited|credited)
        )\b
        """,
    )

    private val CALL_ACTION_RE = regex("""\b(?:call|dial|contact)\b""")

    private val DELIVERY_SUCCESS_RE = regex(
        """
        \b(?:
            (?:order|parcel|package|shipment|consignment).{0,40}(?:delivered|arrived)
            |(?:delivered|arrived)\s+today
            |out\s+for\s+delivery
        )\b
        """,
    )

    private val TRANSACTIONAL_SENDER_RE = Regex(
        """(?:[A-Z]{2}-[A-Z0-9]{3,}|[A-Z]{5,9}|\d{5,6})""",
    )

    private val DLT_MOBILE_RE = Regex("""\+?(?:91)?[6-9]\d{9}""")

    fun analyze(
        rawText: String,
        sender: String? = null,
        knownSender: Boolean = false,
    ): Tier1EvidenceResult {
        val norm = SmsNormalizer.normalize(rawText)
        val lower = norm.normalized.lowercase(Locale.ROOT)
        val accessText = norm.modelText.lowercase(Locale.ROOT)
        val flags = linkedMapOf<String, Boolean>()
        for (code in Codes.EVIDENCE_CODES) flags[code] = false

        flags[Codes.URL_PRESENT] = norm.urls.isNotEmpty()
        flags[Codes.EMAIL_PRESENT] = norm.emails.isNotEmpty()
        flags[Codes.PHONE_PRESENT] = norm.phones.isNotEmpty()
        flags[Codes.LONG_DIGIT_STRING] = norm.flags["long_digit_string"] == true
        flags[Codes.OBFUSCATED_TEXT] = norm.flags["obfuscated"] == true
        flags[Codes.URGENCY_LANGUAGE] = URGENCY_RE.containsMatchIn(lower)
        flags[Codes.ACCOUNT_THREAT] = ACCOUNT_THREAT_RE.containsMatchIn(lower)
        flags[Codes.THREAT_OF_ACTION] = THREAT_OF_ACTION_RE.containsMatchIn(lower)
        flags[Codes.KYC_LANGUAGE] = KYC_RE.containsMatchIn(lower)
        flags[Codes.PRIZE_OR_REWARD_BAIT] = PRIZE_RE.containsMatchIn(lower)
        flags[Codes.PROMOTIONAL_CONTENT] = PROMOTIONAL_RE.containsMatchIn(lower)
        flags[Codes.LOAN_OR_INVESTMENT_BAIT] = LOAN_INVESTMENT_RE.containsMatchIn(lower)
        flags[Codes.DELIVERY_BAIT] = DELIVERY_RE.containsMatchIn(lower)
        flags[Codes.IMPERSONATION] = IMPERSONATION_RE.containsMatchIn(lower)
        flags[Codes.REFUND_BAIT] = REFUND_RE.containsMatchIn(lower)
        flags[Codes.JOB_OFFER_BAIT] = JOB_RE.containsMatchIn(lower)

        val accountAccess = ACCOUNT_ACCESS_ACTION_RE.containsMatchIn(accessText) ||
            (
                ACCOUNT_ACCESS_CREDENTIAL_RE.containsMatchIn(accessText) &&
                    ACCOUNT_ACCESS_CONTEXT_RE.containsMatchIn(accessText)
                )
        flags[Codes.ACCOUNT_ACCESS_LURE] = flags[Codes.URL_PRESENT] == true &&
            accountAccess &&
            !ACCOUNT_ALERT_SUPPRESS_RE.containsMatchIn(lower)

        flags[Codes.CREDENTIAL_REQUEST] = requestContext(
            accessText, REQUEST_VERB_RE, CREDENTIAL_NOUN_RE, window = 60,
        )
        flags[Codes.OTP_REQUEST] = requestContext(
            accessText, REQUEST_VERB_RE, OTP_NOUN_RE, window = 40,
        )
        flags[Codes.PAYMENT_REQUEST] = paymentRequest(lower)

        val urlPresent = flags[Codes.URL_PRESENT] == true
        val apkDownload = urlPresent && (
            norm.urls.any { APK_URL_RE.containsMatchIn(it) } ||
                APK_MENTION_RE.containsMatchIn(lower)
            )

        val dthUtility = DTH_PROVIDER_RE.containsMatchIn(lower) &&
            SERVICE_DISRUPTION_RE.containsMatchIn(lower) &&
            (urlPresent || flags[Codes.PAYMENT_REQUEST] == true || flags[Codes.URGENCY_LANGUAGE] == true)

        val taskScam = TASK_ACTIVITY_RE.containsMatchIn(lower) &&
            TASK_EARNING_RE.containsMatchIn(lower) &&
            (urlPresent || REMOTE_CHANNEL_RE.containsMatchIn(lower))

        val telecomLure = urlPresent &&
            TELECOM_CONTEXT_RE.containsMatchIn(lower) &&
            (apkDownload || TELECOM_UNREALISTIC_RE.containsMatchIn(lower))

        val dataHarvesting = urlPresent &&
            DOCUMENT_NOUN_RE.containsMatchIn(lower) &&
            DOCUMENT_ACTION_RE.containsMatchIn(lower) &&
            DOCUMENT_RISK_RE.containsMatchIn(lower)

        val highDemandGadget = urlPresent &&
            GADGET_RE.containsMatchIn(lower) &&
            GADGET_SCARCITY_RE.containsMatchIn(lower) &&
            GADGET_COMMITMENT_RE.containsMatchIn(lower)

        val deliveryUpdate = urlPresent &&
            flags[Codes.DELIVERY_BAIT] == true &&
            DELIVERY_PROBLEM_RE.containsMatchIn(lower)

        val serviceInterruption = urlPresent &&
            SERVICE_INTERRUPTION_RE.containsMatchIn(lower) &&
            SERVICE_RECOVERY_ACTION_RE.containsMatchIn(lower)

        flags[Codes.DTH_UTILITY_THREAT] = dthUtility
        flags[Codes.TASK_SCAM] = taskScam
        flags[Codes.TELECOM_LURE] = telecomLure
        flags[Codes.DATA_HARVESTING] = dataHarvesting
        flags[Codes.HIGH_DEMAND_GADGET_SCAM] = highDemandGadget
        flags[Codes.APK_DOWNLOAD_LURE] = apkDownload
        flags[Codes.DELIVERY_UPDATE_LURE] = deliveryUpdate
        flags[Codes.SERVICE_INTERRUPTION_LURE] = serviceInterruption

        val benignBlockers = listOf(
            Codes.URL_PRESENT,
            Codes.OTP_REQUEST,
            Codes.CREDENTIAL_REQUEST,
            Codes.ACCOUNT_ACCESS_LURE,
            Codes.ACCOUNT_THREAT,
            Codes.THREAT_OF_ACTION,
            Codes.PAYMENT_REQUEST,
            Codes.PRIZE_OR_REWARD_BAIT,
            Codes.LOAN_OR_INVESTMENT_BAIT,
            Codes.DELIVERY_BAIT,
            Codes.JOB_OFFER_BAIT,
            Codes.KYC_LANGUAGE,
            Codes.URGENCY_LANGUAGE,
            Codes.PROMOTIONAL_CONTENT,
            Codes.DTH_UTILITY_THREAT,
            Codes.TASK_SCAM,
            Codes.TELECOM_LURE,
            Codes.DATA_HARVESTING,
            Codes.HIGH_DEMAND_GADGET_SCAM,
            Codes.APK_DOWNLOAD_LURE,
            Codes.DELIVERY_UPDATE_LURE,
            Codes.SERVICE_INTERRUPTION_LURE,
        )
        flags[Codes.BENIGN_TRANSACTIONAL] = TRANSACTION_RE.containsMatchIn(lower) &&
            benignBlockers.none { flags[it] == true } &&
            !(flags[Codes.PHONE_PRESENT] == true && CALL_ACTION_RE.containsMatchIn(lower))

        val deliveryBlockers = benignBlockers.filter { it != Codes.DELIVERY_BAIT } +
            Codes.REFUND_BAIT
        flags[Codes.BENIGN_DELIVERY] = DELIVERY_SUCCESS_RE.containsMatchIn(lower) &&
            deliveryBlockers.none { flags[it] == true } &&
            !(flags[Codes.PHONE_PRESENT] == true && CALL_ACTION_RE.containsMatchIn(lower))

        senderFlags(flags, sender, knownSender)

        val strongCount = Codes.STRONG_CODES.count { flags[it] == true }
        flags[Codes.MULTIPLE_SOCIAL_ENGINEERING_CUES] = strongCount >= 2 ||
            (
                strongCount >= 1 &&
                    (urlPresent || flags[Codes.URGENCY_LANGUAGE] == true) &&
                    (flags[Codes.ACCOUNT_THREAT] == true ||
                        flags[Codes.IMPERSONATION] == true ||
                        flags[Codes.PROMOTIONAL_CONTENT] == true)
                )

        val newCodes = Codes.NEW_HARDENING_CODES.filter { flags[it] == true }
        return Tier1EvidenceResult(normalized = norm, flags = flags, newCodes = newCodes)
    }

    private fun requestContext(
        text: String,
        verbRe: Regex,
        nounRe: Regex,
        window: Int,
    ): Boolean {
        for (verb in verbRe.findAll(text)) {
            if (isNegated(text, verb.range.first)) continue
            val start = verb.range.last + 1
            val end = minOf(text.length, start + window)
            if (nounRe.containsMatchIn(text.substring(start, end))) return true
        }
        for (noun in nounRe.findAll(text)) {
            val start = noun.range.last + 1
            val end = minOf(text.length, start + window)
            val tail = text.substring(start, end)
            for (verb in verbRe.findAll(tail)) {
                val absolute = start + verb.range.first
                if (!isNegated(text, absolute)) return true
            }
        }
        return false
    }

    private fun senderFlags(
        flags: MutableMap<String, Boolean>,
        sender: String?,
        knownSender: Boolean,
    ) {
        val trimmed = sender?.trim().orEmpty()
        if (trimmed.isEmpty()) return
        val transactional = TRANSACTIONAL_SENDER_RE.matches(trimmed)
        if (!knownSender && !transactional) flags[Codes.SENDER_ID_UNVERIFIED] = true
        val normalizedSender = trimmed.replace(Regex("""[\s-]"""), "")
        if (
            (flags[Codes.IMPERSONATION] == true ||
                flags[Codes.KYC_LANGUAGE] == true ||
                flags[Codes.ACCOUNT_THREAT] == true) &&
            DLT_MOBILE_RE.matches(normalizedSender)
        ) {
            flags[Codes.SENDER_CLAIM_MISMATCH] = true
        }
    }

    private fun paymentRequest(text: String): Boolean {
        if (PAYMENT_SUCCESS_RE.containsMatchIn(text) &&
            !PAYMENT_SUCCESS_HINT_RE.containsMatchIn(text)
        ) {
            return false
        }
        if (PAYMENT_NEGATION_RE.containsMatchIn(text)) return false

        val fee = PAYMENT_FEE_RE.find(text)
        val imperative = PAYMENT_IMPERATIVE_RE.find(text)
        if (fee != null || imperative != null) {
            val match = fee ?: imperative!!
            if (isNegated(text, match.range.first)) return false
            return true
        }

        for (verb in PAYMENT_ACTION_RE.findAll(text)) {
            if (isNegated(text, verb.range.first)) continue
            val start = verb.range.last + 1
            val end = minOf(text.length, start + 60)
            val tail = text.substring(start, end)
            if (PAYMENT_TARGET_RE.containsMatchIn(tail)) return true
        }
        return false
    }

    private fun isNegated(text: String, position: Int, window: Int = 32): Boolean {
        val start = maxOf(0, position - window)
        return NEGATION_RE.containsMatchIn(text.substring(start, position))
    }

    private fun regex(block: String): Regex {
        val pattern = block.trimIndent()
        return try {
            Regex("(?U)$pattern", setOf(RegexOption.IGNORE_CASE, RegexOption.COMMENTS))
        } catch (_: Throwable) {
            Regex(pattern, setOf(RegexOption.IGNORE_CASE, RegexOption.COMMENTS))
        }
    }
}
