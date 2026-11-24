package com.bharat.smsguard.tier1

import java.util.Locale

/** Narrow semantic fast paths, never a blanket "short SMS is safe" rule. */
object RoutineMessages {
    private val greetings = setOf("hi", "hii", "hiii", "hello", "hey", "namaste", "namaskar",
        "good morning", "goodmorning", "good afternoon", "good evening", "good night", "goodnight",
        "how are you", "kaise ho", "kya haal hai", "नमस्ते", "नमस्कार", "ok", "okay", "thanks", "thank you")
    private val spaces = Regex("[\\s\\p{Z}\\u0085\\u001c-\\u001f]+")
    private val otpNotice = Regex("(?i)\\b(?:otp|verification code|one[- ]time password)\\s*(?:is\\s*)?[:=-]?\\s*\\d{4,8}\\b")
    private val safeAdvice = Regex("(?i)\\b(?:do not|don't|never)\\s+(?:share|disclose|reveal|tell|forward)\\b[^.?!;,\\n]*")
    private val action = Regex("(?i)\\b(?:send|share|tell|forward|reply|call|pay|transfer|install|download|provide|enter|submit|click|scan)\\b")

    fun reason(first: Tier1Detection): String? {
        val e = first.evidence
        val text = spaces.replace(e.normalized.normalized, " ").trim().lowercase(Locale.ROOT)
        // A bare link contains no prose for the SMS semantic classifier. The
        // independent URL pipeline still checks every extracted link.
        val prose = e.normalized.modelText.replace("url_present", " ")
        if (e.normalized.urls.isNotEmpty() && e.normalized.emails.isEmpty() &&
            e.normalized.phones.isEmpty() && prose.none { it.isLetterOrDigit() }) return "link_only"
        // A standalone congratulations phrase requests no action. Do not extend
        // this to prize claims with links, fees, contacts or further instructions.
        val celebration = text.trimEnd('.', '!', '?').trim()
        if (celebration in setOf("you won", "we won", "i won", "congratulations", "congrats", "well done") &&
            !e.has(Codes.URL_PRESENT) && !e.has(Codes.EMAIL_PRESENT) && !e.has(Codes.PHONE_PRESENT) &&
            Codes.STRONG_CODES.filter { it != Codes.PRIZE_OR_REWARD_BAIT }.none { e.has(it) }) return "simple_celebration"
        // Evaluate evidence before any bypass; sender formatting alone is not a threat.
        if (e.strongCueCount() > 0 || e.has(Codes.URL_PRESENT) || e.has(Codes.EMAIL_PRESENT) ||
            e.has(Codes.PHONE_PRESENT) || CascadePolicy.returnPromise(text)) return null
        if (text.trimEnd('.', '!', '?') in greetings) return "greeting"
        if (otpNotice.containsMatchIn(text) && !action.containsMatchIn(safeAdvice.replace(text, " "))) return "otp_notice"
        if (e.has(Codes.BENIGN_TRANSACTIONAL)) return "routine_transaction"
        if (e.has(Codes.BENIGN_DELIVERY)) return "routine_delivery"
        if (first.label == "spam" && first.riskLevel == "low" && e.has(Codes.PROMOTIONAL_CONTENT)) return "ordinary_promotion"
        return null
    }

    fun apply(first: Tier1Detection, reason: String): Tier1Detection {
        val label = if (reason == "ordinary_promotion") "spam" else "ham"
        return first.copy(assessment = first.assessment.copy(label = label, riskLevel = "low",
            recommendedActionCodes = ActionCodes.forResult(label, "low", first.evidence.flags)))
    }
}
