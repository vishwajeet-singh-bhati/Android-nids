package com.bharat.smsguard.tier1

data class RulesDecision(
    val label: String,
    val scores: Map<String, Double>,
    val reasonCodes: List<String> = emptyList(),
)

data class RiskAssessment(
    val label: String,
    val riskLevel: String,
    val scores: Map<String, Double>,
    val recommendedActionCodes: List<String>,
    val policyVersion: String,
    val ruleLabel: String,
    val ruleTriggered: Boolean,
    val reasonCodes: List<String>,
)

object RuleBasedClassifier {
    fun classify(evidence: Tier1EvidenceResult): RulesDecision {
        val flags = evidence.flags
        fun has(vararg codes: String) = codes.all { flags[it] == true }
        fun anyOf(vararg codes: String) = codes.any { flags[it] == true }
        val reasons = mutableListOf<String>()

        if (has(Codes.OTP_REQUEST)) reasons += Codes.OTP_REQUEST
        if (has(Codes.CREDENTIAL_REQUEST)) reasons += Codes.CREDENTIAL_REQUEST
        if (has(Codes.ACCOUNT_ACCESS_LURE)) reasons += Codes.ACCOUNT_ACCESS_LURE

        if (has(Codes.PAYMENT_REQUEST) && anyOf(
                Codes.ACCOUNT_THREAT,
                Codes.URGENCY_LANGUAGE,
                Codes.URL_PRESENT,
                Codes.IMPERSONATION,
                Codes.THREAT_OF_ACTION,
                Codes.PRIZE_OR_REWARD_BAIT,
            )
        ) {
            reasons += Codes.PAYMENT_REQUEST
        }

        if (has(Codes.ACCOUNT_THREAT) && flags[Codes.URL_PRESENT] == true && anyOf(
                Codes.URGENCY_LANGUAGE,
                Codes.KYC_LANGUAGE,
                Codes.IMPERSONATION,
                Codes.THREAT_OF_ACTION,
            )
        ) {
            reasons += Codes.ACCOUNT_THREAT
        }

        if (has(Codes.PRIZE_OR_REWARD_BAIT) && anyOf(
                Codes.PAYMENT_REQUEST,
                Codes.URL_PRESENT,
                Codes.URGENCY_LANGUAGE,
                Codes.CREDENTIAL_REQUEST,
            )
        ) {
            reasons += Codes.PRIZE_OR_REWARD_BAIT
        }

        if (anyOf(Codes.LOAN_OR_INVESTMENT_BAIT, Codes.JOB_OFFER_BAIT, Codes.DELIVERY_BAIT) &&
            anyOf(Codes.PAYMENT_REQUEST, Codes.CREDENTIAL_REQUEST, Codes.OTP_REQUEST)
        ) {
            reasons += "FEE_OR_CREDENTIAL_LURE"
        }

        if (has(Codes.REFUND_BAIT) && anyOf(
                Codes.CREDENTIAL_REQUEST,
                Codes.OTP_REQUEST,
                Codes.PAYMENT_REQUEST,
            )
        ) {
            reasons += Codes.REFUND_BAIT
        }

        for (code in Codes.NEW_HARDENING_CODES) {
            if (has(code)) reasons += code
        }

        if (reasons.isNotEmpty()) {
            return RulesDecision("smishing", ruleScores("smishing"), reasons.toList())
        }

        val spamLure = anyOf(
            Codes.PROMOTIONAL_CONTENT,
            Codes.LOAN_OR_INVESTMENT_BAIT,
            Codes.JOB_OFFER_BAIT,
            Codes.PRIZE_OR_REWARD_BAIT,
        ) || (
            flags[Codes.DELIVERY_BAIT] == true &&
                anyOf(
                    Codes.URL_PRESENT,
                    Codes.PAYMENT_REQUEST,
                    Codes.URGENCY_LANGUAGE,
                    Codes.ACCOUNT_THREAT,
                )
            )
        if (spamLure) {
            return RulesDecision("spam", ruleScores("spam"), listOf("PROMOTIONAL_OR_LURE"))
        }
        return RulesDecision("ham", ruleScores("ham"))
    }

    private fun ruleScores(label: String): Map<String, Double> {
        val scores = linkedMapOf("ham" to 0.1, "spam" to 0.1, "smishing" to 0.1)
        scores[label] = 0.8
        return scores
    }
}

class RiskPolicy(
    val highThreshold: Double = 0.80,
    val suspiciousThreshold: Double = 0.45,
    val evidenceFreeHighThreshold: Double = 0.80,
    val policyVersion: String = "policy-0.2-review",
) {
    fun assess(
        scores: Map<String, Double>,
        evidence: Tier1EvidenceResult,
    ): RiskAssessment {
        val probabilities = normaliseScores(scores)
        val modelLabel = LABELS.maxByOrNull { probabilities[it] ?: 0.0 } ?: "ham"
        val pSmishing = probabilities["smishing"] ?: 0.0
        val flags = evidence.flags
        val rules = RuleBasedClassifier.classify(evidence)
        val ruleLabel = rules.label
        val ruleSmishing = ruleLabel == "smishing"

        val criticalRule = flags[Codes.OTP_REQUEST] == true ||
            flags[Codes.CREDENTIAL_REQUEST] == true ||
            flags[Codes.ACCOUNT_ACCESS_LURE] == true ||
            (
                flags[Codes.PAYMENT_REQUEST] == true &&
                    (flags[Codes.ACCOUNT_THREAT] == true || flags[Codes.THREAT_OF_ACTION] == true)
                )
        val patternRule = Codes.NEW_HARDENING_CODES.any { flags[it] == true }
        val overrideRule = criticalRule || patternRule
        val strongCount = evidence.strongCueCount()
        val pHigh = pSmishing >= highThreshold
        val pVeryHigh = pSmishing >= evidenceFreeHighThreshold
        val evidenceHigh = strongCount > 0 || ruleSmishing || criticalRule
        val highSupported = pHigh && (evidenceHigh || pVeryHigh)

        var risk = "low"
        if (modelLabel == "smishing") {
            risk = if (highSupported) "high" else "suspicious"
        }

        if (ruleSmishing) {
            if (overrideRule && (flags[Codes.URL_PRESENT] == true || pSmishing >= suspiciousThreshold)) {
                risk = "high"
            } else if (highSupported || (pSmishing >= suspiciousThreshold && strongCount >= 2)) {
                risk = "high"
            } else if (risk == "low") {
                risk = "suspicious"
            }
        }

        if (highSupported) {
            risk = "high"
        } else if (pSmishing >= suspiciousThreshold && risk == "low") {
            risk = "suspicious"
        }

        var label = modelLabel
        if (overrideRule && (flags[Codes.URL_PRESENT] == true || pSmishing >= suspiciousThreshold)) {
            label = "smishing"
        } else if (ruleSmishing && pSmishing >= suspiciousThreshold) {
            label = "smishing"
        } else if (modelLabel == "ham" && ruleLabel == "spam" && risk == "suspicious") {
            label = "spam"
        }
        if (risk == "high") {
            label = "smishing"
        } else if (label == "smishing" && risk == "low") {
            risk = "suspicious"
        }

        if (flags[Codes.BENIGN_TRANSACTIONAL] == true || flags[Codes.BENIGN_DELIVERY] == true) {
            label = "ham"
            risk = "low"
        }

        // Context patterns can also describe legitimate service messages.
        val explicitSecretRequest = flags[Codes.OTP_REQUEST] == true ||
            flags[Codes.CREDENTIAL_REQUEST] == true || flags[Codes.ACCOUNT_ACCESS_LURE] == true
        if (patternRule && !explicitSecretRequest) {
            label = modelLabel
            risk = "suspicious"
        }
        if (!ruleSmishing && modelLabel != "smishing" && !highSupported) {
            risk = "low"
        }

        return RiskAssessment(
            label = label,
            riskLevel = risk,
            scores = probabilities,
            recommendedActionCodes = ActionCodes.forResult(label, risk, flags),
            policyVersion = policyVersion,
            ruleLabel = ruleLabel,
            ruleTriggered = ruleLabel != "ham",
            reasonCodes = rules.reasonCodes,
        )
    }

    private fun normaliseScores(scores: Map<String, Double>): Map<String, Double> {
        val values = linkedMapOf<String, Double>()
        for (label in LABELS) values[label] = maxOf(0.0, scores[label] ?: 0.0)
        val total = values.values.sum()
        if (total <= 0.0) {
            val uniform = 1.0 / LABELS.size
            return LABELS.associateWith { uniform }
        }
        return LABELS.associateWith { (values[it] ?: 0.0) / total }
    }

    companion object {
        val LABELS = listOf("ham", "spam", "smishing")

        /** Thresholds selected on validation and recorded in artifacts/model/metadata.json. */
        fun production(): RiskPolicy = RiskPolicy(
            highThreshold = 0.385,
            suspiciousThreshold = 0.1009090909090909,
            evidenceFreeHighThreshold = 0.80,
        )
    }
}

object ActionCodes {
    private val ORDER = mapOf(
        "NO_ACTION" to 0,
        "MARK_AS_SPAM" to 1,
        "DO_NOT_INTERACT" to 2,
        "DO_NOT_CLICK" to 3,
        "DO_NOT_SHARE_OTP" to 4,
        "DO_NOT_SHARE_PERSONAL_INFO" to 5,
        "DO_NOT_SEND_MONEY" to 6,
        "VERIFY_BEFORE_ACTING" to 7,
        "VERIFY_USING_OFFICIAL_CHANNEL" to 8,
        "REPORT_AS_SCAM" to 9,
    )

    fun forResult(
        label: String,
        riskLevel: String,
        flags: Map<String, Boolean>,
    ): List<String> {
        val actions = mutableListOf<String>()
        if (riskLevel == "high") {
            if (flags[Codes.URL_PRESENT] == true) actions += "DO_NOT_CLICK"
            if (flags[Codes.OTP_REQUEST] == true ||
                flags[Codes.CREDENTIAL_REQUEST] == true ||
                flags[Codes.ACCOUNT_ACCESS_LURE] == true
            ) {
                actions += "DO_NOT_SHARE_OTP"
                actions += "DO_NOT_SHARE_PERSONAL_INFO"
            }
            if (flags[Codes.PAYMENT_REQUEST] == true) actions += "DO_NOT_SEND_MONEY"
            actions += "VERIFY_USING_OFFICIAL_CHANNEL"
            actions += "REPORT_AS_SCAM"
        } else if (riskLevel == "suspicious") {
            if (flags[Codes.URL_PRESENT] == true) actions += "DO_NOT_CLICK"
            if (flags[Codes.OTP_REQUEST] == true ||
                flags[Codes.CREDENTIAL_REQUEST] == true ||
                flags[Codes.ACCOUNT_ACCESS_LURE] == true
            ) {
                actions += "DO_NOT_SHARE_OTP"
                actions += "DO_NOT_SHARE_PERSONAL_INFO"
            }
            if (flags[Codes.PAYMENT_REQUEST] == true) actions += "DO_NOT_SEND_MONEY"
            actions += "VERIFY_BEFORE_ACTING"
        } else if (label == "spam") {
            actions += "MARK_AS_SPAM"
            actions += "DO_NOT_INTERACT"
        } else {
            actions += "NO_ACTION"
        }
        return actions.distinct().sortedBy { ORDER[it] ?: 99 }
    }
}
