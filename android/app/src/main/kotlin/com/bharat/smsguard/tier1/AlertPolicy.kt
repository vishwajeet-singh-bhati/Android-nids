package com.bharat.smsguard.tier1

/** Notification urgency is separate from certainty of the detector verdict. */
object AlertPolicy {
    fun financialRisk(result: Tier1Detection): Boolean {
        if (result.riskLevel == "low") return false
        val monetary = listOf(Codes.PAYMENT_REQUEST, Codes.LOAN_OR_INVESTMENT_BAIT,
            Codes.PRIZE_OR_REWARD_BAIT, Codes.REFUND_BAIT, Codes.TASK_SCAM)
        return monetary.any { result.evidence.has(it) } ||
            "UNREALISTIC_RETURN_PROMISE" in result.assessment.reasonCodes
    }

    fun attentionRequired(result: Tier1Detection) = result.riskLevel == "high" || financialRisk(result)

    /** Fast evidence-backed review can notify without waiting for neural loading. */
    fun preliminary(first: Tier1Detection): Tier1Detection {
        if (!CascadePolicy.returnPromise(first.evidence.normalized.normalized)) return first
        val risk = if (first.riskLevel == "high") "high" else "suspicious"
        return first.copy(assessment = first.assessment.copy(riskLevel = risk,
            reasonCodes = (first.assessment.reasonCodes + "UNREALISTIC_RETURN_PROMISE").distinct(),
            recommendedActionCodes = ActionCodes.forResult(first.label, risk, first.evidence.flags)))
    }
}
