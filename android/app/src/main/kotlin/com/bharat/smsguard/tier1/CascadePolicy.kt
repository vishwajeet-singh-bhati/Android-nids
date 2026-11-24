package com.bharat.smsguard.tier1

/** Provisional routing/fusion, separate from model scores. No calibration claim. */
object CascadePolicy {
    private val growth = Regex("(?i)\\b(?:double|triple|2x|3x)\\s+(?:your\\s+)?(?:money|investment|capital)\\b")
    private val shortTerm = Regex("(?i)\\b(?:in|within)\\s+(?:[1-7]|one|two|three|four|five|six|seven)\\s+(?:hours?|days?)\\b")
    private val caution = Regex("(?i)\\b(?:beware of|avoid|do not trust|never trust|do not believe|not possible|cannot)\\b")
    fun returnPromise(text: String) = growth.containsMatchIn(text) && shortTerm.containsMatchIn(text) && !caution.containsMatchIn(text)
    fun shouldRoute(first: Tier1Detection): Boolean {
        if (RoutineMessages.reason(first) != null) return false
        val flags = first.evidence.flags
        if (flags[Codes.BENIGN_TRANSACTIONAL] == true || flags[Codes.BENIGN_DELIVERY] == true) return false
        return first.label != "ham" || first.riskLevel != "low" || first.assessment.ruleTriggered ||
            flags[Codes.URL_PRESENT] == true || first.prediction.probability("ham") < 0.90 ||
            returnPromise(first.evidence.normalized.normalized)
    }
    fun fuse(first: Tier1Detection, scores: Map<String, Double>): Tier1Detection {
        val flags = first.evidence.flags
        val promise = returnPromise(first.evidence.normalized.normalized)
        val ordinaryPromotion = first.label == "spam" && first.riskLevel == "low" &&
            flags[Codes.PROMOTIONAL_CONTENT] == true && first.evidence.strongCueCount() == 0 && !promise
        val neuralLabel = scores.maxBy { it.value }.key
        val label = when {
            first.riskLevel == "high" || ordinaryPromotion -> first.label
            first.label == "ham" && first.riskLevel == "low" && neuralLabel == "spam" &&
                first.evidence.strongCueCount() == 0 && !promise -> "ham"
            promise && neuralLabel == "ham" -> "spam"
            else -> neuralLabel
        }
        val risk = when {
            first.riskLevel == "high" -> "high"
            ordinaryPromotion -> "low"
            promise || label == "smishing" || first.riskLevel == "suspicious" -> "suspicious"
            else -> "low"
        }
        return first.copy(assessment = first.assessment.copy(label = label, riskLevel = risk,
            scores = scores, reasonCodes = first.assessment.reasonCodes + if (promise) listOf("UNREALISTIC_RETURN_PROMISE") else emptyList(),
            recommendedActionCodes = ActionCodes.forResult(label, risk, flags)))
    }
}
