package com.bharat.smsguard.tier1

/**
 * End-to-end desktop-JVM Tier-1 detector: normalization, evidence, portable
 * word TF-IDF probabilities, and risk fusion. Android receiver/service code is
 * intentionally outside this class.
 */
data class Tier1Detection(
    val evidence: Tier1EvidenceResult,
    val prediction: PortablePrediction,
    val assessment: RiskAssessment,
) {
    val label: String get() = assessment.label
    val riskLevel: String get() = assessment.riskLevel
    val actionCodes: List<String> get() = assessment.recommendedActionCodes
}

class Tier1Detector(
    private val model: PortableLinearModel,
    private val policy: RiskPolicy = RiskPolicy.production(),
) {
    fun predict(
        rawText: String,
        sender: String? = null,
        knownSender: Boolean = false,
    ): Tier1Detection {
        val evidence = Tier1Evidence.analyze(rawText, sender, knownSender)
        val prediction = model.predictModelText(evidence.normalized.modelText)
        val scores = model.labels.mapIndexed { index, label ->
            label to prediction.probabilities[index]
        }.toMap()
        val assessment = policy.assess(scores, evidence)
        return Tier1Detection(evidence, prediction, assessment)
    }
}
