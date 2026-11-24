package com.bharat.smsguard.tier1

import java.io.File
import java.util.Base64

/** TSV bridge: desktop tests execute the same Kotlin detector/policy as Android. */
fun runCascadeBatch(args: Array<String>) {
    val detector = Tier1Detector(PortableLinearModel.fromJson(File(args[0]).readText()), RiskPolicy.production())
    val input = File(args[1])
    val output = File(args[2])
    val baseline = args.getOrNull(3) == "baseline"
    output.bufferedWriter().use { writer ->
        writer.appendLine("id\ttier1_label\ttier1_risk\trouted\ttier2_label\tfinal_label\tfinal_risk\tfinancial\tattention\trouting_reason\treasons\ttier1_ms\tpreliminary_attention\tany_attention")
        input.forEachLine(Charsets.UTF_8) { line ->
            if (line.isNotBlank()) {
                val parts = line.split('\t')
                val text = String(Base64.getDecoder().decode(parts[1]), Charsets.UTF_8)
                val sender = if (parts[2] == "-") null else String(Base64.getDecoder().decode(parts[2]), Charsets.UTF_8)
                val start = System.nanoTime()
                val first = detector.predict(text, sender)
                val tier1Ms = (System.nanoTime() - start) / 1e6
                val routine = if (baseline) null else RoutineMessages.reason(first)
                val routed = routine == null && CascadePolicy.shouldRoute(first)
                val neural = if (parts.size >= 6 && parts[3] != "-") mapOf("ham" to parts[3].toDouble(), "spam" to parts[4].toDouble(), "smishing" to parts[5].toDouble()) else null
                val result = when {
                    routine != null -> RoutineMessages.apply(first, routine)
                    routed && neural != null -> CascadePolicy.fuse(first, neural)
                    else -> first
                }
                val preliminaryAttention = routine == null && AlertPolicy.attentionRequired(AlertPolicy.preliminary(first))
                writer.appendLine(listOf(parts[0], first.label, first.riskLevel, routed,
                    if (routed && neural != null) neural.maxBy { it.value }.key else "-", result.label,
                    result.riskLevel, AlertPolicy.financialRisk(result), AlertPolicy.attentionRequired(result),
                    routine?.let { "fast_path_$it" } ?: if (routed) "risk_or_uncertainty" else "no_escalation_trigger",
                    result.assessment.reasonCodes.joinToString(","), tier1Ms, preliminaryAttention,
                    preliminaryAttention || AlertPolicy.attentionRequired(result)).joinToString("\t"))
            }
        }
    }
    println("Batch completed: ${output.name}")
}
