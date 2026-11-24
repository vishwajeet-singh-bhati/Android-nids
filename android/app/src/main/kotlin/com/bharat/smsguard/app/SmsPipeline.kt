package com.bharat.smsguard.app

import android.content.Context
import com.bharat.smsguard.tier1.ActionCodes
import com.bharat.smsguard.tier1.Codes
import com.bharat.smsguard.tier1.Tier1Detection
import com.bharat.smsguard.tier1.CascadePolicy
import com.bharat.smsguard.tier1.AlertPolicy
import com.bharat.smsguard.tier1.RoutineMessages

data class PipelineResult(
    val first: Tier1Detection,
    val final: Tier1Detection,
    val tier2Status: String,
    val elapsedMs: Double,
    val tier1Ms: Double = 0.0,
    val tier2Ms: Double = 0.0,
    val routingReason: String = "risk_or_uncertainty",
)

/** Candidate routing policy, to be evaluated on independent Indian data.
 * No blended probability or calibrated confidence is claimed.
 */
object SmsPipeline {
    @Volatile private var second: Tier2Engine? = null
    fun tier2(context: Context): Tier2Engine = synchronized(this) {
        second ?: Tier2Engine(context.applicationContext).also { second = it }
    }

    fun analyze(context: Context, text: String, sender: String? = null,
        onPreliminary: ((Tier1Detection) -> Unit)? = null): PipelineResult {
        val start = System.nanoTime()
        val first = SmsGuardEngine.get(context).predict(text, sender)
        val tier1Ms = (System.nanoTime() - start) / 1e6
        val routine = RoutineMessages.reason(first)
        if (routine != null) return PipelineResult(first, RoutineMessages.apply(first, routine), "not_needed",
            (System.nanoTime() - start) / 1e6, tier1Ms, 0.0, "fast_path_$routine")
        val preliminary = AlertPolicy.preliminary(first)
        if (AlertPolicy.attentionRequired(preliminary)) onPreliminary?.invoke(preliminary)
        val flags = first.evidence.flags
        val needsDeepScan = CascadePolicy.shouldRoute(first)
        if (!needsDeepScan) return PipelineResult(first, first, "not_needed", (System.nanoTime() - start) / 1e6, tier1Ms, 0.0, "no_escalation_trigger")
        val neuralStart = System.nanoTime()
        return try {
            val scores = tier2(context).scores(first.evidence.normalized.modelText)
            PipelineResult(first, CascadePolicy.fuse(first, scores), "completed", (System.nanoTime() - start) / 1e6,
                tier1Ms, (System.nanoTime() - neuralStart) / 1e6)
        } catch (error: Throwable) {
            if (error is VirtualMachineError || error is ThreadDeath) throw error
            android.util.Log.e("SmsGuard", "Tier-2 unavailable (${error.javaClass.simpleName})")
            val risk = if (first.riskLevel == "high") "high" else "suspicious"
            val fallback = first.copy(assessment = first.assessment.copy(riskLevel = risk,
                recommendedActionCodes = ActionCodes.forResult(first.label, risk, flags)))
            PipelineResult(first, fallback, "failed_${error.javaClass.simpleName}", (System.nanoTime() - start) / 1e6,
                tier1Ms, (System.nanoTime() - neuralStart) / 1e6)
        }
    }
}
