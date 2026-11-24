package nids.app

import android.content.Context
import com.bharat.smsguard.app.SmsPipeline
import com.bharat.smsguard.tier1.SmsNormalizer
import com.bharat.smsguard.tier1.Tier1Detection
import org.json.JSONArray
import org.json.JSONObject
import java.util.UUID

/** Bounded, body-free manual results, keyed so an incoming SMS cannot replace a manual check. */
object SafetyResults {
    private val values = LinkedHashMap<String, JSONObject>()
    @Synchronized fun put(id: String, result: JSONObject) {
        values[id] = JSONObject(result.toString())
        while (values.size > 32) values.remove(values.keys.first())
    }
    @Synchronized fun get(id: String): JSONObject? = values[id]?.let { JSONObject(it.toString()) }
    @Synchronized fun clear() = values.clear()
}

object SafetyPipeline {
    private fun smsView(result: Tier1Detection): JSONObject = JSONObject()
        .put("module", "sms_detector").put("schema_version", "1.0").put("label", result.label)
        .put("risk_level", result.riskLevel).put("scores", JSONObject(result.assessment.scores))
        .put("evidence", JSONArray(result.evidence.presentCodes().map { JSONObject().put("code", it).put("present", true) }))
        .put("recommended_action_codes", JSONArray(result.actionCodes))
        .put("model_version", "sms-handoff-2026-11-23").put("policy_version", result.assessment.policyVersion)

    fun analyze(context: Context, text: String, domain: String, sender: String? = null,
                onPreliminary: ((JSONObject) -> Unit)? = null): JSONObject {
        require(domain == "message" || domain == "url")
        require(text.isNotBlank() && text.codePointCount(0, text.length) <= 32768) { "Input is empty or too long" }
        val start = System.nanoTime()
        val checkSms = domain == "message" && SafetyControls.enabled(context, SafetyControls.SMS)
        val checkLinks = SafetyControls.enabled(context, SafetyControls.URL)
        if (!checkSms && !checkLinks) return JSONObject().put("schema", SafetyNote.VERSION)
            .put("domain", domain).put("analysis_status", "disabled").put("risk_level", "low")
        var tier2 = "not_requested"
        var smsRouting = "not_requested"
        var sms = JSONObject().put("module", "sms_detector").put("schema_version", "1.0")
            .put("label", "not_checked").put("risk_level", "low").put("scores", JSONObject())
            .put("evidence", JSONArray()).put("recommended_action_codes", JSONArray())
        val rawLinks = if (domain == "url") listOf(text.trim()) else SmsNormalizer.normalize(text).urls
        val links = rawLinks.mapNotNull { MessageLinkPolicy.tidy(it) }.distinct()
        val submitted = links.take(10)
        val items = if (checkLinks) submitted.map { link ->
            try { LinkDetector.get(context).check(link) } catch (_: Exception) {
                JSONObject().put("decision", JSONObject.NULL).put("error", "detector_unavailable")
            }
        } else null
        // Incoming SMS uses this same path. Check real links before the optional
        // deeper SMS scan, and preserve link evidence in every preliminary update.
        fun combinedWith(message: JSONObject) = MessageLinkPolicy.combine(message, submitted, items,
            links.size - submitted.size, if (checkLinks) null else "url_detector_disabled", hostOnly = true)
        if (domain == "message" && items.orEmpty().any { it.optString("decision") == "PHISHING" }) {
            onPreliminary?.invoke(evidence(sms, combinedWith(sms), domain,
                if (checkSms) "pending" else "disabled", "not_requested").put("phase", "preliminary"))
        }
        if (checkSms) {
            val result = SmsPipeline.analyze(context, text, sender) { first ->
                val early = evidence(smsView(first), combinedWith(smsView(first)), domain, "completed", "pending")
                early.put("phase", "preliminary")
                onPreliminary?.invoke(early)
            }
            sms = smsView(result.final)
            tier2 = result.tier2Status
            smsRouting = result.routingReason
        }
        val combined = MessageLinkPolicy.combine(sms, submitted, items, links.size - submitted.size,
            if (checkLinks) null else "url_detector_disabled", hostOnly = true)
        val final = evidence(sms, combined, domain, if (checkSms) "completed" else "disabled", tier2)
        if (domain == "url") {
            val item = items?.firstOrNull()
            val decision = item?.optString("decision").orEmpty()
            final.put("risk_level", when (decision) { "PHISHING" -> "high"; "LIKELY_SAFE" -> "low"; else -> "suspicious" })
            if (!checkLinks) final.put("analysis_status", "disabled").put("risk_level", "low")
            else if (item == null || !item.isNull("error") || item.optString("model_status") == "failed")
                final.put("analysis_status", "failed")
        }
        return final.put("sms_routing_reason", smsRouting).put("phase", "final").put("elapsed_ms", (System.nanoTime() - start) / 1e6)
    }

    private fun evidence(sms: JSONObject, combined: JSONObject?, domain: String, smsStatus: String, tier2: String): JSONObject {
        val assessment = combined?.getJSONObject("combined")
        val evidence = assessment?.getJSONArray("evidence") ?: sms.getJSONArray("evidence")
        val codes = (0 until evidence.length()).map { evidence.getJSONObject(it).getString("code") }
        val links = combined?.getJSONObject("links")
        val results = links?.optJSONArray("results") ?: JSONArray()
        val stale = (0 until results.length()).any { results.getJSONObject(it).optBoolean("threat_list_stale") }
        return JSONObject().put("schema", SafetyNote.VERSION).put("domain", domain)
            .put("risk_level", assessment?.getString("risk_level") ?: sms.getString("risk_level"))
            .put("sms_label", sms.getString("label")).put("sms_status", smsStatus).put("tier2_status", tier2)
            .put("sms_model_version", sms.optString("model_version"))
            .put("evidence_codes", JSONArray(codes)).put("scores", sms.getJSONObject("scores"))
            .put("action_codes", assessment?.getJSONArray("recommended_action_codes") ?: sms.getJSONArray("recommended_action_codes"))
            .put("link_status", links?.getString("status") ?: "pending")
            .put("link_count", links?.optInt("found") ?: 0).put("links_checked", links?.optInt("checked") ?: 0)
            .put("links", results).put("threat_list_stale", stale).put("analysis_status", "completed")
    }
}
