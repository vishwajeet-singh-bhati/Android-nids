package nids.app

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject

object SafetyControls {
    const val SMS = "sms_enabled"
    const val URL = "url_enabled"
    const val INCOMING = "incoming_sms_enabled"
    fun preferences(context: Context) = context.getSharedPreferences("rakshak_controls", Context.MODE_PRIVATE)
    fun enabled(context: Context, key: String) = preferences(context).getBoolean(key, key != INCOMING)
    fun generation(context: Context) = preferences(context).getLong("generation", 0L)
    fun set(context: Context, key: String, enabled: Boolean) {
        preferences(context).edit().putBoolean(key, enabled).putLong("generation", generation(context) + 1).apply()
    }
}

/** Render only detector codes. Message text and URLs are never supplied to Llama. */
object SafetyNote {
    const val VERSION = "rakshak-safety-v1"

    fun from(evidence: JSONObject?): JSONObject? = evidence?.takeIf { it.optString("schema") == VERSION }

    private fun codes(facts: JSONObject): Set<String> {
        val array = facts.optJSONArray("evidence_codes") ?: JSONArray()
        return (0 until array.length()).map { array.optString(it) }.toSet()
    }

    fun title(facts: JSONObject): String = when {
        facts.optString("analysis_status") == "failed" -> "A safety check could not finish"
        facts.optString("domain") == "url" && facts.optString("risk_level") == "high" -> "Link warning"
        facts.optString("domain") == "url" -> "Link needs a closer look"
        "URL_FLAGGED_PHISHING" in codes(facts) -> "Message contains a risky link"
        else -> "Message needs a closer look"
    }

    fun guidance(facts: JSONObject): String {
        val codes = codes(facts)
        return when {
            "URL_FLAGGED_PHISHING" in codes && "OTP_REQUEST" in codes ->
                "Check the sender through the official app, and keep your verification code private while avoiding unfamiliar links."
            facts.optString("domain") == "url" || "URL_FLAGGED_PHISHING" in codes ->
                "Do not open this link. Use the organisation's official app or type its known website address yourself."
            "OTP_REQUEST" in codes ->
                "Check with the organisation through its official app, and keep your verification code to yourself."
            "CREDENTIAL_REQUEST" in codes || "DATA_HARVESTING" in codes ->
                "Check with the organisation through its official app before sharing any personal details."
            codes.any { it in setOf("PAYMENT_REQUEST", "TASK_SCAM", "LOAN_OR_INVESTMENT_BAIT", "PRIZE_OR_REWARD_BAIT") } ->
                "Check the offer through an official contact before sending money or sharing any personal details."
            else -> "Check who sent the message through an official contact before replying or taking action."
        }
    }

    fun prefix(facts: JSONObject): String {
        val codes = codes(facts)
        val happening = when {
            facts.optString("analysis_status") == "failed" -> "One of the local checks could not finish. This activity still needs a manual check."
            facts.optString("domain") == "url" && facts.optString("risk_level") == "high" ->
                "This link was flagged as possibly leading to a fake website."
            facts.optString("domain") == "url" -> "We could not reliably judge this link."
            "URL_FLAGGED_PHISHING" in codes -> "A link in this message was flagged as possibly leading to a fake website."
            "OTP_REQUEST" in codes -> "This message appears to ask you to share a verification code."
            "CREDENTIAL_REQUEST" in codes -> "This message appears to ask for private sign-in details."
            codes.any { it in setOf("PAYMENT_REQUEST", "TASK_SCAM", "LOAN_OR_INVESTMENT_BAIT") } ->
                "This message includes a request or offer involving money that needs checking."
            else -> "This message has patterns associated with unwanted or scam messages."
        }
        val extra = if ("URL_FLAGGED_PHISHING" in codes && "OTP_REQUEST" in codes)
            " It also appears to ask for a verification code." else ""
        val freshness = if (facts.optBoolean("threat_list_stale")) " The saved list of reported websites is out of date." else ""
        val coverage = when {
            facts.optString("analysis_status") == "partial" -> if (facts.optString("completion_note") == "interrupted")
                " Some checks stopped when the app closed." else " Some checks stopped after the settings changed."
            facts.optString("tier2_status").startsWith("failed") -> " The deeper message check was unavailable."
            facts.optString("domain") == "message" && facts.optString("sms_status") == "disabled" -> " The message text detector was turned off."
            else -> ""
        } + if ("URL_CHECK_UNAVAILABLE" in codes) " Some links were not checked." else ""
        val uncertainty = if (facts.optString("domain") == "url" && facts.optString("risk_level") != "high")
            "A website check cannot guarantee a link is safe." else "This warning does not prove that a scam has occurred."
        return "What happened\n" + happening + extra + freshness + coverage + "\n\n" + uncertainty + "\n\nWhat you can do\n"
    }

    fun render(facts: JSONObject, advice: String = guidance(facts)) = prefix(facts) + advice

    fun quietResult(facts: JSONObject): String {
        val coverage = when {
            "URL_CHECK_UNAVAILABLE" in codes(facts) -> "Some links were not checked. Verify them through the official app or website."
            "URL_CHECK_UNCERTAIN" in codes(facts) -> "A link could not be judged reliably. Verify it through the official app or website."
            else -> "This does not prove the message or link is genuine."
        }
        val disabled = if (facts.optString("sms_status") == "disabled" && facts.optString("domain") == "message")
            " The message text detector was turned off." else ""
        val stale = if (facts.optBoolean("threat_list_stale")) " The saved list of reported websites is out of date." else ""
        return "No warning was raised in the completed checks." + disabled + "\n\n" + coverage + stale
    }

    fun accepted(text: String, facts: JSONObject): Boolean {
        val words = text.trim().split(Regex("\\s+"))
        if (words.size !in 6..30 || text.contains('\n') || text.contains(':') || Regex("\\d|[{}<>]").containsMatchIn(text)) return false
        if (!Regex("^(check|review|verify|look|consider)\\b", RegexOption.IGNORE_CASE).containsMatchIn(text)) return false
        if (words.drop(1).any { Regex("[A-Z]").containsMatchIn(it) }) return false
        val lower = text.lowercase()
        if (Regex("\\b(safe|legitimate|guaranteed|confirmed|infected|hacked|definitely|certainly|uninstall|delete|reset|sudo|adb|click|open|send|share|provide|enter|submit|pay|transfer|visit|download|install|call|reply)\\b").containsMatchIn(lower)) return false
        if ("OTP_REQUEST" in codes(facts) && !("code" in lower &&
            listOf("private", "yourself").any { it in lower })) return false
        val expectedTopic = when {
            facts.optString("domain") == "url" || "URL_FLAGGED_PHISHING" in codes(facts) -> listOf("address", "official", "website")
            "OTP_REQUEST" in codes(facts) -> listOf("code", "official")
            else -> listOf("official", "contact", "organisation", "message")
        }
        return expectedTopic.any { it in lower }
    }

    fun display(row: JSONObject): String {
        val facts = from(row.optJSONObject("model_evidence")) ?: return ""
        val result = row.optJSONObject("explanation")
        return if (result?.optString("pipeline_version") == VERSION &&
            result.optInt("evidence_revision") == row.optInt("revision")) result.optString("display")
        else render(facts)
    }

    fun details(facts: JSONObject): String = "Check type: " + facts.optString("domain") +
        "\nRisk level: " + facts.optString("risk_level") +
        "\nSMS check: " + facts.optString("sms_status", "not_requested") +
        "\nDeep SMS check: " + facts.optString("tier2_status", "not_requested") +
        "\nLinks: " + facts.optString("link_status", "not_requested") +
        "\nEvidence: " + codes(facts).joinToString(", ") +
        "\nModel scores describe model output and are not a guarantee."
}
