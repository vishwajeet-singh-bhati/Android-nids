package nids.app

import org.json.JSONArray
import org.json.JSONObject
import java.net.URI
import java.net.URLDecoder

/** The URL verdict can raise message risk; it never clears SMS evidence. */
object MessageLinkPolicy {
    private val actionOrder = listOf("NO_ACTION", "MARK_AS_SPAM", "DO_NOT_INTERACT", "DO_NOT_CLICK",
        "DO_NOT_SHARE_OTP", "DO_NOT_SHARE_PERSONAL_INFO", "DO_NOT_SEND_MONEY", "VERIFY_BEFORE_ACTING",
        "VERIFY_USING_OFFICIAL_CHANNEL", "REPORT_AS_SCAM")

    fun tidy(raw: String): String? {
        var value = raw.trim().trimStart { it in "([{<'\"\u0060" }
        val closers = mapOf(')' to '(', ']' to '[', '}' to '{', '>' to '<')
        while (value.isNotEmpty()) {
            val last = value.last()
            val opening = closers[last]
            if (last in ".,;:!?'\"\u0060*" || opening != null && value.count { it == last } > value.count { it == opening })
                value = value.dropLast(1)
            else break
        }
        return value.takeIf { it.isNotEmpty() }
    }

    fun redact(raw: String, hostOnly: Boolean = false): String = try {
        val uri = URI(raw.trim())
        val authority = uri.rawAuthority?.substringAfterLast('@').orEmpty()
        val host = authority.substringBeforeLast(':', authority).takeIf { uri.port >= 0 } ?: authority
        if (hostOnly) {
            if (uri.scheme?.lowercase() !in setOf("http", "https") || authority.isEmpty()) "<unparseable URL>"
            else uri.scheme + "://" + host.take(150) + "/..."
        } else {
            var text = if (authority.isNotEmpty()) (uri.scheme?.let { it + "://" } ?: "//") + authority else uri.scheme?.let { it + ":" }.orEmpty()
            text += uri.rawPath.orEmpty()
            if (!uri.rawQuery.isNullOrEmpty()) text += "?" + uri.rawQuery!!.split('&').filter { it.isNotEmpty() }.joinToString("&") {
                if ('=' !in it) "REDACTED" else {
                    val name = URLDecoder.decode(it.substringBefore('='), "UTF-8")
                    (if (Regex("[A-Za-z0-9_.\\-\\[\\]]{1,32}").matches(name)) name else "REDACTED") + "=REDACTED"
                }
            }
            (if (text.length > 200) text.take(200) + "..." else text).map { if (it.isISOControl()) '?' else it }.joinToString("")
        }
    } catch (_: Exception) { "<unparseable URL>" }

    fun combine(sms: JSONObject, links: List<String>, items: List<JSONObject>?,
                notChecked: Int = 0, error: String? = null, hostOnly: Boolean = false): JSONObject {
        require(items == null || items.size == links.size)
        val views = links.mapIndexed { i, url ->
            val item = items?.get(i)
            JSONObject().put("display_url", if (hostOnly) item?.optString("display_url")?.takeIf { it.isNotEmpty() } ?: "<unchecked link>" else redact(url))
                .put("decision", item?.optString("decision")?.takeIf { it != "null" }?.lowercase() ?: JSONObject.NULL)
                .put("risk_score", item?.opt("risk_score") ?: JSONObject.NULL)
                .put("source", item?.opt("source") ?: JSONObject.NULL)
                .put("reasons", item?.optJSONArray("reasons") ?: JSONArray())
                .put("threat_types", item?.optJSONArray("threat_types") ?: JSONArray())
                .put("pending", item?.optJSONArray("pending") ?: JSONArray())
                .put("error", if (item == null) "not_checked" else item.opt("error") ?: JSONObject.NULL)
                .apply {
                    if (hostOnly && item != null) {
                        put("threat_list_stale", item.optBoolean("threat_list_stale", true))
                        put("feeds_updated_at", item.optString("feeds_updated_at"))
                        put("sources", item.optJSONArray("sources") ?: JSONArray())
                        put("model_status", item.optString("model_status", "unknown"))
                        put("model_used", item.optBoolean("model_used"))
                    }
                }
        }
        val decisions = views.map { if (it.isNull("decision")) null else it.getString("decision") }
        val unchecked = notChecked + views.count { it.isNull("decision") || it.optString("model_status") == "failed" }
        val phishing = views.filter { it.optString("decision") == "phishing" }
        val codes = ArrayList<String>()
        if (phishing.isNotEmpty()) {
            codes.add("URL_FLAGGED_PHISHING")
            if (phishing.any { it.optString("source") == "threat_intel" }) codes.add("URL_KNOWN_THREAT")
        }
        if ("uncertain" in decisions) codes.add("URL_CHECK_UNCERTAIN")
        if (unchecked > 0) codes.add("URL_CHECK_UNAVAILABLE")
        if (views.isNotEmpty() && codes.isEmpty()) codes.add("URL_NOT_FLAGGED")
        val smsRisk = sms.getString("risk_level")
        require(smsRisk in setOf("low", "suspicious", "high"))
        val risk = if (phishing.isNotEmpty()) "high" else smsRisk
        val raised = risk != smsRisk
        val actions = sms.optJSONArray("recommended_action_codes")?.let { a -> (0 until a.length()).map { a.getString(it) } }?.toMutableList() ?: ArrayList()
        if (phishing.isNotEmpty()) actions.addAll(listOf("DO_NOT_CLICK", "VERIFY_USING_OFFICIAL_CHANNEL", "REPORT_AS_SCAM"))
        if (raised) actions.removeAll(setOf("NO_ACTION", "MARK_AS_SPAM", "DO_NOT_INTERACT", "VERIFY_BEFORE_ACTING"))
        val evidence = sms.optJSONArray("evidence")?.let { JSONArray(it.toString()) } ?: JSONArray()
        val seen = (0 until evidence.length()).map { evidence.getJSONObject(it).optString("code") }.toSet()
        codes.filter { it !in seen }.forEach { evidence.put(JSONObject().put("code", it).put("present", true)) }
        val found = links.size + notChecked
        val status = when { found == 0 -> "no_links"; unchecked == found -> "unavailable"; unchecked > 0 -> "partial"; else -> "checked" }
        return JSONObject().put("module", "sms_url_bridge").put("schema_version", "1.0").put("sms", sms)
            .put("links", JSONObject().put("status", status).put("found", found).put("checked", found - unchecked)
                .put("not_checked", unchecked).put("error", error ?: JSONObject.NULL)
                .put("complete", views.all { it.getJSONArray("pending").length() == 0 })
                .put("model_versions", JSONArray(items.orEmpty().mapNotNull { it.optString("model_version").takeIf { v -> v.isNotEmpty() } }.distinct().sorted()))
                .put("results", JSONArray(views)))
            .put("combined", JSONObject().put("risk_level", risk).put("raised_by_links", raised).put("evidence", evidence)
                .put("recommended_action_codes", JSONArray(actions.distinct().sortedBy { actionOrder.indexOf(it).let { n -> if (n < 0) actionOrder.size else n } })))
    }
}
