package nids.app

import org.json.JSONObject

/** Verified measurements/ownership stay outside the language-model prompt. */
object HybridActivityNote {
    const val VERSION="hybrid-guidance-v1"
    private fun clean(value: String,limit: Int=100)=value.replace(Regex("[\\p{Cc}\\p{Cf}]")," ").replace(Regex("\\s+")," ").trim().take(limit)
    private fun endpoint(value: String)=value.takeIf{it.length<=100 && it.matches(Regex("[0-9a-fA-F:.\\[\\]%]+:[0-9]+"))} ?: ""
    fun appLabel(facts: JSONObject): String {
        val pkg=facts.optString("app_package","unknown")
        if(pkg=="unknown")return ""
        val label=clean(facts.optString("app_label"),64)
        return if(label.isBlank() || label=="App unknown" || label==pkg)pkg else "$label ($pkg)"
    }
    fun title(facts: JSONObject)=when(facts.optString("suspected_pattern")){
        "Port Scan"->"Possible check for open connections"
        "Brute Force"->"Possible repeated sign-in attempts"
        "Bot"->"Possible automated background activity"
        "DoS"->"Possible connection overload"
        "DDoS"->"Possible overload from several sources"
        "Web Attack"->"Possible suspicious web activity"
        else->"Unusual network activity to review"
    }
    fun ownership(facts: JSONObject): String {
        val app=appLabel(facts);val incoming=facts.optString("socket_role")=="receiver"
        if(app.isNotEmpty())return when {
            facts.optString("owner_match_kind")=="listener"->"$app was listening on the receiving port when checked; delivery to that app is not established."
            incoming->"$app received this traffic. It is not identified as the source of the activity."
            facts.optString("socket_role")=="sender"->"$app owned the connection from this phone. This does not establish harmful intent."
            else->"The connection was associated with $app; its initiating role was not established."
        }
        return when {
            facts.optString("owner_status")=="shared_or_system_uid"->"Android reported shared or system ownership; no single app can be named reliably."
            facts.optString("owner_reason").contains("Ambiguous",true)->"The recorded connection has conflicting app owners, so it cannot be assigned to one app."
            facts.optString("owner_reason").contains("tuple changed",true)->"The connection details were reused before an app could be linked reliably."
            facts.optString("owner_reason").contains("unavailable",true)->"Android connection-ownership data was unavailable when this traffic was checked."
            incoming->"No receiving app could be linked to this connection; a closed port or a brief connection can leave no app match."
            else->"No app could be linked to this connection; it may have ended before ownership was recorded."
        }
    }
    fun prefix(facts: JSONObject): String {
        val summary=title(facts)+" (model estimate). This does not confirm an attack."
        val packets=facts.optInt("flow_packets").coerceAtLeast(0)
        val duration=facts.optDouble("flow_duration_seconds",0.0).takeIf{it.isFinite() && it>=0}
        val timing=if(duration!=null)" over ${java.lang.String.format(java.util.Locale.US,"%.2f",duration)} seconds" else ""
        val measured="Observed: $packets network packets (small pieces of data)$timing."
        val peer=endpoint(facts.optString("remote_endpoint"))
        val local=endpoint(facts.optString("local_endpoint"))
        val path=if(peer.isEmpty())"" else if(facts.optString("socket_role")=="receiver")
            " Source device: $peer." else " Other device: $peer."
        val port=if(local.isEmpty())"" else " Phone port: ${local.substringAfterLast(':')}."
        val context=if(facts.optBoolean("history_complete"))" Recent context: ${facts.optInt("prior_connections_5m").coerceAtLeast(0)} prior connections across ${facts.optInt("target_ports_5m").coerceAtLeast(0)} ports in five minutes." else " Recent connection history is still building."
        val coverage=if(!facts.optBoolean("capture_complete",true))" Some traffic was skipped; this observation is incomplete." else ""
        val caution=when(facts.optString("suspected_pattern")){
            "Brute Force"->" Connection statistics cannot confirm failed logins."
            "Web Attack"->" The model does not establish what a web request contained."
            else->""
        }
        return "$summary\n\n${ownership(facts)}$path$port\n\n$measured$context$coverage$caution\n\n"
    }
    fun guidance(facts: JSONObject)=when(facts.optString("suspected_pattern")){
        "Port Scan"->"Check whether you expected a device search or connection test; review unfamiliar app activity."
        "DoS","DDoS"->"Check for unexpected downloads or repeated connection attempts, and pause unfamiliar app activity."
        "Brute Force"->"Check recent account activity and review apps making unexpected repeated connections."
        "Bot"->"Check expected background syncing and review unfamiliar apps and their permissions."
        "Web Attack"->"Review recent web activity and avoid entering passwords into unexpected prompts."
        else->"Check whether you expected this app or network activity."
    }
    fun render(facts: JSONObject,advice: String=guidance(facts))=prefix(facts)+advice
    fun appSummary(row: JSONObject): String {
        val facts=TsanetExplanationFacts.from(row.optJSONObject("model_evidence")) ?: return row.optJSONObject("attribution")?.optString("app_label","No app link recorded") ?: "No app link recorded"
        val label=appLabel(facts)
        if(label.isNotEmpty())return label
        val local=endpoint(facts.optString("local_endpoint"))
        return if(facts.optString("socket_role")=="receiver" && local.isNotEmpty())"Incoming activity to phone port ${local.substringAfterLast(':')}" else "No single app could be linked; see the activity details"
    }
    fun guidanceAccepted(text: String,facts: JSONObject): Boolean {
        val lower=text.lowercase();val words=text.trim().split(Regex("\\s+"))
        if(words.size !in 6..30 || text.contains('\n') || text.contains(':') || Regex("\\d|<\\||[{}]").containsMatchIn(text))return false
        if(!Regex("^(check|review|verify|look|consider)\\b",RegexOption.IGNORE_CASE).containsMatchIn(text))return false
        // No app names, addresses or proper nouns are supplied to the LLM.
        // An invented name in its guidance must not enter the final note.
        if(words.drop(1).any{Regex("[A-Z]").containsMatchIn(it)})return false
        if(Regex("\\b(malware|virus|attacker|infected|compromised|attack|caused|proof|confirmed|definitely|certainly|uninstall|delete|reset|sudo|adb|disable|assistant)\\b",RegexOption.IGNORE_CASE).containsMatchIn(text))return false
        if(listOf("as an ai","manual check to restate","login attempts","failed login","sign-in attempts","password manager").any{it in lower})return false
        if(Regex("\\b(passwords?|credentials?)\\b").containsMatchIn(lower) &&
            (!Regex("(?:avoid|do not|don't|never)\\s+(?:enter(?:ing)?|provid(?:ing|e)|typ(?:ing|e)|shar(?:ing|e))[^.!?]{0,35}(?:password|credential)").containsMatchIn(lower) || "not avoid" in lower || "don't avoid" in lower))return false
        val topic=when(facts.optString("suspected_pattern")){
            "Port Scan"->listOf("device","connection")
            "DoS","DDoS"->listOf("download","upload","repeated","retr")
            "Brute Force"->listOf("account","app")
            "Bot"->listOf("background","sync","permission")
            "Web Attack"->listOf("web","brows","prompt")
            else->listOf("expected","expect")
        }
        return topic.any{it in lower}
    }
    fun display(row: JSONObject): String {
        if(row.optString("traffic_scope")==NetworkObservationPolicy.LOCAL)return row.optString("factual_note")
        val explanation=row.optJSONObject("explanation")
        if(explanation!=null && explanation.optInt("evidence_revision",-1)==row.optInt("revision") && explanation.optString("pipeline_version")==VERSION)
            return explanation.optString("display")
        val facts=TsanetExplanationFacts.from(row.optJSONObject("model_evidence"))
        if(facts!=null)return render(facts)
        return row.optString("factual_note").ifEmpty{explanation?.optString("display") ?: "A local model flagged unusual connection patterns. This does not confirm an attack. Review whether this activity was expected."}
    }
}
