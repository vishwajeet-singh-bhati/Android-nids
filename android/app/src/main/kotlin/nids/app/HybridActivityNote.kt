package nids.app

import org.json.JSONObject

/** Verified measurements/ownership stay outside the language-model prompt. */
object HybridActivityNote {
    const val VERSION="plain-guidance-v3"
    private fun clean(value: String,limit: Int=100)=value.replace(Regex("[\\p{Cc}\\p{Cf}]")," ").replace(Regex("\\s+")," ").trim().take(limit)
    private fun endpoint(value: String)=value.takeIf{it.length<=100 && it.matches(Regex("[0-9a-fA-F:.\\[\\]%]+:[0-9]+"))} ?: ""
    fun appLabel(facts: JSONObject): String {
        val pkg=facts.optString("app_package","unknown")
        if(pkg=="unknown")return ""
        val label=clean(facts.optString("app_label"),64)
        return if(label.isBlank() || label=="App unknown" || label==pkg)pkg else "$label ($pkg)"
    }
    fun title(facts: JSONObject)=when(facts.optString("suspected_pattern")){
        "Rejected connection"->"Incoming connection was rejected"
        "Port Scan"->"Possible check for open connections"
        "Brute Force"->if(facts.has("auth_episode_protocol"))"Repeated ${facts.optString("auth_episode_protocol")} connections" else "Possible repeated sign-in attempts"
        "Bot"->"Possible automated background activity"
        "DoS"->"Possible connection overload"
        "DDoS"->"Possible overload from several sources"
        "Web Attack"->"Possible suspicious web activity"
        else->"Unusual network activity to review"
    }
    fun activityTitle(row: JSONObject): String {
        SafetyNote.from(row.optJSONObject("model_evidence"))?.let{return SafetyNote.title(it)}
        TsanetExplanationFacts.from(row.optJSONObject("model_evidence"))?.let{return title(it)}
        return row.optString("title","Network activity to review")
    }
    fun ownership(facts: JSONObject): String {
        if(facts.optBoolean("rejected_incoming_handshake"))return "No completed connection or message content was seen in this attempt. This does not identify an app as responsible."
        val app=clean(facts.optString("app_label"),64).takeIf{it.isNotBlank() && it!="App unknown"} ?: appLabel(facts)
        if(facts.optString("app_package","unknown")!="unknown" && app.isNotEmpty())return when{
            facts.optString("owner_match_kind")=="listener"->app+" was available to receive connections, but we could not confirm it received this one."
            facts.optString("socket_role")=="receiver"->app+" received the connection."
            facts.optString("socket_role")=="sender"->app+" made the connection."
            else->"The connection was linked to "+app+"."
        }
        return "We could not identify the app for this connection."
    }
    fun details(facts: JSONObject): String {
        val summary=title(facts)+(if(facts.optBoolean("rejected_incoming_handshake"))" (observed handshake)" else if(facts.has("auth_episode_protocol"))" (connection pattern)" else " (model estimate)")+". This does not confirm an attack."
        val packets=facts.optInt("flow_packets").coerceAtLeast(0)
        val duration=facts.optDouble("flow_duration_seconds",0.0).takeIf{it.isFinite() && it>=0}
        val timing=if(duration!=null)" over ${java.lang.String.format(java.util.Locale.US,"%.2f",duration)} seconds" else ""
        val measured=if(facts.has("auth_episode_protocol")){
            "Observed ${facts.optInt("auth_episode_connections")} incoming connections from the same device to the same phone port within 30 seconds. The latest connection had $packets packets$timing."
        }else "Observed: $packets network packets (small pieces of data)$timing."
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
        val hypothesis=if(facts.optBoolean("rejected_incoming_handshake"))" Original model estimate: ${clean(facts.optString("model_suspected_pattern"))}. This small rejected handshake does not establish that type." else ""
        return "$summary\n\n${ownership(facts)}$path$port\n\n$measured$context$coverage$caution$hypothesis\n\n"
    }
    fun prefix(facts: JSONObject): String {
        val happening=when(facts.optString("suspected_pattern")){
            "Rejected connection"->"Another device tried to connect to your phone. The recorded attempt ended with a rejection."
            "Port Scan"->"Someone may be checking which connections your phone accepts."
            "Brute Force"->"Repeated connections may be sign-in attempts."
            "Bot"->"Some background connections look automated."
            "DoS"->"Repeated connections may be putting a service on your phone under pressure."
            "DDoS"->"Connections from several devices may be putting a service on your phone under pressure."
            "Web Attack"->"A web connection looked unusual and may need your attention."
            else->"A connection looked different from the usual pattern."
        }
        val limited=if(!facts.optBoolean("capture_complete",true))" Some traffic was missed." else ""
        return "What happened\n"+happening+" "+ownership(facts)+"\n\nThis may be normal activity. An attack has not been confirmed."+limited+"\n\nWhat you can do\n"
    }
    fun guidance(facts: JSONObject)=when(facts.optString("suspected_pattern")){
        "Rejected connection"->"Check whether you expected this connection attempt; use a trusted network if it keeps happening."
        "Port Scan"->"Check whether you started a device search, and review any app activity you do not recognise."
        "DoS","DDoS"->"Check for unexpected downloads or repeated connection attempts, and pause unfamiliar app activity."
        "Brute Force"->"Check recent account activity and review apps making unexpected repeated connections."
        "Bot"->"Check whether an app is syncing in the background, and review apps you do not recognise."
        "Web Attack"->"Review recent web activity and avoid entering passwords into unexpected prompts."
        else->"Check whether you expected this app or network activity."
    }
    fun render(facts: JSONObject,advice: String=guidance(facts))=prefix(facts)+advice
    fun appSummary(row: JSONObject): String {
        SafetyNote.from(row.optJSONObject("model_evidence"))?.let{return if(it.optString("domain")=="url")"Link check" else "Message check"}
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
            "Rejected connection"->listOf("network","expected","expect","connection")
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
        if(SafetyNote.from(row.optJSONObject("model_evidence"))!=null)return SafetyNote.display(row)
        if(row.optString("traffic_scope")==NetworkObservationPolicy.LOCAL)return row.optString("factual_note")
        val explanation=row.optJSONObject("explanation")
        if(explanation!=null && explanation.optInt("evidence_revision",-1)==row.optInt("revision") && explanation.optString("pipeline_version")==VERSION)
            return explanation.optString("display")
        val facts=TsanetExplanationFacts.from(row.optJSONObject("model_evidence"))
        if(facts!=null)return render(facts)
        return row.optString("factual_note").ifEmpty{explanation?.optString("display") ?: "A local model flagged unusual connection patterns. This does not confirm an attack. Review whether this activity was expected."}
    }
}
