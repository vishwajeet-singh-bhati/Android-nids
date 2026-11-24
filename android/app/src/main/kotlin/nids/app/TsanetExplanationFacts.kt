package nids.app

import org.json.JSONObject

/** Only sensor measurements and the model hypothesis can reach the explainer. */
object TsanetExplanationFacts{
    val classes=listOf("Benign","Bot","Brute Force","DDoS","DoS","Port Scan","Web Attack","Unclassified")
    fun ownerSnapshot(fresh: JSONObject,cached: JSONObject?): JSONObject{
        if(fresh.optString("reason").contains("Ambiguous",true))return fresh
        if(fresh.optString("match_kind")=="listener" && cached?.optString("status")=="best_effort" && cached.optString("match_kind")!="listener")
            return JSONObject(cached.toString()).put("cached_for_current_flow",true)
        if(fresh.optString("status")!="unknown" || fresh.optString("reason").contains("Ambiguous",true))return fresh
        return if(cached?.optString("status")=="best_effort")JSONObject(cached.toString()).put("cached_for_current_flow",true) else fresh
    }
    fun from(evidence: JSONObject?): JSONObject?{
        if(evidence==null || evidence.optString("schema")!="tsanet_phone_evidence_v1")return null
        val category=evidence.optInt("class_id",0)
        if(category !in 1..7)return null
        val aligned=evidence.optString("feature_schema")=="phone-aligned-v2"
        if(category==7 && (!aligned || !evidence.optBoolean("binary_flag")))return null
        val owner=evidence.optJSONObject("attribution") ?: JSONObject()
        val packages=owner.optJSONArray("packages")
        val app=if(owner.optString("status")=="best_effort" && packages?.length()==1)
            packages.optString(0).take(100).replace(Regex("[^A-Za-z0-9._]"),"") else "unknown"
        val facts=JSONObject().put("suspected_pattern",classes[category]).put("app_package",app)
            .put("app_label",owner.optString("app_label",app))
            .put("owner_status",owner.optString("status","unknown")).put("owner_reason",owner.optString("reason"))
            .put("owner_match_kind",owner.optString("match_kind","connected"))
            .put("local_endpoint",owner.optString("local_endpoint")).put("remote_endpoint",owner.optString("remote_endpoint"))
            .put("socket_role",if(owner.optString("direction")=="incoming")"receiver" else if(owner.optString("direction")=="outgoing")"sender" else "unknown")
            .put("flow_packets",evidence.optInt("flow_packets"))
            .put("flow_duration_seconds",evidence.optDouble("flow_duration_seconds"))
            .put("sampled_prior_connections_5m",evidence.optInt("sampled_prior_connections_5m"))
            .put("sampled_target_ports_5m",evidence.optInt("sampled_target_ports_5m"))
            .put("prior_connections_5m",if(aligned)evidence.optInt("prior_connections_5m") else evidence.optInt("sampled_prior_connections_5m"))
            .put("target_ports_5m",if(aligned)evidence.optInt("target_ports_5m") else evidence.optInt("sampled_target_ports_5m"))
            .put("history_sampled",!aligned).put("type_established",category in 1..6)
            .put("history_window_minutes",5).put("history_complete",evidence.optBoolean("history_complete"))
            .put("capture_complete",evidence.optBoolean("capture_healthy",true))
            .put("attack_confirmed",false)
        evidence.optJSONObject("authentication_episode")?.let { episode ->
            val name=episode.optString("protocol")
            val count=episode.optInt("connections_in_window")
            if(name in setOf("SSH","FTP") && count>=4 && category==2){
                facts.put("auth_episode_protocol",name).put("auth_episode_connections",count)
            }
        }
        return facts
    }
    fun guidance(category: String)=when(category){
        "Port Scan"->"Check whether device discovery or connection testing was expected; review the associated app if it was not."
        "DoS","DDoS"->"Check unexpected downloads, uploads or repeated retries; pause unfamiliar activity and review the network."
        "Brute Force"->"Check whether repeated service connections were expected; review unfamiliar background apps and account activity."
        "Bot"->"Check expected syncing or scheduled activity; review the associated app's background data and permissions."
        "Web Attack"->"Review the associated app and recent web activity; do not enter credentials into unexpected prompts."
        else->"Review whether the app and network activity were expected."
    }
    fun fallback(facts: JSONObject): String{
        val category=facts.optString("suspected_pattern","unusual activity")
        val app=facts.optString("app_package","unknown")
        val owner=if(app=="unknown")"App ownership is unknown." else if(facts.optString("socket_role")=="receiver")
            "$app received this traffic." else "$app is the associated socket owner."
        val warm=if(!facts.optBoolean("capture_complete"))" Some traffic was skipped." else if(!facts.optBoolean("history_complete"))" Recent history is still building." else ""
        val pattern=if(category=="Unclassified")"The model flagged unusual network activity; its type is undetermined." else "The model suggests possible $category activity."
        return "$pattern The connection contained ${facts.optInt("flow_packets")} packets. $owner This does not confirm an attack.$warm ${guidance(category)}"
    }
    fun prompt(facts: JSONObject): String{
        val app=facts.optString("app_package","unknown")
        val ownership=if(app=="unknown")"Socket ownership is unknown." else if(facts.optString("socket_role")=="receiver")"$app received the traffic." else "$app is the associated socket owner."
        val history=if(facts.optBoolean("history_complete"))"Recent connection history is available." else "Recent connection history is still building."
        val capture=if(facts.optBoolean("capture_complete",true))"" else "Some traffic was skipped; the observation is incomplete."
        val category=facts.optString("suspected_pattern")
        val estimate=if(category=="Unclassified")"Binary model flagged unusual network activity; diagnosis did not establish a type." else "Model estimate: possible $category activity."
        val sampling=if(facts.optBoolean("history_sampled"))"sampled " else ""
        return "$estimate Observed connection: ${facts.optInt("flow_packets")} packets over ${facts.optDouble("flow_duration_seconds")} seconds. Prior five minutes: ${facts.optInt("prior_connections_5m")} ${sampling}connections and ${facts.optInt("target_ports_5m")} ports. $ownership $history $capture This does not confirm an attack. Manual check: ${guidance(category)}"
    }
    fun draftConsistent(text: String,facts: JSONObject): Boolean{
        val app=facts.optString("app_package","unknown")
        val names=Regex("\\b(?:com|org|net|io|android|nids)(?:\\.[A-Za-z][A-Za-z0-9_]*)+\\b").findAll(text).map{it.value}.toList()
        if(names.any{it!=app})return false
        val lower=text.lowercase()
        if(app=="unknown" && !listOf("unknown","could not","cannot").any{it in lower})return false
        if(app!="unknown" && app.lowercase() !in lower)return false
        if(facts.optString("socket_role")=="receiver" && "receiv" !in lower)return false
        val number=Regex("\\b\\d+(?:\\.\\d+)?\\b")
        val allowed=number.findAll(facts.toString()).mapNotNull{it.value.toDoubleOrNull()}.toSet()
        return number.findAll(text.replace(app,"")).all{it.value.toDoubleOrNull() in allowed}
    }
}
