package nids.app

import org.json.JSONObject

/** Optional V6 evidence adapter. No raw capture text or inferred app ownership. */
object CascadeExplanationFacts {
    private val categories=setOf("port_scan","ddos","dos","credential_attack","web_attack","bot_activity",
        "infiltration","heartbleed","mixed_suspicious","unknown_suspicious")
    fun from(evidence: JSONObject?): JSONObject? {
        if(evidence==null || evidence.optString("schema")!="nids_cascade_evidence_v1" ||
            !evidence.optBoolean("binary_flag") || evidence.optString("capture_quality")!="healthy")return null
        val diagnosis=evidence.optJSONObject("diagnosis") ?: return null
        val category=diagnosis.optString("category").takeIf{it in categories} ?: "unknown_suspicious"
        val owner=evidence.optJSONObject("attribution") ?: JSONObject()
        val total=owner.optLong("contributing_flows",0);val matched=owner.optLong("matched_flows",0)
        val supplied=owner.optString("app_package")
        val known=owner.optString("status")=="best_effort" && total>0 && matched==total &&
            supplied!="unknown" && supplied.matches(Regex("[A-Za-z0-9._]{1,100}"))
        val direction=owner.optString("direction").takeIf{it in setOf("incoming","outgoing","mixed","unknown")} ?: "unknown"
        val facts=evidence.optJSONObject("traffic_facts") ?: JSONObject()
        val measured=JSONObject().put("window_seconds",5)
        for(key in listOf("packets","payload_bytes","outgoing_syn","incoming_syn","outgoing_rst","incoming_rst",
            "distinct_peers","distinct_remote_ports","completed_handshakes","failed_handshakes","retransmissions")){
            measured.put(key,maxOf(0L,facts.optLong(key,0)))
        }
        return JSONObject().put("suspected_pattern",category).put("app_package",if(known)supplied else "unknown")
            .put("app_attribution",if(known)"best_effort_all_contributing_flows" else "unknown_or_mixed")
            .put("socket_role",if(direction=="incoming")"receiver" else if(direction=="outgoing")"sender" else "unknown_or_mixed")
            .put("direction",direction).put("measured_facts",measured).put("attack_confirmed",false)
    }
    fun fallback(facts: JSONObject): String {
        val category=facts.optString("suspected_pattern","unknown_suspicious")
        val description=if(category=="unknown_suspicious")"an unusual traffic pattern" else "a possible ${category.replace('_',' ')} pattern"
        val app=facts.optString("app_package","unknown")
        val owner=if(app=="unknown")"The contributing apps could not be established."
            else if(facts.optString("socket_role")=="receiver")"$app owns the receiving sockets."
            else "$app is the observed socket owner."
        return "The detector found $description. $owner This does not confirm an attack; review expected app activity and network settings."
    }
}
