package nids.app

import org.json.JSONObject

/** Evidence-only prototype. No new detection, attack confirmation or app blame. */
object PerformancePlainNote {
    fun prefix(facts: JSONObject): String {
        val pattern=when(facts.optString("suspected_pattern")) {
            "Bot"->"Possible automated background communication (model estimate)."
            "Brute Force"->"Possible repeated sign-in attempts (model estimate)."
            "DDoS"->"Possible connection overload from several sources (model estimate)."
            "DoS"->"Possible connection overload (model estimate)."
            "Port Scan"->"Possible check for open connections (model estimate)."
            "Web Attack"->"Possible suspicious web activity (model estimate)."
            else->"The model flagged unusual network activity; the type is unknown."
        }
        val app=facts.optString("app_package","unknown")
        val owner=if(app=="unknown")"The app involved is unknown." else if(facts.optString("socket_role")=="receiver")
            "$app received this traffic." else "Associated app: $app."
        val warnings=when {
            !facts.optBoolean("capture_complete") && !facts.optBoolean("history_complete")->" Some traffic was missed and recent history is incomplete."
            !facts.optBoolean("capture_complete")->" Some traffic was missed."
            !facts.optBoolean("history_complete")->" Recent history is incomplete."
            else->""
        }
        return "$pattern This does not confirm an attack. Observed: ${facts.optInt("flow_packets")} network packets (small pieces of data). $owner$warnings "
    }
    fun guidance(facts: JSONObject)=when(facts.optString("suspected_pattern")) {
        "Port Scan"->"Check whether you expected a device search or connection test; review unfamiliar app activity."
        "DoS","DDoS"->"Check for unexpected downloads or repeated connection attempts, and pause unfamiliar app activity."
        "Brute Force"->"Check recent account activity and review apps making unexpected repeated connections."
        "Bot"->"Check expected background syncing and review unfamiliar apps and their permissions."
        "Web Attack"->"Review recent web activity and avoid entering passwords into unexpected prompts."
        else->"Check whether you expected this app or network activity."
    }
    fun render(facts: JSONObject)=prefix(facts)+guidance(facts)
}
