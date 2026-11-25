package nids.app

import java.net.InetAddress
import org.json.JSONObject

/** Local IPC is observed separately; it is not declared benign or an external attack. */
object NetworkObservationPolicy {
    const val LOCAL="device_local"
    fun rejectedIncomingEvidence(evidence: JSONObject): Boolean {
        if(evidence.optString("feature_schema")!="phone-aligned-v2" ||
           evidence.optString("flow_close_reason")!="tcp_reset")return false
        val flow=evidence.optJSONArray("flow_features") ?: return false
        val context=evidence.optJSONArray("context_features") ?: return false
        if(flow.length()!=32 || context.length()!=115)return false
        return nids.core.RejectedHandshakeEvidence.matches(FloatArray(32){flow.optDouble(it,Double.NaN).toFloat()},
            FloatArray(115){context.optDouble(it,Double.NaN).toFloat()},
            evidence.optJSONObject("attribution")?.optString("direction")=="incoming",
            evidence.optBoolean("capture_healthy",false),evidence.optInt("class_id"))
    }
    fun rejectedFingerprint(evidence: JSONObject): String {
        val owner=evidence.getJSONObject("attribution")
        return "rejected-incoming-v1|${endpointIp(owner.optString("remote_endpoint"))}|${owner.optString("local_endpoint")}"
    }
    fun expectedRepeatKey(evidence: JSONObject): String? {
        if(evidence.optString("traffic_scope")!="external_network" ||
           !evidence.optBoolean("gate_flagged") || !rejectedIncomingEvidence(evidence))return null
        val ports=evidence.optInt("target_ports_5m",-1)
        if(ports !in 0..1)return null
        val owner=evidence.getJSONObject("attribution")
        val local=owner.optString("local_endpoint")
        val remote=owner.optString("remote_endpoint")
        if(endpointIp(local).isBlank() || endpointIp(remote).isBlank() ||
           (local.substringAfterLast(':').toIntOrNull() ?: 0) !in 1..65535)return null
        return rejectedFingerprint(evidence)
    }
    fun groupingWindowMs(evidence: JSONObject)=if(rejectedIncomingEvidence(evidence))300000L else 30000L
    fun endpointIp(endpoint: String): String=endpoint.substringBeforeLast(':',"").removePrefix("[").removeSuffix("]")
    private fun loopback(ip: String): Boolean=try {
        val literal=ip.substringBefore('%')
        if(!literal.matches(Regex("[0-9a-fA-F:.]+")) || ':' !in literal && !literal.matches(Regex("\\d+\\.\\d+\\.\\d+\\.\\d+")))false
        else InetAddress.getByName(literal).isLoopbackAddress
    }catch(_: Exception){false}
    fun isDeviceLocal(source: String,destination: String)=loopback(source) && loopback(destination)
    fun localEvidence(evidence: JSONObject): Boolean {
        val owner=evidence.optJSONObject("attribution") ?: return false
        return isDeviceLocal(endpointIp(owner.optString("initiator")),endpointIp(owner.optString("responder")))
    }
    fun explanationAllowed(row: JSONObject)=row.optString("disposition") !in setOf("dismissed","out_of_scope") && row.optString("traffic_scope")!=LOCAL
    fun liveSocketOwner(protocol: Int,state: String,uid: Int,inode: Long)=uid>=0 && inode>0 && (protocol!=6 || state!="06")
    fun localNote(evidence: JSONObject): String {
        val owner=evidence.optJSONObject("attribution") ?: JSONObject()
        val source=owner.optString("initiator").take(100);val target=owner.optString("responder").take(100)
        return "This connection stayed inside this phone: $source to $target. It was moved out of the external-network intrusion assessment. This does not establish whether the local activity is safe. The original model result remains in the saved evidence. If this activity is unfamiliar, review installed apps and developer tools."
    }
}
