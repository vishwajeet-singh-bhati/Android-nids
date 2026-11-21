package nids.app

import java.net.InetAddress
import org.json.JSONObject

/** Local IPC is observed separately; it is not declared benign or an external attack. */
object NetworkObservationPolicy {
    const val LOCAL="device_local"
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
