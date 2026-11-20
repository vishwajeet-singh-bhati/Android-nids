package nids.app

import android.content.Context
import android.os.SystemClock
import nids.core.Event
import org.json.JSONArray
import org.json.JSONObject
import java.net.InetAddress
import java.util.concurrent.TimeUnit

/** Best-effort connected-socket snapshots. Missing/ambiguous owners remain unknown. */
class UidResolver(private val ctx: Context) {
    private data class Seen(val uids: Set<Int>, val at: Long)
    private val owners = HashMap<String, Seen>()
    private var localIps=emptySet<String>()
    private var observedAddresses=emptySet<String>()
    @Synchronized fun watchedAddresses(): Set<String> = observedAddresses.toSet()
    @Volatile var status = "not sampled"; private set
    private fun address(value: String): String {
        val i = value.lastIndexOf(':')
        val ip = value.substring(0,i)
        val b = ip.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        val out = ByteArray(b.size)
        for (j in b.indices) out[j] = b[(j / 4) * 4 + 3 - j % 4]
        return canonical(InetAddress.getByAddress(out).hostAddress!!) + ":" + value.substring(i+1).toInt(16)
    }
    private fun canonical(ip: String) = InetAddress.getByName(ip.substringBefore('%')).address.joinToString("") { "%02x".format(it.toInt() and 255) }
    private fun endpoint(s: String): String {
        val i = s.lastIndexOf(':')
        return canonical(s.substring(0,i)) + s.substring(i)
    }
    fun refresh() {
        android.os.Process.setThreadPriority(android.os.Process.THREAD_PRIORITY_BACKGROUND)
        val now = SystemClock.elapsedRealtime()
        val updates=HashMap<String,Seen>();val ips=HashSet<String>();val addresses=HashSet<String>()
        var p: Process? = null
        try {
            val command=listOf("/proc/net/tcp","/proc/net/tcp6","/proc/net/udp","/proc/net/udp6").joinToString("; ") { "echo FILE:$it; cat $it" }+"; echo LOCAL_IPS; ip -o addr show"
            val process = ProcessBuilder("su", "-c", command).redirectErrorStream(true).start()
            p = process
            val text = StringBuilder()
            val reader = Thread { process.inputStream.bufferedReader().useLines { ls -> ls.forEach { if (text.length < 1000000) text.append(it).append('\n') } } }.apply { isDaemon=true; start() }
            require(process.waitFor(2, TimeUnit.SECONDS)) { "socket snapshot timed out" }
            reader.join(500)
            require(process.exitValue() == 0 && !reader.isAlive) { "socket snapshot unavailable" }
            var proto = 0;var readingIps=false
            var rows = 0
            for (line in text.lines()) {
                if(line=="LOCAL_IPS"){readingIps=true;continue}
                if(readingIps){Regex("\\binet6?\\s+([^/\\s]+)").find(line)?.groupValues?.get(1)?.let{try{
                    ips.add(canonical(it));addresses.add(InetAddress.getByName(it.substringBefore('%')).hostAddress!!.substringBefore('%'))
                }catch(_: Exception){}};continue}
                if (line.startsWith("FILE:")) { proto = if ("tcp" in line) 6 else 17; continue }
                val c = line.trim().split(Regex("\\s+"))
                if (c.size < 10 || !c[0].endsWith(':') || c[0] == "sl") continue
                val uid = c[7].toIntOrNull() ?: continue
                if (c[2].substringBefore(':').all { it == '0' }) continue
                val key = "$proto|${address(c[1])}|${address(c[2])}"
                val prev = updates[key]
                updates[key] = Seen((prev?.uids ?: emptySet()) + uid, now)
                rows++
            }
            synchronized(this){
                owners.entries.removeAll{now-it.value.at>10000}
                for((key,value) in updates){val old=owners[key];owners[key]=Seen((old?.uids ?: emptySet())+value.uids,now)}
                while(owners.size>4096)owners.remove(owners.minBy{it.value.at}.key)
                localIps=ips
                observedAddresses=addresses
            }
            status = "connected socket snapshot: $rows rows"
        } catch (e: Exception) { status = "unavailable: ${e.message}" }
        finally { p?.destroy() }
    }
    fun lookup(e: Event): JSONObject = if(e.type=="flow_alert")lookupFlow(e.ipProto,e.initiator,e.responder) else JSONObject().put("status","unknown")
    @Synchronized fun lookupFlow(proto: Int,initiator: String,responder: String): JSONObject {
        val out=JSONObject().put("status","unknown").put("method","root_connected_socket_snapshot").put("app_label","App unknown").put("direction","unknown")
        return try{
            val a=endpoint(initiator);val b=endpoint(responder)
            val aLocal=a.substringBeforeLast(':') in localIps;val bLocal=b.substringBeforeLast(':') in localIps
            val direction=if(aLocal && !bLocal)"outgoing" else if(bLocal && !aLocal)"incoming" else if(aLocal && bLocal)"local" else "unknown"
            out.put("direction",direction).put("transport",if(proto==6)"TCP" else if(proto==17)"UDP" else "other")
            out.put("initiator",initiator).put("responder",responder)
            out.put("local_endpoint",if(aLocal)initiator else if(bLocal)responder else "unknown")
            out.put("remote_endpoint",if(aLocal && !bLocal)responder else if(bLocal && !aLocal)initiator else "unknown")
            val now=SystemClock.elapsedRealtime()
            val hits=listOfNotNull(owners["$proto|$a|$b"],owners["$proto|$b|$a"]).filter{now-it.at<=10000}
            val uids=hits.flatMap{it.uids}.toSet()
            if(uids.size==1){
                val uid=uids.first();val packages=ctx.packageManager.getPackagesForUid(uid)?.toList() ?: emptyList()
                val labels=packages.map{pkg -> try{ctx.packageManager.getApplicationLabel(ctx.packageManager.getApplicationInfo(pkg,0)).toString().replace(Regex("[\\p{Cc}\\p{Cf}]"),"").take(80)}catch(_: Exception){pkg}}
                out.put("status",if(packages.size==1)"best_effort" else "shared_or_system_uid").put("uid",uid).put("packages",JSONArray(packages)).put("labels",JSONArray(labels)).put("app_label",if(labels.size==1)labels[0] else if(uid==0)"System/root process" else "Shared or system UID $uid").put("snapshot_age_ms",hits.minOf{now-it.at})
            }else out.put("reason",if(uids.isEmpty())"No connected-socket match; short-lived connections may be missed" else "Ambiguous socket ownership")
            out.put("ownership_note",if(direction=="incoming")"A socket owner, if shown, received this traffic; it is not identified as the attacker." else "A socket match associates traffic with an app; it does not prove malicious intent.")
        }catch(_: Exception){out.put("reason","Socket ownership unavailable")}
    }
}
