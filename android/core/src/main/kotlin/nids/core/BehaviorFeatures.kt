package nids.core

import java.util.ArrayDeque
import java.util.TreeSet
import kotlin.math.floor
import kotlin.math.ln1p

data class BehaviorSnapshot(val host: String, val endSecond: Long, val features: FloatArray)

/** Continuous causal metadata, with compressed one-second buckets and bounded state. */
class BehaviorActivity(private val maxHosts: Int = 10000, private val maxEntries: Int = 250000) {
    private class Bin(val second: Long) {
        var packets=0L; var bytes=0L; var syn=0L; var rst=0L; var tcp=0L; var udp=0L
        val peers=HashSet<String>(); val remote=HashSet<Int>(); val local=HashSet<Int>()
        fun entries()=peers.size+remote.size+local.size
    }
    private val states=HashMap<String,ArrayDeque<Bin>>()
    private val active=TreeSet<String>()
    private var second: Long?=null
    private var entries=0
    var resets=0L;private set
    var degradedUntil=Long.MIN_VALUE;private set
    fun healthy(now: Long)=now>=degradedUntil
    private fun vector(host: String,end: Long): FloatArray {
        val bins=states[host] ?: return FloatArray(27)
        val result=FloatArray(27)
        intArrayOf(5,30,60).forEachIndexed { i,horizon ->
            var n=0L;var bytes=0L;var syn=0L;var rst=0L;var tcp=0L;var udp=0L
            val peers=HashSet<String>();val remote=HashSet<Int>();val local=HashSet<Int>()
            for(b in bins)if(b.second>=end-horizon && b.second<end){n+=b.packets;bytes+=b.bytes;syn+=b.syn;rst+=b.rst;tcp+=b.tcp;udp+=b.udp;peers.addAll(b.peers);remote.addAll(b.remote);local.addAll(b.local)}
            longArrayOf(n,bytes,syn,rst,peers.size.toLong(),remote.size.toLong(),local.size.toLong()).forEachIndexed { j,value -> result[i*9+j]=ln1p(value.toDouble()).toFloat() }
            result[i*9+7]=tcp.toFloat()/maxOf(1L,n).toFloat();result[i*9+8]=udp.toFloat()/maxOf(1L,n).toFloat()
        }
        return result
    }
    fun advance(ts: Double): List<BehaviorSnapshot> {
        require(ts.isFinite())
        val old=second ?: run {second=floor(ts).toLong();return emptyList()}
        val current=maxOf(old,floor(ts).toLong())
        if(current==old)return emptyList()
        val ready=active.map { BehaviorSnapshot(it,old+1,vector(it,old+1)) }
        active.clear();second=current
        val iterator=states.entries.iterator()
        while(iterator.hasNext()){
            val bins=iterator.next().value
            while(bins.isNotEmpty() && bins.first.second<current-60)entries-=bins.removeFirst().entries()
            if(bins.isEmpty())iterator.remove()
        }
        return ready
    }
    fun push(p: ParsedPacket): List<BehaviorSnapshot> {
        val ready=advance(p.ts)
        update(p,p.srcIp,p.dstIp,p.sport,p.dport);update(p,p.dstIp,p.srcIp,p.dport,p.sport)
        if(states.size>maxHosts || entries>maxEntries){states.clear();active.clear();entries=0;resets++;degradedUntil=second!!+60}
        return ready
    }
    private fun update(p: ParsedPacket,host: String,peer: String,local: Int,remote: Int){
        val bins=states.getOrPut(host){ArrayDeque()}
        val b=if(bins.isEmpty() || bins.last.second!=second){Bin(second!!).also{bins.addLast(it)}} else bins.last
        b.packets++;b.bytes+=p.payloadLen
        if(p.tcpFlags and 2 != 0)b.syn++
        if(p.tcpFlags and 4 != 0)b.rst++
        if(p.ipProto==6)b.tcp++
        if(p.ipProto==17)b.udp++
        if(b.peers.add(peer))entries++
        if(b.remote.add(remote))entries++
        if(b.local.add(local))entries++
        active.add(host)
    }
    fun flush(): List<BehaviorSnapshot> = second?.let{advance((it+1).toDouble())} ?: emptyList()
}
