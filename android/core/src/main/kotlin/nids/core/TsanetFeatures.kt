package nids.core

import java.util.ArrayDeque
import kotlin.math.floor
import kotlin.math.ln
import kotlin.math.max
import kotlin.math.sqrt

/** Full-flow statistics in CICFlowMeter units; no payload contents are retained. */
private class TsanetStats {
    var n=0; var mean=0.0; var m2=0.0; var total=0.0; var low=Double.POSITIVE_INFINITY; var high=0.0
    fun add(x: Double){n++;val delta=x-mean;mean+=delta/n;m2+=delta*(x-mean);total+=x;low=minOf(low,x);high=max(high,x)}
    fun minimum()=if(n==0)0.0 else low
    fun deviation()=if(n<2)0.0 else sqrt(max(0.0,m2/(n-1)))
}

data class TsanetSnapshot(
    val flow: FloatArray,val context: FloatArray,val protocol: Int,
    val source: String,val sourcePort: Int,val destination: String,val destinationPort: Int,
    val start: Double,val end: Double,val packets: Int,val closeReason: String,
    val historyAgeSeconds: Double,val key: String,
    val auxiliary: FloatArray=FloatArray(0),
)

class TsanetFlowCollector(
    private val collectHistory: Boolean=true,
    private val finiteZeroDuration: Boolean=false,
    private val maxDuration: Double=120.0,
    private val tcpIdle: Double=120.0,
    private val udpIdle: Double=30.0,
    private val maxActive: Int=4096,
    private val protocolFeatures: Boolean=false,
    private val sequenceAware: Boolean=false,
) {
    private class Flow(val first: ParsedPacket,val key: String,protocol: Boolean){
        val semantics=if(protocol)WireSemantics() else null
        var last=first.ts;var previous=first.ts;var forwardLast=first.ts;var backwardLast=0.0
        val fwd=TsanetStats();val bwd=TsanetStats();val iat=TsanetStats();val fi=TsanetStats();val bi=TsanetStats()
        var syn=0;var rst=0;var ack=0;var fwdFin=false;var bwdFin=false
        val packets get()=fwd.n+bwd.n
        fun add(p: ParsedPacket){
            val forward=p.srcIp==first.srcIp && p.sport==first.sport
            semantics?.push(p,forward)
            if(packets>0)iat.add(max(0.0,(p.ts-previous)*1e6))
            if(forward){if(fwd.n>0)fi.add(max(0.0,(p.ts-forwardLast)*1e6));fwd.add(p.payloadLen.toDouble());forwardLast=p.ts}
            else{if(bwd.n>0)bi.add(max(0.0,(p.ts-backwardLast)*1e6));bwd.add(p.payloadLen.toDouble());backwardLast=p.ts}
            if(p.tcpFlags and 2!=0)syn++
            if(p.tcpFlags and 4!=0)rst++
            if(p.tcpFlags and 16!=0)ack++
            if(p.tcpFlags and 1!=0){if(forward)fwdFin=true else bwdFin=true}
            previous=p.ts;last=max(last,p.ts)
        }
        fun vector(allowZeroDuration: Boolean=false): FloatArray?{
            val duration=(last-first.ts)*1e6
            if(duration<0 || duration==0.0 && !allowZeroDuration)return null
            val values=doubleArrayOf(duration,fwd.n.toDouble(),bwd.n.toDouble(),fwd.total,bwd.total,
                fwd.high,fwd.minimum(),fwd.mean,fwd.deviation(),bwd.high,bwd.minimum(),bwd.mean,bwd.deviation(),
                if(duration>0)(fwd.total+bwd.total)*1e6/duration else 0.0,if(duration>0)packets*1e6/duration else 0.0,
                iat.mean,iat.deviation(),iat.high,iat.minimum(),
                fi.total,fi.mean,fi.deviation(),fi.high,fi.minimum(),
                bi.total,bi.mean,bi.deviation(),bi.high,bi.minimum(),syn.toDouble(),rst.toDouble(),ack.toDouble())
            return FloatArray(32){values[it].toFloat()}.takeIf{a->a.all{it.isFinite()}}
        }
    }
    private data class History(val source: String,val destination: String,val sport: Int,val dport: Int,
        val lower: Double,val upper: Double,val measures: DoubleArray,val available: Double)
    private val active=LinkedHashMap<String,Flow>()
    private val history=ArrayDeque<History>()
    private var firstSeen=Double.NaN
    private var clock=0.0
    var completed=0L;private set
    var invalidFlows=0L;private set
    var evictions=0L;private set
    var latePackets=0L;private set
    val activeFlows get()=active.size
    fun isActive(key: String)=active.containsKey(key)
    val historyFlows get()=history.size
    fun historyAge(now: Double)=if(firstSeen.isNaN())0.0 else max(0.0,now-firstSeen)

    fun feed(p: ParsedPacket): List<TsanetSnapshot>{
        if(p.ipProto!=6 && p.ipProto!=17)return emptyList()
        if(firstSeen.isNaN())firstSeen=p.ts
        if(p.ts+0.001<clock){latePackets++;return emptyList()}
        clock=max(clock,p.ts)
        val output=ArrayList<TsanetSnapshot>()
        val key=flowKey(p.ipProto,p.srcIp,p.sport,p.dstIp,p.dport)
        var flow=active[key]
        val newSyn=p.ipProto==6 && p.tcpFlags and 2!=0 && p.tcpFlags and 16==0
        val tupleChanged=flow!=null && newSyn && flow.packets>1 && p.ts-flow.first.ts>1.0 && flow.bwd.n>0 && (!sequenceAware || p.seq!=flow.first.seq)
        if(flow!=null && (p.ts-flow.first.ts>=maxDuration || p.ts-flow.last>=tcpIdle ||
                tupleChanged)){
            active.remove(key)
            finish(flow,if(tupleChanged)"tuple_reused" else "flow_boundary",p.ts)?.let{output.add(it)}
            flow=null
        }
        if(flow==null){
            if(active.size>=maxActive){active.remove(active.keys.first());evictions++}
            flow=Flow(p,key,protocolFeatures);active[key]=flow
        }
        flow.add(p)
        if(p.ipProto==6 && p.tcpFlags and 4!=0){active.remove(key);finish(flow,"tcp_reset",p.ts)?.let{output.add(it)}}
        return output
    }

    fun tick(now: Double, flush: Boolean=false): List<TsanetSnapshot>{
        val output=ArrayList<TsanetSnapshot>()
        val iterator=active.entries.iterator()
        while(iterator.hasNext() && output.size<128){
            val flow=iterator.next().value
            val idle=now-flow.last
            val closed=flow.fwdFin && flow.bwdFin && idle>=1.0
            if(flush || closed || now-flow.first.ts>=maxDuration || idle>=if(flow.first.ipProto==17)udpIdle else tcpIdle){
                iterator.remove()
                finish(flow,if(flush)"monitor_stop" else if(closed)"tcp_fin" else "timeout",now)?.let{output.add(it)}
            }
        }
        while(history.isNotEmpty() && now-history.first.available>1080.0)history.removeFirst()
        return output
    }

    private fun finish(f: Flow,reason: String,available: Double): TsanetSnapshot?{
        val vector=f.vector(finiteZeroDuration)
        if(vector==null){invalidFlows++;return null}
        // Match the coarse training clock without inventing within-minute order.
        val lower=floor(f.first.ts/60.0)*60.0+(f.last-f.first.ts)
        val context=if(collectHistory)summarize(f.first.srcIp,f.first.dstIp,lower) else FloatArray(0)
        completed++
        val snapshot=TsanetSnapshot(vector,context,f.first.ipProto,f.first.srcIp,f.first.sport,
            f.first.dstIp,f.first.dport,f.first.ts,f.last,f.packets,reason,historyAge(available),f.key,f.semantics?.values ?: FloatArray(0))
        // Reproduce the training-bank density without using any inferred labels.
        val sample=(f.key+"|"+(f.first.ts*1e6).toLong()).hashCode().toLong() and 0xffffffffL
        if(collectHistory && sample%10<7){
            if(history.size>=50000){history.removeFirst();evictions++}
            history.addLast(History(f.first.srcIp,f.first.dstIp,f.first.sport,f.first.dport,lower,lower+60.0,
                doubleArrayOf(1.0,f.fwd.n.toDouble(),f.bwd.n.toDouble(),f.fwd.total,f.bwd.total,
                    if(f.bwd.n==0)1.0 else 0.0,if(f.rst>0)1.0 else 0.0,if(f.syn>0)1.0 else 0.0,
                    if(f.first.ipProto==6)1.0 else 0.0,if(f.first.ipProto==17)1.0 else 0.0),available))
        }
        return snapshot
    }

    private fun summarize(source: String,destination: String,anchor: Double): FloatArray{
        val output=FloatArray(78)
        for((wi,window) in doubleArrayOf(120.0,300.0,900.0).withIndex())for((role,host) in listOf(source,destination).withIndex()){
            val sums=DoubleArray(10);val peers=HashSet<String>();val remote=HashSet<Int>();val local=HashSet<Int>()
            fun add(h: History,reverse: Boolean){
                for(k in 0..9)sums[k]+=when{reverse && k==1->h.measures[2];reverse && k==2->h.measures[1]
                    reverse && k==3->h.measures[4];reverse && k==4->h.measures[3]
                    reverse && k==5->if(h.measures[1]==0.0)1.0 else 0.0;else->h.measures[k]}
                peers.add(if(reverse)h.source else h.destination)
                remote.add(if(reverse)h.sport else h.dport);local.add(if(reverse)h.dport else h.sport)
            }
            for(h in history)if(h.upper<anchor && h.lower>=anchor-window){
                if(h.source==host)add(h,false)
                if(h.destination==host)add(h,true)
            }
            val offset=wi*26+role*13
            for(k in 0..4)output[offset+k]=ln(1+sums[k]).toFloat()
            output[offset+5]=ln(1.0+peers.size).toFloat();output[offset+6]=ln(1.0+remote.size).toFloat();output[offset+7]=ln(1.0+local.size).toFloat()
            if(sums[0]>0)for(k in 0..4)output[offset+8+k]=(sums[5+k]/sums[0]).toFloat()
        }
        return output
    }

    companion object{
        fun flowKey(protocol: Int,source: String,sport: Int,destination: String,dport: Int): String{
            val a="$source:$sport";val b="$destination:$dport"
            return if(a<=b)"$protocol|$a|$b" else "$protocol|$b|$a"
        }
    }
}
