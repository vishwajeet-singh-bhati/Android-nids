package nids.core

import java.util.ArrayDeque
import java.util.PriorityQueue
import kotlin.math.floor
import kotlin.math.ln

data class AlignedSnapshot(val flow: TsanetSnapshot,val watched: String,val context: FloatArray,val legacyContext: FloatArray,val decisionTime: Double)

/** Version 2: the same implementation runs in offline extraction and Android checks.
 * Each view contains only traffic incident to its watched endpoint. Remote history
 * cannot include the remote endpoint's conversations with other clients.
 */
class AlignedTsanetCollector(private val watched: Set<String>?=null,private val includeLegacy: Boolean=false){
    private data class Entry(val packet: ParsedPacket,val order: Long)
    private data class History(val source: String,val destination: String,val sport: Int,val dport: Int,val protocol: Int,
        val values: DoubleArray,val available: Double,val lower: Double,val sample: Boolean)
    private val raw=TsanetFlowCollector(false,true,30.0,30.0,10.0,250000,true,true)
    private val reorder=PriorityQueue<Entry>(compareBy<Entry>{it.packet.ts}.thenBy{it.order})
    private val histories=HashMap<String,ArrayDeque<History>>()
    private val banks=HashMap<String,Bank>()
    private class Counts{
        val sums=DoubleArray(13)
        val peers=HashMap<String,Int>();val local=HashMap<Int,Int>();val remote=HashMap<Int,Int>()
        private fun <T> change(map: MutableMap<T,Int>,key: T,delta: Int){val n=(map[key] ?: 0)+delta;if(n==0)map.remove(key) else map[key]=n}
        fun update(h: History,host: String,delta: Int){
            val reverse=h.destination==host;val v=h.values
            val a=doubleArrayOf(1.0,v[if(reverse)1 else 0],v[if(reverse)0 else 1],v[if(reverse)3 else 2],v[if(reverse)2 else 3],
                if(v[if(reverse)0 else 1]==0.0)1.0 else 0.0,if(v[5]>0)1.0 else 0.0,if(v[4]>0)1.0 else 0.0,
                if(h.protocol==6)1.0 else 0.0,if(h.protocol==17)1.0 else 0.0,v[6],v[7],v[8])
            for(i in a.indices)sums[i]+=delta*a[i]
            change(peers,if(reverse)h.source else h.destination,delta)
            change(local,if(reverse)h.dport else h.sport,delta);change(remote,if(reverse)h.sport else h.dport,delta)
        }
        fun write(out: FloatArray,offset: Int){
            if(sums[0]<=0)return
            for(i in 0..4)out[offset+i]=ln(1+maxOf(0.0,sums[i])).toFloat()
            out[offset+5]=ln(1.0+peers.size).toFloat();out[offset+6]=ln(1.0+remote.size).toFloat();out[offset+7]=ln(1.0+local.size).toFloat()
            for(i in 0..4)out[offset+8+i]=(sums[5+i]/sums[0]).toFloat()
            for(i in 0..2)out[offset+13+i]=ln(1+maxOf(0.0,sums[10+i])).toFloat()
        }
    }
    private class Window(val seconds: Double,val host: String){
        var evictions=0L
        val rows=ArrayDeque<History>();val local=Counts();val remote=HashMap<String,Counts>()
        fun add(h: History){val peer=if(h.source==host)h.destination else h.source
            rows.addLast(h);local.update(h,host,1);remote.getOrPut(peer){Counts()}.update(h,peer,1)}
        fun expire(now: Double){while(rows.isNotEmpty() && (rows.first.available<now-seconds || rows.size>50000)){
            if(rows.size>50000 && rows.first.available>=now-seconds)evictions++
            val h=rows.removeFirst();val peer=if(h.source==host)h.destination else h.source
            local.update(h,host,-1);val count=remote.getValue(peer);count.update(h,peer,-1);if(count.sums[0]<=0)remote.remove(peer)
        }}
    }
    private class Bank(val host: String){
        var firstSeen=Double.NaN
        val pending=ArrayDeque<History>();val windows=arrayOf(Window(5.0,host),Window(30.0,host),Window(300.0,host))
        fun advance(now: Double){
            while(pending.isNotEmpty() && pending.first.available<now){val h=pending.removeFirst();for(w in windows)if(h.available>=now-w.seconds)w.add(h)}
            for(w in windows)w.expire(now)
        }
        fun context(s: TsanetSnapshot,now: Double): FloatArray{
            advance(now);val out=FloatArray(115)
            for((wi,w) in windows.withIndex())for((role,endpoint) in listOf(s.source,s.destination).withIndex()){
                (if(endpoint==host)w.local else w.remote[endpoint])?.write(out,wi*32+role*16)
            }
            for(i in 0 until 18)out[96+i]=s.auxiliary.getOrElse(i){0f}
            out[114]=ln(1+minOf(300.0,maxOf(0.0,now-(if(firstSeen.isNaN())s.start else firstSeen)))).toFloat()
            check(out.all{it.isFinite()});return out
        }
        fun empty()=pending.isEmpty() && windows.all{it.rows.isEmpty()}
    }
    private var serial=0L;private var latest=Double.NEGATIVE_INFINITY;private var processed=Double.NEGATIVE_INFINITY
    private var lastTick=Double.NEGATIVE_INFINITY
    var late=0L;private set
    var forcedReorder=0L;private set
    private var legacyEvictions=0L
    val historyEvictions get()=legacyEvictions+banks.values.sumOf{b->b.windows.sumOf{it.evictions}}
    val flowEvictions get()=raw.evictions
    val invalidFlows get()=raw.invalidFlows
    val activeFlows get()=raw.activeFlows
    private fun relevant(p: ParsedPacket)=watched==null || p.srcIp in watched || p.dstIp in watched
    fun feed(p: ParsedPacket): List<AlignedSnapshot>{
        if(p.ipProto !in setOf(6,17) || !relevant(p))return emptyList()
        latest=maxOf(latest,p.ts);reorder.add(Entry(p,serial++))
        val output=ArrayList<AlignedSnapshot>()
        while(reorder.isNotEmpty() && (reorder.peek().packet.ts<=latest-.05 || reorder.size>65536)){
            if(reorder.size>65536)forcedReorder++
            process(reorder.remove().packet,output)
        }
        return output
    }
    private fun process(p: ParsedPacket,out: MutableList<AlignedSnapshot>){
        if(p.ts<processed){late++;return}
        processed=p.ts
        for(host in listOf(p.srcIp,p.dstIp).distinct())if(watched==null || host in watched){val bank=banks.getOrPut(host){Bank(host)};if(bank.firstSeen.isNaN())bank.firstSeen=p.ts}
        ticks(p.ts,out)
        for(s in raw.feed(p))emit(s,p.ts,out)
    }
    private fun ticks(until: Double,out: MutableList<AlignedSnapshot>){
        val limit=floor(until)
        if(!lastTick.isFinite())lastTick=limit
        while(lastTick<limit){
            if(raw.activeFlows==0){lastTick=limit;break}
            lastTick++
            for(s in raw.tick(lastTick))emit(s,lastTick,out)
        }
    }
    fun advance(now: Double,finish: Boolean=false): List<AlignedSnapshot>{
        val out=ArrayList<AlignedSnapshot>()
        while(reorder.isNotEmpty() && (finish || reorder.peek().packet.ts<=now-.05))process(reorder.remove().packet,out)
        val clock=maxOf(processed,now-.05)
        ticks(clock,out)
        if(finish)for(s in raw.tick(clock,true))emit(s,clock,out)
        processed=maxOf(processed,clock)
        return out
    }
    private fun emit(s: TsanetSnapshot,now: Double,out: MutableList<AlignedSnapshot>){
        val hosts=listOf(s.source,s.destination).distinct().filter{watched==null || it in watched}
        for(host in hosts){
            val ctx=banks.getOrPut(host){Bank(host)}.context(s,now)
            val legacy=if(includeLegacy){
                val history=histories.getOrPut(host){ArrayDeque()}
                while(history.isNotEmpty() && now-history.first.available>1080)history.removeFirst()
                context(history,host,s,now,true)
            }else FloatArray(0)
            out.add(AlignedSnapshot(s,host,ctx,legacy,now))
        }
        val f=s.flow
        val sample=((s.key+"|"+(s.start*1e6).toLong()).hashCode().toLong() and 0xffffffffL)%10<7
        val h=History(s.source,s.destination,s.sourcePort,s.destinationPort,s.protocol,
            doubleArrayOf(f[1].toDouble(),f[2].toDouble(),f[3].toDouble(),f[4].toDouble(),f[29].toDouble(),f[30].toDouble(),
                s.auxiliary.getOrElse(2){0f}.toDouble(),s.auxiliary.getOrElse(0){0f}.toDouble(),
                (s.auxiliary.getOrElse(6){0f}+s.auxiliary.getOrElse(7){0f}).toDouble()),
            now,floor(s.start/60)*60+(s.end-s.start),sample)
        for(host in hosts){
            banks.getValue(host).pending.addLast(h)
            if(includeLegacy){val history=histories.getValue(host);if(history.size>=50000){history.removeFirst();legacyEvictions++};history.addLast(h)}
        }
        if(serial%10000L==0L){val iterator=histories.entries.iterator();while(iterator.hasNext()){
            val row=iterator.next();while(row.value.isNotEmpty() && now-row.value.first.available>1080)row.value.removeFirst()
            if(row.value.isEmpty())iterator.remove()
        };val rows=banks.entries.iterator();while(rows.hasNext()){val bank=rows.next().value;bank.advance(now);if(bank.empty())rows.remove()}}
    }
    private fun context(history: ArrayDeque<History>,watchedHost: String,s: TsanetSnapshot,now: Double,legacy: Boolean): FloatArray{
        val output=FloatArray(78)
        val windows=if(legacy)doubleArrayOf(120.0,300.0,900.0) else doubleArrayOf(5.0,30.0,300.0)
        val anchor=if(legacy)floor(s.start/60)*60+(s.end-s.start) else now
        for((wi,window) in windows.withIndex())for((role,host) in listOf(s.source,s.destination).withIndex()){
            val sums=DoubleArray(10);val peers=HashSet<String>();val remote=HashSet<Int>();val local=HashSet<Int>()
            for(h in history){
                if(legacy){if(!h.sample || h.lower+60>=anchor || h.lower<anchor-window)continue}
                else if(h.available>=anchor || h.available<anchor-window)continue
                if(h.source!=host && h.destination!=host)continue
                val reverse=h.destination==host
                sums[0]++;sums[1]+=h.values[if(reverse)1 else 0];sums[2]+=h.values[if(reverse)0 else 1]
                sums[3]+=h.values[if(reverse)3 else 2];sums[4]+=h.values[if(reverse)2 else 3]
                sums[5]+=if(h.values[if(reverse)0 else 1]==0.0)1.0 else 0.0
                sums[6]+=if(h.values[5]>0)1.0 else 0.0;sums[7]+=if(h.values[4]>0)1.0 else 0.0
                sums[8]+=if(h.protocol==6)1.0 else 0.0;sums[9]+=if(h.protocol==17)1.0 else 0.0
                peers.add(if(reverse)h.source else h.destination)
                remote.add(if(reverse)h.sport else h.dport);local.add(if(reverse)h.dport else h.sport)
            }
            val offset=wi*26+role*13
            for(k in 0..4)output[offset+k]=ln(1+sums[k]).toFloat()
            output[offset+5]=ln(1.0+peers.size).toFloat();output[offset+6]=ln(1.0+remote.size).toFloat();output[offset+7]=ln(1.0+local.size).toFloat()
            if(sums[0]>0)for(k in 0..4)output[offset+8+k]=(sums[k+5]/sums[0]).toFloat()
        }
        check(output.all{it.isFinite()});return output
    }
}
