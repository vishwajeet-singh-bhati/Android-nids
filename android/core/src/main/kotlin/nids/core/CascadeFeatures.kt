package nids.core

import java.util.ArrayDeque
import kotlin.math.floor
import kotlin.math.ln1p

data class CascadeConnectionKey(val protocol: Int,val aIp: String,val aPort: Int,val bIp: String,val bPort: Int)
data class CascadeSnapshot(val host: String,val endSecond: Long,val features: FloatArray,
    val sequence: FloatArray,val mask: FloatArray,val contributingFlows: Set<CascadeConnectionKey>,val healthy: Boolean)

/** V6 feature contract. Candidate-only until model/phone gates pass. */
class CascadeActivity {
    private data class Endpoint(val ip: String,val port: Int)
    private class Connection(var last: Double) {
        var sender: Endpoint?=null;var synSeq: Long?=null;var synackSeq: Long?=null
        var synack=false;var established=false;var failed=false
        val high=HashMap<Endpoint,Long>()
    }
    private class Bin(val second: Long) {
        val counts=DoubleArray(24);val peers=HashSet<String>();val remote=HashSet<Int>();val local=HashSet<Int>()
        val connections=HashMap<CascadeConnectionKey,Int>()
    }
    private data class Event(val ts: Double,val values: FloatArray)
    private val connections=HashMap<CascadeConnectionKey,Connection>()
    private val states=HashMap<String,ArrayDeque<Bin>>()
    private val recent=HashMap<String,ArrayDeque<Event>>()
    private val active=java.util.TreeSet<String>()
    private var second: Long?=null
    private var sweep=Double.NEGATIVE_INFINITY
    private var invalidUntil=Long.MIN_VALUE
    private var pendingInvalidation=false
    var latePackets=0L;private set
    fun invalidate(){
        val now=second;states.clear();recent.clear();active.clear();connections.clear()
        if(now==null)pendingInvalidation=true else invalidUntil=maxOf(invalidUntil,now+60)
    }
    private fun key(p: ParsedPacket): CascadeConnectionKey {
        val ordered=p.srcIp<p.dstIp || p.srcIp==p.dstIp && p.sport<=p.dport
        return if(ordered)CascadeConnectionKey(p.ipProto,p.srcIp,p.sport,p.dstIp,p.dport)
        else CascadeConnectionKey(p.ipProto,p.dstIp,p.dport,p.srcIp,p.sport)
    }
    private fun outcomes(p: ParsedPacket,k: CascadeConnectionKey): IntArray {
        if(!sweep.isFinite() || p.ts-sweep>=5){connections.entries.removeAll{p.ts-it.value.last>120};sweep=p.ts}
        require(connections.size<=100000){"Cascade connection state limit reached"}
        if(p.ipProto!=6)return intArrayOf(0,0,0)
        val sender=Endpoint(p.srcIp,p.sport);val pureSyn=p.tcpFlags and 2!=0 && p.tcpFlags and 16==0
        var state=connections[k]
        if(state==null || pureSyn && (state.sender!=sender || state.synSeq!=p.seq)){
            state=Connection(p.ts);connections[k]=state
        }
        var done=0;var failed=0;var retrans=0
        if(pureSyn){if(state.sender==sender && state.synSeq==p.seq)retrans=1;state.sender=sender;state.synSeq=p.seq}
        if(p.tcpFlags and 2!=0 && p.tcpFlags and 16!=0 && state.sender!=null && sender!=state.sender &&
            p.ack==((state.synSeq!!+1) and 0xffffffffL)){state.synack=true;state.synackSeq=p.seq}
        if(state.synack && !state.established && sender==state.sender && p.tcpFlags and 16!=0 &&
            p.tcpFlags and 6==0 && p.ack==((state.synackSeq!!+1) and 0xffffffffL)){
            state.established=true;done=1
        }
        if(p.tcpFlags and 4!=0 && state.sender!=null && !state.established && !state.failed){state.failed=true;failed=1}
        if(p.payloadLen>0 && p.tcpFlags and 6==0){
            val end=(p.seq+p.payloadLen) and 0xffffffffL;val old=state.high[sender]
            if(old!=null && ((old-end) and 0xffffffffL)<0x80000000L)retrans=1 else state.high[sender]=end
        }
        state.last=maxOf(state.last,p.ts)
        return intArrayOf(done,failed,retrans)
    }
    fun advance(ts: Double): List<CascadeSnapshot> {
        require(ts.isFinite())
        val sec=floor(ts).toLong();val old=second ?: run{second=sec;return emptyList()}
        if(sec<=old)return emptyList()
        val end=old+1;val result=active.map{snapshot(it,end)}
        active.clear();second=sec
        val iterator=states.entries.iterator()
        while(iterator.hasNext()){
            val entry=iterator.next();val bins=entry.value
            while(bins.isNotEmpty() && bins.first.second<sec-60)bins.removeFirst()
            if(bins.isEmpty()){recent.remove(entry.key);iterator.remove()}
        }
        return result
    }
    fun push(p: ParsedPacket): List<CascadeSnapshot> {
        require(p.ts.isFinite())
        if(p.ipProto!=6 && p.ipProto!=17)return emptyList()
        val sec=floor(p.ts).toLong()
        if(pendingInvalidation){invalidUntil=maxOf(invalidUntil,sec+60);pendingInvalidation=false}
        val now=second
        if(now!=null && sec<now){latePackets++;invalidUntil=maxOf(invalidUntil,now+60);return emptyList()}
        val ready=advance(p.ts);val k=key(p);val outcome=outcomes(p,k)
        update(p,k,outcome,p.srcIp,p.dstIp,p.sport,p.dport,true)
        update(p,k,outcome,p.dstIp,p.srcIp,p.dport,p.sport,false)
        require(states.size<=10000){"Cascade endpoint state limit reached"}
        return ready
    }
    private fun update(p: ParsedPacket,k: CascadeConnectionKey,outcome: IntArray,host: String,peer: String,local: Int,remote: Int,out: Boolean){
        val bins=states.getOrPut(host){ArrayDeque()}
        val b=if(bins.isEmpty() || bins.last.second!=second)Bin(second!!).also{bins.addLast(it)} else bins.last
        val c=b.counts;c[0]++;c[1]+=p.payloadLen;c[if(out)2 else 3]++;c[if(out)4 else 5]+=p.payloadLen
        if(p.tcpFlags and 2!=0 && p.tcpFlags and 16==0)c[if(out)6 else 7]++
        if(p.tcpFlags and 2!=0 && p.tcpFlags and 16!=0)c[if(out)8 else 9]++
        if(p.tcpFlags and 4!=0)c[if(out)10 else 11]++
        if(p.tcpFlags and 1!=0)c[12]++;if(p.tcpFlags and 8!=0)c[13]++
        if(p.ipProto==6)c[18]++;if(p.ipProto==17)c[19]++
        c[20]+=outcome[0];c[21]+=outcome[1];c[22]+=outcome[2]
        b.peers.add(peer);b.remote.add(remote);b.local.add(local)
        b.connections[k]=(b.connections[k] ?: 0) or if(out)1 else 2
        val events=recent.getOrPut(host){ArrayDeque()};val previous=events.lastOrNull()?.ts ?: p.ts
        val values=FloatArray(11);values[0]=if(out)1f else -1f;values[1]=ln1p(p.payloadLen.toDouble()).toFloat()
        values[2]=ln1p(maxOf(0.0,p.ts-previous)*1000).toFloat()
        intArrayOf(1,2,4,8,16,32).forEachIndexed{j,bit->values[j+3]=if(p.tcpFlags and bit!=0)1f else 0f}
        values[9]=if(p.ipProto==6)1f else 0f;values[10]=if(p.ipProto==17)1f else 0f
        if(events.size==64)events.removeFirst();events.addLast(Event(p.ts,values));active.add(host)
    }
    private fun snapshot(host: String,end: Long): CascadeSnapshot {
        val bins=states.getValue(host);val features=FloatArray(72);val contributors=HashSet<CascadeConnectionKey>()
        intArrayOf(5,30,60).forEachIndexed{i,horizon->
            val c=DoubleArray(24);val peers=HashSet<String>();val remote=HashSet<Int>();val local=HashSet<Int>()
            val conns=HashMap<CascadeConnectionKey,Int>()
            for(b in bins)if(b.second>=end-horizon && b.second<end){
                for(j in c.indices)c[j]+=b.counts[j]
                peers.addAll(b.peers);remote.addAll(b.remote);local.addAll(b.local)
                for((k,v) in b.connections)conns[k]=(conns[k] ?: 0) or v
            }
            if(i==0)contributors.addAll(conns.keys)
            c[14]=peers.size.toDouble();c[15]=remote.size.toDouble();c[16]=local.size.toDouble();c[17]=conns.size.toDouble()
            c[18]/=maxOf(1.0,c[0]);c[19]/=maxOf(1.0,c[0]);c[23]=conns.values.count{it==3}.toDouble()/maxOf(1,conns.size)
            for(j in 0 until 18)c[j]=ln1p(c[j]);for(j in 20..22)c[j]=ln1p(c[j])
            for(j in c.indices)features[i*24+j]=c[j].toFloat()
        }
        val sequence=FloatArray(64*12);val mask=FloatArray(64)
        recent.getValue(host).filter{it.ts>=end-5 && it.ts<end}.forEachIndexed{i,event->
            event.values.copyInto(sequence,i*12);sequence[i*12+11]=ln1p(maxOf(0.0,end-event.ts)*1000).toFloat();mask[i]=1f
        }
        return CascadeSnapshot(host,end,features,sequence,mask,contributors,end>=invalidUntil)
    }
    fun flush(): List<CascadeSnapshot> = second?.let{advance((it+1).toDouble())} ?: emptyList()
}
