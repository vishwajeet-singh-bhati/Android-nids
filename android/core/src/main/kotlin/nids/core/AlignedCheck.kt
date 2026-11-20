package nids.core

import kotlin.math.abs
import kotlin.math.ln

object AlignedCheck{
    fun packet(t: Double,source: String="10.0.0.1",destination: String="10.0.0.2",sport: Int=40000,dport: Int=80,
        flags: Int=16,text: String="",seq: Long=100)=ParsedPacket(t,6,source,destination,sport,dport,0,flags,seq,text.toByteArray().size,text.toByteArray())
    fun run(): Map<String,Any>{
        check(AlignedContract.NAMES.size==AlignedContract.CONTEXT)
        val collector=AlignedTsanetCollector(setOf("10.0.0.1"));val results=ArrayList<AlignedSnapshot>()
        for(i in 0..3){val t=1000.0+i*.2
            results.addAll(collector.feed(packet(t,sport=40000+i,flags=2)))
            results.addAll(collector.feed(packet(t+.01,"10.0.0.2","10.0.0.1",80,40000+i,20)))
        }
        results.addAll(collector.advance(1002.0));check(results.size==4)
        check(results.first().flow.flow[29]==1f && results.first().flow.flow[30]==1f)
        check(abs(results.last().context[0]-ln(4.0))<1e-5){"Rapid histories are missing"}
        val all=AlignedTsanetCollector();val local=AlignedTsanetCollector(setOf("10.0.0.1"))
        val a=ArrayList<AlignedSnapshot>();val b=ArrayList<AlignedSnapshot>()
        val traffic=listOf(packet(2000.0,"10.0.0.2","10.0.0.3",41000,80,2),packet(2000.01,"10.0.0.3","10.0.0.2",80,41000,20),
            packet(2001.0,sport=42000,flags=2),packet(2001.01,"10.0.0.2","10.0.0.1",80,42000,20))
        for(p in traffic){a.addAll(all.feed(p));b.addAll(local.feed(p))};a.addAll(all.advance(2002.0));b.addAll(local.advance(2002.0))
        val visible=a.single{it.watched=="10.0.0.1"};check(visible.context.contentEquals(b.single().context)){"Remote third-party traffic leaked"}
        val zero=AlignedTsanetCollector(setOf("10.0.0.1"));zero.feed(packet(3000.0,flags=2));val one=zero.advance(3032.0,true).single()
        check(one.flow.flow[0]==0f && one.flow.flow[14]==0f && one.flow.flow[1]==1f)
        val semantics=WireSemantics();semantics.push(packet(4000.0,text="GET /login HTTP/1.1\r\n\r\n",seq=1000),true)
        val first=packet(4000.1,text="HTTP/1.1 40",seq=2000);semantics.push(first,false)
        semantics.push(first,false);semantics.push(packet(4000.2,text="1 Unauthorized\r\n\r\n",seq=2011),false)
        check(semantics.values[0]==1f && semantics.values[2]==1f && semantics.values[11]>0)
        val sql=WireSemantics();sql.push(packet(4100.0,text="GET /?q=%27%20OR%201=1-- HTTP/1.1\r\n\r\n"),true);check(sql.values[6]==1f)
        val normal=WireSemantics();normal.push(packet(4100.0,text="GET /normal?order=1 HTTP/1.1\r\n\r\n"),true);check(normal.values[6]==0f && normal.values[7]==0f)
        val body=WireSemantics();body.push(packet(4150.0,text="HTTP/1.1 200 OK\r\n\r\nGET /?q=union%20select HTTP/1.1\r\n"),false)
        check(body.values[0]==0f && body.values[6]==0f)
        val tls=WireSemantics();tls.push(ParsedPacket(4200.0,6,"a","b",1,2,0,16,10,5,byteArrayOf(22,3,3,0,0)),true)
        check(tls.values[8]==1f && tls.values[0]==0f && tls.values[2]==0f)
        val expiry=AlignedTsanetCollector(setOf("10.0.0.1"));expiry.feed(packet(5000.0,flags=2));expiry.feed(packet(5000.01,"10.0.0.2","10.0.0.1",80,40000,20));expiry.advance(5001.0)
        expiry.feed(packet(5400.0,sport=44000,flags=2));expiry.feed(packet(5400.01,"10.0.0.2","10.0.0.1",80,44000,20));val later=expiry.advance(5402.0).single()
        check(later.context.take(96).all{it==0f})
        val clock=AlignedTsanetCollector(setOf("10.0.0.1"));clock.feed(packet(6000.0,flags=2));clock.advance(6001.0)
        clock.feed(packet(6000.5,sport=45000,flags=2));clock.advance(6002.0);check(clock.late==1L)
        return mapOf("passed" to true,"rapid_history" to true,"phone_visibility" to true,"zero_duration" to true,
            "http_reassembly" to true,"payload_duplicate" to true,"sql_negative_control" to true,"encrypted_scope" to true,"expiry" to true)
    }
    @JvmStatic fun main(args: Array<String>){println(AlignedContract.json(run()))}
}
