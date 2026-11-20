package nids.core

import kotlin.math.abs
import kotlin.math.ln
import kotlin.math.sqrt

object TsanetCheck{
    private fun packet(t: Double,reverse: Boolean=false,length: Int=0,flags: Int=16,sport: Int=40000,dport: Int=443)=
        if(!reverse)ParsedPacket(t,6,"10.0.0.1","10.0.0.2",sport,dport,0,flags,0,length,byteArrayOf())
        else ParsedPacket(t,6,"10.0.0.2","10.0.0.1",dport,sport,0,flags,0,length,byteArrayOf())
    private fun close(collector: TsanetFlowCollector,start: Double,sport: Int): TsanetSnapshot{
        collector.feed(packet(start,length=10,flags=2,sport=sport))
        return collector.feed(packet(start+.5,true,20,20,sport)).single()
    }
    @JvmStatic fun main(args: Array<String>){
        val draft=ExplanationText.notificationDraft("Here is a rewritten notification at most 65 words:\n\nThe model suggests possible Port Scan activity.\nThis does not confirm an attack.\nThis does not confirm an attack.")
        check(!draft.contains("65") && Regex("This does not confirm an attack").findAll(draft).count()==1)
        check(draft.startsWith("The model suggests"))
        val c=TsanetFlowCollector()
        check(c.feed(packet(1000.0,length=10,flags=2)).isEmpty())
        check(c.feed(packet(1001.0,true,20,18)).isEmpty())
        check(c.feed(packet(1002.0,length=30)).isEmpty())
        val x=c.feed(packet(1003.0,true,0,20)).single()
        check(x.flow.size==32 && x.context.size==78 && x.context.all{it==0f})
        val expected=doubleArrayOf(3e6,2.0,2.0,40.0,20.0,30.0,10.0,20.0,sqrt(200.0),20.0,0.0,10.0,sqrt(200.0),
            20.0,4.0/3,1e6,0.0,1e6,1e6,2e6,2e6,0.0,2e6,2e6,2e6,2e6,0.0,2e6,2e6,2.0,1.0,3.0)
        for(i in expected.indices)check(abs(x.flow[i]-expected[i])<maxOf(.01,abs(expected[i])*1e-6)){"Feature $i: ${x.flow[i]} expected ${expected[i]}"}
        val h=TsanetFlowCollector()
        var expectedHistory=0
        for(port in 41000..41030){
            val start=1000.0+(port-41000)
            val snapshot=close(h,start,port)
            check(snapshot.context.all{it==0f}) // Same coarse completion interval is never visible.
            val sample=(snapshot.key+"|"+(start*1e6).toLong()).hashCode().toLong() and 0xffffffffL
            if(start<1020 && sample%10<7)expectedHistory++
        }
        check(h.historyFlows in 10..30)
        val later=close(h,1120.0,42000)
        check(later.context[0]>0 && later.context[5]>0 && later.context[13]>0)
        check(abs(later.context[0]-ln(1.0+expectedHistory))<1e-6)
        val expired=close(h,3000.0,43000)
        check(expired.context.all{it==0f})
        val before=h.completed
        h.feed(packet(4000.0,sport=44000));h.tick(4201.0)
        check(h.completed==before && h.invalidFlows>0)
        h.feed(packet(3000.0,sport=44001));check(h.latePackets>0)
        println("TSANET_FEATURE_CHECK_PASS: 32 statistics, temporal exclusion, history sampling/expiry and invalid-rate coverage")
    }
}
