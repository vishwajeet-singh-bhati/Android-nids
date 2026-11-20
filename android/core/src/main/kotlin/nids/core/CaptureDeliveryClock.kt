package nids.core

/** Transport buffering must not move the extractor ahead of queued capture events.
 * Uses packet time while traffic arrives; extrapolates only after a quiet grace.
 * This adapter changes delivery scheduling, not trained flow/history semantics.
 */
class CaptureDeliveryClock(private val idleGraceMillis: Long=2000){
    private var latestCapture=Double.NaN
    private var lastDeliveryMillis=0L
    init{require(idleGraceMillis>=0)}
    fun received(captureSeconds: Double,monotonicMillis: Long){
        require(captureSeconds.isFinite())
        latestCapture=if(latestCapture.isNaN())captureSeconds else maxOf(latestCapture,captureSeconds)
        lastDeliveryMillis=monotonicMillis
    }
    fun advanceTo(monotonicMillis: Long,queuedPackets: Int): Double?{
        if(latestCapture.isNaN() || queuedPackets>0)return null
        val idle=maxOf(0L,monotonicMillis-lastDeliveryMillis-idleGraceMillis)
        return latestCapture+idle/1000.0
    }
}

object CaptureDeliveryClockCheck{
    private fun traffic(): List<ParsedPacket>{
        val rows=ArrayList<ParsedPacket>()
        for(i in 0..19){val ts=1000.0+i*.1
            rows.add(AlignedCheck.packet(ts,sport=40000+i,flags=2))
            rows.add(AlignedCheck.packet(ts+.01,"10.0.0.2","10.0.0.1",80,40000+i,20))
        }
        rows.add(AlignedCheck.packet(1010.0,sport=45000,flags=2))
        return rows
    }
    fun run(): Map<String,Any>{
        val clock=CaptureDeliveryClock();check(clock.advanceTo(1000,0)==null)
        clock.received(10.0,5000);check(clock.advanceTo(7000,1)==null)
        check(clock.advanceTo(6000,0)==10.0);check(clock.advanceTo(8000,0)==11.0)
        val packets=traffic();val expected=ArrayList<AlignedSnapshot>();val actual=ArrayList<AlignedSnapshot>()
        val baseline=AlignedTsanetCollector(setOf("10.0.0.1"));val live=AlignedTsanetCollector(setOf("10.0.0.1"))
        val delivery=CaptureDeliveryClock()
        for((index,p) in packets.withIndex()){
            expected.addAll(baseline.feed(p))
            // Simulate arbitrarily shifted arrival clock and batched/backlogged packets.
            val now=900000L+(index/10)*1000
            delivery.received(p.ts,now);actual.addAll(live.feed(p))
            delivery.advanceTo(now,if(index%10==9)0 else 9-index%10)?.let{actual.addAll(live.advance(it))}
        }
        expected.addAll(baseline.advance(1045.0,true))
        delivery.advanceTo(900000L+((packets.size-1)/10)*1000+37000,0)?.let{actual.addAll(live.advance(it))}
        check(live.late==0L && expected.size==actual.size)
        for((a,b) in expected.zip(actual)){
            check(a.flow.key==b.flow.key && a.flow.flow.contentEquals(b.flow.flow) && a.context.contentEquals(b.context))
            check(a.decisionTime==b.decisionTime)
        }
        return mapOf("passed" to true,"wall_clock_offset_independent" to true,"backlogged_packets_not_skipped" to true,
            "matching_flow_context_and_decision_times" to true,"rows" to actual.size,"late_packets" to live.late)
    }
    @JvmStatic fun main(args: Array<String>){println(AlignedContract.json(run()))}
}
