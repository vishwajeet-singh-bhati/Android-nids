package nids.core

import kotlin.math.floor

/** Single-consumer event timeline. Late arrivals degrade quality instead of moving into a future bin. */
class BehaviorTimeline(private val idleGraceMs: Long = 2000) {
    private var activity=BehaviorActivity()
    private var watermark=Long.MIN_VALUE
    private var anchorTs=Double.NEGATIVE_INFINITY
    private var anchorMs=0L
    private var invalidUntil=Long.MIN_VALUE
    var latePackets=0L;private set
    var lossSignals=0L;private set
    var idleClosures=0L;private set
    private var previousResets=0L
    private var pendingInvalidation=false
    val featureResets get()=previousResets+activity.resets
    fun healthy(end: Long)=end>=invalidUntil && activity.healthy(end)
    fun invalidate(){
        lossSignals++;previousResets+=activity.resets;activity=BehaviorActivity()
        if(watermark!=Long.MIN_VALUE)invalidUntil=maxOf(invalidUntil,watermark+60) else pendingInvalidation=true
    }
    fun push(p: ParsedPacket, receivedMs: Long): List<BehaviorSnapshot> {
        require(p.ts.isFinite())
        val second=floor(p.ts).toLong()
        if(pendingInvalidation){invalidUntil=maxOf(invalidUntil,second+60);pendingInvalidation=false}
        if(second<watermark){latePackets++;invalidUntil=maxOf(invalidUntil,watermark+60);return emptyList()}
        val ready=activity.push(p);watermark=second
        if(p.ts>=anchorTs){anchorTs=p.ts;anchorMs=receivedMs}
        return ready
    }
    fun idle(nowMs: Long): List<BehaviorSnapshot> {
        if(!anchorTs.isFinite() || nowMs-anchorMs<idleGraceMs)return emptyList()
        val target=anchorTs+(nowMs-anchorMs-idleGraceMs)/1000.0
        val second=floor(target).toLong()
        if(second<=watermark)return emptyList()
        val ready=activity.advance(target);watermark=second
        if(ready.isNotEmpty())idleClosures++
        return ready
    }
}

/** Behavioral checks for idle finalization, clock jumps, late packets and loss abstention. */
object BehaviorTimelineCheck {
    @JvmStatic fun main(args: Array<String>){
        fun packet(t: Double)=ParsedPacket(t,6,"a","b",100,200,0,2,0,64,byteArrayOf())
        val timeline=BehaviorTimeline();check(timeline.push(packet(100.2),1000).isEmpty())
        check(timeline.idle(2999).isEmpty());check(timeline.idle(4000).size==2)
        check(timeline.idle(5000).isEmpty())
        check(timeline.push(packet(100.9),5100).isEmpty());check(timeline.latePackets==1L)
        check(!timeline.healthy(102));check(timeline.healthy(162))
        val ordered=BehaviorTimeline();ordered.push(packet(200.2),0)
        val next=ordered.push(packet(201.1),100);check(next.size==2 && next.all{it.endSecond==201L})
        ordered.invalidate();check(!ordered.healthy(202));check(ordered.healthy(261))
        check(ordered.idle(50).isEmpty()) // monotonic clock cannot run backwards into a flush
        val confirmation=BehaviorConfirmation()
        check(!confirmation.accept("a",1,true));check(confirmation.accept("a",2,true))
        check(!confirmation.accept("b",2,true));check(!confirmation.accept("a",4,true))
        check(!confirmation.accept("a",5,false));check(!confirmation.accept("a",6,true))
        confirmation.clear();check(!confirmation.accept("a",7,true))
        println("BEHAVIOR_TIMELINE_PASS idle_no_duplicates late_abstention loss_abstention monotonic_clock")
    }
}
