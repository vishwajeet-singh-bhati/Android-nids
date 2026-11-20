package nids.core

import java.io.File
import kotlin.math.abs

/** Public metadata fixture parity, independent of Android and inference runtime. */
object ShortFlowGolden {
    @JvmStatic fun main(args: Array<String>) {
        val directory = File(args.single())
        val expected = File(directory, "expected.tsv").readLines().associateBy { it.substringBefore('\t').toInt() }
        val tracker = FlowTracker(FlowConfig(maxPacketsPerFlow = 8))
        val activity = ShortFlowActivity()
        var checked = 0; var maxError = 0.0
        File(directory, "packets.tsv").useLines { lines -> lines.forEachIndexed { index, line ->
            val c = line.split('\t')
            val p = ParsedPacket(c[0].toDouble(), c[1].toInt(), c[2], c[3], c[4].toInt(), c[5].toInt(), c[6].toInt(), c[7].toInt(), c[8].toLong(), c[9].toInt(), byteArrayOf())
            activity.update(p); val flow = tracker.process(p)
            if (flow != null && flow.packets.size in setOf(1, 2, 4, 8)) {
                val gold = expected[index]?.split('\t') ?: error("Unexpected prefix at packet $index")
                check(gold[1].toInt() == flow.flowIndex && gold[2].toInt() == flow.packets.size)
                val t = ShortFlowEncoder.encode(flow, activity); val actual = t.packets + t.mask + t.context
                val wanted = gold[3].split(',').map { it.toFloat() }
                check(wanted.size == actual.size)
                actual.indices.forEach { i -> val delta = abs(actual[i].toDouble() - wanted[i]); maxError = maxOf(maxError, delta); check(delta < 1e-5) { "Feature mismatch packet=$index column=$i actual=${actual[i]} expected=${wanted[i]}" } }
                checked++
            } else check(index !in expected) { "Missing prefix at packet $index" }
            tracker.drainFinished()
        } }
        check(checked == expected.size)
        var invoked=0
        val recovery=ShortFlowMonitor(ShortFlowScorer{invoked++;5.0},1.0)
        fun packet(ts: Double,port: Int)=ParsedPacket(ts,6,"10.0.0.1","10.0.0.2",port,80,0,2,1,0,byteArrayOf())
        check(recovery.feed(packet(0.0,1000))!=null)
        recovery.invalidate(1.0);check(recovery.feed(packet(2.0,1001))==null && invoked==1)
        check(recovery.feed(packet(62.0,1002))!=null && recovery.captureGaps==1L)
        println("SHORTFLOW_FEATURE_PARITY_PASS prefixes=$checked max_abs_error=$maxError")
    }
}
