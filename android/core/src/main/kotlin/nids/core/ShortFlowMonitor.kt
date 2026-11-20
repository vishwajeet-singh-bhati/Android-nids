package nids.core

fun interface ShortFlowScorer { fun score(tensors: ShortFlowTensors): Double }
data class ShortFlowWarning(val ts: Double, val flowIndex: Int, val initiator: String, val responder: String, val prefix: Int, val logit: Double)

/** Learned short-flow path. Warnings are unconfirmed traffic anomalies. */
class ShortFlowMonitor(private val scorer: ShortFlowScorer, private val threshold: Double, private val maxFlows: Int = 10000) {
    private var activity = ShortFlowActivity()
    private var tracker = FlowTracker(FlowConfig(maxPacketsPerFlow = 8))
    private val warned = HashSet<Int>()
    private var degradedUntil = Double.NEGATIVE_INFINITY
    var packets = 0L; private set
    var inferences = 0L; private set
    var warnings = 0L; private set
    var inferenceNanos = 0L; private set
    var evictions = 0L; private set
    val featureResets get() = activity.resets
    val activeFlows get() = tracker.activeCount
    var captureGaps=0L; private set
    fun invalidate(ts: Double){
        require(ts.isFinite());captureGaps++;activity=ShortFlowActivity()
        tracker=FlowTracker(FlowConfig(maxPacketsPerFlow=8));warned.clear();degradedUntil=ts+60.0
    }
    fun feed(packet: ParsedPacket): ShortFlowWarning? {
        packets++
        if (packet.ipProto != 6 && packet.ipProto != 17) return null
        activity.update(packet)
        val flow = tracker.process(packet)
        tracker.drainFinished().forEach { warned.remove(it.flowIndex) }
        if (tracker.activeCount > maxFlows) {
            evictions += tracker.evictOldest(maxFlows).toLong()
            tracker.drainFinished().forEach { warned.remove(it.flowIndex) }
            degradedUntil = packet.ts + 5.0
        }
        if (flow == null || flow.packets.size !in setOf(1, 2, 4, 8) || !activity.healthy(packet.ts) || packet.ts < degradedUntil) return null
        val start = System.nanoTime(); val score = scorer.score(ShortFlowEncoder.encode(flow, activity))
        inferenceNanos += System.nanoTime() - start; inferences++
        require(score.isFinite()) { "Non-finite short-flow model output" }
        if (score < threshold || !warned.add(flow.flowIndex)) return null
        warnings++
        return ShortFlowWarning(packet.ts, flow.flowIndex, flow.initiator.toString(), flow.responder.toString(), flow.packets.size, score)
    }
}
