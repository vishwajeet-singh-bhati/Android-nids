package nids.core

import java.util.ArrayDeque
import kotlin.math.ln1p

/** Causal five-second activity state. Identifiers are local keys, never model inputs. */
class ShortFlowActivity(private val horizon: Double = 5.0, private val maxEvents: Int = 250000) {
    private data class Observation(val ts: Double, val peer: String, val remotePort: Int, val localPort: Int, val bytes: Int, val syn: Int, val rst: Int)
    private class State {
        val queue = ArrayDeque<Observation>()
        val peers = HashMap<String, Int>()
        val remote = HashMap<Int, Int>()
        val local = HashMap<Int, Int>()
        var bytes = 0L; var syn = 0; var rst = 0
    }
    private val states = HashMap<String, State>()
    private var events = 0
    var degradedUntil = Double.NEGATIVE_INFINITY; private set
    var resets = 0L; private set
    fun healthy(ts: Double) = ts >= degradedUntil
    private fun <K> decrement(map: MutableMap<K, Int>, key: K) {
        val n = (map[key] ?: 0) - 1
        if (n <= 0) map.remove(key) else map[key] = n
    }
    fun update(p: ParsedPacket) {
        require(p.ts.isFinite())
        if (events + 2 > maxEvents) {
            states.clear(); events = 0; degradedUntil = p.ts + horizon; resets++
        }
        updateEndpoint(p, p.srcIp, p.dstIp, p.sport, p.dport)
        updateEndpoint(p, p.dstIp, p.srcIp, p.dport, p.sport)
    }
    private fun updateEndpoint(p: ParsedPacket, host: String, peer: String, local: Int, remote: Int) {
        val s = states.getOrPut(host) { State() }
        while (s.queue.isNotEmpty() && s.queue.first.ts < p.ts - horizon) {
            val old = s.queue.removeFirst(); events--
            decrement(s.peers, old.peer); decrement(s.remote, old.remotePort); decrement(s.local, old.localPort)
            s.bytes -= old.bytes; s.syn -= old.syn; s.rst -= old.rst
        }
        val event = Observation(p.ts, peer, remote, local, p.payloadLen, if (p.tcpFlags and 2 != 0) 1 else 0, if (p.tcpFlags and 4 != 0) 1 else 0)
        s.queue.addLast(event); events++
        s.peers[peer] = (s.peers[peer] ?: 0) + 1
        s.remote[remote] = (s.remote[remote] ?: 0) + 1
        s.local[local] = (s.local[local] ?: 0) + 1
        s.bytes += event.bytes; s.syn += event.syn; s.rst += event.rst
    }
    fun vector(host: String): FloatArray {
        val s = states[host] ?: return FloatArray(7)
        return doubleArrayOf(s.queue.size.toDouble(), s.bytes.toDouble(), s.syn.toDouble(), s.rst.toDouble(), s.peers.size.toDouble(), s.remote.size.toDouble(), s.local.size.toDouble()).map { ln1p(it).toFloat() }.toFloatArray()
    }
}

data class ShortFlowTensors(val packets: FloatArray, val mask: FloatArray, val context: FloatArray)

object ShortFlowEncoder {
    fun encode(flow: Flow, activity: ShortFlowActivity): ShortFlowTensors {
        val x = FloatArray(8 * 9); val mask = FloatArray(8); var previous = flow.startTs
        flow.packets.take(8).forEachIndexed { i, p ->
            val o = i * 9
            x[o] = p.direction.toFloat(); x[o + 1] = ln1p(p.payloadLen.toDouble()).toFloat()
            x[o + 2] = ln1p(maxOf(0.0, p.ts - previous) * 1000.0).toFloat()
            intArrayOf(1, 2, 4, 8, 16, 32).forEachIndexed { j, bit -> x[o + 3 + j] = if (p.tcpFlags and bit != 0) 1f else 0f }
            mask[i] = 1f; previous = p.ts
        }
        val context = activity.vector(flow.initiator.ip) + activity.vector(flow.responder.ip) + floatArrayOf(if (flow.ipProto == 6) 1f else 0f, if (flow.ipProto == 17) 1f else 0f)
        return ShortFlowTensors(x, mask, context)
    }
}
