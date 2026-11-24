package nids.dataset

import java.io.File
import java.util.ArrayDeque
import java.util.PriorityQueue
import nids.core.AlignedContract
import nids.core.AlignedPacketParser
import nids.core.CaptureFileStream
import nids.core.ParsedPacket

/** Passive packet-time features. Identity keys are private replay metadata, not model inputs. */
class ServicePressure {
    data class Socket(val remote: String, val remotePort: Int, val localPort: Int)
    data class Sample(val socket: Socket, val time: Double, val pending: Int, val established: Int,
                      val activeSources: Int, val starts5s: Int, val startingSources5s: Int)
    private data class Connection(val synSequence: Long, var last: Double, var stage: Int = 0,
                                  var remoteFin: Boolean = false, var localFin: Boolean = false)
    private data class Start(val time: Double, val source: String)
    private data class Service(val sockets: MutableMap<Socket, Connection> = HashMap(),
                               val recent: ArrayDeque<Start> = ArrayDeque())
    private val connections = LinkedHashMap<Socket, Connection>(32, 0.75f, true)
    private val services = HashMap<Int, Service>()
    private var clock = Double.NEGATIVE_INFINITY
    var idleExpired = 0L; private set
    var capacityEvictions = 0L; private set

    private fun remove(socket: Socket) {
        connections.remove(socket)
        services.getValue(socket.localPort).sockets.remove(socket)
    }

    private fun expire(now: Double) {
        while (connections.isNotEmpty()) {
            val oldest = connections.entries.first()
            if (oldest.value.last + 30.0 >= now) break
            remove(oldest.key)
            idleExpired++
        }
        val it = services.values.iterator()
        while (it.hasNext()) {
            val service = it.next()
            while (service.recent.isNotEmpty() && service.recent.first.time < now - 5) service.recent.removeFirst()
            if (service.recent.isEmpty() && service.sockets.isEmpty()) it.remove()
        }
    }

    fun observe(packet: ParsedPacket, phone: String): Sample? {
        val incoming = packet.dstIp == phone && packet.srcIp != phone
        val outgoing = packet.srcIp == phone && packet.dstIp != phone
        if (packet.ipProto != 6 || !incoming && !outgoing) return null
        require(packet.ts >= clock)
        clock = packet.ts
        expire(clock)
        val socket = if (incoming) Socket(packet.srcIp, packet.sport, packet.dport)
                     else Socket(packet.dstIp, packet.dport, packet.sport)
        val flags = packet.tcpFlags
        val syn = flags and 2 != 0
        val ack = flags and 16 != 0
        val previous = connections[socket]
        if (incoming && syn && !ack) {
            if (previous != null && previous.synSequence == packet.seq) {
                previous.last = clock
                return null
            }
            if (previous != null) remove(socket)
            if (connections.size == 16384) {
                remove(connections.keys.first())
                capacityEvictions++
            }
            val service = services.getOrPut(socket.localPort) { Service() }
            // Snapshot before this SYN is inserted. The current source is counted in the
            // arrival features, but the concurrency features describe earlier sockets.
            val established = service.sockets.values.count { it.stage == 2 }
            val activeSources = service.sockets.keys.mapTo(HashSet()) { it.remote }.size
            val current = Connection(packet.seq, clock)
            service.sockets[socket] = current
            connections[socket] = current
            if (service.recent.size == 16384) {
                service.recent.removeFirst()
                capacityEvictions++
            }
            service.recent.addLast(Start(clock, socket.remote))
            return Sample(socket, clock, service.sockets.size - 1 - established, established,
                          activeSources, service.recent.size, service.recent.mapTo(HashSet()) { it.source }.size)
        }
        if (previous == null) return null
        previous.last = clock
        if (outgoing && syn && ack && previous.stage == 0) previous.stage = 1
        if (incoming && ack && !syn && previous.stage == 1) previous.stage = 2
        if (flags and 1 != 0) {
            if (incoming) previous.remoteFin = true else previous.localFin = true
        }
        if (flags and 4 != 0 || previous.remoteFin && previous.localFin) remove(socket)
        return null
    }
}

object PressureReplay {
    private fun checkLifecycle() {
        val phone = "192.0.2.1"
        val peer = "192.0.2.2"
        val other = "192.0.2.3"
        val state = ServicePressure()
        fun packet(time: Double, flags: Int, remote: String = peer, port: Int = 10000,
                   service: Int = 443, inbound: Boolean = true): ServicePressure.Sample? {
            val p = if (inbound) ParsedPacket(time, 6, remote, phone, port, service, 0, flags, 10, 0, byteArrayOf())
                    else ParsedPacket(time, 6, phone, remote, service, port, 0, flags, 10, 0, byteArrayOf())
            return state.observe(p, phone)
        }
        val first = checkNotNull(packet(1.0, 2))
        check(first.pending == 0 && first.established == 0 && first.starts5s == 1)
        check(packet(1.1, 2) == null) // SYN retry
        packet(1.2, 18, inbound = false)
        packet(1.3, 16)
        val concurrent = checkNotNull(packet(1.4, 2, remote = other))
        check(concurrent.established == 1 && concurrent.starts5s == 2 && concurrent.startingSources5s == 2)
        val separateService = checkNotNull(packet(1.5, 2, service = 444))
        check(separateService.established == 0 && separateService.starts5s == 1)
        packet(1.6, 17)
        packet(1.7, 17, inbound = false)
        packet(1.8, 4, remote = other, inbound = false)
        val closed = checkNotNull(packet(1.9, 2, port = 10001))
        check(closed.pending == 0 && closed.established == 0 && closed.starts5s == 3)
        val idle = checkNotNull(packet(32.0, 2, port = 10002))
        check(idle.pending == 0 && idle.starts5s == 1 && state.idleExpired == 2L)
        println("PRESSURE_LIFECYCLE_PASS")
    }

    @JvmStatic fun main(args: Array<String>) {
        if (args.contentEquals(arrayOf("--self-check"))) {
            checkLifecycle()
            return
        }
        require(args.size == 3) { "capture.pcap phone-address output.tsv" }
        val phone = args[1]
        val state = ServicePressure()
        val pending = PriorityQueue(compareBy<IndexedValue<ParsedPacket>> { it.value.ts }.thenBy { it.index })
        var latest = Double.NEGATIVE_INFINITY
        var committed = Double.NEGATIVE_INFINITY
        var accepted = 0
        var dropped = 0
        var rows = 0
        var frames = 0
        File(args[2]).bufferedWriter().use { writer ->
            fun flush(until: Double) {
                while (pending.isNotEmpty() && pending.peek().value.ts <= until) {
                    val packet = pending.remove().value
                    if (packet.ts < committed) {
                        dropped++
                        continue
                    }
                    committed = packet.ts
                    val sample = state.observe(packet, phone) ?: continue
                    val key = sample.socket
                    writer.appendLine(listOf(key.remote, key.remotePort, key.localPort, sample.time,
                        sample.pending, sample.established, sample.activeSources, sample.starts5s,
                        sample.startingSources5s).joinToString("\t"))
                    rows++
                }
            }
            File(args[0]).inputStream().buffered(65536).use { stream ->
                val capture = CaptureFileStream(stream)
                while (true) {
                    val frame = capture.next() ?: break
                    frames++
                    latest = maxOf(latest, frame.ts)
                    val packet = AlignedPacketParser.decode(frame)
                    if (packet?.ipProto == 6 && (packet.srcIp == phone || packet.dstIp == phone)) {
                        pending.add(IndexedValue(accepted++, packet))
                    }
                    flush(latest - 0.05)
                    require(pending.size <= 65536) { "Packet reorder capacity exceeded" }
                }
            }
            flush(Double.POSITIVE_INFINITY)
        }
        println(AlignedContract.json(mapOf("frames" to frames, "samples" to rows, "late_drops" to dropped,
            "idle_expired" to state.idleExpired, "capacity_evictions" to state.capacityEvictions)))
    }
}
