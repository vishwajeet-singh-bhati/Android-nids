package nids.authentication

import java.io.File

/** Optional alert policy over completed inbound TCP summaries. */
class AuthenticationEpisodePolicy {
    companion object {
        const val PREF = "experimental_authentication_episodes"
        const val WINDOW_SECONDS = 30.0
        const val MIN_CONNECTIONS = 4
    }

    data class Result(val classId: Int, val emit: Boolean, val protocol: String? = null,
                      val connections: Int = 0, val firstStart: Double? = null)
    private data class Service(val protocol: String, val peer: String, val local: String, val port: Int)
    private class Episode(val firstStart: Double, var lastDecision: Double) {
        val connections = LinkedHashMap<Int, Double>()
        var notified = false
    }

    private val episodes = LinkedHashMap<Service, Episode>()

    fun clear() = episodes.clear()

    fun apply(baseline: Int, observedAt: Double, start: Double, watched: String, source: String,
              destination: String, sourcePort: Int, destinationPort: Int, protocol: Int,
              ssh: Boolean, ftp: Boolean, hasSyn: Boolean): Result {
        val original = Result(baseline, baseline != 0)
        if (protocol != 6 || destination != watched || source == destination || ssh == ftp || !hasSyn) return original
        val service = Service(if (ssh) "SSH" else "FTP", source, destination, destinationPort)
        // Keep recent evidence bounded. Under pressure, preserve the original detector.
        while (episodes.isNotEmpty() && observedAt - episodes.entries.first().value.lastDecision > WINDOW_SECONDS) {
            episodes.remove(episodes.entries.first().key)
        }
        var episode = episodes.remove(service)
        if (episode == null) {
            if (episodes.size >= 1024) return original
            episode = Episode(start, observedAt)
        }
        episodes[service] = episode
        episode.lastDecision = observedAt
        val iterator = episode.connections.values.iterator()
        while (iterator.hasNext()) {
            if (observedAt - iterator.next() <= WINDOW_SECONDS) break
            iterator.remove()
        }
        if (episode.connections.size < 256) episode.connections.putIfAbsent(sourcePort, observedAt)
        if (baseline !in setOf(0, 2, 7)) return original
        val count = episode.connections.size
        if (count < MIN_CONNECTIONS) return Result(0, false, service.protocol, count, episode.firstStart)
        val firstWarning = !episode.notified
        episode.notified = true
        return Result(2, firstWarning, service.protocol, count, episode.firstStart)
    }
}

/** Reads private TSV rows prepared from a previously captured native trace. */
object AuthenticationEpisodeReplay {
    @JvmStatic fun main(args: Array<String>) {
        require(args.size == 1)
        var session = ""
        val policy = AuthenticationEpisodePolicy()
        File(args[0]).forEachLine { line ->
            val f = line.split('\t')
            require(f.size == 13)
            if (f[0] != session) {
                session = f[0]
                policy.clear()
            }
            val result = policy.apply(f[1].toInt(), f[2].toDouble(), f[3].toDouble(), f[4], f[5], f[6],
                f[7].toInt(), f[8].toInt(), f[9].toInt(), f[10] == "1", f[11] == "1", f[12] == "1")
            println(listOf(result.classId, if (result.emit) 1 else 0, result.protocol.orEmpty(), result.connections).joinToString("\t"))
        }
    }
}
