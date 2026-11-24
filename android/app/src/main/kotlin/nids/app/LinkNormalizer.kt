package nids.app

import android.icu.text.IDNA
import org.json.JSONObject
import java.util.Locale
import kotlin.math.ln

class InvalidLink(val reason: String): IllegalArgumentException(reason)

/** Literal parsing only. No resolver, socket or URL fetch is used. */
class LinkNormalizer(psl: String) {
    private val idna = IDNA.getUTS46Instance(IDNA.NONTRANSITIONAL_TO_ASCII or IDNA.CHECK_BIDI or IDNA.CHECK_CONTEXTJ)
    private val publicRules = HashSet<String>()
    private val allRules = HashSet<String>()

    init {
        var privateSection = false
        for (line in psl.lineSequence()) {
            val rule = line.trim()
            if (rule.contains("BEGIN PRIVATE DOMAINS")) privateSection = true
            if (rule.isEmpty() || rule.startsWith("//")) continue
            val prefix = when { rule.startsWith("*.") -> "*."; rule.startsWith("!") -> "!"; else -> "" }
            val name = ascii(rule.removePrefix(prefix))
            allRules.add(prefix + name)
            if (!privateSection) publicRules.add(prefix + name)
        }
    }

    private fun ascii(host: String): String {
        if (host.all { it.code < 128 }) return host.lowercase(Locale.ROOT)
        val info = IDNA.Info()
        val result = idna.nameToASCII(host, StringBuilder(), info).toString()
        if (info.hasErrors()) throw InvalidLink("idna_failure")
        return result.lowercase(Locale.ROOT)
    }

    private fun domainParts(host: String, rules: Set<String>): List<String> {
        val labels = host.split('.')
        var suffixSize = 0
        for (i in labels.indices) {
            val candidate = labels.drop(i).joinToString(".")
            if ("!" + candidate in rules) {
                suffixSize = labels.size - i - 1
                break
            }
            if (candidate in rules) suffixSize = maxOf(suffixSize, labels.size - i)
            if (i > 0 && "*." + candidate in rules) suffixSize = maxOf(suffixSize, labels.size - i + 1)
        }
        val domainIndex = labels.size - suffixSize - 1
        val suffix = if (suffixSize > 0) labels.takeLast(suffixSize).joinToString(".") else ""
        val domain = labels.getOrNull(domainIndex) ?: ""
        val subdomain = labels.take(maxOf(0, domainIndex)).joinToString(".")
        val registered = if (domain.isNotEmpty() && suffix.isNotEmpty()) domain + "." + suffix else ""
        return listOf(subdomain, domain, suffix, registered)
    }

    private fun ipv4(host: String): List<Int>? {
        val parts = host.split('.')
        if (parts.size != 4 || parts.any { it.isEmpty() || it.length > 1 && it[0] == '0' ||
                    !it.all { c -> c in '0'..'9' } }) return null
        val numbers = parts.map { it.toIntOrNull() ?: return null }
        return numbers.takeIf { it.all { n -> n in 0..255 } }
    }

    private fun ipv6(input: String): String? {
        if (':' !in input || '%' in input) return null
        var host = input
        if ('.' in host) {
            val tail = ipv4(host.substringAfterLast(':')) ?: return null
            host = host.substringBeforeLast(':') + ":" +
                ((tail[0] shl 8) + tail[1]).toString(16) + ":" +
                ((tail[2] shl 8) + tail[3]).toString(16)
        }
        if (!host.all { it in "0123456789abcdef:" } || host.windowed(2).count { it == "::" } > 1) return null
        val halves = host.split("::", limit = 2)
        fun groups(s: String): List<Int>? {
            if (s.isEmpty()) return emptyList()
            val pieces = s.split(':')
            if (pieces.any { it.isEmpty() || it.length > 4 }) return null
            return pieces.map { it.toIntOrNull(16) ?: return null }
        }
        val left = groups(halves[0]) ?: return null
        val right = if (halves.size == 2) groups(halves[1]) ?: return null else emptyList()
        val missing = 8 - left.size - right.size
        if (halves.size == 1 && missing != 0 || halves.size == 2 && missing < 1) return null
        val values = left + List(missing) { 0 } + right
        var bestStart = -1
        var bestLength = 1
        var i = 0
        while (i < 8) {
            if (values[i] != 0) { i++; continue }
            var end = i
            while (end < 8 && values[end] == 0) end++
            if (end - i > bestLength) { bestStart = i; bestLength = end - i }
            i = end
        }
        if (bestStart < 0) return values.joinToString(":") { it.toString(16) }
        return values.take(bestStart).joinToString(":") { it.toString(16) } + "::" +
            values.drop(bestStart + bestLength).joinToString(":") { it.toString(16) }
    }

    private fun component(text: String): String {
        val encoded = StringBuilder()
        for (cp in text.codePoints().toArray()) {
            if (cp < 128) encoded.append(cp.toChar())
            else for (byte in String(Character.toChars(cp)).toByteArray(Charsets.UTF_8))
                encoded.append("%%%02X".format(Locale.US, byte.toInt() and 255))
        }
        return Regex("%([0-9a-fA-F]{2})").replace(encoded.toString()) {
            val char = it.groupValues[1].toInt(16).toChar()
            if (char in 'A'..'Z' || char in 'a'..'z' || char in '0'..'9' || char in "-._~") char.toString()
            else it.value.uppercase(Locale.ROOT)
        }
    }

    fun normalize(raw: String, inputType: String = "full_url"): JSONObject {
        if (raw.codePointCount(0, raw.length) > 8192) throw InvalidLink("too_long")
        var text = raw.trim { it.isWhitespace() || Character.isSpaceChar(it) }.replace(Regex("[\\t\\r\\n]"), "")
        if (text.isEmpty()) throw InvalidLink("empty")
        if (text.any { it == ' ' || it.code < 32 || it.code == 127 }) throw InvalidLink("illegal_characters")
        val domainOnly = inputType == "domain"
        require(inputType in setOf("domain", "full_url"))
        if (domainOnly && text.any { it in "/\\?#@" }) throw InvalidLink("not_a_hostname")
        var scheme: String? = null
        var inferred = false
        var path = ""
        var query = ""
        var userinfo = false
        var port: Int? = null
        var host: String
        if (domainOnly) {
            host = text.removePrefix("[").removeSuffix("]")
        } else {
            val cut = text.indexOfFirst { it == '?' || it == '#' }.let { if (it < 0) text.length else it }
            text = text.substring(0, cut).replace('\\', '/') + text.substring(cut)
            val prefix = Regex("^[A-Za-z][A-Za-z0-9+.\\-]*://").find(text)
            inferred = prefix == null
            scheme = prefix?.value?.substringBefore(':')?.lowercase(Locale.ROOT) ?: "http"
            if (scheme !in setOf("http", "https", "ftp")) throw InvalidLink("unsupported_scheme")
            val rest = (if (prefix == null) text else text.substring(prefix.value.length)).substringBefore('#')
            val authority = rest.takeWhile { it != '/' && it != '?' }
            val tail = rest.substring(authority.length)
            path = component(tail.substringBefore('?')).ifEmpty { "/" }
            query = component(if ('?' in tail) tail.substringAfter('?') else "")
            userinfo = '@' in authority
            val address = authority.substringAfterLast('@')
            var portText: String? = null
            if (address.startsWith('[')) {
                val closing = address.indexOf(']')
                if (closing < 0) throw InvalidLink("unparseable")
                host = address.substring(1, closing).lowercase(Locale.ROOT)
                if (ipv6(host) == null) throw InvalidLink("unparseable")
                val extra = address.substring(closing + 1)
                if (extra.isNotEmpty() && !extra.startsWith(':')) throw InvalidLink("unparseable")
                if (extra.startsWith(':')) portText = extra.substring(1)
            } else {
                if ('[' in address || ']' in address) throw InvalidLink("unparseable")
                host = address.substringBefore(':')
                if (':' in address) portText = address.substringAfter(':')
            }
            if (!portText.isNullOrEmpty()) {
                port = portText.toIntOrNull() ?: throw InvalidLink("unparseable")
                if (port !in 0..65535) throw InvalidLink("unparseable")
                if (port == mapOf("http" to 80, "https" to 443, "ftp" to 21)[scheme]) port = null
            }
        }
        host = host.trim('[', ']').trimEnd('.').lowercase(Locale.ROOT)
        if (host.isEmpty()) throw InvalidLink("no_host")
        if ('%' in host) throw InvalidLink("invalid_host")
        val ipv6 = ipv6(host)
        val isIp = ipv6 != null || ipv4(host) != null
        host = ipv6 ?: if (isIp) host else ascii(host)
        if (!isIp && (!host.matches(Regex("[a-z0-9_.-]+")) || ".." in host || host.startsWith('.')))
            throw InvalidLink("invalid_host")
        val parts = if (isIp) listOf("", "", "", "") else domainParts(host, publicRules)
        val site = if (isIp) "" else domainParts(host, allRules)[3]
        val rendered = if (':' in host) "[" + host + "]" else host
        val model = rendered + (port?.let { ":" + it } ?: "") + path + if (query.isEmpty()) "" else "?" + query
        return JSONObject().put("scheme", scheme ?: JSONObject.NULL).put("scheme_inferred", inferred)
            .put("host", host).put("port", port ?: JSONObject.NULL).put("path", path).put("query", query)
            .put("has_userinfo", userinfo).put("is_ip", isIp).put("has_punycode", host.split('.').any { it.startsWith("xn--") })
            .put("subdomain", parts[0]).put("domain", parts[1]).put("suffix", parts[2]).put("registered_domain", parts[3])
            .put("canonical", if (domainOnly) model else scheme + "://" + model).put("model_string", model).put("site", site)
    }

    fun tokens(n: JSONObject): LongArray {
        val text = n.getString("model_string")
        val chars = if (text.length <= 256) text.map { it.code.toLong() - 30 } else
            text.take(191).map { it.code.toLong() - 30 } + listOf(2L) + text.takeLast(64).map { it.code.toLong() - 30 }
        return LongArray(256) { if (it < chars.size) chars[it].takeIf { v -> v in 3..96 || v == 2L } ?: 1L else 0L }
    }

    fun features(n: JSONObject): DoubleArray {
        val text = n.getString("model_string")
        val host = n.getString("host")
        val path = n.getString("path")
        val query = n.getString("query")
        val labels = if (n.getBoolean("is_ip")) emptyList() else host.split('.')
        val segments = path.split('/').filter { it.isNotEmpty() }
        val digits = text.count { it in '0'..'9' }
        val special = text.count { !(it in 'a'..'z' || it in 'A'..'Z' || it in '0'..'9') }
        fun ratio(a: Int, b: Int) = if (b == 0) 0.0 else a.toDouble() / b
        fun entropy(s: String): Double = if (s.isEmpty()) 0.0 else s.groupingBy { it }.eachCount().values.sumOf {
            val p = it.toDouble() / s.length
            -p * ln(p) / ln(2.0)
        }.coerceAtLeast(0.0)
        return doubleArrayOf(
            text.length.toDouble(), host.length.toDouble(), path.length.toDouble(), query.length.toDouble(),
            n.getString("registered_domain").length.toDouble(), labels.size.toDouble(),
            n.getString("subdomain").let { if (it.isEmpty()) 0.0 else it.split('.').size.toDouble() },
            text.count { it == '.' }.toDouble(), digits.toDouble(), special.toDouble(),
            host.count { it == '-' }.toDouble(), (labels.maxOfOrNull { it.length } ?: 0).toDouble(),
            text.count { it == '_' }.toDouble(), text.count { it == '%' }.toDouble(),
            query.split('&').count { it.isNotEmpty() }.toDouble(), segments.size.toDouble(),
            (segments.maxOfOrNull { it.length } ?: 0).toDouble(), ratio(digits, text.length),
            ratio(special, text.length), ratio(host.count { it in '0'..'9' }, host.length),
            entropy(text), entropy(host), entropy(path + if (query.isEmpty()) "" else "?" + query),
            if (n.getBoolean("is_ip")) 1.0 else 0.0, if (n.getBoolean("has_punycode")) 1.0 else 0.0,
            if (n.getBoolean("has_userinfo")) 1.0 else 0.0, if (n.has("port") && !n.isNull("port")) 1.0 else 0.0
        )
    }
}
