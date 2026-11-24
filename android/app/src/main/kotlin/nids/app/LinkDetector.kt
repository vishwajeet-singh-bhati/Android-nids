package nids.app

import android.content.Context
import android.database.sqlite.SQLiteDatabase
import org.json.JSONArray
import org.json.JSONObject
import org.pytorch.executorch.EValue
import org.pytorch.executorch.Module
import org.pytorch.executorch.Tensor
import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.time.Instant
import kotlin.math.exp
import kotlin.math.ln
import kotlin.math.sqrt

/** Bundled detector assets are attested before loading. */
object SafetyAssets {
    fun install(context: Context, asset: String, expected: String): File {
        val target = File(context.filesDir, asset)
        target.parentFile!!.mkdirs()
        if (target.exists() && LearnedShortFlowScorer.sha256(target) == expected) return target
        val temporary = File(target.parentFile, target.name + ".tmp")
        context.assets.open(asset).use { input -> temporary.outputStream().use { input.copyTo(it) } }
        check(LearnedShortFlowScorer.sha256(temporary) == expected) { "Detector asset checksum failed" }
        check(temporary.renameTo(target)) { "Cannot install bundled detector" }
        return target
    }
}

class LinkDetector(private val context: Context): AutoCloseable {
    val config = JSONObject(context.assets.open("url/url_model.json").bufferedReader().use { it.readText() })
    private val hashes = JSONObject(context.assets.open("url/MANIFEST.json").bufferedReader().use { it.readText() }).getJSONObject("files")
    private fun asset(name: String) = SafetyAssets.install(context, "url/" + name, hashes.getJSONObject(name).getString("sha256"))
    val normalizer = LinkNormalizer(asset("public_suffix_list.dat").readText())
    private val redirectors = asset("redirectors.txt").readLines().filter { it.isNotBlank() && !it.startsWith("#") }.toSet()
    private val popular = asset("popular.txt").readLines().filter { it.isNotBlank() && !it.startsWith("#") }.toSet()
    private val database = SQLiteDatabase.openDatabase(asset("threat_intel.sqlite3").absolutePath, null, SQLiteDatabase.OPEN_READONLY)
    private val moduleDelegate = lazy {
        Module.load(asset("url_cnn.pte").absolutePath, Module.LOAD_MODE_MMAP, 1).also { it.loadMethod("forward") }
    }
    private val module by moduleDelegate
    private data class NgramWeights(val index: Map<String, Int>, val idf: DoubleArray, val coefficients: DoubleArray, val intercept: Double)
    private val ngramWeights by lazy { loadNgrams() }

    private fun loadNgrams(): NgramWeights {
        val bytes = ByteBuffer.wrap(asset("ngram_lr.bin").readBytes()).order(ByteOrder.LITTLE_ENDIAN)
        val magic = ByteArray(8).also { bytes.get(it) }.toString(Charsets.US_ASCII)
        check(magic == "NGRAMLR1")
        val count = bytes.int
        check(count == config.getJSONObject("ngram").getInt("terms"))
        val intercept = bytes.double
        val index = HashMap<String, Int>(400000)
        val idfs = DoubleArray(count)
        val coefficients = DoubleArray(count)
        repeat(count) { i ->
            val size = bytes.get().toInt() and 255
            check(size in 2..5)
            index[ByteArray(size).also { bytes.get(it) }.toString(Charsets.US_ASCII)] = i
            idfs[i] = bytes.double
            coefficients[i] = bytes.double
        }
        check(!bytes.hasRemaining())
        return NgramWeights(index, idfs, coefficients, intercept)
    }

    fun scaled(raw: DoubleArray): FloatArray {
        val features = config.getJSONObject("features")
        val mean = features.getJSONArray("mean")
        val std = features.getJSONArray("std")
        return FloatArray(raw.size) { i ->
            val value = raw[i].toFloat().toDouble()
            ((if (i < 17) ln(1 + value) else value) - mean.getDouble(i)).div(std.getDouble(i)).toFloat()
        }
    }

    fun ngramLogit(text: String): Double {
        val weights = ngramWeights
        val counts = LinkedHashMap<Int, Int>()
        for (size in 2..5) for (start in 0..text.length - size) {
            val index = weights.index[text.substring(start, start + size)] ?: continue
            counts[index] = (counts[index] ?: 0) + 1
        }
        val weighted = counts.mapValues { (i, count) -> (1 + ln(count.toDouble())) * weights.idf[i] }
        val norm = sqrt(weighted.values.sumOf { it * it })
        if (norm == 0.0) return weights.intercept
        return weights.intercept + weighted.entries.sumOf { (i, value) -> value / norm * weights.coefficients[i] }
    }

    fun cnnLogit(ids: LongArray, features: FloatArray): Double {
        val output = module.forward(
            EValue.from(Tensor.fromBlob(ids, longArrayOf(1, 256))),
            EValue.from(Tensor.fromBlob(features, longArrayOf(1, 27)))
        )[0].toTensor().dataAsFloatArray
        check(output.size == 1 && output[0].isFinite())
        return output[0].toDouble()
    }

    private fun intel(n: JSONObject, now: Instant, domainOnly: Boolean): JSONObject {
        val model = if (domainOnly) "" else n.getString("model_string")
        val whenText = java.time.format.DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss'Z'", java.util.Locale.ROOT)
            .withZone(java.time.ZoneOffset.UTC).format(now)
        fun found(where: String, values: Array<String>) = database.rawQuery(
            "SELECT DISTINCT source FROM indicators WHERE " + where, values
        ).use { cursor -> buildList { while (cursor.moveToNext()) add(cursor.getString(0)) } }
        val exact = if (model.isEmpty()) emptyList() else found("url_key=? AND expires_at>?", arrayOf(model, whenText))
        val hosts = found("host=? AND host_match_ok=1 AND url_key!=? AND expires_at>?",
            arrayOf(n.getString("host"), model, whenText))
        val site = n.getString("site")
        val siblings = if (site.isEmpty()) emptyList() else found("site=? AND host!=? AND host_match_ok=1 AND expires_at>?",
            arrayOf(site, n.getString("host"), whenText))
        val updated = database.rawQuery("SELECT value FROM meta WHERE key='feeds_updated_at'", null).use {
            if (it.moveToFirst()) it.getString(0) else ""
        }
        val stale = runCatching { now.epochSecond - Instant.parse(updated).epochSecond > 48 * 3600 }.getOrDefault(true)
        return JSONObject().put("strong", exact.isNotEmpty() || hosts.isNotEmpty()).put("sibling", siblings.isNotEmpty())
            .put("sources", JSONArray((exact + hosts + siblings).distinct())).put("feeds_updated_at", updated).put("stale", stale)
    }

    /** includeDebug is used only by contract tests; user results contain redacted links. */
    @Synchronized
    fun check(raw: String, inputType: String = "full_url", now: Instant = Instant.now(), includeDebug: Boolean = false): JSONObject {
        val result = JSONObject().put("model_version", config.getString("model_version"))
        val n = try { normalizer.normalize(raw, inputType) } catch (error: InvalidLink) {
            return result.put("decision", JSONObject.NULL).put("source", JSONObject.NULL).put("risk_score", JSONObject.NULL)
                .put("error", "invalid_input:" + error.reason)
        }
        val threat = intel(n, now, inputType == "domain")
        val hidden = listOf(n.getString("host"), n.getString("registered_domain"), n.getString("site")).any { it in redirectors }
        val isPopular = !n.getBoolean("is_ip") && n.getString("site") in popular
        var probability: Double? = null
        var outcome: String? = null
        val debug = JSONObject()
        // Reference export scores shorteners too; live decisions can skip this unused work.
        var modelStatus = "not_needed"
        if (inputType == "full_url" && (includeDebug || !hidden && !threat.getBoolean("strong"))) {
            try {
            val ids = normalizer.tokens(n)
            val rawFeatures = normalizer.features(n)
            val features = scaled(rawFeatures)
            val cnn = cnnLogit(ids, features)
            val ngram = ngramLogit(n.getString("model_string"))
            val c = config.getJSONObject("calibrator")
            val z = c.getDouble("bias") + cnn * c.getJSONArray("weights").getDouble(0) +
                ngram * c.getJSONArray("weights").getDouble(1)
            probability = if (z >= 0) 1.0 / (1.0 + exp(-z)) else exp(z) / (1.0 + exp(z))
            outcome = when {
                probability > c.getDouble("t_phishing") -> "PHISHING"
                probability < c.getDouble("t_safe") -> "LIKELY_SAFE"
                else -> "UNCERTAIN"
            }
            check(probability.isFinite())
            modelStatus = "completed"
            if (includeDebug) debug.put("token_ids", JSONArray(ids.toList()))
                .put("features_raw", JSONArray(rawFeatures.toList())).put("features_scaled", JSONArray(features.toList()))
                .put("logits", JSONObject().put("full_url_hybrid", cnn).put("char_ngram_lr", ngram))
                .put("probability", probability).put("model_outcome", outcome)
            } catch (error: Exception) {
                if (includeDebug) throw error
                probability = null
                outcome = null
                modelStatus = "failed"
            }
        }
        var decision: String
        var source: String
        when {
            threat.getBoolean("strong") -> { decision = "PHISHING"; source = "threat_intel" }
            hidden || outcome == null -> { decision = "UNCERTAIN"; source = "rule" }
            isPopular && outcome == "PHISHING" -> { decision = "UNCERTAIN"; source = "rule" }
            else -> { decision = outcome; source = "model" }
        }
        if (threat.getBoolean("sibling") && decision == "LIKELY_SAFE") { decision = "UNCERTAIN"; source = "threat_intel" }
        result.put("decision", decision).put("source", source).put("risk_score", probability ?: JSONObject.NULL)
            .put("error", JSONObject.NULL).put("display_url", displayHost(n))
            .put("threat_list_stale", threat.getBoolean("stale")).put("feeds_updated_at", threat.getString("feeds_updated_at"))
            .put("sources", threat.getJSONArray("sources")).put("is_redirector", hidden).put("is_popular", isPopular)
            .put("model_used", outcome != null).put("model_status", modelStatus)
        if (includeDebug) {
            debug.put("normalized", n).put("site", n.getString("site"))
            for (k in debug.keys()) result.put(k, debug.get(k))
        }
        return result
    }

    private fun displayHost(n: JSONObject): String {
        val host = n.getString("host")
        return (n.optString("scheme").takeIf { it != "null" && it.isNotEmpty() }?.let { it + "://" } ?: "") +
            (if (':' in host) "[" + host + "]" else host) + "/…"
    }

    override fun close() { if (moduleDelegate.isInitialized()) module.close(); database.close() }

    companion object {
        @Volatile private var instance: LinkDetector? = null
        fun get(context: Context): LinkDetector = instance ?: synchronized(this) {
            instance ?: LinkDetector(context.applicationContext).also { instance = it }
        }
    }
}
