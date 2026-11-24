package com.bharat.smsguard.tier1

import java.io.File
import kotlin.math.exp
import kotlin.math.ln
import kotlin.math.sqrt

data class PortablePrediction(
    val logits: DoubleArray,
    val probabilities: DoubleArray,
    val label: String,
) {
    fun probability(label: String): Double {
        val index = LABELS.indexOf(label)
        return if (index >= 0) probabilities[index] else 0.0
    }

    companion object {
        val LABELS = listOf("ham", "spam", "smishing")
    }
}

/**
 * Kotlin implementation of the exported sms-linear-v1 word TF-IDF model.
 *
 * The current production export is word-only (`block_sizes = [13545, 0, 0]`).
 * This loader rejects non-empty char/indicator blocks rather than silently
 * producing different scores from Python.
 */
class PortableLinearModel private constructor(
    val labels: List<String>,
    val temperature: Double,
    private val vocabulary: Map<String, Int>,
    private val idf: DoubleArray,
    private val coefficients: Array<DoubleArray>,
    private val intercepts: DoubleArray,
    private val wordNgramMin: Int,
    private val wordNgramMax: Int,
    private val sublinearTf: Boolean,
) {
    // Python's re \w matches Unicode letters, numbers and underscore, but not
    // combining marks or other connector punctuation. Java's (?U)\w includes
    // marks, so use an explicit Python-compatible character class.
    private val tokenRegex = Regex("""[\p{L}\p{N}_]+""")

    fun vectorize(modelText: String): DoubleArray {
        val tokens = tokenRegex.findAll(modelText).map { it.value }.toList()
        val counts = IntArray(idf.size)
        for (n in wordNgramMin..wordNgramMax) {
            if (n <= 0 || n > tokens.size) continue
            for (index in 0..tokens.size - n) {
                val term = if (n == 1) {
                    tokens[index]
                } else {
                    tokens.subList(index, index + n).joinToString(" ")
                }
                val termIndex = vocabulary[term] ?: continue
                counts[termIndex]++
            }
        }

        val vector = DoubleArray(idf.size)
        var normSquared = 0.0
        for (index in counts.indices) {
            val count = counts[index]
            if (count == 0) continue
            val value = if (sublinearTf) 1.0 + ln(count.toDouble()) else count.toDouble()
            val weighted = value * idf[index]
            vector[index] = weighted
            normSquared += weighted * weighted
        }
        val norm = sqrt(normSquared)
        if (norm > 0.0) {
            for (index in vector.indices) vector[index] /= norm
        }
        return vector
    }

    fun predictModelText(modelText: String): PortablePrediction {
        val vector = vectorize(modelText)
        val logits = DoubleArray(labels.size) { labelIndex ->
            var value = intercepts[labelIndex]
            val row = coefficients[labelIndex]
            for (i in vector.indices) value += row[i] * vector[i]
            value
        }
        val scaled = DoubleArray(logits.size) { logits[it] / temperature }
        val max = scaled.maxOrNull() ?: 0.0
        val exps = DoubleArray(scaled.size) { exp(scaled[it] - max) }
        val total = exps.sum()
        val probabilities = DoubleArray(exps.size) { exps[it] / total }
        val best = probabilities.indices.maxByOrNull { probabilities[it] } ?: 0
        return PortablePrediction(logits, probabilities, labels[best])
    }

    fun predict(rawText: String): PortablePrediction =
        predictModelText(SmsNormalizer.normalize(rawText).modelText)

    fun probabilityMap(prediction: PortablePrediction): Map<String, Double> =
        labels.mapIndexed { index, label -> label to prediction.probabilities[index] }.toMap()

    companion object {
        fun load(file: File): PortableLinearModel =
            fromJson(file.readText(Charsets.UTF_8))

        fun fromJson(json: String): PortableLinearModel {
            val root = JsonParser(json).parse().asObject()
            require(root.string("format") == "sms-linear-v1") {
                "unsupported portable model format"
            }
            val labels = root.array("labels").map { it.asString() }
            require(labels == PortablePrediction.LABELS) { "unexpected portable labels" }
            val temperature = root.number("temperature")
            require(temperature > 0.0) { "temperature must be positive" }

            val blocks = root.objectValue("feature_blocks")
            val blockSizes = blocks.array("block_sizes").map { it.asInt() }
            require(blockSizes.size == 3) { "expected three feature blocks" }
            val word = blocks.objectValue("word")
            require(word.string("analyzer") == "word") { "only word analyzer is supported" }
            require(blockSizes[1] == 0) { "char_wb block is not supported by this port yet" }
            require(blockSizes[2] == 0) { "indicator block is not supported by this port yet" }

            val ngramRange = word.array("ngram_range").map { it.asInt() }
            require(ngramRange.size == 2) { "bad word ngram range" }
            val vocabulary = LinkedHashMap<String, Int>()
            for ((term, value) in word.objectValue("vocabulary")) {
                vocabulary[term] = value.asInt()
            }
            val idf = word.array("idf").map { it.asDouble() }.toDoubleArray()
            require(idf.size == vocabulary.size) { "word vocabulary/idf size mismatch" }
            require(blockSizes[0] == idf.size) { "word block size mismatch" }

            val coefficients = root.array("coefficients").map { row ->
                row.asArray().map { it.asDouble() }.toDoubleArray()
            }.toTypedArray()
            require(coefficients.size == labels.size) { "coefficient row count mismatch" }
            for (row in coefficients) {
                require(row.size == idf.size) { "coefficient width mismatch" }
            }
            val intercepts = root.array("intercepts").map { it.asDouble() }.toDoubleArray()
            require(intercepts.size == labels.size) { "intercept count mismatch" }

            return PortableLinearModel(
                labels = labels,
                temperature = temperature,
                vocabulary = vocabulary,
                idf = idf,
                coefficients = coefficients,
                intercepts = intercepts,
                wordNgramMin = ngramRange[0],
                wordNgramMax = ngramRange[1],
                sublinearTf = word.bool("sublinear_tf"),
            )
        }

        private fun JsonValue.asObject(): Map<String, JsonValue> =
            (this as? JsonValue.Obj)?.values ?: throw IllegalArgumentException("expected object")

        private fun JsonValue.asArray(): List<JsonValue> =
            (this as? JsonValue.Arr)?.values ?: throw IllegalArgumentException("expected array")

        private fun JsonValue.asString(): String =
            (this as? JsonValue.Str)?.value ?: throw IllegalArgumentException("expected string")

        private fun JsonValue.asDouble(): Double =
            (this as? JsonValue.Num)?.value ?: throw IllegalArgumentException("expected number")

        private fun JsonValue.asInt(): Int = asDouble().toInt()

        private fun Map<String, JsonValue>.objectValue(key: String): Map<String, JsonValue> =
            (get(key) ?: throw IllegalArgumentException("missing $key")).asObject()

        private fun Map<String, JsonValue>.array(key: String): List<JsonValue> =
            (get(key) ?: throw IllegalArgumentException("missing $key")).asArray()

        private fun Map<String, JsonValue>.string(key: String): String =
            (get(key) ?: throw IllegalArgumentException("missing $key")).asString()

        private fun Map<String, JsonValue>.number(key: String): Double =
            (get(key) ?: throw IllegalArgumentException("missing $key")).asDouble()

        private fun Map<String, JsonValue>.bool(key: String): Boolean =
            (get(key) as? JsonValue.Bool)?.value
                ?: throw IllegalArgumentException("missing boolean $key")
    }
}
