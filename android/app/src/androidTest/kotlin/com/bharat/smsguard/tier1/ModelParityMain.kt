package com.bharat.smsguard.tier1

import java.io.File
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.util.Base64
import kotlin.math.abs
import kotlin.system.exitProcess

/**
 * Compares Kotlin portable-model logits/probabilities against a PyTorch-free
 * Python oracle. It prints only case IDs and aggregate numerical differences.
 */
fun runModelParity(args: Array<String>) {
    if (args.size != 2) {
        System.err.println("usage: model-parity <portable_model.json> <fixture.tsv>")
        error("SMS parity arguments failed")
    }

    val model = PortableLinearModel.load(File(args[0]))
    val lines = Files.readAllLines(Path.of(args[1]), StandardCharsets.UTF_8)
    if (lines.isEmpty()) {
        System.err.println("empty fixture")
        error("SMS parity arguments failed")
    }

    val header = lines.first().split('\t')
    val expectedHeader = listOf(
        "id", "text_b64", "sender_b64", "logit_ham", "logit_spam",
        "logit_smishing", "p_ham", "p_spam", "p_smishing", "label",
    )
    check(header == expectedHeader) { "unexpected fixture header: $header" }

    var matched = 0
    val mismatches = mutableListOf<String>()
    var maxLogitDiff = 0.0
    var maxProbabilityDiff = 0.0

    for (line in lines.drop(1)) {
        if (line.isBlank()) continue
        val row = line.split('\t')
        check(row.size == expectedHeader.size) { "bad row width: ${row.size}" }
        val id = row[0]
        val text = decode(row[1])
        val prediction = model.predict(text)
        val expectedLogits = doubleArrayOf(
            row[3].toDouble(),
            row[4].toDouble(),
            row[5].toDouble(),
        )
        val expectedProbabilities = doubleArrayOf(
            row[6].toDouble(),
            row[7].toDouble(),
            row[8].toDouble(),
        )

        var logitDiff = 0.0
        var probabilityDiff = 0.0
        for (index in expectedLogits.indices) {
            logitDiff = maxOf(logitDiff, abs(prediction.logits[index] - expectedLogits[index]))
            probabilityDiff = maxOf(
                probabilityDiff,
                abs(prediction.probabilities[index] - expectedProbabilities[index]),
            )
        }
        maxLogitDiff = maxOf(maxLogitDiff, logitDiff)
        maxProbabilityDiff = maxOf(maxProbabilityDiff, probabilityDiff)

        val reasons = mutableListOf<String>()
        if (logitDiff > 1e-9) reasons += "logits"
        if (probabilityDiff > 1e-12) reasons += "probabilities"
        if (prediction.label != row[9]) reasons += "label"
        if (reasons.isEmpty()) {
            matched++
        } else {
            mismatches += "$id: ${reasons.joinToString(",")} (logit=$logitDiff, p=$probabilityDiff)"
        }
    }

    val total = matched + mismatches.size
    println(
        "total=$total matched=$matched mismatched=${mismatches.size} " +
            "max_logit_diff=$maxLogitDiff max_probability_diff=$maxProbabilityDiff",
    )
    if (mismatches.isNotEmpty()) {
        mismatches.take(30).forEach { println("MISMATCH $it") }
        if (mismatches.size > 30) println("... ${mismatches.size - 30} more")
        error("SMS parity runner failed")
    }
}

private fun decode(value: String): String {
    if (value == "-" || value.isEmpty()) return ""
    return String(Base64.getDecoder().decode(value), StandardCharsets.UTF_8)
}
