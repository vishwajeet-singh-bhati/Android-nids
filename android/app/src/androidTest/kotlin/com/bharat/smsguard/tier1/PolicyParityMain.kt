package com.bharat.smsguard.tier1

import java.io.File
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.util.Base64
import kotlin.math.abs
import kotlin.system.exitProcess

/** Compares end-to-end Kotlin and Python policy decisions. */
fun runPolicyParity(args: Array<String>) {
    if (args.size != 2) {
        System.err.println("usage: tier1-parity --policy <portable_model.json> <fixture.tsv>")
        error("SMS parity arguments failed")
    }

    val model = PortableLinearModel.load(File(args[0]))
    val detector = Tier1Detector(model, RiskPolicy.production())
    val lines = Files.readAllLines(Path.of(args[1]), StandardCharsets.UTF_8)
    if (lines.isEmpty()) {
        System.err.println("empty fixture")
        error("SMS parity arguments failed")
    }
    val header = lines.first().split('\t')
    val expectedHeader = listOf(
        "id", "text_b64", "sender_b64", "label", "risk", "actions",
        "rule_label", "rule_triggered", "reason_codes", "p_ham", "p_spam",
        "p_smishing",
    )
    check(header == expectedHeader) { "unexpected fixture header: $header" }

    var matched = 0
    val mismatches = mutableListOf<String>()
    var maxScoreDiff = 0.0

    for (line in lines.drop(1)) {
        if (line.isBlank()) continue
        val row = line.split('\t')
        check(row.size == expectedHeader.size) { "bad row width: ${row.size}" }
        val id = row[0]
        val text = decode(row[1])
        val sender = decode(row[2]).ifBlank { null }
        val detection = detector.predict(text, sender)
        val assessment = detection.assessment

        val reasons = mutableListOf<String>()
        if (assessment.label != row[3]) reasons += "label(${assessment.label}!=${row[3]})"
        if (assessment.riskLevel != row[4]) reasons += "risk(${assessment.riskLevel}!=${row[4]})"
        val actions = assessment.recommendedActionCodes.joinToString("|")
        if (actions != row[5]) reasons += "actions($actions!=${row[5]})"
        if (assessment.ruleLabel != row[6]) reasons += "rule_label"
        if (assessment.ruleTriggered != (row[7] == "1")) reasons += "rule_triggered"
        val reasonCodes = assessment.reasonCodes.joinToString("|")
        if (reasonCodes != row[8]) reasons += "reason_codes($reasonCodes!=${row[8]})"

        val expectedScores = doubleArrayOf(
            row[9].toDouble(),
            row[10].toDouble(),
            row[11].toDouble(),
        )
        val labels = RiskPolicy.LABELS
        for (index in labels.indices) {
            val actual = assessment.scores[labels[index]] ?: 0.0
            maxScoreDiff = maxOf(maxScoreDiff, abs(actual - expectedScores[index]))
        }
        if (reasons.isEmpty()) {
            matched++
        } else {
            mismatches += "$id: ${reasons.joinToString(", ")}"
        }
    }

    val total = matched + mismatches.size
    println(
        "total=$total matched=$matched mismatched=${mismatches.size} " +
            "max_score_diff=$maxScoreDiff",
    )
    if (mismatches.isNotEmpty()) {
        mismatches.take(40).forEach { println("MISMATCH $it") }
        if (mismatches.size > 40) println("... ${mismatches.size - 40} more")
        error("SMS parity runner failed")
    }
}

private fun decode(value: String): String {
    if (value == "-" || value.isEmpty()) return ""
    return String(Base64.getDecoder().decode(value), StandardCharsets.UTF_8)
}
