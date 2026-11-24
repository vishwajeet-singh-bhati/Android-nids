package com.bharat.smsguard.tier1

import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.util.Base64
import kotlin.system.exitProcess

/** Compares the complete indicator flag vector against the Python oracle. */
fun runFlagParity(args: Array<String>) {
    val fixturePath = args.firstOrNull()
    if (fixturePath == null) {
        System.err.println("usage: tier1-parity --flags <fixture.tsv>")
        error("SMS parity arguments failed")
    }

    val lines = Files.readAllLines(Path.of(fixturePath), StandardCharsets.UTF_8)
    if (lines.isEmpty()) {
        System.err.println("empty fixture")
        error("SMS parity arguments failed")
    }
    val header = lines.first().split('\t')
    val expectedHeader = listOf("id", "text_b64", "sender_b64", "flags", "strong_count")
    check(header == expectedHeader) { "unexpected fixture header: $header" }

    var matched = 0
    val mismatches = mutableListOf<String>()
    for (line in lines.drop(1)) {
        if (line.isBlank()) continue
        val row = line.split('\t')
        check(row.size == expectedHeader.size) { "bad row width: ${row.size}" }
        val id = row[0]
        val text = decode(row[1])
        val sender = decode(row[2]).ifBlank { null }
        val evidence = Tier1Evidence.analyze(text, sender)
        val actualFlags = Codes.EVIDENCE_CODES.joinToString("") {
            if (evidence.has(it)) "1" else "0"
        }
        val reasons = mutableListOf<String>()
        if (actualFlags != row[3]) {
            val differing = Codes.EVIDENCE_CODES.filterIndexed { index, _ ->
                actualFlags[index] != row[3][index]
            }
            reasons += "flags(${differing.joinToString("/")})"
        }
        if (evidence.strongCueCount() != row[4].toInt()) reasons += "strong_count"
        if (reasons.isEmpty()) {
            matched++
        } else {
            mismatches += "$id: ${reasons.joinToString(",")}"
        }
    }

    val total = matched + mismatches.size
    println("total=$total matched=$matched mismatched=${mismatches.size}")
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
