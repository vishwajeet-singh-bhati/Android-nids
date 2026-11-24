package com.bharat.smsguard.tier1

import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.util.Base64
import kotlin.system.exitProcess

/**
 * Compares the Kotlin Tier-1 implementation against a Python-generated TSV
 * oracle. The fixture contains base64-encoded SMS bodies so delimiters never
 * interfere with parsing; no message body is printed by this program.
 */
fun runTier1Parity(args: Array<String>) {
    val fixturePath = args.firstOrNull()
    if (fixturePath == null) {
        System.err.println("usage: tier1-parity <fixture.tsv>")
        error("SMS parity arguments failed")
    }

    val lines = Files.readAllLines(Path.of(fixturePath), StandardCharsets.UTF_8)
    if (lines.isEmpty()) {
        System.err.println("empty fixture")
        error("SMS parity arguments failed")
    }

    val header = lines.first().split('\t')
    val expectedHeader = listOf(
        "id", "text_b64", "sender_b64", "normalized_b64", "model_text_b64",
        "urls_b64", "phone_count", "email_count", "url_present",
        "payment_request", "urgency", "delivery_bait", "kyc", "account_threat",
        "impersonation", "new_codes", "dlt",
    )
    check(header == expectedHeader) {
        "unexpected fixture header: $header"
    }

    var matched = 0
    val mismatches = mutableListOf<String>()

    for (line in lines.drop(1)) {
        if (line.isBlank()) continue
        val row = line.split('\t')
        check(row.size == expectedHeader.size) { "bad row width: ${row.size}" }
        val id = row[0]
        val text = decode(row[1])
        val sender = decode(row[2]).ifBlank { null }
        val actual = Tier1Evidence.analyze(text, sender)
        val reasons = mutableListOf<String>()

        if (actual.normalized.normalized != decode(row[3])) reasons += "normalized"
        if (actual.normalized.modelText != decode(row[4])) reasons += "model_text"

        val expectedUrls = decode(row[5]).split('\n').filter { it.isNotBlank() }
        if (actual.normalized.urls != expectedUrls) reasons += "urls"
        if (actual.normalized.phones.size != row[6].toInt()) reasons += "phone_count"
        if (actual.normalized.emails.size != row[7].toInt()) reasons += "email_count"

        fun checkFlag(column: Int, code: String, name: String) {
            val expected = row[column] == "1"
            if (actual.has(code) != expected) reasons += name
        }
        checkFlag(8, Codes.URL_PRESENT, "url_present")
        checkFlag(9, Codes.PAYMENT_REQUEST, "payment_request")
        checkFlag(10, Codes.URGENCY_LANGUAGE, "urgency")
        checkFlag(11, Codes.DELIVERY_BAIT, "delivery_bait")
        checkFlag(12, Codes.KYC_LANGUAGE, "kyc")
        checkFlag(13, Codes.ACCOUNT_THREAT, "account_threat")
        checkFlag(14, Codes.IMPERSONATION, "impersonation")

        val expectedCodes = row[15].split(',').filter { it.isNotBlank() && it != "-" }
        if (actual.newCodes != expectedCodes) reasons += "new_codes"

        if (actual.dltSenderMismatch != (row[16] == "1")) reasons += "dlt"

        if (reasons.isEmpty()) {
            matched++
        } else {
            mismatches += "$id: ${reasons.joinToString(",")}"
        }
    }

    val total = matched + mismatches.size
    println("total=$total matched=$matched mismatched=${mismatches.size}")
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
