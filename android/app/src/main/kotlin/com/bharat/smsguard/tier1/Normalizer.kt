package com.bharat.smsguard.tier1

import java.text.Normalizer
import java.util.Locale

/**
 * Kotlin port of sms_detection.preprocessing.normalize.
 *
 * This intentionally mirrors the Python reference, including URL/email/phone
 * masking and the conservative leetspeak handling. It uses only JVM APIs so the
 * same source can be reused by the Android Tier-1 module.
 */
data class NormalizedSms(
    val raw: String,
    val normalized: String,
    val modelText: String,
    val urls: List<String>,
    val emails: List<String>,
    val phones: List<String>,
    val flags: Map<String, Boolean>,
)

object SmsNormalizer {
    private val ZERO_WIDTH = Regex("[\u200b-\u200f\u2060\ufeff\u00ad]")
    private val FULLWIDTH = Regex("[\uff01-\uff5e]")
    private val MIXED_SCRIPT = Regex("[A-Za-z]")
    private val CYRILLIC_GREEK = Regex("[\\u0400-\\u04ff\\u0370-\\u03ff]")
    private val WHITESPACE = Regex("\\s+")

    private val HOMOGLYPHS = mapOf(
        'а' to 'a', 'е' to 'e', 'о' to 'o', 'р' to 'p', 'с' to 'c', 'у' to 'y',
        'х' to 'x', 'і' to 'i', 'ј' to 'j', 'ѕ' to 's', 'ԁ' to 'd', 'ӏ' to 'l',
        'α' to 'a', 'β' to 'b', 'ε' to 'e', 'ι' to 'i', 'κ' to 'k', 'ν' to 'v',
        'ο' to 'o', 'ρ' to 'p', 'τ' to 't', 'υ' to 'u', 'χ' to 'x',
    )

    private val LEET_MAP = mapOf(
        '0' to 'o', '1' to 'i', '3' to 'e', '4' to 'a',
        '5' to 's', '7' to 't', '@' to 'a', '$' to 's',
    )

    private val LEET_SECURITY_WORDS = setOf(
        "access", "account", "accounts", "alert", "amazon", "axis", "bank",
        "banking", "bhim", "block", "blocked", "claim", "click", "credit",
        "credited", "custom", "customs", "debit", "debited", "delivery",
        "flipkart", "free", "gift", "google", "government", "hack", "hacked",
        "hdfc", "icici", "income", "job", "kotak", "kyc", "loan", "login",
        "logins", "lottery", "netbanking", "netflix", "offer", "otp", "package",
        "parcel", "passcode", "password", "passwords", "pay", "payment", "paytm",
        "phonepe", "police", "prize", "refund", "reward", "sbi", "secure",
        "security", "suspend", "suspended", "tax", "upi", "update", "updated",
        "username", "verification", "verified", "verify", "wallet", "winner",
        "won",
    )

    private val EMAIL_RE = Regex("""(?i)(?<![\w.+-])[\w.+-]+@[\w-]+(?:\.[\w-]+)+""")
    private val PHONE_RE = Regex(
        """(?ix)
        (?<!\d)
        (?:
            (?:\+?91[\s.-]?)?[6-9]\d{9}
            |0\d{2,4}[\s.-]?\d{6,8}
            |1800[\s.-]?\d{2,4}[\s.-]?\d{4}
            |\+\d{1,3}[\s.-]?\d{6,14}
        )
        (?!\d)
        """.trimIndent(),
    )
    private val URL_RE = Regex(
        """(?ix)
        \b
        (?:
            (?:https?|ftp)://[^\s<>"']+
            |www\.[^\s<>"']+
            |(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+
             (?:com|net|org|in|co|io|ly|me|app|info|biz|xyz|online|site|link|click|top|club|shop|live|pro|icu|tk|ml|ga|cf|gq)
             (?::\d{2,5})?
             (?:/[^\s<>"']*)?
        )
        """.trimIndent(),
    )
    private val LONG_DIGIT_RE = Regex("""(?<!\d)\d{8,}(?!\d)""")
    private val SPACED_LETTERS_RE = Regex("""(?:\b[a-zA-Z]\s+){4,}[a-zA-Z]\b""")
    private val EXCESSIVE_PUNCT_RE = Regex("""[!?]{3,}|(?:[!?.,;:]\s*){5,}""")
    private val LEET_TOKEN_RE = Regex("""[A-Za-z0-9@${'$'}]+""")
    private val HAS_LETTER_RE = Regex("[A-Za-z]")
    private val HAS_LEET_CHAR_RE = Regex("""[0-9@${'$'}]""")
    private val AMOUNT_RE = Regex(
        """(?:rs|inr|usd|gbp|eur)?\d+(?:\.\d+)?""",
        RegexOption.IGNORE_CASE,
    )
    private val IDENTIFIER_RE = Regex("""\d+[a-z]{1,2}\d*""", RegexOption.IGNORE_CASE)

    private const val URL_TOKEN = "url_present"
    private const val EMAIL_TOKEN = "email_present"
    private const val PHONE_TOKEN = "phone_present"

    fun normalize(raw: String?): NormalizedSms {
        val source = raw ?: ""
        val zeroWidth = ZERO_WIDTH.containsMatchIn(source)
        val fullwidth = FULLWIDTH.containsMatchIn(source)
        val mixedScript = MIXED_SCRIPT.containsMatchIn(source) &&
            CYRILLIC_GREEK.containsMatchIn(source)
        val spacedLetters = SPACED_LETTERS_RE.containsMatchIn(source)
        val excessivePunct = EXCESSIVE_PUNCT_RE.containsMatchIn(source)
        val longDigits = LONG_DIGIT_RE.containsMatchIn(PHONE_RE.replace(source, " "))
        val excessiveCaps = isExcessiveCaps(source)
        val leetspeak = hasLeetToken(source)

        var text = Normalizer.normalize(source, Normalizer.Form.NFKC)
        text = ZERO_WIDTH.replace(text, "")

        if (mixedScript) {
            text = text.map { ch ->
                HOMOGLYPHS[ch.lowercaseChar()] ?: ch
            }.joinToString("")
        }

        // An @ inside URL credentials or a query is part of that URL. Masking
        // it as an email first would destroy the address before URL extraction.
        val explicitUrls = Regex("""(?i)\b(?:https?|ftp)://[^\s<>"']+""")
            .findAll(text).map { it.range }.toList()
        fun insideUrl(match: MatchResult) = explicitUrls.any { match.range.first in it }
        val emails = EMAIL_RE.findAll(text).filterNot { insideUrl(it) }.map { it.value }.distinct().toList()
        val textWithoutEmails = EMAIL_RE.replace(text) { if (insideUrl(it)) it.value else " $EMAIL_TOKEN " }
        val urls = URL_RE.findAll(textWithoutEmails).map { it.value }.distinct().toList()
        val textWithoutUrls = URL_RE.replace(textWithoutEmails, " $URL_TOKEN ")
        val phones = PHONE_RE.findAll(textWithoutUrls).map { it.value }.distinct().toList()
        val masked = PHONE_RE.replace(textWithoutUrls, " $PHONE_TOKEN ")

        val normalized = WHITESPACE.replace(masked, " ").trim()
        val modelText = normalized.lowercase(Locale.ROOT)
            .split(WHITESPACE)
            .filter { it.isNotEmpty() }
            .joinToString(" ") { deleetToken(it) }

        val flags = linkedMapOf(
            "zero_width" to zeroWidth,
            "fullwidth" to fullwidth,
            "mixed_script_homoglyph" to mixedScript,
            "spaced_letters" to spacedLetters,
            "excessive_punctuation" to excessivePunct,
            "excessive_caps" to excessiveCaps,
            "long_digit_string" to longDigits,
            "leetspeak" to leetspeak,
        )
        flags["obfuscated"] = listOf(
            zeroWidth, fullwidth, mixedScript, spacedLetters, leetspeak,
        ).any { it }

        return NormalizedSms(
            raw = source,
            normalized = normalized,
            modelText = modelText,
            urls = urls,
            emails = emails,
            phones = phones,
            flags = flags,
        )
    }

    private fun isExcessiveCaps(text: String): Boolean {
        val letters = text.filter { it.isLetter() }
        if (letters.length < 20) return false
        val uppercase = letters.count { it.isUpperCase() }
        return uppercase.toDouble() / letters.length >= 0.7
    }

    private fun hasLeetToken(text: String): Boolean {
        for (token in LEET_TOKEN_RE.findAll(text).map { it.value }) {
            if (token.length !in 3..20) continue
            if (!HAS_LETTER_RE.containsMatchIn(token)) continue
            if (!HAS_LEET_CHAR_RE.containsMatchIn(token)) continue
            if (AMOUNT_RE.matches(token)) continue
            val converted = token.map { LEET_MAP[it] ?: it }.joinToString("")
            if (converted.lowercase(Locale.ROOT) in LEET_SECURITY_WORDS) return true
        }
        return false
    }

    private fun deleetToken(token: String): String {
        if (token.length !in 3..30) return token
        if (!HAS_LETTER_RE.containsMatchIn(token)) return token
        if (!HAS_LEET_CHAR_RE.containsMatchIn(token)) return token
        if (AMOUNT_RE.matches(token)) return token
        if (IDENTIFIER_RE.matches(token)) return token
        val converted = token.map { LEET_MAP[it] ?: it }.joinToString("")
        return if (converted.lowercase(Locale.ROOT) in LEET_SECURITY_WORDS) converted else token
    }
}
