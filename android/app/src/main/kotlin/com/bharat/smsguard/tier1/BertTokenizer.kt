package com.bharat.smsguard.tier1

import java.text.Normalizer
import java.util.Locale

/** Uncased BERT BasicTokenizer + greedy WordPiece. Fixed exported length 128. */
class BertTokenizer(vocabLines: List<String>) {
    private val vocab = vocabLines.withIndex().associate { it.value to it.index.toLong() }
    private val special = Regex("\\[PAD]|\\[UNK]|\\[CLS]|\\[SEP]|\\[MASK]")
    data class Input(val ids: LongArray, val mask: LongArray, val types: LongArray)
    fun encode(text: String): Input {
        val words = mutableListOf<String>()
        var offset = 0
        for (match in special.findAll(text)) {
            words += basic(text.substring(offset, match.range.first))
            words += match.value
            offset = match.range.last + 1
        }
        words += basic(text.substring(offset))
        val pieces = words.flatMap { word ->
            if (vocab.containsKey(word)) listOf(vocab.getValue(word)) else wordPiece(word)
        }.take(126)
        val ids = LongArray(128)
        ids[0] = vocab.getValue("[CLS]")
        pieces.forEachIndexed { i, id -> ids[i + 1] = id }
        ids[pieces.size + 1] = vocab.getValue("[SEP]")
        return Input(ids, LongArray(128) { if (it < pieces.size + 2) 1 else 0 }, LongArray(128))
    }
    private fun wordPiece(word: String): List<Long> {
        val chars = word.codePoints().toArray()
        if (chars.size > 100) return listOf(vocab.getValue("[UNK]"))
        var start = 0
        val out = mutableListOf<Long>()
        while (start < chars.size) {
            var end = chars.size
            var found: Long? = null
            while (end > start) {
                val part = (if (start > 0) "##" else "") + String(chars, start, end - start)
                found = vocab[part]
                if (found != null) break
                end--
            }
            if (found == null) return listOf(vocab.getValue("[UNK]"))
            out += found
            start = end
        }
        return out
    }
    private fun basic(text: String): List<String> {
        val cleaned = StringBuilder()
        text.codePoints().forEach { cp ->
            val kind = Character.getType(cp)
            when {
                cp == 0 || cp == 0xfffd -> Unit
                cp == 9 || cp == 10 || cp == 13 || Character.isWhitespace(cp) || kind == Character.SPACE_SEPARATOR.toInt() -> cleaned.append(' ')
                kind in listOf(Character.CONTROL.toInt(), Character.FORMAT.toInt(), Character.PRIVATE_USE.toInt(), Character.SURROGATE.toInt(), Character.UNASSIGNED.toInt()) -> Unit
                chinese(cp) -> cleaned.append(' ').appendCodePoint(cp).append(' ')
                else -> cleaned.appendCodePoint(cp)
            }
        }
        val normalized = Normalizer.normalize(cleaned.toString().lowercase(Locale.ROOT), Normalizer.Form.NFD)
        val tokens = mutableListOf<String>()
        val current = StringBuilder()
        fun flush() { if (current.isNotEmpty()) { tokens += current.toString(); current.setLength(0) } }
        normalized.codePoints().forEach { cp ->
            val kind = Character.getType(cp)
            val punctuation = (cp in 33..47 || cp in 58..64 || cp in 91..96 || cp in 123..126) ||
                kind in listOf(Character.CONNECTOR_PUNCTUATION.toInt(), Character.DASH_PUNCTUATION.toInt(), Character.START_PUNCTUATION.toInt(), Character.END_PUNCTUATION.toInt(), Character.INITIAL_QUOTE_PUNCTUATION.toInt(), Character.FINAL_QUOTE_PUNCTUATION.toInt(), Character.OTHER_PUNCTUATION.toInt())
            when {
                kind == Character.NON_SPACING_MARK.toInt() -> Unit
                Character.isWhitespace(cp) -> flush()
                punctuation -> { flush(); tokens += String(Character.toChars(cp)) }
                else -> current.appendCodePoint(cp)
            }
        }
        flush()
        return tokens
    }
    private fun chinese(cp: Int) = cp in 0x4e00..0x9fff || cp in 0x3400..0x4dbf ||
        cp in 0x20000..0x2a6df || cp in 0x2a700..0x2b73f || cp in 0x2b740..0x2b81f ||
        cp in 0x2b820..0x2ceaf || cp in 0xf900..0xfaff || cp in 0x2f800..0x2fa1f
}
