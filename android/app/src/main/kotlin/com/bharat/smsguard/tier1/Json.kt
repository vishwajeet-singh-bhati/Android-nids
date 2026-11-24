package com.bharat.smsguard.tier1

/**
 * Small, dependency-free JSON reader for the portable model payload.
 * It supports the standard JSON value types and is intentionally not a
 * general-purpose streaming parser.
 */
sealed class JsonValue {
    data object Null : JsonValue()
    data class Bool(val value: Boolean) : JsonValue()
    data class Num(val value: Double) : JsonValue()
    data class Str(val value: String) : JsonValue()
    data class Arr(val values: List<JsonValue>) : JsonValue()
    data class Obj(val values: Map<String, JsonValue>) : JsonValue()
}

class JsonParseException(message: String) : IllegalArgumentException(message)

class JsonParser(private val text: String) {
    private var index = 0

    fun parse(): JsonValue {
        skipWhitespace()
        val value = parseValue()
        skipWhitespace()
        if (index != text.length) fail("trailing characters")
        return value
    }

    private fun parseValue(): JsonValue {
        if (index >= text.length) fail("unexpected end of input")
        return when (val ch = text[index]) {
            '{' -> parseObject()
            '[' -> parseArray()
            '"' -> JsonValue.Str(parseString())
            't' -> parseLiteral("true", JsonValue.Bool(true))
            'f' -> parseLiteral("false", JsonValue.Bool(false))
            'n' -> parseLiteral("null", JsonValue.Null)
            '-', in '0'..'9' -> parseNumber()
            else -> fail("unexpected character '$ch'")
        }
    }

    private fun parseObject(): JsonValue.Obj {
        expect('{')
        skipWhitespace()
        val values = LinkedHashMap<String, JsonValue>()
        if (peek('}')) {
            index++
            return JsonValue.Obj(values)
        }
        while (true) {
            skipWhitespace()
            if (!peek('"')) fail("object key must be a string")
            val key = parseString()
            skipWhitespace()
            expect(':')
            skipWhitespace()
            values[key] = parseValue()
            skipWhitespace()
            when {
                peek(',') -> index++
                peek('}') -> {
                    index++
                    return JsonValue.Obj(values)
                }
                else -> fail("expected ',' or '}'")
            }
        }
    }

    private fun parseArray(): JsonValue.Arr {
        expect('[')
        skipWhitespace()
        val values = ArrayList<JsonValue>()
        if (peek(']')) {
            index++
            return JsonValue.Arr(values)
        }
        while (true) {
            skipWhitespace()
            values.add(parseValue())
            skipWhitespace()
            when {
                peek(',') -> index++
                peek(']') -> {
                    index++
                    return JsonValue.Arr(values)
                }
                else -> fail("expected ',' or ']'")
            }
        }
    }

    private fun parseString(): String {
        expect('"')
        val builder = StringBuilder()
        while (index < text.length) {
            val ch = text[index++]
            when (ch) {
                '"' -> return builder.toString()
                '\\' -> {
                    if (index >= text.length) fail("unterminated escape")
                    when (val escaped = text[index++]) {
                        '"', '\\', '/' -> builder.append(escaped)
                        'b' -> builder.append('\b')
                        'f' -> builder.append('\u000c')
                        'n' -> builder.append('\n')
                        'r' -> builder.append('\r')
                        't' -> builder.append('\t')
                        'u' -> {
                            if (index + 4 > text.length) fail("short unicode escape")
                            val hex = text.substring(index, index + 4)
                            val code = hex.toIntOrNull(16) ?: fail("bad unicode escape")
                            builder.append(code.toChar())
                            index += 4
                        }
                        else -> fail("unknown escape '\\$escaped'")
                    }
                }
                else -> {
                    if (ch < ' ') fail("control character in string")
                    builder.append(ch)
                }
            }
        }
        fail("unterminated string")
    }

    private fun parseNumber(): JsonValue.Num {
        val start = index
        if (peek('-')) index++
        if (index >= text.length) fail("short number")
        if (peek('0')) {
            index++
        } else {
            if (text[index] !in '1'..'9') fail("bad number")
            while (index < text.length && text[index] in '0'..'9') index++
        }
        if (peek('.')) {
            index++
            if (index >= text.length || text[index] !in '0'..'9') fail("bad fraction")
            while (index < text.length && text[index] in '0'..'9') index++
        }
        if (peek('e') || peek('E')) {
            index++
            if (peek('+') || peek('-')) index++
            if (index >= text.length || text[index] !in '0'..'9') fail("bad exponent")
            while (index < text.length && text[index] in '0'..'9') index++
        }
        val value = text.substring(start, index).toDoubleOrNull() ?: fail("bad number")
        return JsonValue.Num(value)
    }

    private fun parseLiteral(literal: String, value: JsonValue): JsonValue {
        if (!text.startsWith(literal, index)) fail("expected '$literal'")
        index += literal.length
        return value
    }

    private fun skipWhitespace() {
        while (index < text.length && text[index] in WHITESPACE) index++
    }

    private fun peek(ch: Char): Boolean = index < text.length && text[index] == ch

    private fun expect(ch: Char) {
        if (!peek(ch)) fail("expected '$ch'")
        index++
    }

    private fun fail(message: String): Nothing {
        throw JsonParseException("$message at offset $index")
    }

    private companion object {
        val WHITESPACE = charArrayOf(' ', '\t', '\n', '\r')
    }
}
