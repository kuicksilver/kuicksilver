// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server.h1

import io.ktor.utils.io.InternalAPI
import kotlinx.io.InternalIoApi
import kotlinx.io.indexOf
import kotlinx.io.readByteArray

/**
 * The longest request line (without its line end) the server parses: Ktor's `parseRequest` limit for one line
 * (`HTTP_LINE_LIMIT`, 8 KiB).
 */
internal const val MAX_REQUEST_LINE_BYTES: Int = 8_192

/** A request head the server refuses before Ktor's parser sees it: [status] with [reason], then the connection closes. */
internal class RequestHeadRefused(
    val status: Int,
    val reason: String,
    message: String,
) : Exception(message)

/**
 * Checks the request head at the start of [this] input (empty lines before it already skipped) before Ktor's parser reads
 * it, and throws [RequestHeadRefused] for one the server refuses. A request line longer than [MAX_REQUEST_LINE_BYTES]
 * is a request-target longer than the server parses: 414 (RFC 9112 section 3: the server MUST respond with 414), unless
 * no method and separator start it (400, as before). The request line itself is checked by [checkRequestLine] as soon
 * as it is there, the field lines by [checkFieldSection] once the whole head is. Returns without a verdict when the
 * input ends or the head limit is reached before the head's end: the parser then reports that as it did.
 */
@OptIn(InternalAPI::class, InternalIoApi::class)
internal suspend fun HeadLimitedInput.checkRequestHead() {
    val buffer = readBuffer.buffer
    var scanned = 0L
    var lineStart = 0L
    var fieldsStart = -1L
    while (true) {
        val limit = if (fieldsStart < 0) minOf(buffer.size, MAX_REQUEST_LINE_BYTES + 2L) else buffer.size
        val lf = if (scanned < limit) buffer.indexOf(LF_BYTE, scanned, limit) else -1L
        if (lf < 0) {
            if (fieldsStart < 0 && buffer.size >= MAX_REQUEST_LINE_BYTES + 2L) refuseLongLine(buffer)
            scanned = limit
            if (!awaitContent((buffer.size + 1).toInt())) return
            continue
        }
        val end = if (lf > lineStart && buffer[lf - 1] == CR_BYTE) lf - 1 else lf
        if (fieldsStart < 0) {
            if (end > MAX_REQUEST_LINE_BYTES) refuseLongLine(buffer)
            val line = buffer.peek().readByteArray(end.toInt())
            val minor = checkRequestLine(line)
            if (line[minor] > '1'.code.toByte()) replaceBufferedByte(minor.toLong(), '1'.code.toByte())
            fieldsStart = lf + 1
        } else if (end == lineStart) {
            val fields = buffer.peek()
            fields.skip(fieldsStart)
            checkFieldSection(fields.readByteArray((lineStart - fieldsStart).toInt()))
            return
        }
        lineStart = lf + 1
        scanned = lf + 1
    }
}

/**
 * Checks the field lines of a request head ([fields]: each line with its line end, without the empty line that ends the
 * section). RFC 9110 section 5.5: a recipient of CR, LF or NUL within a field value MUST either reject the message or
 * replace each of them with SP; field-content is VCHAR, obs-text, SP and HTAB, so the other control characters (DEL
 * among them) are invalid too: 400, as Go's net/http does. Ktor's parser refuses only CR and LF in a value. A line
 * without a colon is left to the parser, which refuses it.
 */
internal fun checkFieldSection(fields: ByteArray) {
    var start = 0
    while (start < fields.size) {
        var lf = start
        while (lf < fields.size && fields[lf] != LF_BYTE) lf++
        val end = if (lf > start && fields[lf - 1] == CR_BYTE) lf - 1 else lf
        val colon = (start until end).firstOrNull { fields[it] == ':'.code.toByte() }
        if (colon != null) {
            for (i in colon + 1 until end) {
                val c = fields[i].toInt() and 0xFF
                if ((c < 0x20 && c != 0x09) || c == 0x7F) refuse("A control character in a field value")
            }
        }
        start = lf + 1
    }
}

/**
 * Checks a request line (without its line end) against `method SP request-target SP HTTP-version` (RFC 9112 section 3)
 * and returns the index of the minor version digit, or throws [RequestHeadRefused]. Ktor's parser is lenient where this
 * is not: it takes any run of non-whitespace as the method (section 3.1: method = token), any Unicode whitespace (U+00A0
 * among them) as a separator, and passes control characters in the target. Here:
 * - the separators are the whitespace section 3 lets a recipient take as SP (SP, HTAB, VT, FF, a bare CR), also before
 *   the method and after the version; any other control character (NUL, DEL, ...) or a Unicode space anywhere: 400;
 * - the method is a token (RFC 9110 section 5.6.2), else 400;
 * - the version is `"HTTP/" DIGIT "." DIGIT`, case-sensitive (section 2.3), else 400; a major version other than 1 gets
 *   505 (RFC 9110 section 15.6.6); a higher minor version is processed as HTTP/1.1, the highest minor version the
 *   server conforms to (RFC 9110 section 6.2: a recipient SHOULD), so the caller rewrites the digit before Ktor's parser,
 *   which knows only 1.0 and 1.1, sees it. Go's net/http does the same (505 for a major other than 1).
 */
internal fun checkRequestLine(line: ByteArray): Int {
    for (i in line.indices) {
        val b = line[i]
        val c = b.toInt() and 0xFF
        if ((c < 0x20 && !isRequestLineWhitespace(b)) || c == 0x7F) refuse("A control character in the request line")
        if (c >= 0x80 && unicodeSpaceLength(line, i) > 0) refuse("A Unicode space in the request line")
    }
    var i = 0
    val n = line.size

    fun skipWhitespace() {
        while (i < n && isRequestLineWhitespace(line[i])) i++
    }

    skipWhitespace()
    val methodStart = i
    while (i < n && isTcharByte(line[i])) i++
    if (i == methodStart || i == n || !isRequestLineWhitespace(line[i])) refuse("The method is not a token")
    skipWhitespace()
    val targetStart = i
    while (i < n && !isRequestLineWhitespace(line[i])) i++
    if (i == targetStart || i == n) refuse("No request-target or no version")
    skipWhitespace()
    val version = i
    while (i < n && !isRequestLineWhitespace(line[i])) i++
    val ok =
        i - version == 8 &&
            line.decodeToString(version, version + 5) == "HTTP/" &&
            line[version + 5] in DIGITS &&
            line[version + 6] == '.'.code.toByte() &&
            line[version + 7] in DIGITS
    if (!ok) refuse("Invalid HTTP-version")
    skipWhitespace()
    if (i != n) refuse("Extra characters in the request line")
    if (line[version + 5] != '1'.code.toByte()) {
        throw RequestHeadRefused(505, "HTTP Version Not Supported", "HTTP major version other than 1")
    }
    return version + 7
}

private val DIGITS = '0'.code.toByte()..'9'.code.toByte()

private fun refuse(message: String): Nothing = throw RequestHeadRefused(400, "Bad Request", message)

/**
 * The length of the UTF-8 sequence at [i] when it encodes a character above U+007F that Kotlin's `Char.isWhitespace` takes
 * as whitespace (U+00A0, U+1680, U+2000 to U+200A, U+2028, U+2029, U+202F, U+205F, U+3000), else 0. Ktor's parser
 * decodes the head as UTF-8 and skips or splits on such characters; on the wire they are obs-text or invalid bytes.
 */
internal fun unicodeSpaceLength(
    bytes: ByteArray,
    i: Int,
): Int {
    fun at(k: Int) = if (i + k < bytes.size) bytes[i + k].toInt() and 0xFF else -1
    return when (at(0)) {
        0xC2 -> {
            if (at(1) == 0xA0) 2 else 0
        }

        0xE1 -> {
            if (at(1) == 0x9A && at(2) == 0x80) 3 else 0
        }

        0xE2 -> {
            val b1 = at(1)
            val b2 = at(2)
            when {
                b1 == 0x80 && (b2 in 0x80..0x8A || b2 == 0xA8 || b2 == 0xA9 || b2 == 0xAF) -> 3
                b1 == 0x81 && b2 == 0x9F -> 3
                else -> 0
            }
        }

        0xE3 -> {
            if (at(1) == 0x80 && at(2) == 0x80) 3 else 0
        }

        else -> {
            0
        }
    }
}

/** 414 when the over-long line starts with a method token and a separator, else 400. */
private fun refuseLongLine(buffer: kotlinx.io.Buffer): Nothing {
    var i = 0L
    while (i < buffer.size && isTcharByte(buffer[i])) i++
    if (i > 0 && i < buffer.size && isRequestLineWhitespace(buffer[i])) {
        throw RequestHeadRefused(414, "URI Too Long", "The request line is longer than $MAX_REQUEST_LINE_BYTES bytes")
    }
    throw RequestHeadRefused(400, "Bad Request", "The request line is longer than $MAX_REQUEST_LINE_BYTES bytes")
}

/** tchar (RFC 9110 section 5.6.2) as a byte. */
internal fun isTcharByte(b: Byte): Boolean {
    val c = b.toInt() and 0xFF
    return c in 'a'.code..'z'.code ||
        c in 'A'.code..'Z'.code ||
        c in '0'.code..'9'.code ||
        c.toChar() in "!#$%&'*+-.^_`|~"
}

/** The whitespace RFC 9112 section 3 lets a recipient take as the SP separator of a request line: SP, HTAB, VT, FF, CR. */
internal fun isRequestLineWhitespace(b: Byte): Boolean = b == SP_BYTE || b == HTAB_BYTE || b == VT_BYTE || b == FF_BYTE || b == CR_BYTE

private const val SP_BYTE: Byte = 0x20
private const val HTAB_BYTE: Byte = 0x09
private const val VT_BYTE: Byte = 0x0B
private const val FF_BYTE: Byte = 0x0C
private const val CR_BYTE: Byte = 0x0D
private const val LF_BYTE: Byte = 0x0A
