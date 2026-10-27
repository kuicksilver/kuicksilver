// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server.h1

import io.ktor.utils.io.InternalAPI
import kotlinx.io.InternalIoApi
import kotlinx.io.indexOf

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
 * Checks the request line at the start of [this] input (empty lines before it already skipped) before Ktor's parser reads
 * it, and throws [RequestHeadRefused] for one the server refuses. A request line longer than [MAX_REQUEST_LINE_BYTES]
 * is a request-target longer than the server parses: 414 (RFC 9112 section 3: the server MUST respond with 414), unless
 * no method and separator start it (400, as before). Returns without a verdict when the input ends or the head limit is
 * reached before the line end: the parser then reports that as it did.
 */
@OptIn(InternalAPI::class, InternalIoApi::class)
internal suspend fun HeadLimitedInput.checkRequestHead() {
    val buffer = readBuffer.buffer
    var scanned = 0L
    while (true) {
        val lf = buffer.indexOf(LF_BYTE, scanned, minOf(buffer.size, MAX_REQUEST_LINE_BYTES + 2L))
        if (lf >= 0) {
            val end = if (lf > 0 && buffer[lf - 1] == CR_BYTE) lf - 1 else lf
            if (end > MAX_REQUEST_LINE_BYTES) refuseLongLine(buffer)
            return
        }
        if (buffer.size >= MAX_REQUEST_LINE_BYTES + 2L) refuseLongLine(buffer)
        scanned = buffer.size
        if (!awaitContent((buffer.size + 1).toInt())) return
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
