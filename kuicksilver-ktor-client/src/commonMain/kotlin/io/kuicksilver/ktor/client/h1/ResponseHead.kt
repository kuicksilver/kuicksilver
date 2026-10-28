// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client.h1

import io.ktor.http.cio.ParserException
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.ClosedReadChannelException
import io.ktor.utils.io.InternalAPI
import kotlinx.io.Buffer
import kotlinx.io.EOFException
import kotlinx.io.readByteArray

/**
 * One response head (status line, field lines, the empty line) read from [input], for Ktor's `parseResponse`; null when
 * [input] ends before the head's first byte. Ktor's parser takes a head that ends before its empty line for a complete
 * one without fields, so the head is read here first: a head cut before its empty line is incomplete (RFC 9112 section
 * 8) and fails with [ClosedReadChannelException], as a connection closed before any response does, which keeps the
 * stale-connection retry of an idempotent request. Lines end with LF, a CR before it included (section 2.2). The bytes
 * are taken one at a time up to the head's last LF: what follows (a body, a tunnel's bytes) stays in [input]. A head
 * above [maxBytes] fails with [ParserException].
 *
 * A control character other than HTAB anywhere in a line (NUL, a bare CR, 0x7F...) fails with [ParserException]: NUL,
 * CR and LF in a field value are invalid and dangerous and MUST be rejected or replaced, the other CTLs are invalid too
 * (RFC 9110 section 5.5; a bare CR, RFC 9112 section 2.2). The reason phrase allows the same characters as a field value
 * (RFC 9112 section 4).
 *
 * An obs-fold (a field line that starts with SP or HTAB continues the one before) is replaced with one SP, as a user
 * agent MUST (RFC 9112 section 5.2); such a line right after the status line continues no field and fails with
 * [ParserException] (section 2.2 allows rejecting it). The status line is checked and normalized by [statusLineOf].
 */
@OptIn(InternalAPI::class)
internal suspend fun readResponseHeadBytes(
    input: ByteReadChannel,
    maxBytes: Int,
): ByteArray? {
    val head = Buffer()
    val line = Buffer()
    var taken = 0
    var statusLine = true
    // the field line read last, held back while the next line may continue it (obs-fold)
    var field: ByteArray? = null
    while (true) {
        if (input.readBuffer.exhausted() && !input.awaitContent()) {
            if (taken == 0) return null
            throw ClosedReadChannelException(EOFException("The response head ended before its empty line"))
        }
        val from = input.readBuffer
        while (!from.exhausted()) {
            if (taken == maxBytes) throw responseHeadTooLarge(maxBytes)
            val b = from.readByte()
            taken++
            if (b != LF) {
                line.writeByte(b)
                continue
            }
            var content = line.readByteArray()
            if (content.isNotEmpty() && content.last() == CR) content = content.copyOf(content.size - 1)
            content.firstOrNull { isForbiddenControl(it) }?.let {
                throw ParserException("Control character 0x${(it.toInt() and 0xff).toString(16).padStart(2, '0')} in the response head")
            }
            when {
                statusLine -> {
                    statusLine = false
                    head.write(statusLineOf(content))
                    head.write(CRLF)
                }

                content.isEmpty() -> {
                    field?.let {
                        head.write(it)
                        head.write(CRLF)
                    }
                    head.write(CRLF)
                    return head.readByteArray()
                }

                isOws(content[0]) -> {
                    val previous = field ?: throw ParserException("A line that starts with whitespace right after the status line")
                    field = previous.trimOwsEnd() + SP + content.trimOwsStart()
                }

                else -> {
                    field?.let {
                        head.write(it)
                        head.write(CRLF)
                    }
                    field = content
                }
            }
        }
    }
}

/**
 * [line] as a status line `HTTP-version SP 3DIGIT [SP reason-phrase]` (RFC 9112 section 4), else [ParserException];
 * Ktor's parser took `HTTP/1.1 20` for status 20. The SP before an absent reason phrase may be missing, as Go and OkHttp
 * accept. `HTTP/1.x` with x above 1 is returned as `HTTP/1.1`, the highest minor version this client conforms to (RFC
 * 9110 section 6.2 SHOULD); another major version fails. Three digits outside 100..599 are an invalid status code, and
 * "A client that receives a response with an invalid status code SHOULD process the response as if it had a 5xx (Server
 * Error) status code" (RFC 9110 section 15): the line is returned as a 500 whose reason phrase is the code and reason
 * the server sent (`HTTP/1.1 600 Six` as `HTTP/1.1 500 600 Six`), so Ktor's response validation, retries on server
 * errors and the framing all take it for a 5xx, and a 0xx is never taken for an interim response.
 */
private fun statusLineOf(line: ByteArray): ByteArray {
    fun invalid(): Nothing = throw ParserException("Invalid status line: ${line.decodeToString().take(64)}")

    fun digit(i: Int) = line[i] in '0'.code.toByte()..'9'.code.toByte()

    if (line.size < 12 || !HTTP_SLASH.indices.all { line[it] == HTTP_SLASH[it] }) invalid()
    if (!digit(5) || line[6] != '.'.code.toByte() || !digit(7) || line[8] != SP) invalid()
    if (!digit(9) || !digit(10) || !digit(11) || (line.size > 12 && line[12] != SP)) invalid()
    if (line[5] != '1'.code.toByte()) throw ParserException("Unsupported HTTP version: ${line.decodeToString(0, 8)}")
    val code = (line[9] - '0'.code.toByte()) * 100 + (line[10] - '0'.code.toByte()) * 10 + (line[11] - '0'.code.toByte())
    val status =
        if (code in 100..599) {
            line
        } else {
            var end = line.size
            while (end > 9 && isOws(line[end - 1])) end--
            line.copyOf(9) + "500 ".encodeToByteArray() + line.copyOfRange(9, end)
        }
    if (status[7] <= '1'.code.toByte()) return status
    return status.copyOf().also { it[7] = '1'.code.toByte() }
}

private val HTTP_SLASH = "HTTP/".encodeToByteArray()

private fun isOws(b: Byte) = b == SP || b == HTAB

private fun ByteArray.trimOwsEnd(): ByteArray {
    var end = size
    while (end > 0 && isOws(this[end - 1])) end--
    return copyOf(end)
}

private fun ByteArray.trimOwsStart(): ByteArray {
    var start = 0
    while (start < size && isOws(this[start])) start++
    return copyOfRange(start, size)
}

/** A CTL other than HTAB (RFC 5234 appendix B.1): 0x00-0x08, 0x0A-0x1F, 0x7F. */
private fun isForbiddenControl(b: Byte): Boolean = (b in 0x00..0x1F && b != HTAB) || b == DEL

/** The failure of a response head above [maxBytes]. */
internal fun responseHeadTooLarge(maxBytes: Int = MAX_RESPONSE_HEAD_BYTES) =
    ParserException("The response head is larger than $maxBytes bytes")

private const val HTAB: Byte = 0x09
private const val SP: Byte = 0x20
private const val CR: Byte = 0x0D
private const val DEL: Byte = 0x7F
private const val LF: Byte = 0x0A
private val CRLF = byteArrayOf(CR, LF)
