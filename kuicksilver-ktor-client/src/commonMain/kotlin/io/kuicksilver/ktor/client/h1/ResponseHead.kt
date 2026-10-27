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
            if (!statusLine && content.isEmpty()) {
                head.write(CRLF)
                return head.readByteArray()
            }
            statusLine = false
            head.write(content)
            head.write(CRLF)
        }
    }
}

/** The failure of a response head above [maxBytes]. */
internal fun responseHeadTooLarge(maxBytes: Int = MAX_RESPONSE_HEAD_BYTES) =
    ParserException("The response head is larger than $maxBytes bytes")

private const val CR: Byte = 0x0D
private const val LF: Byte = 0x0A
private val CRLF = byteArrayOf(CR, LF)
