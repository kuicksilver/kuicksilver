// Copyright 2014-2026 JetBrains s.r.o and contributors. Use of this source code is governed by the Apache 2.0 license.
// Modifications Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
// Vendored from Ktor 3.6.0 ktor-http-cio ChunkedTransferEncoding.kt (decodeChunked, parseChunkSize), adapted: the trailer
// section is read and discarded instead of failing with "Expected CR", and a body that ends before its last chunk fails.
// Kept identical with kuicksilver-ktor-client's h1/ChunkedBody.kt (the two engines share no module above ktor-network).
package io.kuicksilver.ktor.server.h1

import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.ByteWriteChannel
import io.ktor.utils.io.InternalAPI
import io.ktor.utils.io.close
import io.ktor.utils.io.copyTo
import io.ktor.utils.io.readByte
import kotlinx.io.EOFException
import kotlinx.io.IOException

private const val MAX_CHUNK_SIZE_LENGTH = 128

/** Bytes of the trailer section after the last chunk, field lines and line endings together. */
internal const val MAX_TRAILER_SECTION = 16 * 1024

/**
 * Decodes the chunked transfer coding (RFC 9112 section 7.1) from [input] into [out], which is closed at the end. The
 * trailer section after the last chunk is read up to its empty line and discarded (section 7.1.2: a recipient MAY
 * discard the trailer fields); it is limited to [MAX_TRAILER_SECTION] bytes. A message that ends before its last chunk
 * is incomplete (section 8) and fails with [EOFException].
 */
internal suspend fun decodeChunkedBody(
    input: ByteReadChannel,
    out: ByteWriteChannel,
) {
    try {
        while (true) {
            val chunkSize = parseChunkSize(input)
            if (chunkSize == 0L) {
                skipTrailerSection(input)
                break
            }
            val copied = input.copyTo(out, chunkSize)
            if (copied < chunkSize) throw EOFException("The chunked body ended inside a chunk")
            skipCrLf(input)
            out.flush()
        }
    } catch (t: Throwable) {
        out.close(t)
        throw t
    } finally {
        out.flushAndClose()
    }
}

private suspend fun skipCrLf(input: ByteReadChannel) {
    if (input.readByte() != CR) throw IOException("Expected CR")
    if (input.readByte() != LF) throw IOException("Expected LF")
}

/** The trailer section: field lines up to an empty line (CRLF; a bare LF is accepted as for the header section, section 2.2). */
private suspend fun skipTrailerSection(input: ByteReadChannel) {
    var total = 0
    var lineLength = 0
    var afterCr = false
    while (true) {
        val b = input.readByte()
        if (++total > MAX_TRAILER_SECTION) throw IOException("Trailer section larger than $MAX_TRAILER_SECTION bytes")
        if (afterCr && b != LF) throw IOException("Bare CR in the trailer section")
        when (b) {
            LF -> {
                if (lineLength == 0) return
                lineLength = 0
            }

            CR -> {}

            else -> {
                lineLength++
            }
        }
        afterCr = b == CR
    }
}

private const val CR = '\r'.code.toByte()
private const val LF = '\n'.code.toByte()
private const val SEMICOLON = ';'.code.toByte()
private const val QUOTE = '"'.code.toByte()

/** Ktor 3.6.0's strict chunk-size line parser (KTOR-9263): hex digits, extensions skipped, CRLF only, 128 bytes at most. */
@OptIn(InternalAPI::class)
private suspend fun parseChunkSize(input: ByteReadChannel): Long {
    val buffer = input.readBuffer
    var result = 0L
    var inExtension = false
    var inQuotes = false
    var afterCr = false
    var i = 0
    while (i++ < MAX_CHUNK_SIZE_LENGTH) {
        if (buffer.exhausted() && !input.awaitContent()) throw EOFException("The chunked body ended before its last chunk")
        val byte = buffer.readByte()
        if (inQuotes && byte != QUOTE) continue
        try {
            when (byte) {
                CR -> {
                    continue
                }

                LF -> {
                    if (!afterCr) throw IOException("Illegal newline character in chunk size")
                    if (i < 3) throw IOException("Empty chunk size")
                    return result
                }

                QUOTE -> {
                    inQuotes = !inQuotes
                }

                SEMICOLON -> {
                    if (i == 1) throw IOException("Empty chunk size")
                    inExtension = true
                }

                else -> {
                    if (inExtension) continue
                    val digit = hexDigit(byte.toInt() and 0xff)
                    if (digit == -1L) throw IOException("Invalid chunk size character: 0x${(byte.toInt() and 0xff).toString(16)}")
                    if ((result and -0x1000000000000000L) != 0L) throw IOException("Chunk size overflow")
                    result = (result shl 4) or digit
                }
            }
        } finally {
            afterCr = byte == CR
        }
    }
    throw IOException("Chunk size limit exceeded")
}

private fun hexDigit(v: Int): Long =
    when (v) {
        in 0x30..0x39 -> v - 0x30L
        in 'a'.code..'f'.code -> v - 'a'.code + 10L
        in 'A'.code..'F'.code -> v - 'A'.code + 10L
        else -> -1L
    }
