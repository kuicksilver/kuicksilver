// Copyright 2014-2026 JetBrains s.r.o and contributors. Use of this source code is governed by the Apache 2.0 license.
// Modifications Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
// Vendored from Ktor 3.6.0 ktor-http-cio ChunkedTransferEncoding.kt (decodeChunked, parseChunkSize), adapted: the trailer
// section is read and discarded instead of failing with "Expected CR", a body that ends before its last chunk fails, and
// the chunk-size line is parsed by the grammar of RFC 9112 section 7.1 (Ktor skipped a bare CR anywhere in it).
// Kept identical with kuicksilver-ktor-server's h1/ChunkedBody.kt (the two engines share no module above ktor-network).
package io.kuicksilver.ktor.client.h1

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

/** A chunked body that breaks the grammar of RFC 9112 section 7.1: a peer error, unlike an [EOFException] (a lost connection). */
internal class MalformedChunkedBodyException(
    message: String,
) : IOException(message)

/**
 * Decodes the chunked transfer coding (RFC 9112 section 7.1) from [input] into [out], which is closed at the end. The
 * trailer section after the last chunk is read up to its empty line and discarded (section 7.1.2: a recipient MAY
 * discard the trailer fields); it is limited to [MAX_TRAILER_SECTION] bytes. A message that ends before its last chunk
 * is incomplete (section 8) and fails with [EOFException]; a body that breaks the grammar fails with
 * [MalformedChunkedBodyException]. [out] is closed with [readerFailure] of the failure, which its reader sees.
 */
internal suspend fun decodeChunkedBody(
    input: ByteReadChannel,
    out: ByteWriteChannel,
    readerFailure: (Throwable) -> Throwable = { it },
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
        out.close(readerFailure(t))
        throw t
    } finally {
        out.flushAndClose()
    }
}

private suspend fun skipCrLf(input: ByteReadChannel) {
    if (input.readByte() != CR) throw MalformedChunkedBodyException("Expected CR")
    if (input.readByte() != LF) throw MalformedChunkedBodyException("Expected LF")
}

/** The trailer section: field lines up to an empty line (CRLF; a bare LF is accepted as for the header section, section 2.2). */
private suspend fun skipTrailerSection(input: ByteReadChannel) {
    var total = 0
    var lineLength = 0
    var afterCr = false
    while (true) {
        val b = input.readByte()
        if (++total > MAX_TRAILER_SECTION) throw MalformedChunkedBodyException("Trailer section larger than $MAX_TRAILER_SECTION bytes")
        if (afterCr && b != LF) throw MalformedChunkedBodyException("Bare CR in the trailer section")
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

/** Where [parseChunkSize] is in `chunk-size [ chunk-ext ] CRLF` (RFC 9112 section 7.1.1). */
private enum class LineState {
    /** In `1*HEXDIG`. */
    SIZE,

    /** In BWS after the size or an extension value: only a `;` may follow. */
    BEFORE_SEMICOLON,

    /** In BWS after a `;`, before `chunk-ext-name`. */
    BEFORE_NAME,

    /** In `chunk-ext-name` (a token). */
    NAME,

    /** In BWS after `chunk-ext-name`: only `=` or the next `;` may follow. */
    AFTER_NAME,

    /** In BWS after `=`, before `chunk-ext-val`. */
    BEFORE_VALUE,

    /** In a token `chunk-ext-val`. */
    TOKEN_VALUE,

    /** In a quoted-string `chunk-ext-val`. */
    QUOTED_VALUE,

    /** After a backslash in a quoted-string (quoted-pair). */
    QUOTED_PAIR,

    /** After the closing quote of a quoted-string. */
    AFTER_QUOTED,

    /** After CR: only LF may follow (section 2.2: a bare CR is invalid). */
    CR_SEEN,
}

/**
 * Reads one chunk-size line strictly by the grammar of RFC 9112 section 7.1:
 * `chunk-size [ chunk-ext ] CRLF`, `chunk-size = 1*HEXDIG`,
 * `chunk-ext = *( BWS ";" BWS chunk-ext-name [ BWS "=" BWS chunk-ext-val ] )`, `chunk-ext-val = token / quoted-string`;
 * extensions are skipped. Whitespace (BWS) is taken only where the grammar has it, before a `;` and around the `=` of an
 * extension, so none right before the CRLF. The line ends at CRLF only: a bare CR is invalid (section 2.2), and a bare LF, which section
 * 2.2 lets a recipient accept in the start line and field lines only, is invalid too, as in Ktor 3.6.0 (KTOR-9263).
 * Any other byte, a size that does not fit a signed 64-bit length, or a line longer than 128 bytes fails with
 * [MalformedChunkedBodyException]: a recipient that tolerates what a front proxy reads differently (a CR skipped inside the size, a quote
 * outside an extension) frames the body differently, the chunk-line request smuggling class.
 */
@OptIn(InternalAPI::class)
private suspend fun parseChunkSize(input: ByteReadChannel): Long {
    val buffer = input.readBuffer
    var result = 0L
    var digits = 0
    var state = LineState.SIZE
    var i = 0
    while (i++ < MAX_CHUNK_SIZE_LENGTH) {
        if (buffer.exhausted() && !input.awaitContent()) throw EOFException("The chunked body ended before its last chunk")
        val b = buffer.readByte().toInt() and 0xff
        state =
            when (state) {
                LineState.SIZE -> {
                    val digit = hexDigit(b)
                    if (digit >= 0) {
                        if (result > Long.MAX_VALUE shr 4) throw MalformedChunkedBodyException("Chunk size overflow")
                        result = (result shl 4) or digit
                        digits++
                        LineState.SIZE
                    } else {
                        if (digits == 0) throw MalformedChunkedBodyException("Empty chunk size")
                        when {
                            b == CR_INT -> LineState.CR_SEEN
                            b == SEMICOLON -> LineState.BEFORE_NAME
                            isWhitespace(b) -> LineState.BEFORE_SEMICOLON
                            else -> invalid(b)
                        }
                    }
                }

                // BWS is followed by the ";" of the next extension, never by the line end
                LineState.BEFORE_SEMICOLON -> {
                    when {
                        b == SEMICOLON -> LineState.BEFORE_NAME
                        isWhitespace(b) -> state
                        b == CR_INT -> whitespaceBeforeLineEnd()
                        else -> invalid(b)
                    }
                }

                LineState.BEFORE_NAME -> {
                    when {
                        isTchar(b) -> LineState.NAME
                        isWhitespace(b) -> state
                        else -> invalid(b)
                    }
                }

                LineState.NAME -> {
                    when {
                        isTchar(b) -> state
                        b == CR_INT -> LineState.CR_SEEN
                        b == SEMICOLON -> LineState.BEFORE_NAME
                        b == EQUALS -> LineState.BEFORE_VALUE
                        isWhitespace(b) -> LineState.AFTER_NAME
                        else -> invalid(b)
                    }
                }

                // BWS after a name is followed by its "=" or the ";" of the next extension
                LineState.AFTER_NAME -> {
                    when {
                        b == SEMICOLON -> LineState.BEFORE_NAME
                        b == EQUALS -> LineState.BEFORE_VALUE
                        isWhitespace(b) -> state
                        b == CR_INT -> whitespaceBeforeLineEnd()
                        else -> invalid(b)
                    }
                }

                LineState.BEFORE_VALUE -> {
                    when {
                        isTchar(b) -> LineState.TOKEN_VALUE
                        b == QUOTE -> LineState.QUOTED_VALUE
                        isWhitespace(b) -> state
                        else -> invalid(b)
                    }
                }

                LineState.TOKEN_VALUE -> {
                    when {
                        isTchar(b) -> state
                        b == CR_INT -> LineState.CR_SEEN
                        b == SEMICOLON -> LineState.BEFORE_NAME
                        isWhitespace(b) -> LineState.BEFORE_SEMICOLON
                        else -> invalid(b)
                    }
                }

                // qdtext = HTAB / SP / %x21 / %x23-5B / %x5D-7E / obs-text (RFC 9110 section 5.6.4)
                LineState.QUOTED_VALUE -> {
                    when {
                        b == QUOTE -> LineState.AFTER_QUOTED
                        b == BACKSLASH -> LineState.QUOTED_PAIR
                        isWhitespace(b) || b in 0x21..0x7e || b >= 0x80 -> state
                        else -> invalid(b)
                    }
                }

                // quoted-pair = "\" ( HTAB / SP / VCHAR / obs-text )
                LineState.QUOTED_PAIR -> {
                    if (isWhitespace(b) || b in 0x21..0x7e || b >= 0x80) LineState.QUOTED_VALUE else invalid(b)
                }

                LineState.AFTER_QUOTED -> {
                    when {
                        b == CR_INT -> LineState.CR_SEEN
                        b == SEMICOLON -> LineState.BEFORE_NAME
                        isWhitespace(b) -> LineState.BEFORE_SEMICOLON
                        else -> invalid(b)
                    }
                }

                LineState.CR_SEEN -> {
                    if (b == LF_INT) return result
                    throw MalformedChunkedBodyException("Bare CR in a chunk size line")
                }
            }
    }
    throw MalformedChunkedBodyException("Chunk size line longer than $MAX_CHUNK_SIZE_LENGTH bytes")
}

private const val CR_INT = '\r'.code
private const val LF_INT = '\n'.code
private const val SEMICOLON = ';'.code
private const val EQUALS = '='.code
private const val QUOTE = '"'.code
private const val BACKSLASH = '\\'.code

/**
 * SP or HTAB right before the line end (`5 \r\n`): outside the grammar, which has BWS only before a `;` and around the
 * `=` of an extension (RFC 9112 section 7.1), so the line is refused as any other invalid one; the message says why, as
 * the peer that writes such lines is otherwise hard to tell from a broken body.
 */
private fun whitespaceBeforeLineEnd(): Nothing =
    throw MalformedChunkedBodyException(
        "Whitespace before the end of a chunk size line (RFC 9112 section 7.1 allows it only before the \";\" and around " +
            "the \"=\" of a chunk extension)",
    )

private fun invalid(b: Int): Nothing =
    throw MalformedChunkedBodyException(
        if (b == LF_INT) "Bare LF in a chunk size line" else "Invalid character in a chunk size line: 0x${b.toString(16)}",
    )

private fun isWhitespace(b: Int): Boolean = b == ' '.code || b == '\t'.code

/** tchar (RFC 9110 section 5.6.2). */
private fun isTchar(b: Int): Boolean =
    b in 'a'.code..'z'.code || b in 'A'.code..'Z'.code || b in '0'.code..'9'.code || b.toChar() in "!#$%&'*+-.^_`|~"

private fun hexDigit(v: Int): Long =
    when (v) {
        in 0x30..0x39 -> v - 0x30L
        in 'a'.code..'f'.code -> v - 'a'.code + 10L
        in 'A'.code..'F'.code -> v - 'A'.code + 10L
        else -> -1L
    }
