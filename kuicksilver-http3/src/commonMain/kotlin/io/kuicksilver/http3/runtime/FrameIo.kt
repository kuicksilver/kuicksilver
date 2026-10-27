// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3.runtime

import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.ByteWriteChannel
import io.ktor.utils.io.discard
import io.ktor.utils.io.readAvailable
import io.ktor.utils.io.writeFully
import io.kuicksilver.http3.frame.FrameAction
import io.kuicksilver.http3.frame.FrameHeaders
import io.kuicksilver.http3.frame.FrameRules
import io.kuicksilver.http3.frame.FrameType
import io.kuicksilver.http3.frame.VarInt
import kotlinx.io.Buffer
import kotlinx.io.readByteArray

/**
 * The stream ended cleanly (FIN) in the middle of a frame or varint: a connection error H3_FRAME_ERROR on every stream
 * type (RFC 9114 section 7.1). H3_REQUEST_INCOMPLETE is for a request stream that ends between frames without a
 * complete message (section 4.1); an abrupt end (reset) surfaces as its own cause instead.
 */
internal class IncompleteFrame : Exception("stream ended inside a frame")

/** EOF: the cause if the channel was closed with one (a reset, a lost connection), else [IncompleteFrame]. */
private fun ByteReadChannel.eof(): Nothing = throw closedCause ?: IncompleteFrame()

/** A varint, or null at a clean end of stream before its first byte. */
internal suspend fun ByteReadChannel.readVarIntOrNull(): Long? {
    val first = ByteArray(1)
    if (readAvailable(first, 0, 1) <= 0) {
        closedCause?.let { throw it }
        return null
    }
    val n = VarInt.encodedLength(first[0])
    if (n == 1) return VarInt.read(first, 0, 1)
    val b = ByteArray(n)
    b[0] = first[0]
    readExactInto(b, 1, n - 1)
    return VarInt.read(b, 0, n)
}

internal suspend fun ByteReadChannel.readVarInt(): Long = readVarIntOrNull() ?: eof()

private suspend fun ByteReadChannel.readExactInto(
    b: ByteArray,
    off: Int,
    len: Int,
) {
    var o = off
    val end = off + len
    while (o < end) {
        val r = readAvailable(b, o, end - o)
        if (r < 0) eof()
        o += r
    }
}

internal suspend fun ByteReadChannel.readExact(n: Int): ByteArray {
    val b = ByteArray(n)
    readExactInto(b, 0, n)
    return b
}

/** Drops [n] bytes as they arrive, never holding more than the channel's own buffer. */
internal suspend fun ByteReadChannel.skipExact(n: Long) {
    var left = n
    while (left >
        0
    ) {
        val d = discard(left)
        if (d == 0L) eof()
        left -= d
    }
}

/** Copies [n] payload bytes to [out] in chunks, each handed over by [handOver]. */
internal suspend fun ByteReadChannel.copyExact(
    n: Long,
    out: ByteWriteChannel,
    buf: ByteArray,
    handOver: suspend () -> Unit = { out.flush() },
) {
    var left = n
    while (left >
        0
    ) {
        val r = readAvailable(buf, 0, minOf(buf.size.toLong(), left).toInt())
        if (r <
            0
        ) {
            eof()
        }
        out.writeFully(buf, 0, r)
        handOver()
        left -= r
    }
}

internal suspend fun ByteWriteChannel.writeFrame(
    type: Long,
    payload: ByteArray,
    off: Int = 0,
    len: Int = payload.size - off,
) {
    val h = ByteArray(16)
    val n = FrameHeaders.write(type, len.toLong(), h, 0)
    writeFully(h, 0, n)
    writeFully(payload, off, off + len)
}

/** One frame of a request stream as the reader sees it. */
internal sealed interface RequestFrame {
    class Headers(
        val block: ByteArray,
    ) : RequestFrame

    /** A HEADERS frame longer than the reader buffers; its payload was not read. */
    class HeadersTooLarge(
        val length: Long,
    ) : RequestFrame

    /** DATA: the caller reads [length] payload bytes before the next frame. */
    class Data(
        val length: Long,
    ) : RequestFrame

    object End : RequestFrame
}

/**
 * Frame reader for a request stream (RFC 9114 section 4.1): reserved and unknown frames are skipped as they stream by
 * (section 7.2.8); [onSkipped] is called for each unknown one, so a flood of them can spend glitch tokens (section 8.1).
 * Reserved types (0x1f * N + 0x21) are GREASE a peer is meant to send and cost nothing.
 */
internal class RequestFrames(
    val input: ByteReadChannel,
    private val isServerSide: Boolean,
    private val maxHeadersFrame: Long,
    private val onSkipped: () -> Unit = {},
    private val onBuffered: (Long) -> Unit = {},
) {
    /**
     * [maxHeadersFrame], at most Int.MAX_VALUE: the payload is read into one array. At the largest `maxFieldSectionSize`
     * (2^30) the bound is 2^31, and a length of 2^31 compared as a Long but read as an Int was negative.
     */
    private val headersLimit = minOf(maxHeadersFrame, Int.MAX_VALUE.toLong())

    suspend fun next(): RequestFrame {
        while (true) {
            val type = input.readVarIntOrNull() ?: return RequestFrame.End
            val len = input.readVarInt()
            when (FrameRules.checkRequest(type, isServerSide)) {
                FrameAction.Skip -> {
                    if (!FrameType.isGrease(type)) onSkipped()
                    input.skipExact(len)
                }

                FrameAction.Process -> {
                    return when {
                        type == FrameType.HEADERS && len > headersLimit -> RequestFrame.HeadersTooLarge(len)
                        type == FrameType.HEADERS -> RequestFrame.Headers(readGrowing(len.toInt()))
                        else -> RequestFrame.Data(len)
                    }
                }
            }
        }
    }

    /** A HEADERS payload held only as far as it arrived, never allocated from the declared length. */
    private suspend fun readGrowing(len: Int): ByteArray {
        val acc = Buffer()
        val chunk = ByteArray(minOf(len, CHUNK))
        var got = 0
        try {
            while (got <
                len
            ) {
                val r = input.readAvailable(chunk, 0, minOf(chunk.size, len - got))
                if (r <
                    0
                ) {
                    input.eof()
                }
                acc.write(chunk, 0, r)
                got += r
                onBuffered(r.toLong())
            }
            return acc.readByteArray()
        } finally {
            onBuffered(-got.toLong())
        }
    }

    private companion object {
        const val CHUNK = 4096
    }
}
