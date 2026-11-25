// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3.runtime

import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.ByteWriteChannel
import io.ktor.utils.io.discard
import io.ktor.utils.io.readAvailable
import io.ktor.utils.io.writeFully
import io.kuicksilver.http3.Http3ErrorCode
import io.kuicksilver.http3.Http3Exception
import io.kuicksilver.http3.frame.FrameAction
import io.kuicksilver.http3.frame.FrameHeaders
import io.kuicksilver.http3.frame.FrameRules
import io.kuicksilver.http3.frame.FrameType
import io.kuicksilver.http3.frame.H3ProtocolError
import io.kuicksilver.http3.frame.VarInt
import io.kuicksilver.quic.Initiator
import io.kuicksilver.tls.completedWithin
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.job
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

/**
 * [readVarIntOrNull] with the number of bytes the integer took on the wire, which a non-minimal encoding makes larger
 * than its value needs (WebTransport counts a stream's body without its header, draft-ietf-webtrans-http3-17 section 5.4).
 */
internal suspend fun ByteReadChannel.readVarIntSizedOrNull(): Pair<Long, Int>? {
    val first = ByteArray(1)
    if (readAvailable(first, 0, 1) <= 0) {
        closedCause?.let { throw it }
        return null
    }
    val n = VarInt.encodedLength(first[0])
    if (n == 1) return VarInt.read(first, 0, 1) to 1
    val b = ByteArray(n)
    b[0] = first[0]
    readExactInto(b, 1, n - 1)
    return VarInt.read(b, 0, n) to n
}

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
 * (section 7.2.8). Frames that carry nothing a message needs cost a glitch token each through [onUseless] (section 10.5:
 * "Implementations SHOULD track the use of these features and set limits on their use"): every unknown type, and
 * reserved (GREASE) types and empty DATA frames beyond the first [FREE_USELESS_FRAMES] of the stream, which leaves a
 * peer the GREASE it is meant to send.
 */
internal class RequestFrames(
    val input: ByteReadChannel,
    private val isServerSide: Boolean,
    private val maxHeadersFrame: Long,
    private val onUseless: (what: String) -> Unit = {},
    private val onBuffered: (Long) -> Unit = {},
    /** The first frame type, when the caller already read it to tell a request from a WebTransport stream. */
    firstType: Long? = null,
    /** WebTransport is on: its `WT_STREAM` signal is a connection error here (see [FrameRules.checkRequest]). */
    private val webTransport: Boolean = false,
    /** That error's code, the one of the connection's WebTransport draft when the signal is met ([H3Session.wtMisplacedSignalCode]). */
    private val wtMisplacedCode: () -> Long = { Http3ErrorCode.FRAME_ERROR },
    /**
     * Runs with a HEADERS payload's encoded Required Insert Count (its QPACK prefix, RFC 9204 section 4.5.1) before the
     * rest of the payload is read: a section that waits for inserts waits there, its bytes left in the stream's window.
     */
    private val beforeFieldSection: (suspend (encodedRic: Long) -> Unit)? = null,
    /**
     * Sets how far the transport may read ahead of this reader (`QuicStream.readAhead`), for the whole stream: a frame
     * header is read with [FRAME_HEADER_AHEAD], a HEADERS payload (head or trailers) only once [budget] granted it (and with
     * [beforeFieldSection], its prefix byte by byte first), a DATA or skipped payload with the next frame header. So no more
     * than a frame header of a field section is ever taken from the stream's flow-control window before it may be held
     * (RFC 9114 section 10.5), nor before it may decode (RFC 9204 section 2.2.1).
     */
    private val limitReadAhead: ((Long) -> Unit)? = null,
    /** The connection's [HeaderBudget]: every HEADERS payload is reserved in it before any of it is read. */
    private val budget: HeaderBudget? = null,
    /**
     * How long a HEADERS frame may take from its frame header to its last byte (`Http3Settings.maxHeaderBlockTime`); null:
     * no deadline. Beyond it the stream fails with H3_REQUEST_CANCELLED ([StreamFailure]).
     */
    var sectionDeadline: kotlin.time.Duration? = null,
    /** The stream, for the deadline's error. */
    private val streamId: Long? = null,
    /** What a reader waiting for [budget] also wakes for: its stream's or its connection's end; made only when it waits. */
    private val budgetWatch: (() -> EndWatch)? = null,
    /** Test hook: runs once a HEADERS section under [sectionDeadline] was read whole, with the job of the deadline's scope. */
    private val afterSectionForTest: (suspend (kotlinx.coroutines.Job) -> Unit)? = null,
    /**
     * The connection's qlog events, null when it is not traced: DATA, skipped and refused frames are logged here as they
     * are parsed (with [streamId]); a HEADERS frame once its section was decoded (`decodeSection`), with its fields.
     */
    private val qlog: H3Qlog? = null,
) {
    // inline: an untraced connection allocates nothing here, not even the lambda
    private inline fun parsed(
        type: Long,
        length: Long?,
        frame: (H3Qlog) -> String,
    ) {
        val q = qlog ?: return
        val id = streamId ?: return
        if (q.enabled) q.frameParsed(id, type, length, frame(q))
    }

    private fun ahead(bytes: Long) {
        limitReadAhead?.invoke(bytes.coerceAtLeast(1))
    }

    /** A payload of [len] bytes and the next frame header, read in one pull (saturating: a 2^62 payload needs no more). */
    private fun aheadPayload(len: Long) = ahead(if (len > Long.MAX_VALUE - FRAME_HEADER_AHEAD) len else len + FRAME_HEADER_AHEAD)

    private var pendingType = firstType

    /** GREASE and empty DATA frames this stream may still send for free. */
    private var freeUseless = FREE_USELESS_FRAMES

    private fun useless(what: String) {
        if (freeUseless > 0) freeUseless-- else onUseless(what)
    }

    /**
     * [maxHeadersFrame], at most Int.MAX_VALUE: the payload is read into one array. At the largest `maxFieldSectionSize`
     * (2^30) the bound is 2^31, and a length of 2^31 compared as a Long but read as an Int was negative.
     */
    private val headersLimit = minOf(maxHeadersFrame, Int.MAX_VALUE.toLong())

    suspend fun next(): RequestFrame {
        while (true) {
            ahead(FRAME_HEADER_AHEAD)
            val type = pendingType?.also { pendingType = null } ?: input.readVarIntOrNull() ?: return RequestFrame.End
            // checked before the length is read: after the WT_STREAM signal comes a Session ID, not a length
            val action =
                try {
                    FrameRules.checkRequest(
                        type,
                        isServerSide,
                        webTransport,
                        if (webTransport) wtMisplacedCode() else Http3ErrorCode.FRAME_ERROR,
                    )
                } catch (e: H3ProtocolError) {
                    // a frame a request stream must not carry; its length is not read (WT_STREAM has none)
                    parsed(type, null) { it.controlFrame(type, null) }
                    throw e
                }
            val len = input.readVarInt()
            when (action) {
                FrameAction.Skip -> {
                    parsed(type, len) { it.other(type, len) }
                    if (FrameType.isGrease(
                            type,
                        )
                    ) {
                        useless("reserved frames on a request stream")
                    } else {
                        onUseless("unknown frame on a request stream")
                    }
                    aheadPayload(len)
                    input.skipExact(len)
                }

                FrameAction.Process -> {
                    if (type != FrameType.HEADERS) aheadPayload(len) // DATA: its payload, which the caller reads next
                    if (type == FrameType.DATA && len == 0L) useless("empty DATA frames")
                    if (type == FrameType.DATA) parsed(type, len) { H3Qlog.DATA }
                    // too large to read: logged without its fields, as quic-go logs a HEADERS frame it cannot decode
                    if (type == FrameType.HEADERS && len > headersLimit) parsed(type, len) { it.headers(emptyList()) }
                    return when {
                        type == FrameType.HEADERS && len > headersLimit -> RequestFrame.HeadersTooLarge(len)
                        type == FrameType.HEADERS -> RequestFrame.Headers(readSectionInTime(len.toInt()))
                        else -> RequestFrame.Data(len)
                    }
                }
            }
        }
    }

    @OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)
    private suspend fun readSectionInTime(len: Int): ByteArray {
        val deadline = sectionDeadline ?: return readSection(len)
        // a section read whole as the deadline fires is the section: withTimeoutOrNull drops a result when its timeout
        // (another thread) lands after the block returned, and the stream failed for a frame that had arrived
        return completedWithin(deadline) {
            readSection(len).also { afterSectionForTest?.invoke(currentCoroutineContext().job) }
        }
            ?: throw StreamFailure(
                Http3ErrorCode.REQUEST_CANCELLED,
                Http3Exception.Protocol(
                    Http3ErrorCode.REQUEST_CANCELLED,
                    Initiator.Local,
                    streamId,
                    "a HEADERS frame on stream $streamId did not arrive within $deadline",
                ),
                byPeer = false, // our deadline, no fault the peer's frames show
            )
    }

    /** Runs [block] with [bytes] reserved in [budget], waiting for them first. */
    private suspend inline fun <T> reserved(
        bytes: Long,
        block: () -> T,
    ): T {
        val b = budget ?: return block()
        b.reserve(bytes, budgetWatch)
        try {
            return block()
        } finally {
            b.release(bytes)
        }
    }

    /**
     * A HEADERS payload: its Required Insert Count prefix (an 8-bit prefixed integer, RFC 9204 section 4.1.1) first, then
     * [beforeFieldSection], then the rest, once [budget] granted it. A prefix longer than any valid one is left to the
     * decoder to refuse.
     */
    private suspend fun readSection(len: Int): ByteArray {
        val hook =
            beforeFieldSection ?: return reserved(len.toLong()) {
                ahead(len.toLong())
                readGrowing(len)
            }
        ahead(1) // the prefix byte by byte: nothing of the section after it leaves the window before the hook decided
        val prefix = ByteArray(minOf(len, MAX_RIC_PREFIX))
        var n = 0
        var value = 0L
        var shift = 0
        val one = ByteArray(1)
        while (n < prefix.size) {
            if (input.readAvailable(one, 0, 1) < 0) input.eof()
            val b = one[0].toInt() and 0xff
            prefix[n++] = one[0]
            if (n == 1) {
                value = b.toLong()
                if (b < 0xff) break
            } else {
                value += (b and 0x7f).toLong() shl shift
                shift += 7
                if (b and 0x80 == 0) break
            }
        }
        val complete = (n == 1 && value < 0xff) || (n > 1 && prefix[n - 1].toInt() and 0x80 == 0)
        if (complete && value >= 0) hook(value)
        return reserved((len - n).toLong()) {
            ahead((len - n).toLong())
            prefix.copyOf(n) + readGrowing(len - n)
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

    internal companion object {
        const val CHUNK = 4096

        /**
         * Reserved (GREASE) and empty DATA frames a request stream carries for free (RFC 9114 section 10.5: legitimate
         * uses, such as GREASE, stay free, a flood spends glitch tokens).
         */
        const val FREE_USELESS_FRAMES = 8

        /** The longest Required Insert Count prefix read ahead: 1 byte and 9 continuation bytes hold any 62-bit value. */
        const val MAX_RIC_PREFIX = 10

        /**
         * How far a frame header is read ahead: a type and a length of up to 16383 in one pull. What it may take beyond a
         * HEADERS frame's header is the start of its Required Insert Count prefix, which is read before anything else of
         * the section anyway.
         */
        const val FRAME_HEADER_AHEAD = 3L
    }
}
