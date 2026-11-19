// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3.message

import io.kuicksilver.http3.Http3ErrorCode
import io.kuicksilver.http3.frame.H3ProtocolError
import io.kuicksilver.http3.frame.VarInt

/**
 * The Capsule Protocol of RFC 9297 section 3.2 over the data of a stream: type, length, value. Sans-IO: the caller feeds
 * the stream's bytes as they arrive and calls [endOfStream] at its FIN.
 *
 * - Types in [known] are delivered whole; one longer than [maxCapsuleLength] is a stream error H3_MESSAGE_ERROR.
 * - A DATAGRAM capsule (0x00) in [known] is bounded by [maxDatagramLength] alone: a longer one is skipped as its bytes
 *   arrive and counted in [skippedDatagrams] (section 3.5: an endpoint that cannot handle a datagram drops it).
 * - Other types are skipped as their bytes arrive, never buffered (section 3.2: unknown types are silently dropped).
 * - A stream that ends inside a capsule, value or header, is a malformed message (section 3.3): [endOfStream] throws.
 * - A delivered capsule of a type in [terminal] must be the stream's last: any byte after it, even of a capsule type
 *   that would be skipped, is a malformed message (WebTransport's WT_CLOSE_SESSION, draft-ietf-webtrans-http3 section 6).
 *
 * At most one capsule value is held at a time, so memory is bounded by `max(maxCapsuleLength, maxDatagramLength)`
 * whatever lengths the peer announces.
 */
internal class CapsuleParser(
    private val maxCapsuleLength: Long = 65_536,
    private val maxDatagramLength: Long = 65_536,
    private val known: Set<Long> = setOf(DATAGRAM),
    private val terminal: Set<Long> = emptySet(),
    /**
     * Judges each DATAGRAM capsule by the Context ID at the start of its value (RFC 9298 sections 4 and 5) once that
     * varint is in, before the rest is buffered: [DatagramVerdict.Skip] drops it as its bytes arrive,
     * [DatagramVerdict.Abort] is H3_DATAGRAM_ERROR. A value too short for a Context ID is dropped without a call. Null:
     * every DATAGRAM capsule up to [maxDatagramLength] is delivered.
     */
    private val filter: DatagramFilter? = null,
) {
    /** A capsule of a [terminal] type was delivered: nothing may follow it. */
    private var ended = false

    private val header = ByteArray(16)
    private var headerLen = 0
    private var type = -1L
    private var remaining = 0L
    private var skipping = false
    private var payload: ByteArray? = null
    private var filled = 0

    /** Reading the Context ID of a DATAGRAM capsule for [filter], into [peek]. */
    private var peeking = false
    private val peek = ByteArray(8)
    private var peekLen = 0

    /** Largest buffer held at once (tests check that unknown and oversized capsules are not buffered). */
    var maxBuffered: Int = 0
        private set

    /** DATAGRAM capsules longer than `maxDatagramLength`, dropped without buffering. */
    var skippedDatagrams: Long = 0
        private set

    /** Parses all of `bytes[off, off + len)`, calling [out] for each complete capsule of a known type. */
    fun feed(
        bytes: ByteArray,
        off: Int,
        len: Int,
        out: (type: Long, value: ByteArray) -> Unit,
    ) {
        parse(bytes, off, len, out, stopAfterOne = false)
    }

    /**
     * Like [feed], but stops right after the first capsule it delivers to [out]; returns the bytes consumed. A reader that
     * suspends to hand each capsule on holds at most one at a time this way, whatever number fit in its read buffer.
     */
    fun feedOne(
        bytes: ByteArray,
        off: Int,
        len: Int,
        out: (type: Long, value: ByteArray) -> Unit,
    ): Int = parse(bytes, off, len, out, stopAfterOne = true)

    private fun parse(
        bytes: ByteArray,
        off: Int,
        len: Int,
        out: (type: Long, value: ByteArray) -> Unit,
        stopAfterOne: Boolean,
    ): Int {
        var p = off
        val end = off + len
        while (p < end) {
            if (ended) throw H3ProtocolError(Http3ErrorCode.MESSAGE_ERROR, "data after a terminal capsule")
            if (type < 0) { // collect the two varints
                header[headerLen++] = bytes[p++]
                val t = VarInt.read(header, 0, headerLen)
                if (t < 0) continue
                val tn = VarInt.encodedLength(header[0])
                val l = VarInt.read(header, tn, headerLen)
                if (l < 0) continue
                headerLen = 0
                peekLen = 0
                type = t
                remaining = l
                peeking = t == DATAGRAM && filter != null && t in known
                skipping =
                    when {
                        t !in known -> {
                            true
                        }

                        peeking -> {
                            // nothing to read a Context ID from: a datagram that cannot be parsed is dropped
                            (l == 0L).also {
                                if (it) {
                                    peeking = false
                                    skippedDatagrams++
                                }
                            }
                        }

                        t == DATAGRAM -> {
                            (l > maxDatagramLength).also { if (it) skippedDatagrams++ }
                        }

                        l > maxCapsuleLength -> {
                            throw H3ProtocolError(Http3ErrorCode.MESSAGE_ERROR, "capsule of $l bytes above $maxCapsuleLength")
                        }

                        else -> {
                            false
                        }
                    }
                if (!skipping && !peeking) {
                    payload = ByteArray(l.toInt())
                    filled = 0
                    maxBuffered = maxOf(maxBuffered, l.toInt())
                }
                if (remaining == 0L && finish(out) && stopAfterOne) return p - off
                continue
            }
            if (peeking) {
                peek[peekLen++] = bytes[p++]
                remaining--
                val ctx = VarInt.read(peek, 0, peekLen)
                if (ctx >= 0) {
                    peeking = false
                    judge(ctx)
                } else if (remaining == 0L) {
                    peeking = false // the value ended inside its Context ID
                    skipping = true
                    skippedDatagrams++
                }
                if (remaining == 0L && finish(out) && stopAfterOne) return p - off
                continue
            }
            val n = minOf((end - p).toLong(), remaining).toInt()
            if (!skipping) {
                bytes.copyInto(payload!!, filled, p, p + n)
                filled += n
            }
            p += n
            remaining -= n
            if (remaining == 0L && finish(out) && stopAfterOne) return p - off
        }
        return p - off
    }

    /** [filter]'s verdict on the DATAGRAM capsule whose Context ID [ctx] was just read; [remaining] bytes of payload follow. */
    private fun judge(ctx: Long) {
        when (filter!!.verdict(ctx, remaining)) {
            DatagramVerdict.Deliver -> {
                val total = peekLen + remaining
                if (total > maxDatagramLength) {
                    skipping = true
                    skippedDatagrams++
                    return
                }
                payload = ByteArray(total.toInt()).also { peek.copyInto(it, 0, 0, peekLen) }
                filled = peekLen
                maxBuffered = maxOf(maxBuffered, total.toInt())
            }

            DatagramVerdict.Skip -> {
                skipping = true
            }

            DatagramVerdict.Abort -> {
                throw H3ProtocolError(Http3ErrorCode.DATAGRAM_ERROR, "HTTP datagram of context $ctx refused: $remaining bytes")
            }
        }
    }

    /** The stream's FIN: throws H3_MESSAGE_ERROR when it cut a capsule (RFC 9297 section 3.3); a boundary is a clean end. */
    fun endOfStream() {
        if (headerLen != 0 || type >= 0) throw H3ProtocolError(Http3ErrorCode.MESSAGE_ERROR, "truncated capsule")
    }

    /** Ends the current capsule; true when it was delivered to [out]. */
    private fun finish(out: (Long, ByteArray) -> Unit): Boolean {
        val t = type
        val b = payload
        type = -1
        payload = null
        if (skipping || b == null) return false
        if (t in terminal) ended = true
        out(t, b)
        return true
    }

    companion object {
        const val DATAGRAM: Long = 0x00
    }
}

/** What a DATAGRAM capsule's or an HTTP datagram's Context ID makes of it (RFC 9298 sections 4 and 5). */
internal enum class DatagramVerdict {
    /** Buffer and hand it on. */
    Deliver,

    /** Drop it, without buffering the rest of a capsule. */
    Skip,

    /** Abort the stream with H3_DATAGRAM_ERROR. */
    Abort,
}

/** Judges an HTTP datagram by its Context ID and the length of the payload after it. */
internal fun interface DatagramFilter {
    fun verdict(
        contextId: Long,
        payloadLength: Long,
    ): DatagramVerdict
}
