// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.core

import io.kuicksilver.native.PacketBuffer
import io.kuicksilver.quic.QuicLimits
import io.kuicksilver.quic.StreamPriority
import io.kuicksilver.quic.TransportError
import io.kuicksilver.quic.stream.RangeBudget
import io.kuicksilver.quic.stream.Reassembler
import io.kuicksilver.quic.stream.SendStream
import io.kuicksilver.quic.wire.QuicWireException

/**
 * CRYPTO data per encryption level (RFC 9000 section 7.5): a send queue with retransmission and an ordered receive
 * buffer capped at [outOfOrderCap] bytes per level and [postHandshakeCap] bytes in total after the handshake. The stream of
 * a level ends at [levelCap] bytes (Initial and Handshake: as ngtcp2's absolute CRYPTO offset limits) and is sealed once TLS
 * reads a higher level (RFC 9001 section 4.1.3).
 */
internal class CryptoStreams(
    private val outOfOrderCap: Int,
    private val postHandshakeCap: Int,
    private val levelCap: LongArray,
) {
    constructor(limits: QuicLimits) : this(
        limits.cryptoOutOfOrderPerLevel,
        limits.cryptoPostHandshake,
        longArrayOf(limits.cryptoInitialMax, 0, limits.cryptoHandshakeMax, Long.MAX_VALUE),
    )

    val send: Array<SendStream> = Array(4) { SendStream(it.toLong(), StreamPriority.Default) }
    private val budget = RangeBudget(Int.MAX_VALUE)
    private val recv = Array(4) { Reassembler(1024, budget) }
    private val received = LongArray(4)
    private val sealed = BooleanArray(4)
    private var postHandshakeBytes = 0L
    private val scratch = ByteArray(16384)

    /**
     * Buffers received CRYPTO bytes; refuses before copying when they would exceed the caps. At a sealed level, data within what
     * was already received is a retransmission and is dropped; data past it is a PROTOCOL_VIOLATION (RFC 9001 section 4.1.3:
     * otherwise a peer could keep feeding a level TLS never reads again).
     */
    fun onData(
        level: Int,
        offset: Long,
        data: PacketBuffer,
        off: Int,
        len: Int,
        handshakeDone: Boolean,
    ) {
        val end = offset + len
        if (sealed[level]) {
            if (end > received[level]) {
                throw QuicWireException(TransportError.PROTOCOL_VIOLATION, 0x06, "CRYPTO data past the end of a previous encryption level")
            }
            return
        }
        if (end > levelCap[level]) {
            throw QuicWireException(
                TransportError.CRYPTO_BUFFER_EXCEEDED,
                0x06,
                "CRYPTO data beyond ${levelCap[level]} bytes at level $level",
            )
        }
        val r = recv[level]
        if (end >
            r.readOffset + outOfOrderCap
        ) {
            throw QuicWireException(TransportError.CRYPTO_BUFFER_EXCEEDED, 0x06, "CRYPTO data beyond the $outOfOrderCap-byte buffer")
        }
        if (handshakeDone &&
            level == 3
        ) {
            postHandshakeBytes += len
            if (postHandshakeBytes >
                postHandshakeCap
            ) {
                throw QuicWireException(
                    TransportError.CRYPTO_BUFFER_EXCEEDED,
                    0x06,
                    "more than $postHandshakeCap bytes of post-handshake CRYPTO",
                )
            }
        }
        if (end > received[level]) received[level] = end
        r.insert(offset, data, off, len)
    }

    /**
     * Seals [level] once TLS reads a higher one (RFC 9001 section 4.1.3): data still waiting for a gap to fill is data TLS will
     * never consume, a PROTOCOL_VIOLATION.
     */
    fun seal(level: Int) {
        if (sealed[level]) return
        sealed[level] = true
        if (recv[level].bufferedBytes > 0) {
            throw QuicWireException(TransportError.PROTOCOL_VIOLATION, 0x06, "CRYPTO data left unconsumed at a previous encryption level")
        }
        recv[level].clear()
    }

    fun isSealed(level: Int): Boolean = sealed[level]

    /** Hands every contiguous byte of [level] to [sink]; returns true when something was delivered. */
    fun deliver(
        level: Int,
        sink: (ByteArray, Int) -> Unit,
    ): Boolean {
        var any = false
        while (true) {
            val n = recv[level].read(scratch, 0, scratch.size)
            if (n == 0) break
            sink(scratch, n)
            any = true
        }
        return any
    }

    fun discard(level: Int) {
        recv[level].clear()
    }

    /** CRYPTO bytes buffered out of order over all levels (admission's handshake-buffer accounting). */
    val bufferedBytes: Long get() {
        var n = 0L
        for (r in recv) n += r.bufferedBytes
        return n
    }
}
