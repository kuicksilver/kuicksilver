// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.core

import io.kuicksilver.native.PacketBuffer
import io.kuicksilver.quic.StreamPriority
import io.kuicksilver.quic.TransportError
import io.kuicksilver.quic.stream.RangeBudget
import io.kuicksilver.quic.stream.Reassembler
import io.kuicksilver.quic.stream.SendStream
import io.kuicksilver.quic.wire.QuicWireException

/**
 * CRYPTO data per encryption level (RFC 9000 section 7.5): a send queue with retransmission and an ordered receive
 * buffer capped at [outOfOrderCap] bytes per level and [postHandshakeCap] bytes in total after the handshake.
 */
internal class CryptoStreams(
    private val outOfOrderCap: Int,
    private val postHandshakeCap: Int,
) {
    val send: Array<SendStream> = Array(4) { SendStream(it.toLong(), StreamPriority.Default) }
    private val budget = RangeBudget(Int.MAX_VALUE)
    private val recv = Array(4) { Reassembler(1024, budget) }
    private var postHandshakeBytes = 0L
    private val scratch = ByteArray(16384)

    /** Buffers received CRYPTO bytes; refuses before copying when they would exceed the caps. */
    fun onData(
        level: Int,
        offset: Long,
        data: PacketBuffer,
        off: Int,
        len: Int,
        handshakeDone: Boolean,
    ) {
        val r = recv[level]
        if (offset + len >
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
        r.insert(offset, data, off, len)
    }

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
