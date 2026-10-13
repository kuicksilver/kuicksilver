// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.stream

import io.kuicksilver.native.PacketBuffer
import io.kuicksilver.quic.TimeMark
import io.kuicksilver.quic.TransportError
import io.kuicksilver.quic.flow.RecvFlowController
import io.kuicksilver.quic.wire.QuicWireException

internal enum class RecvState { Recv, SizeKnown, DataRecvd, ResetRecvd, DataRead, ResetRead }

/** The receiving half of a stream (RFC 9000 section 3.2) with its reassembly buffer and flow control window. */
internal class RecvStream(
    val id: Long,
    private val reassembler: Reassembler,
    val flow: RecvFlowController,
) {
    var state: RecvState = RecvState.Recv
    var finalSize: Long = -1
        private set

    /** Highest offset received so far (exclusive). */
    var highest: Long = 0
        private set
    var resetCode: Long = 0
        private set
    var stopped: Boolean = false // we sent STOP_SENDING

    /** When the peer's last STREAM_DATA_BLOCKED for this stream arrived; one per RTT is answered (RFC 9000 section 4.1). */
    var blockedSeenAt: TimeMark = TimeMark.NEVER

    /** Bytes of this stream already credited back to the connection window (read by the application or abandoned). */
    var connCredited: Long = 0

    /** Credits everything received so far that the application will never read; returns the amount (RFC 9000 section 4.1: the receiver's limit follows consumption, abandoned bytes count as consumed). */
    fun abandon(): Long {
        val credit = highest - connCredited
        connCredited = highest
        return credit
    }

    /** Drops buffered data after STOP_SENDING: nothing will read it. */
    fun discardBuffered() {
        reassembler.clear()
    }

    /** Returns how far the highest received offset advanced (for the connection-level flow accounting). */
    fun onData(
        offset: Long,
        data: PacketBuffer,
        off: Int,
        len: Int,
        fin: Boolean,
    ): Long {
        val end = offset + len
        if (finalSize >= 0 &&
            (end > finalSize || (fin && end != finalSize))
        ) {
            throw QuicWireException(TransportError.FINAL_SIZE_ERROR, 0x08, "stream $id: data beyond or final size changed")
        }
        if (fin) {
            if (end <
                highest
            ) {
                throw QuicWireException(TransportError.FINAL_SIZE_ERROR, 0x08, "stream $id: final size below received data")
            }
            finalSize =
                end
            if (state == RecvState.Recv) state = RecvState.SizeKnown
        }
        if (state == RecvState.ResetRecvd || state == RecvState.ResetRead) return 0
        flow.onData(end)
        val advanced = if (end > highest) end - highest else 0L
        if (end > highest) highest = end
        if (!stopped) reassembler.insert(offset, data, off, len)
        if (finalSize >= 0 && reassembler.readOffset + reassembler.readable == finalSize &&
            state == RecvState.SizeKnown
        ) {
            state = RecvState.DataRecvd
        }
        return advanced
    }

    fun onReset(
        code: Long,
        size: Long,
    ): Long {
        if (size < highest ||
            (finalSize >= 0 && size != finalSize)
        ) {
            throw QuicWireException(TransportError.FINAL_SIZE_ERROR, 0x04, "stream $id: reset final size conflicts with received data")
        }
        if (state == RecvState.ResetRecvd || state == RecvState.ResetRead || state == RecvState.DataRead) return 0
        flow.onData(size) // a final size beyond the stream window is FLOW_CONTROL_ERROR (RFC 9000 sections 4.1, 4.5, 19.10)
        val advanced = size - highest
        finalSize = size
        highest = size
        resetCode = code
        state = RecvState.ResetRecvd
        reassembler.clear()
        return advanced
    }

    val readable: Int get() = reassembler.readable

    /** -1 at the end of the stream (all data read and FIN seen), 0 when nothing is available yet. */
    fun read(
        into: ByteArray,
        off: Int,
        len: Int,
    ): Int {
        if (state == RecvState.ResetRecvd) {
            state = RecvState.ResetRead
            return -1
        }
        if (state == RecvState.ResetRead) return -1
        val n = reassembler.read(into, off, len)
        if (n == 0 && finalSize >= 0 && reassembler.readOffset == finalSize) {
            state = RecvState.DataRead
            return -1
        }
        return n
    }

    /** Read to the end, reset and surfaced, or stopped by us with its final size known: nothing will ever be read from a stopped half, so it is done as soon as the peer has nothing more to send (review: stopped halves were never retired). */
    val finished: Boolean get() = state == RecvState.DataRead || state == RecvState.ResetRead || (stopped && finalSize >= 0)
}
