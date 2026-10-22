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

    /** A RESET_STREAM or RESET_STREAM_AT was received: [resetCode] is the peer's and must not change. */
    private var resetSeen = false

    /**
     * draft-ietf-quic-reliable-stream-reset-11 section 5.2: a later reset with another application error code is an error,
     * once RESET_STREAM_AT is in play on the stream. RFC 9000 does not forbid a plain peer two RESET_STREAMs with different
     * codes, so those stay ignored.
     */
    private fun checkCode(
        code: Long,
        frameType: Long,
    ) {
        if (resetSeen && code != resetCode) {
            throw QuicWireException(TransportError.STREAM_STATE_ERROR, frameType, "stream $id: reset code changed from $resetCode to $code")
        }
    }

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

    /**
     * Takes a STREAM frame. Every check comes first: the final size, the stream window, then the connection window ([conn], of
     * which [connReceived] bytes were charged), then the reassembly buffer, which may refuse the frame with [ReassemblyFull].
     * Only then are [highest], the final size and the state committed: a refused frame leaves the stream as it was, so bytes
     * buffered later below its offset are still charged to the connection (RFC 9000 section 4.1; 0.2.1 review: a refused frame
     * used to raise [highest] uncharged, and a stream then held its whole window outside the connection limit). Returns how far
     * [highest] advanced, which the caller adds to its connection total.
     */
    fun onData(
        offset: Long,
        data: PacketBuffer,
        off: Int,
        len: Int,
        fin: Boolean,
        conn: RecvFlowController,
        connReceived: Long,
    ): Long {
        val end = offset + len
        if (finalSize >= 0 &&
            (end > finalSize || (fin && end != finalSize))
        ) {
            throw QuicWireException(TransportError.FINAL_SIZE_ERROR, 0x08, "stream $id: data beyond or final size changed")
        }
        if (fin &&
            end < highest
        ) {
            throw QuicWireException(TransportError.FINAL_SIZE_ERROR, 0x08, "stream $id: final size below received data")
        }
        if (state == RecvState.ResetRecvd || state == RecvState.ResetRead) return 0
        flow.onData(end)
        val advanced = if (end > highest) end - highest else 0L
        if (advanced > 0) conn.onData(connReceived + advanced) // a FLOW_CONTROL_ERROR leaves the total within the limit
        if (!stopped) reassembler.insert(offset, data, off, len)
        if (advanced > 0) highest = end
        if (fin) {
            finalSize = end
            if (state == RecvState.Recv) state = RecvState.SizeKnown
        }
        if (finalSize >= 0 && reassembler.readOffset + reassembler.readable == finalSize &&
            state == RecvState.SizeKnown
        ) {
            state = RecvState.DataRecvd
        }
        return advanced
    }

    /** RESET_STREAM: checked against the final size and both windows ([conn], [connReceived] as in [onData]) before it is applied. */
    fun onReset(
        code: Long,
        size: Long,
        conn: RecvFlowController,
        connReceived: Long,
    ): Long {
        if (size < highest ||
            (finalSize >= 0 && size != finalSize)
        ) {
            throw QuicWireException(TransportError.FINAL_SIZE_ERROR, 0x04, "stream $id: reset final size conflicts with received data")
        }
        if (reliableSize >= 0) checkCode(code, 0x04)
        if (state == RecvState.ResetRecvd || state == RecvState.ResetRead || state == RecvState.DataRead) return 0
        flow.onData(size) // a final size beyond the stream window is FLOW_CONTROL_ERROR (RFC 9000 sections 4.1, 4.5, 19.10)
        val advanced = size - highest
        if (advanced > 0) conn.onData(connReceived + advanced)
        finalSize = size
        highest = size
        resetCode = code
        resetSeen = true
        state = RecvState.ResetRecvd
        reassembler.clear()
        return advanced
    }

    /** RESET_STREAM_AT: the bytes below this are delivered before the reset; -1 without one. */
    var reliableSize: Long = -1
        private set

    /** Set when reading reached the reliable size and the stream turned [RecvState.ResetRecvd]; taken by [takeResetAtReached]. */
    private var resetAtReached = false

    /**
     * RESET_STREAM_AT (draft-ietf-quic-reliable-stream-reset section 3): checked like RESET_STREAM, then the stream keeps
     * delivering the bytes below [reliable] (the smallest reliable size received counts, section 3) and turns
     * [RecvState.ResetRecvd] once they were read; when they already were, at once ([takeResetAtReached] tells).
     */
    fun onResetAt(
        code: Long,
        size: Long,
        reliable: Long,
        conn: RecvFlowController,
        connReceived: Long,
    ): Long {
        if (size < highest ||
            (finalSize >= 0 && size != finalSize)
        ) {
            throw QuicWireException(TransportError.FINAL_SIZE_ERROR, 0x24, "stream $id: reset final size conflicts with received data")
        }
        checkCode(code, 0x24)
        if (state == RecvState.ResetRecvd || state == RecvState.ResetRead || state == RecvState.DataRead) return 0
        flow.onData(size)
        val advanced = size - highest
        if (advanced > 0) conn.onData(connReceived + advanced)
        finalSize = size
        highest = size
        resetCode = code
        resetSeen = true
        if (reliableSize < 0 || reliable < reliableSize) reliableSize = reliable
        if (state == RecvState.Recv) state = RecvState.SizeKnown
        if (stopped || reassembler.readOffset >= reliableSize) reachResetAt()
        return advanced
    }

    private fun reachResetAt() {
        state = RecvState.ResetRecvd
        reassembler.clear()
        resetAtReached = true
    }

    /** True once after the reliable bytes of a RESET_STREAM_AT were all read (or none were left to read). */
    fun takeResetAtReached(): Boolean = resetAtReached.also { resetAtReached = false }

    val readable: Int get() =
        if (reliableSize <
            0
        ) {
            reassembler.readable
        } else {
            maxOf(0L, minOf(reassembler.readable.toLong(), reliableSize - reassembler.readOffset)).toInt()
        }

    /**
     * STOP_SENDING still has a purpose: no RESET_STREAM arrived ("any state where it has not received a RESET_STREAM frame",
     * RFC 9000 section 3.2) and the data is not all here (section 3.2: "little value ... in the Data Recvd state").
     */
    val wantsStopSending: Boolean get() = state == RecvState.Recv || state == RecvState.SizeKnown

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
        var max = len
        if (reliableSize >= 0) {
            val left = reliableSize - reassembler.readOffset
            if (left <= 0) {
                reachResetAt()
                return 0
            }
            max = minOf(len.toLong(), left).toInt()
        }
        val n = reassembler.read(into, off, max)
        if (reliableSize >= 0 && reassembler.readOffset >= reliableSize) {
            reachResetAt()
            return n
        }
        if (n == 0 && finalSize >= 0 && reassembler.readOffset == finalSize) {
            state = RecvState.DataRead
            return -1
        }
        return n
    }

    /** Read to the end, reset and surfaced, or stopped by us with its final size known: nothing will ever be read from a stopped half, so it is done as soon as the peer has nothing more to send (review: stopped halves were never retired). */
    val finished: Boolean get() = state == RecvState.DataRead || state == RecvState.ResetRead || (stopped && finalSize >= 0)
}
