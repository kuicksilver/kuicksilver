// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.stream

import io.kuicksilver.native.PacketBuffer
import io.kuicksilver.native.of
import io.kuicksilver.quic.TransportError
import io.kuicksilver.quic.flow.RecvFlowController
import io.kuicksilver.quic.wire.QuicWireException
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * The receiving half of a stream (RFC 9000 sections 3.2, 4.5; draft-ietf-quic-reliable-stream-reset-11) where the mutation run
 * found no test.
 */
class RecvStreamGapsTest {
    private val budget = RangeBudget(1000)

    private fun stream(window: Long = 1L shl 30): RecvStream = RecvStream(0, Reassembler(64, budget), RecvFlowController(window, window))

    private fun conn(limit: Long = 1L shl 40) = RecvFlowController(limit, limit)

    private fun RecvStream.data(
        offset: Long,
        len: Int,
        fin: Boolean = false,
        c: RecvFlowController = conn(),
    ): Long {
        val b = PacketBuffer.of(ByteArray(len + 1) { (offset + it).toByte() })
        try {
            return onData(offset, b, 0, len, fin, c, 0)
        } finally {
            b.close()
        }
    }

    private fun code(block: () -> Unit): Long = assertFailsWith<QuicWireException>(block = block).code

    /**
     * RFC 9000 section 4.5: "Once a final size for a stream is known, it cannot change. If a RESET_STREAM or STREAM frame is received
     * indicating a change in the final size for the stream, an endpoint SHOULD respond with an error of type FINAL_SIZE_ERROR", also
     * when the known final size is 0; and "a RESET_STREAM_AT frame with a final size below the data received" likewise.
     */
    @Test fun negative_finalSizeZeroCannotChange() {
        val err = TransportError.FINAL_SIZE_ERROR
        assertEquals(err, code { stream().also { it.data(0, 0, fin = true) }.data(0, 5) }, "data beyond final size 0")
        assertEquals(err, code { stream().also { it.data(0, 0, fin = true) }.onReset(1, 5, conn(), 0) }, "RESET_STREAM changing it")
        assertEquals(err, code { stream().also { it.data(0, 0, fin = true) }.onResetAt(1, 5, 0, conn(), 0) }, "RESET_STREAM_AT changing it")
        assertEquals(err, code { stream().also { it.data(0, 10) }.onResetAt(1, 5, 0, conn(), 0) }, "RESET_STREAM_AT below the data")
    }

    /** RFC 9000 section 3.2: "Data Recvd" once every byte up to the final size arrived, also for a final size of 0; not with a gap. */
    @Test fun negative_dataRecvdExactlyWhenEveryByteArrived() {
        val empty = stream()
        empty.data(0, 0, fin = true)
        assertEquals(RecvState.DataRecvd, empty.state)
        val gap = stream()
        gap.data(5, 5, fin = true)
        assertEquals(RecvState.SizeKnown, gap.state, "bytes 0..5 are missing")
        val reset = stream()
        reset.data(0, 5)
        reset.onReset(1, 5, conn(), 5)
        reset.data(0, 5)
        assertEquals(RecvState.ResetRecvd, reset.state, "data after the reset changes nothing")
    }

    /** RFC 9000 section 3.2: in "Reset Recvd" received STREAM data is discarded (nothing to read, no reassembly range kept). */
    @Test fun negative_dataAfterResetIsDiscarded() {
        val r = stream()
        r.onReset(1, 100, conn(), 0)
        val before = budget.used
        r.data(50, 10)
        assertEquals(before, budget.used)
        assertEquals(0, r.readable)
        assertEquals(-1, r.read(ByteArray(10), 0, 10))
    }

    /** Abandoned bytes credit the connection once: what was received less what was already credited (RFC 9000 section 4.1). */
    @Test fun negative_abandonCreditsOnlyWhatWasNotCreditedYet() {
        val r = stream()
        r.data(0, 100)
        r.connCredited = 40
        assertEquals(60L, r.abandon())
        assertEquals(0L, r.abandon())
    }

    /** RFC 9000 section 4.5: a reset's final size counts against the connection limit (FLOW_CONTROL_ERROR beyond it). */
    @Test fun negative_resetFinalSizeBeyondTheConnectionLimitIsFlowControlError() {
        val err = TransportError.FLOW_CONTROL_ERROR
        assertEquals(err, code { stream().onReset(1, 2000, conn(1000), 0) })
        assertEquals(err, code { stream().onResetAt(1, 2000, 0, conn(1000), 0) })
        assertEquals(err, code { stream(window = 1000).onResetAt(1, 2000, 0, conn(), 0) }, "beyond the stream window")
    }

    /** A reset drops the buffered bytes: their reassembly ranges go back to the connection's budget. */
    @Test fun negative_resetReleasesBufferedRanges() {
        for (at in listOf(false, true)) {
            val r = stream()
            val before = budget.used
            r.data(10, 10)
            assertTrue(budget.used > before)
            if (at) r.onResetAt(1, 100, 0, conn(), 20) else r.onReset(1, 100, conn(), 20)
            assertEquals(before, budget.used, "resetAt=$at")
        }
    }

    /**
     * draft-ietf-quic-reliable-stream-reset-11 section 5.2: "the initiator MUST NOT change the Application Error Code in subsequent
     * RESET_STREAM_AT or RESET_STREAM frames" (STREAM_STATE_ERROR at the receiver), also after a Reliable Size of 0; the first
     * RESET_STREAM_AT of a stream may carry any code.
     */
    @Test fun negative_codeAfterResetStreamAtCannotChange() {
        val first = stream()
        first.onResetAt(9, 100, 0, conn(), 0)
        assertEquals(9L, first.resetCode)
        assertEquals(TransportError.STREAM_STATE_ERROR, code { first.onReset(6, 100, conn(), 100) })
    }

    /**
     * draft-ietf-quic-reliable-stream-reset-11 section 5.2: "The receiver MUST ignore the increase in Reliable Size and continue to use
     * the smallest Reliable Size received", also when that is 0.
     */
    @Test fun negative_reliableSizeNeverIncreases() {
        val r = stream()
        r.data(0, 100)
        r.onResetAt(1, 100, 30, conn(), 100)
        r.onResetAt(1, 100, 50, conn(), 100)
        assertEquals(30L, r.reliableSize)
        r.onResetAt(1, 100, 20, conn(), 100)
        assertEquals(20L, r.reliableSize)
    }

    /** After RESET_STREAM_AT the reader gets the reliable bytes and no more; reading the last of them surfaces the reset at once. */
    @Test fun negative_readStopsAtTheReliableSizeAndSurfacesTheReset() {
        val r = stream()
        r.data(0, 100)
        r.onResetAt(1, 100, 50, conn(), 100)
        assertEquals(RecvState.SizeKnown, r.state, "the reliable bytes are still to be read")
        assertFalse(r.takeResetAtReached())
        assertEquals(20, r.read(ByteArray(20), 0, 20))
        assertEquals(30, r.readable)
        assertEquals(30, r.read(ByteArray(100), 0, 100))
        assertTrue(r.takeResetAtReached(), "the last reliable byte was read")
        assertEquals(RecvState.ResetRecvd, r.state)
        assertEquals(-1, r.read(ByteArray(100), 0, 100))
    }

    /** A RESET_STREAM_AT repeated after the reset reached the reader, or after all data was read, changes nothing. */
    @Test fun negative_resetStreamAtAfterTheEndChangesNothing() {
        val r = stream()
        r.data(0, 10)
        r.onResetAt(1, 10, 10, conn(), 10)
        assertFalse(r.takeResetAtReached(), "10 bytes still to read")
        assertEquals(10, r.read(ByteArray(10), 0, 10))
        assertTrue(r.takeResetAtReached())
        assertEquals(0L, r.onResetAt(1, 10, 5, conn(), 10))
        assertFalse(r.takeResetAtReached(), "the repeat reaches nothing again")

        val plain = stream()
        plain.onReset(1, 10, conn(), 0)
        plain.onReset(2, 10, conn(), 10)
        assertEquals(1L, plain.resetCode, "a repeated RESET_STREAM is ignored (RFC 9000 permits no other code; the first stands)")

        val read = stream()
        read.data(0, 10, fin = true)
        assertEquals(10, read.read(ByteArray(10), 0, 10))
        assertEquals(-1, read.read(ByteArray(10), 0, 10))
        read.onResetAt(1, 10, 0, conn(), 10)
        assertEquals(RecvState.DataRead, read.state, "everything was read already")
        assertFalse(read.takeResetAtReached())
    }

    /** A new stream has seen no reset: nothing to surface, any first code accepted. */
    @Test fun negative_freshStreamHasNoReset() {
        val r = stream()
        assertFalse(r.takeResetAtReached())
        r.data(0, 10)
        assertEquals(10, r.read(ByteArray(10), 0, 10))
        assertFalse(r.takeResetAtReached())
        r.onResetAt(7, 10, 10, conn(), 10)
        assertEquals(7L, r.resetCode)
    }
}
