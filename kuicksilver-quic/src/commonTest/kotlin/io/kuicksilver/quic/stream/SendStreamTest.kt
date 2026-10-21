// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.stream

import io.kuicksilver.quic.StreamPriority
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class SendStreamTest {
    private fun stream(bytes: Int): SendStream =
        SendStream(0, StreamPriority.Default).also { it.enqueue(ByteArray(bytes), 0, bytes, false) }

    private fun SendStream.take(max: Int): SendRange? {
        val r = SendRange()
        if (!nextRange(max, r)) return null
        markSent(r.offset, r.length, r.fin)
        return r
    }

    @Test fun lostRangeReportedTwiceIsRetransmittedOnce() {
        // the same CRYPTO/STREAM range sent in two packets (an original and a PTO probe) and both declared lost at once:
        // quiche fails the TLS handshake when a Finished arrives twice in one Handshake packet
        val s = stream(36)
        s.take(36)
        s.onLost(0, 36)
        s.onLost(0, 36)
        val r = s.take(100)!!
        assertEquals(0L to 36, r.offset to r.length)
        assertFalse(s.hasRetransmit, "the duplicate report must not queue the range a second time")
    }

    @Test fun overlappingLostRangesMerge() {
        val s = stream(60)
        s.take(60)
        s.onLost(0, 30)
        s.onLost(20, 40)
        s.onLost(10, 5)
        val r = s.take(100)!!
        assertEquals(0L to 60, r.offset to r.length)
        assertFalse(s.hasRetransmit)
    }

    @Test fun disjointLostRangesStaySeparateAndOrdered() {
        val s = stream(100)
        s.take(100)
        s.onLost(50, 10)
        s.onLost(0, 10)
        assertEquals(0L to 10, s.take(100)!!.let { it.offset to it.length })
        assertEquals(
            50L to 10,
            s.take(100)!!.let {
                it.offset to
                    it.length
            },
        )
        assertTrue(!s.hasRetransmit)
    }

    @Test fun retransmittedDataDoesNotCarryAFinThatIsStillInFlight() {
        // interop run 20261015-170940, kuicksilver->quiche:handshakeloss: the response went out as 1024 bytes and then an empty
        // FIN; a PTO probe resent the bytes as one frame with FIN while that empty FIN was still in flight. quiche's receiver had
        // read the 1024 bytes, took the final size from the duplicate frame, dropped the frame as a duplicate and never woke
        // the application for the FIN; the later empty FIN changed nothing, and the request timed out
        val s = stream(1024)
        assertFalse(s.take(2000)!!.fin)
        s.enqueue(ByteArray(0), 0, 0, true)
        val finOnly = s.take(2000)!!
        assertEquals(Triple(1024L, 0, true), Triple(finOnly.offset, finOnly.length, finOnly.fin))
        s.onLost(0, 1024)
        val again = s.take(2000)!!
        assertEquals(Triple(0L, 1024, false), Triple(again.offset, again.length, again.fin), "the FIN is in flight on its own")
        assertEquals(null, s.take(2000))
        s.onLost(1024, 0, fin = true)
        val fin = s.take(2000)!!
        assertEquals(Triple(1024L, 0, true), Triple(fin.offset, fin.length, fin.fin), "a lost FIN goes again in a frame of its own")
    }

    @Test fun lostDataAndLostFinGoAsDataThenAnEmptyFin() {
        val s = stream(100)
        s.enqueue(ByteArray(0), 0, 0, true)
        val first = s.take(2000)!!
        assertTrue(first.fin && first.length == 100, "first transmission: data and FIN in one frame")
        s.onLost(0, 100, fin = true)
        val data = s.take(2000)!!
        assertEquals(Triple(0L, 100, false), Triple(data.offset, data.length, data.fin))
        val fin = s.take(2000)!!
        assertEquals(Triple(100L, 0, true), Triple(fin.offset, fin.length, fin.fin))
    }

    @Test fun anAcknowledgementRemovesItsBytesFromTheLostQueue() {
        // a range declared lost (spuriously, or its first copy late) and then acknowledged is not sent again
        val s = stream(100)
        s.take(100)
        s.onLost(0, 100)
        s.onAcked(0, 40)
        s.onAcked(60, 10)
        val first = s.take(100)!!
        assertEquals(40L to 20, first.offset to first.length)
        val second = s.take(100)!!
        assertEquals(70L to 30, second.offset to second.length)
        assertFalse(s.hasPending, "nothing left: the acknowledged bytes are not queued for retransmission")
    }

    @Test fun aLossOfPartlyAcknowledgedBytesQueuesOnlyTheGaps() {
        val s = stream(100)
        s.take(100)
        s.onAcked(10, 20)
        s.onAcked(50, 10)
        s.onLost(0, 100)
        val got = generateSequence { s.take(100)?.let { it.offset to it.length } }.toList()
        assertEquals(listOf(0L to 10, 30L to 20, 60L to 40), got)
    }

    @Test fun lostRangesFullyAcknowledgedLeaveNothingPending() {
        val s = stream(30)
        s.take(30)
        s.onLost(0, 10)
        s.onLost(20, 10)
        assertTrue(s.hasPending)
        s.onAcked(0, 30)
        assertFalse(s.hasRetransmit)
        assertFalse(s.hasPending)
    }
}
