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
}
