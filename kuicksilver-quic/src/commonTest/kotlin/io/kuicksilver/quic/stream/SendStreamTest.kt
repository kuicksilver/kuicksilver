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
}
