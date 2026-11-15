// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.recovery

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class SentPacketsTest {
    /**
     * RFC 9000 section 21.6 (the peer controls what stays outstanding): appending packets costs amortized O(1) array work, so
     * 20 000 packets in flight never cost a pass over the window per packet sent.
     */
    @Test fun negative_appendingIsAmortizedConstantWork() {
        val s = SentPackets()
        val n = 20_000
        for (pn in 0 until n) s.add(SentPacket().also { it.pn = pn.toLong() })
        assertEquals(n, s.size)
        assertTrue(s.workForTest <= 4L * n, "array work ${s.workForTest} for $n appends")
        assertEquals((0L until n).toList(), s.map { it.pn })
    }
}
