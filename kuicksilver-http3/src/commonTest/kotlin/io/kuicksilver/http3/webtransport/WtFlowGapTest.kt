// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3.webtransport

import io.kuicksilver.http3.Capsule
import kotlin.test.Test
import kotlin.test.assertEquals

/** When WT_MAX_DATA goes out (draft-ietf-webtrans-http3-16 section 5.6). */
class WtFlowGapTest {
    /**
     * Section 5.6: "Endpoints SHOULD send WT_MAX_DATA and WT_MAX_STREAMS capsules as they consume data"; the session gives
     * the credit back once half of its window is consumed, as one capsule, not one per read: below half nothing goes out.
     */
    @Test fun negative_maxDataGoesOutAtHalfTheWindow() {
        val sent = ArrayList<Capsule>()
        val f = WtSessionFlow(0, 0, 100, 0, 0, 0, sendCapsule = { sent += it })
        f.onReceived(100)
        f.onConsumed(10)
        f.onConsumed(39) // 49 consumed: the limit is still 51 bytes ahead
        assertEquals(0, sent.size, "no WT_MAX_DATA before half the window is consumed")
        f.onConsumed(2) // 51 consumed
        assertEquals(listOf(WtFlow.MAX_DATA to 151L), sent.map { it.type to WtFlow.valueOf(it) })
        assertEquals(151L to 100L, f.receiveDataForTest)
    }
}
