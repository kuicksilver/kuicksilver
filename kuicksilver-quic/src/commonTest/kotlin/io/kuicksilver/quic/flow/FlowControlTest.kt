// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.flow

import io.kuicksilver.quic.TimeMark
import io.kuicksilver.quic.wire.QuicWireException
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds

class FlowControlTest {
    private val t0 = TimeMark(1_000_000_000L)
    private val srtt = 10.milliseconds

    private fun stream() = RecvFlowController(524_288, 6_291_456)

    @Test fun maxStreamDataAfterQuarterRead() {
        val f = stream()
        assertEquals(524_288L, f.limit)
        f.onData(200_000)
        assertEquals(-1L, f.onConsumed(131_071, t0, srtt))
        assertEquals(655_360L, f.onConsumed(1, t0, srtt))
        assertEquals(655_360L, f.limit)
    }

    // auto-tuning as quic-go (flow_controller_base.go maybeAdjustWindowSize): an epoch of more than half a window that was read
    // in less than 4 x fraction x sRTT (the whole window in under 4 RTT) doubles the window

    @Test fun windowDoublesWhenReadFasterThanAWindowPerFourRtt() {
        val f = stream()
        f.onData(400_000)
        assertEquals(655_360L, f.onConsumed(131_072, t0, srtt))
        assertEquals(786_432L, f.onConsumed(131_072, t0 + 5.milliseconds, srtt))
        // 3/4 of the window in 10 ms < 4 x 0.75 x 10 ms
        assertEquals(393_216L + 1_048_576L, f.onConsumed(131_072, t0 + 10.milliseconds, srtt))
        assertEquals(1_048_576L, f.window)
    }

    @Test fun windowDoesNotDoubleForAReaderJustBelowThatRate() {
        // a quarter every 1.6 RTT: 3/4 of the window in 32 ms >= 30 ms (the former rule, a quarter within 2 RTT, doubled here
        // and settled at 8-16 x the bandwidth-delay product)
        val f = stream()
        f.onData(400_000)
        f.onConsumed(131_072, t0, srtt)
        f.onConsumed(131_072, t0 + 16.milliseconds, srtt)
        f.onConsumed(131_072, t0 + 32.milliseconds, srtt)
        assertEquals(524_288L, f.window)
    }

    @Test fun windowDoesNotDoubleWhenUpdatesAreSlow() {
        val f = stream()
        f.onData(400_000)
        f.onConsumed(131_072, t0, srtt)
        f.onConsumed(131_072, t0 + 25.milliseconds, srtt)
        f.onConsumed(131_072, t0 + 50.milliseconds, srtt)
        assertEquals(524_288L, f.window)
    }

    @Test fun windowCappedAtSixMiB() {
        val f = stream()
        var consumed = 0L
        var t = t0
        repeat(20) {
            f.onData(f.limit)
            consumed += f.window / 4
            f.onConsumed(f.window / 4, t, srtt)
            t += 1.milliseconds
        }
        assertEquals(6_291_456L, f.window)
    }

    @Test fun connectionWindowFollowsStreamWindow() {
        val c = RecvFlowController(786_432, 15_728_640)
        c.ensureWindowAtLeast(1_572_864)
        assertTrue(c.window >= 1_572_864)
        c.ensureWindowAtLeast(100_000_000)
        assertEquals(15_728_640L, c.window)
    }

    @Test fun dataBeyondLimitIsFlowControlError() {
        val f = stream()
        f.onData(524_288)
        val e = assertFailsWith<QuicWireException> { f.onData(524_289) }
        assertEquals(0x03L, e.code)
    }

    @Test fun windowNeverShrinks() {
        val s = SendFlowController(1000)
        s.onMaxUpdate(500)
        assertEquals(1000L, s.available)
        s.onMaxUpdate(2000)
        assertEquals(2000L, s.available)
    }

    @Test fun dataBlockedOncePerLimit() {
        val s = SendFlowController(1000)
        s.consume(1000)
        assertEquals(0L, s.available)
        assertEquals(1000L, s.takeBlocked())
        assertEquals(-1L, s.takeBlocked())
        s.onMaxUpdate(1500)
        assertEquals(-1L, s.takeBlocked())
        s.consume(500)
        assertEquals(1500L, s.takeBlocked())
        assertEquals(-1L, s.takeBlocked())
    }

    @Test fun negative_connectionFlowControlSum() {
        val conn = RecvFlowController(786_432, 15_728_640)
        val streams = List(100) { stream() }
        var total = 0L
        val e =
            assertFailsWith<QuicWireException> {
                for (s in streams) {
                    s.onData(10_000)
                    total += 10_000
                    conn.onData(total)
                }
            }
        assertEquals(0x03L, e.code)
        assertTrue(total <= 790_000, "the 79th stream crosses 786 432 although every stream is within 524 288")
    }
}
