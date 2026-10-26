// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.recovery

import io.kuicksilver.native.PacketBuffer
import io.kuicksilver.quic.CollectingHandler
import io.kuicksilver.quic.TestFrame
import io.kuicksilver.quic.TimeMark
import io.kuicksilver.quic.wire.FrameDecoder
import io.kuicksilver.quic.wire.PacketType
import io.kuicksilver.quic.wire.WireReader
import io.kuicksilver.quic.wire.WireWriter
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

class AckTrackerTest {
    private val t0 = TimeMark(1_000_000_000L)

    private fun ackFrame(
        a: AckTracker,
        now: TimeMark,
        exponent: Int = 3,
    ): TestFrame.Ack {
        val b = PacketBuffer.allocate(512)
        try {
            val w = WireWriter(b, 0, b.capacity)
            a.writeAck(w, now, exponent)
            val h = CollectingHandler()
            FrameDecoder.decode(WireReader(b, 0, w.pos), PacketType.OneRtt, h)
            return h.frames.single() as TestFrame.Ack
        } finally {
            b.close()
        }
    }

    @Test fun ackAfterTwoAckElicitingPackets() {
        val a = AckTracker(64)
        a.onPacketReceived(0, true, t0)
        assertFalse(a.ackRequired)
        a.onPacketReceived(1, true, t0 + 1.milliseconds)
        assertTrue(a.ackRequired)
    }

    @Test fun ackDeadlineIs25ms() {
        val a = AckTracker(64)
        assertEquals(TimeMark.NEVER, a.ackDeadline(25.milliseconds))
        a.onPacketReceived(0, true, t0)
        assertEquals(t0 + 25.milliseconds, a.ackDeadline(25.milliseconds))
    }

    @Test fun initialAndHandshakeAckImmediately() {
        val a = AckTracker(64, immediate = true)
        a.onPacketReceived(0, true, t0)
        assertTrue(a.ackRequired)
    }

    @Test fun outOfOrderTriggersImmediateAck() {
        val a = AckTracker(64)
        a.onPacketReceived(0, true, t0)
        a.onPacketReceived(2, true, t0)
        assertTrue(a.ackRequired)
        val b = AckTracker(64)
        b.onPacketReceived(1, true, t0)
        assertFalse(b.ackRequired)
        b.onPacketReceived(0, true, t0)
        assertTrue(b.ackRequired, "a packet below the largest is reordering")
    }

    @Test fun nonAckElicitingAloneNeverTriggersAck() {
        val a = AckTracker(64)
        repeat(10) { a.onPacketReceived(it.toLong(), false, t0) }
        assertFalse(a.ackRequired)
        assertEquals(TimeMark.NEVER, a.ackDeadline(25.milliseconds))
    }

    @Test fun rangesCappedAt64OldestMerged() {
        val a = AckTracker(64)
        for (pn in 1..399 step 2) a.onPacketReceived(pn.toLong(), true, t0)
        val f = ackFrame(a, t0)
        assertTrue(f.ranges.size <= 64)
        assertEquals(399L, f.largest)
        assertEquals(399L to 399L, f.ranges.first())
        assertTrue(f.ranges.last().first > 1)
    }

    @Test fun ackDelayEncodedWithExponent3() {
        val a = AckTracker(64)
        a.onPacketReceived(7, true, t0)
        val f =
            ackFrame(
                a,
                t0 + 20.milliseconds,
            )
        ; assertEquals(2500L, f.ackDelay)
        assertEquals(listOf(7L to 7L), f.ranges)
    }

    @Test fun duplicateDetected() {
        val a = AckTracker(64)
        assertFalse(a.isDuplicate(5))
        a.onPacketReceived(5, true, t0)
        assertTrue(a.isDuplicate(5))
        assertFalse(a.isDuplicate(6))
    }

    @Test fun ackOfAckDropsOldRanges() {
        val a = AckTracker(64)
        for (pn in 0L..9L) a.onPacketReceived(pn, true, t0)
        val b = PacketBuffer.allocate(64)
        try {
            a.writeAck(WireWriter(b, 0, 64), t0, 3)
        } finally {
            b.close()
        }
        a.onPacketReceived(11, true, t0)
        a.onAckFrameAcknowledged(9)
        val f = ackFrame(a, t0)
        assertEquals(listOf(11L to 11L), f.ranges)
    }

    @Test fun reorderedPacketBelowTrackedRangesIsNotDuplicate() {
        // the first packets of a space arrive swapped: 1 then 0 — 0 was never seen, it is not a duplicate (final review, Important 12)
        val a = AckTracker(64)
        a.onPacketReceived(1, true, t0)
        assertFalse(a.isDuplicate(0))
        a.onPacketReceived(0, true, t0)
        assertEquals(1, a.rangeCount)
        // after the floor moved to L, L+2 then L+1: L+1 is new
        val b = AckTracker(64)
        for (pn in 0L..10L) b.onPacketReceived(pn, true, t0)
        b.onPacketReceived(13, true, t0)
        assertFalse(b.isDuplicate(12))
        assertFalse(b.isDuplicate(11))
        assertTrue(b.isDuplicate(13))
        assertTrue(b.isDuplicate(5))
    }

    @Test fun packetsBelowEvictedRangesAreDuplicates() {
        val a = AckTracker(4)
        for (pn in listOf(0L, 10L, 20L, 30L, 40L)) a.onPacketReceived(pn, true, t0) // five ranges: the lowest (0) was evicted
        assertEquals(4, a.rangeCount)
        assertTrue(a.isDuplicate(0), "at or below the evicted range: treated as seen")
        assertFalse(a.isDuplicate(5), "never received, above the watermark: not a duplicate")
        assertFalse(a.isDuplicate(15))
    }

    /** Once the peer acknowledged packets carrying our ACKs, the ranges below them are not reported again (RFC 9000 section 13.2.4); a lossy phase must not leave dozens of stale ranges in every later ACK. */
    @Test fun acknowledgedAckFramesRetireOldRanges() {
        val p = io.kuicksilver.quic.CorePair()
        try {
            assertTrue(p.handshake())
            var lossy = true
            p.filterToServer = { i, _ -> !(lossy && i % 5 == 3) } // every fifth client datagram is lost: the server sees many gaps
            val c = p.client
            val up = c.openStream(true)
            val chunk = ByteArray(8192)
            var sent = 0
            var got = 0

            fun pump(total: Int) =
                p.runUntil(30.seconds) {
                    val s = p.server!!
                    while (sent <
                        total
                    ) {
                        val n = c.writeStream(up, chunk, 0, minOf(chunk.size, total - sent), false)
                        if (n <= 0) break
                        sent += n
                    }
                    while (true) {
                        val n = s.readStream(up, chunk, 0, chunk.size)
                        if (n <=
                            0
                        ) {
                            break
                        }
                        got += n
                    }
                    got == total && c.stats.bytesInFlight == 0L
                }
            assertTrue(pump(300_000), "lossy upload finished")
            assertTrue(
                p.server!!.stats.ackRanges > 2,
                "the lossy phase left gaps: ${p.server!!.stats.ackRanges} lost ${c.stats.lostPackets} sent ${c.stats.packetsSent} recv ${p.server!!.stats.packetsReceived} dropped-index ${p.sentToServer}",
            )
            lossy = false
            assertTrue(pump(600_000), "clean upload finished")
            assertTrue(
                p.server!!.stats.ackRanges <= 2,
                "after the client acknowledged the server's ACKs only recent ranges remain: ${p.server!!.stats.ackRanges}",
            )
        } finally {
            p.close()
        }
    }

    @Test fun ceMarkedPacketIsAcknowledgedImmediately() {
        // RFC 9000 section 13.2.1: "an endpoint SHOULD immediately acknowledge all packets marked with the ECN Congestion Experienced
        // (CE) codepoint in the IP header", so the sender learns of the congestion within one RTT (quic-go queues an ACK the same way)
        val a = AckTracker(64)
        a.onPacketReceived(0, true, t0, ce = true)
        assertTrue(a.ackRequired)
        val b = AckTracker(64)
        b.onPacketReceived(0, false, t0, ce = true)
        assertFalse(b.ackRequired, "a packet that is not ack-eliciting still elicits no ACK")
    }

    @Test fun skippedPacketNumbersCostAtMostOneAckEach() {
        // quiche and quinn skip packet numbers on purpose (a defence against optimistic ACKs; 74 skips in 80 000 packets from
        // quiche's interop server, 11 in 77 000 from quinn's, measured 2026-10-20). A receiver cannot tell a skip from a loss, so
        // the packet after it is acknowledged at once (RFC 9000 section 13.2.1; quic-go, quinn and ngtcp2 do the same), but only
        // that packet: the ones after it are acknowledged every second packet again, and the hole stays a gap in the ranges
        for (offset in 0 until 50) {
            val a = AckTracker(64)
            var pn = 0L
            var acks = 0
            var skips = 0
            var last: TestFrame.Ack? = null
            repeat(1000) { i ->
                if (i > 0 && i % 50 == offset) {
                    pn++
                    skips++
                }
                a.onPacketReceived(pn++, true, t0)
                if (a.ackRequired) {
                    acks++
                    last = ackFrame(a, t0)
                }
            }
            assertTrue(acks in 500..500 + skips, "offset $offset: $acks ACKs for 1000 packets with $skips skipped numbers")
            assertEquals(skips + 1, last!!.ranges.size, "offset $offset: every skipped number is a gap: ${last.ranges}")
        }
    }

    @Test fun refusedPacketIsSeenButNeverAcknowledged() {
        // RFC 9000 sections 12.3 and 13.1: a packet dropped after some of its frames ran is not processed again, nor acknowledged
        val a = AckTracker(64)
        a.onPacketReceived(0, true, t0)
        a.onPacketRefused(1)
        a.onPacketReceived(2, true, t0)
        assertTrue(a.isDuplicate(1))
        assertFalse(a.isDuplicate(3))
        val ack = ackFrame(a, t0)
        assertEquals(2L, ack.largest)
        assertEquals(listOf(2L to 2L, 0L to 0L), ack.ranges, "packet 1 stays a gap in the ACK")
    }

    @Test fun refusedPacketsBeyondTheKeptOnesBecomeAFloor() {
        val a = AckTracker(64)
        for (pn in 0L until 20) a.onPacketRefused(2 * pn)
        for (pn in 0L until 20) assertTrue(a.isDuplicate(2 * pn), "refused $pn")
        assertTrue(a.isDuplicate(5), "below the floor of the forgotten refusals")
        assertFalse(a.isDuplicate(41))
    }

    @Test fun refusedPacketsAlreadySeenSpendNoSlot() {
        // a refused number at or below a floor, or already kept, is a duplicate already: it must not push kept ones out
        val a = AckTracker(64)
        for (pn in 0L until 20) a.onPacketRefused(2 * pn) // keeps 8..38, floor at 6
        repeat(16) { a.onPacketRefused(3) }
        repeat(16) { a.onPacketRefused(38) }
        assertFalse(a.isDuplicate(39), "kept refusals were evicted by numbers already seen")
        assertFalse(a.isDuplicate(9))
        assertTrue(a.isDuplicate(8))
    }
}
