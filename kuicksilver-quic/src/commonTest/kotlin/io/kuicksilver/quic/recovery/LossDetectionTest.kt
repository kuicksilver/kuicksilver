// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.recovery

import io.kuicksilver.quic.QuicConfig
import io.kuicksilver.quic.TimeMark
import io.kuicksilver.quic.quicConfig
import io.kuicksilver.quic.wire.AckFrameView
import io.kuicksilver.quic.wire.QuicWireException
import io.kuicksilver.tls.TlsRole
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds

class LossDetectionTest {
    @Test fun hugeAckDelayDoesNotOverflow() {
        val (ld, l) = ld()
        ld.handshakeConfirmed = true
        ld.peerAddressValidated = true
        ld.peerAckDelayExponent = 20
        send(ld, SpaceId.Application, 0, t0)
        ld.onAck(SpaceId.Application, ack(0L to 0L, delay = Long.MAX_VALUE / 4), t0 + 100.milliseconds)
        assertEquals(listOf(0L), l.acked)
        assertTrue(
            ld.rtt.smoothed > Duration.ZERO && ld.rtt.smoothed <= 100.milliseconds,
            "a peer-chosen ack_delay cannot wrap the arithmetic: ${ld.rtt.smoothed}",
        )
    }

    private val t0 = TimeMark(10_000_000_000L)

    private class Listener : LossListener {
        val acked = ArrayList<Long>()
        val lost = ArrayList<Long>()
        val events = ArrayList<String>()
        var ecnCalls = 0

        override fun onEcnAck(
            space: SpaceId,
            countsPresent: Boolean,
            countsValid: Boolean,
            newlyAckedMarked: Int,
            ceGrew: Boolean,
            now: TimeMark,
            largestSentTime: TimeMark,
            pathId: Int,
        ) {
            ecnCalls++
        }

        override fun onAcked(
            space: SpaceId,
            p: SentPacket,
        ) {
            acked += p.pn
        }

        override fun onLost(
            space: SpaceId,
            p: SentPacket,
        ) {
            lost += p.pn
        }

        override fun onCongestion(event: CongestionEvent) {
            events += "${event.kind}:${event.bytes}:${event.persistentCongestion}"
        }

        override fun onDiscarded(bytes: Int) {}
    }

    private fun ld(
        role: TlsRole = TlsRole.Client,
        config: QuicConfig = QuicConfig.Default,
    ): Pair<LossDetection, Listener> {
        val l = Listener()
        return LossDetection(RttEstimator(config.initialRtt), config, role, l) to
            l
    }

    private fun send(
        ld: LossDetection,
        space: SpaceId,
        pn: Long,
        at: TimeMark,
        size: Int = 1200,
        ackEliciting: Boolean = true,
        marked: Boolean = false,
    ) {
        val p = ld.space(space).newSentPacket()
        p.pn = pn
        p.timeSent = at
        p.size = size
        p.ackEliciting = ackEliciting
        p.ecnMarked = marked
        p.inFlight =
            ackEliciting
        ld.onPacketSent(space, p, at)
    }

    private fun ack(
        vararg ranges: Pair<Long, Long>,
        delay: Long = 0,
        ecn: LongArray? = null,
    ): AckFrameView =
        AckFrameView().also { v ->
            v.largest =
                ranges[0].second
            ; v.ackDelay = delay
            for ((s, l) in ranges) v.addRange(s, l)
            if (ecn != null) v.setEcn(ecn[0], ecn[1], ecn[2])
        }

    @Test fun staleAckDoesNotReachEcnValidation() {
        // RFC 9000 section 13.4.2.1: an ACK that does not raise the largest acknowledged packet was reordered on the way; its counts
        // are older than the ones already validated and must not be validated (or counted) again
        val (ld, l) = ld()
        for (pn in 0L..3L) send(ld, SpaceId.Application, pn, t0 + pn.toInt().milliseconds, marked = true)
        ld.onAck(SpaceId.Application, ack(3L to 3L, ecn = longArrayOf(4, 0, 0)), t0 + 100.milliseconds)
        assertEquals(1, l.ecnCalls)
        ld.onAck(SpaceId.Application, ack(0L to 1L, ecn = longArrayOf(2, 0, 0)), t0 + 101.milliseconds)
        assertEquals(1, l.ecnCalls, "a stale ACK does not reach ECN validation")
    }

    private fun sample(
        ld: LossDetection,
        rtt: Duration,
    ) {
        ld.rtt.onSample(rtt, 0.milliseconds, true, 25.milliseconds)
    }

    @Test fun packetThreshold3() {
        val (ld, l) = ld()
        for (pn in 1L..5L) send(ld, SpaceId.Application, pn, t0 + pn.toInt().milliseconds)
        ld.onAck(SpaceId.Application, ack(5L to 5L), t0 + 100.milliseconds)
        assertEquals(listOf(1L, 2L), l.lost)
        assertEquals(listOf(5L), l.acked)
    }

    @Test fun timeThreshold9Over8() {
        val (ld, _) = ld()
        sample(ld, 100.milliseconds)
        for (pn in 1L..5L) send(ld, SpaceId.Application, pn, t0 + (pn.toInt() * 10).milliseconds)
        // latest = 100 ms; 1..3 lost (threshold / time), 4 waits for its time
        ld.onAck(SpaceId.Application, ack(5L to 5L), t0 + 150.milliseconds)
        assertEquals(t0 + 40.milliseconds + 112.5.milliseconds, ld.timeout(), "loss timer = sent(4) + 9/8 x max(sRTT, latest)")
    }

    @Test fun timeThresholdFloor1ms() {
        val (ld, _) = ld()
        sample(ld, 100.microsecondsAsDuration())
        for (pn in 1L..3L) send(ld, SpaceId.Application, pn, t0 + (pn.toInt() * 10).milliseconds)
        send(ld, SpaceId.Application, 4, t0 + 50.milliseconds)
        send(
            ld,
            SpaceId.Application,
            5,
            t0 + 50.milliseconds + 200.microsecondsAsDuration(),
        )
        // latest 0.3 ms: 9/8 x latest < 1 ms, so the floor applies
        ld.onAck(SpaceId.Application, ack(5L to 5L), t0 + 50.milliseconds + 500.microsecondsAsDuration())
        assertEquals(t0 + 50.milliseconds + 1.milliseconds, ld.timeout())
    }

    @Test fun initialPto999ms() {
        val (ld, _) = ld()
        send(ld, SpaceId.Initial, 0, t0)
        assertEquals(t0 + 999.milliseconds, ld.timeout())
    }

    @Test fun appSpacePtoAddsMaxAckDelayAfterConfirmed() {
        val (ld, _) = ld()
        ld.handshakeConfirmed = true
        ld.peerAddressValidated = true
        send(ld, SpaceId.Application, 0, t0)
        assertEquals(t0 + 999.milliseconds + 25.milliseconds, ld.timeout())
    }

    @Test fun ptoBackoffDoubles() {
        // each expiry sends a probe (a new ack-eliciting packet), which re-bases the timer: 999 -> 1998 -> 3996 ms
        val (ld, _) = ld()
        send(ld, SpaceId.Initial, 0, t0)
        val t1 = ld.timeout()
        assertEquals(t0 + 999.milliseconds, t1)
        val p1 = ld.onTimeout(t1)
        assertNotNull(p1)
        assertEquals(SpaceId.Initial, p1.space)
        assertEquals(1, ld.ptoCount)
        send(ld, SpaceId.Initial, 1, t1)
        val t2 = ld.timeout()
        assertEquals(t1 + 1998.milliseconds, t2)
        ld.onTimeout(t2)
        assertEquals(2, ld.ptoCount)
        send(ld, SpaceId.Initial, 2, t2)
        assertEquals(t2 + 3996.milliseconds, ld.timeout())
    }

    @Test fun ptoCountResetOnAck() {
        val (ld, _) = ld()
        ld.peerAddressValidated = true
        ld.handshakeConfirmed = true
        send(ld, SpaceId.Application, 0, t0)
        ld.onTimeout(t0 + 1024.milliseconds)
        assertEquals(1, ld.ptoCount)
        send(ld, SpaceId.Application, 1, t0 + 1000.milliseconds)
        ld.onAck(SpaceId.Application, ack(1L to 1L), t0 + 1100.milliseconds)
        assertEquals(0, ld.ptoCount)
    }

    @Test fun clientAntiDeadlockPtoWithNothingInFlight() {
        val (ld, _) = ld(TlsRole.Client)
        ld.peerAddressValidated = false
        ld.onPacketSent(
            SpaceId.Initial,
            ld.space(SpaceId.Initial).newSentPacket().also {
                it.pn =
                    0
                ; it.timeSent = t0
                it.size = 1200
                it.ackEliciting = true
                it.inFlight = true
            },
            t0,
        )
        ld.onAck(SpaceId.Initial, ack(0L to 0L), t0 + 50.milliseconds)
        assertEquals(0L, ld.bytesInFlight)
        assertNotEquals(TimeMark.NEVER, ld.timeout(), "client arms a PTO with nothing in flight until the peer validated its address")
        val (srv, _) = ld(TlsRole.Server)
        assertEquals(TimeMark.NEVER, srv.timeout(), "server never arms a timer without packets in flight")
    }

    @Test fun persistentCongestionDuration975ms() {
        val (ld, _) = ld()
        sample(ld, 100.milliseconds)
        assertEquals(975.milliseconds, ld.persistentCongestionDuration())
    }

    @Test fun discardSpaceRemovesBytesInFlight() {
        val (ld, _) = ld()
        send(ld, SpaceId.Initial, 0, t0)
        send(ld, SpaceId.Handshake, 0, t0)
        assertEquals(2400L, ld.bytesInFlight)
        ld.discard(SpaceId.Initial)
        assertEquals(1200L, ld.bytesInFlight)
    }

    @Test fun negative_ackForUnsentPacket() {
        val (ld, _) = ld()
        send(ld, SpaceId.Application, 0, t0)
        val e =
            assertFailsWith<QuicWireException> {
                ld.onAck(
                    SpaceId.Application,
                    ack(0L to 7L),
                    t0,
                )
            }
        ; assertEquals(0x0aL, e.code)
    }

    @Test fun negative_ackForSkippedPacketNumber() {
        val (ld, _) = ld()
        val sp = ld.space(SpaceId.Application)
        val r = Random(3)
        var skipped = -1L
        while (skipped < 0) {
            val pn = sp.takePn(r)
            send(ld, SpaceId.Application, pn, t0)
            skipped = sp.lastSkipped
        }
        val e = assertFailsWith<QuicWireException> { ld.onAck(SpaceId.Application, ack(skipped to skipped), t0) }
        assertEquals(0x0aL, e.code)
    }

    @Test fun ackOnlyPacketsNotStored() {
        val (ld, _) = ld()
        repeat(100) { send(ld, SpaceId.Application, it.toLong(), t0, ackEliciting = false) }
        assertEquals(0, ld.storedPackets(SpaceId.Application))
        assertEquals(0L, ld.bytesInFlight)
    }

    @Test fun skipWindowWithinBounds() {
        for (seed in 1..100) {
            val sp = PacketNumberSpace(SpaceId.Application)
            val r = Random(seed)
            var prev = -1L
            var count = 0
            while (count <
                5
            ) {
                sp.takePn(r)
                if (sp.lastSkipped !=
                    prev
                ) {
                    if (prev >=
                        0
                    ) {
                        val gap =
                            sp.lastSkipped - prev
                        assertTrue(gap in 128..1023, "seed $seed gap $gap")
                    }
                    prev = sp.lastSkipped
                    count++
                }
            }
        }
        val init = PacketNumberSpace(SpaceId.Initial)
        val r = Random(1)
        repeat(5000) { init.takePn(r) }
        assertEquals(-1L, init.lastSkipped, "no skipping outside the Application space")
    }

    @Test fun persistentCongestionDetected() {
        val (ld, l) = ld()
        sample(ld, 100.milliseconds)
        ld.handshakeConfirmed = true
        ld.peerAddressValidated = true
        for (pn in 0L..20L) send(ld, SpaceId.Application, pn, t0 + (pn.toInt() * 100).milliseconds)
        ld.onAck(SpaceId.Application, ack(20L to 20L), t0 + 2100.milliseconds)
        assertTrue(
            l.events.any { it.startsWith("Lost") && it.endsWith("true") },
            "packets 0..17 span > 975 ms of continuous loss: ${l.events}",
        )
    }

    @Test fun manyRangesAckExactlyTheListedPackets() {
        // a sparse ACK (every other packet of 400) must acknowledge exactly the listed packets; the walk is linear in sent + ranges (final review, Important 13)
        val (ld, l) = ld()
        ld.handshakeConfirmed = true
        ld.peerAddressValidated = true
        for (pn in 0L until 400L) send(ld, SpaceId.Application, pn, t0 + pn.toInt().milliseconds)
        val ranges =
            Array(200) { k ->
                val pn = 399L - 2 * k
                pn to pn
            }
        ld.onAck(SpaceId.Application, ack(*ranges), t0 + 500.milliseconds)
        assertEquals((1L..399L step 2).toList().sorted(), l.acked.sorted())
        assertTrue(l.lost.all { it % 2 == 0L }, "only unacknowledged even packets can be lost")
    }
}

private fun Int.microsecondsAsDuration(): Duration = kotlin.time.Duration.parse("${this}us")
