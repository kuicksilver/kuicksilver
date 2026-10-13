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
import kotlin.time.Duration.Companion.microseconds
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

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
        val spurious = ArrayList<Long>()
        var settled = 0
        val delivered = ArrayList<String>()
        var ecnCalls = 0

        override fun onDelivered(
            p: SentPacket,
            now: TimeMark,
        ) {
            delivered += "${p.pn}:lost=${lost.size}"
        }

        override fun onSpuriousLoss(
            space: SpaceId,
            pn: Long,
            bytes: Int,
            cc: io.kuicksilver.quic.CongestionController?,
            pathId: Int,
            now: TimeMark,
        ) {
            spurious += pn
        }

        override fun onLossSettled(
            cc: io.kuicksilver.quic.CongestionController?,
            now: TimeMark,
        ) {
            settled++
        }

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

        val lossByPath = ArrayList<String>()

        override fun onCongestion(event: CongestionEvent) {
            events += "${event.kind}:${event.bytes}:${event.persistentCongestion}"
            if (event.kind == CongestionKind.Lost) lossByPath += "${event.pathId}:${event.persistentCongestion}"
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
        inFlight: Boolean = ackEliciting,
        pathId: Int = 0,
    ) {
        val p = ld.space(space).newSentPacket()
        p.pn = pn
        p.timeSent = at
        p.size = size
        p.ackEliciting = ackEliciting
        p.ecnMarked = marked
        p.inFlight = inFlight
        p.pathId = pathId
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

    @Test fun ackOfOldestPacketIsSublinear() {
        // RFC 9002 appendix A.7 and RFC 9000 section 21.6: the peer chooses what it acknowledges and how much is outstanding; an ACK of the
        // oldest packet must not walk every packet in flight
        val (ld, l) = ld()
        for (pn in 0L until 10_000L) send(ld, SpaceId.Application, pn, t0 + pn.toInt().microseconds)
        ld.visitedForTest = 0
        ld.onAck(SpaceId.Application, ack(0L to 0L), t0 + 100.milliseconds)
        assertEquals(listOf(0L), l.acked)
        assertTrue(ld.visitedForTest < 64, "packets visited for an ACK of the oldest of 10 000: ${ld.visitedForTest}")
        assertEquals(9_999, ld.storedPackets(SpaceId.Application))
    }

    @Test fun ackOfTombstoneRangeIsSublinear() {
        // review of k7/f1-core (RFC 9000 section 21.6): a peer repeating an ACK over a range already acknowledged must not make every
        // frame walk the tombstones that range left behind. The packet threshold (RFC 9002 section 6.1.1) declares every packet more
        // than 3 below the largest acknowledged lost on that same ACK, so the front skip removes the run below 999 at once and no
        // tombstone run can sit under a live packet older than largest - 2.
        val (ld, l) = ld()
        for (pn in 0L until 1500L) send(ld, SpaceId.Application, pn, t0 + pn.toInt().microseconds)
        ld.onAck(SpaceId.Application, ack(500L to 998L), t0 + 100.milliseconds)
        assertEquals(499, l.acked.size)
        assertEquals(500, l.lost.size, "0..499 are lost by the packet threshold")
        assertEquals(501, ld.storedPackets(SpaceId.Application))
        repeat(10) {
            ld.visitedForTest = 0
            ld.onAck(SpaceId.Application, ack(500L to 998L), t0 + 101.milliseconds)
            assertTrue(ld.visitedForTest < 64, "slots visited for a repeated ACK of 499 tombstones: ${ld.visitedForTest}")
        }
        assertEquals(499, l.acked.size)
        assertEquals(501, ld.storedPackets(SpaceId.Application))
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

    @Test fun initialPtoFollowsInitialRtt() {
        // RFC 9002 section 6.2.2: before the first sample PTO = 3 x initial RTT (quic-go's 100 ms default gives 300 ms), doubling per expiry
        val (ld, _) = ld(config = quicConfig { initialRtt = 100.milliseconds })
        send(ld, SpaceId.Initial, 0, t0)
        assertEquals(t0 + 300.milliseconds, ld.timeout())
        assertNotNull(ld.onTimeout(t0 + 300.milliseconds))
        send(ld, SpaceId.Initial, 1, t0 + 300.milliseconds)
        assertEquals(t0 + 300.milliseconds + 600.milliseconds, ld.timeout())
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

    /** An RTT sample of [rtt] taken through an ACK of packet [pn] sent at [at] (the time of the first sample matters, RFC 9002 section 7.6.2). */
    private fun sampleByAck(
        ld: LossDetection,
        pn: Long,
        at: TimeMark,
        rtt: Duration = 100.milliseconds,
    ) {
        send(ld, SpaceId.Application, pn, at)
        ld.onAck(SpaceId.Application, ack(pn to pn), at + rtt)
    }

    @Test fun persistentCongestionDetected() {
        val (ld, l) = ld()
        ld.handshakeConfirmed = true
        ld.peerAddressValidated = true
        sampleByAck(ld, 0, t0 - 200.milliseconds)
        for (pn in 1L..20L) send(ld, SpaceId.Application, pn, t0 + (pn.toInt() * 100).milliseconds)
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

    @Test fun aLostPacketAcknowledgedLaterIsASpuriousLoss() {
        // RFC 9002 section 6.1: packet 1 is reordered behind 2..5, the packet threshold declares it lost, then its ACK arrives
        val (ld, l) = ld()
        ld.handshakeConfirmed = true
        for (pn in 0L..5L) send(ld, SpaceId.Application, pn, t0 + pn.toInt().milliseconds)
        ld.onAck(SpaceId.Application, ack(2L to 5L, 0L to 0L), t0 + 50.milliseconds)
        assertEquals(listOf(1L), l.lost)
        assertTrue(l.spurious.isEmpty())
        ld.onAck(SpaceId.Application, ack(0L to 5L), t0 + 52.milliseconds)
        assertEquals(listOf(1L), l.spurious, "the late ACK of packet 1")
        ld.onAck(SpaceId.Application, ack(0L to 5L), t0 + 53.milliseconds)
        assertEquals(listOf(1L), l.spurious, "reported once")
        assertEquals(0, l.settled)
    }

    @Test fun aTimeThresholdLossAcknowledgedLaterIsSpuriousToo() {
        val (ld, l) = ld()
        ld.handshakeConfirmed = true
        for (pn in 0L..2L) send(ld, SpaceId.Application, pn, t0)
        ld.onAck(SpaceId.Application, ack(1L to 2L), t0 + 40.milliseconds) // 0 is below the largest, within the packet threshold
        assertTrue(l.lost.isEmpty())
        val timer = ld.timeout()
        ld.onTimeout(timer) // 9/8 RTT later: lost by the time threshold
        assertEquals(listOf(0L), l.lost)
        ld.onAck(SpaceId.Application, ack(0L to 2L), timer + 1.milliseconds)
        assertEquals(listOf(0L), l.spurious)
    }

    @Test fun aLostPacketNeverAcknowledgedSettlesAfterThePersistentCongestionPeriod() {
        val (ld, l) = ld()
        ld.handshakeConfirmed = true
        for (pn in 0L..5L) send(ld, SpaceId.Application, pn, t0 + pn.toInt().milliseconds)
        ld.onAck(SpaceId.Application, ack(2L to 5L, 0L to 0L), t0 + 50.milliseconds)
        assertEquals(listOf(1L), l.lost)
        send(ld, SpaceId.Application, 6, t0 + 60.milliseconds)
        ld.onAck(SpaceId.Application, ack(6L to 6L), t0 + 60.milliseconds + ld.persistentCongestionDuration() * 2)
        assertEquals(1, l.settled)
        assertTrue(l.spurious.isEmpty())
        ld.onAck(SpaceId.Application, ack(0L to 6L), t0 + 10.seconds)
        assertTrue(l.spurious.isEmpty(), "forgotten: no longer reported")
    }

    @Test fun moreLostPacketsThanRememberedSettleTheOldest() {
        val (ld, l) = ld()
        ld.handshakeConfirmed = true
        val n = LOST_KEEP + 10L
        for (pn in 0L..n + 2) send(ld, SpaceId.Application, pn, t0)
        ld.onAck(SpaceId.Application, ack(n + 2 to n + 2), t0 + 30.milliseconds) // everything below n is lost
        assertEquals(n.toInt(), l.lost.size)
        assertEquals(10, l.settled)
        ld.onAck(SpaceId.Application, ack(0L to n + 2), t0 + 31.milliseconds)
        assertEquals((10L until n).toList(), l.spurious.sorted())
    }

    @Test fun anAckReportsItsPacketsDeliveredBeforeItsLosses() {
        // review of k7/bbr: the rate sampler sees C.delivered of this ACK before the losses it reveals (TCP's order)
        val (ld, l) = ld()
        ld.handshakeConfirmed = true
        for (pn in 0L..5L) send(ld, SpaceId.Application, pn, t0)
        ld.onAck(SpaceId.Application, ack(2L to 5L), t0 + 30.milliseconds)
        assertEquals(listOf(0L, 1L), l.lost)
        assertEquals(listOf("5:lost=0", "4:lost=0", "3:lost=0", "2:lost=0"), l.delivered)
    }

    @Test fun discardingASpaceSettlesItsLostPackets() {
        val (ld, l) = ld()
        for (pn in 0L..5L) send(ld, SpaceId.Initial, pn, t0)
        ld.onAck(SpaceId.Initial, ack(5L to 5L), t0 + 30.milliseconds)
        assertEquals(3, l.lost.size)
        ld.discard(SpaceId.Initial, t0 + 31.milliseconds)
        assertEquals(3, l.settled)
    }

    @Test fun persistentCongestionIgnoresPacketsSentBeforeTheFirstRttSample() {
        // RFC 9002 section 7.6.2: "The persistent congestion period SHOULD NOT start until there is at least one RTT sample." A lost
        // first Initial and two lost PTO probes, then an ACK of the third probe: the sample comes from that ACK, so none of the lost
        // packets was sent with an RTT sample in hand (ngtcp2 filters by first_rtt_sample_ts)
        val (ld, l) = ld()
        send(ld, SpaceId.Initial, 0, t0)
        send(ld, SpaceId.Initial, 1, t0 + 1.seconds)
        send(ld, SpaceId.Initial, 2, t0 + 3.seconds)
        send(ld, SpaceId.Initial, 3, t0 + 7.seconds)
        ld.onAck(SpaceId.Initial, ack(3L to 3L), t0 + 7.seconds + 30.milliseconds)
        assertEquals(listOf(0L, 1L, 2L), l.lost)
        assertEquals(listOf("0:false"), l.lossByPath, "no RTT sample existed when the lost packets were sent")
    }

    @Test fun persistentCongestionSpansAckOnlyAndSkippedPacketNumbers() {
        // RFC 9002 section 7.6.2: what breaks the period is an acknowledged packet between the two lost ones, not a packet number
        // that loss detection never stored (ACK-only packets) or never used (a skipped number, RFC 9000 section 21.4)
        val (ld, l) = ld()
        ld.handshakeConfirmed = true
        ld.peerAddressValidated = true
        sampleByAck(ld, 0, t0 - 200.milliseconds)
        var pn = 1L
        for (k in 0 until 20) {
            send(ld, SpaceId.Application, pn, t0 + (k * 100).milliseconds)
            pn += if (k % 3 == 0) 2 else 1 // every third gap is an ACK-only or skipped packet number
        }
        send(ld, SpaceId.Application, pn, t0 + 2100.milliseconds)
        ld.onAck(SpaceId.Application, ack(pn to pn), t0 + 2200.milliseconds)
        assertTrue(l.lossByPath.single().endsWith("true"), "2 s of contiguous loss: ${l.lossByPath}")
    }

    @Test fun anAcknowledgedPacketBetweenTheLostOnesBreaksPersistentCongestion() {
        val (ld, l) = ld()
        ld.handshakeConfirmed = true
        ld.peerAddressValidated = true
        sampleByAck(ld, 0, t0 - 200.milliseconds)
        for (pn in 1L..20L) send(ld, SpaceId.Application, pn, t0 + (pn.toInt() * 100).milliseconds)
        ld.onAck(SpaceId.Application, ack(10L to 10L), t0 + 1050.milliseconds) // 1..7 lost now (packet threshold), 10 delivered
        ld.onAck(SpaceId.Application, ack(20L to 20L), t0 + 2100.milliseconds) // 8, 9 and 11..17: a delivered packet splits them
        assertTrue(l.lossByPath.none { it.endsWith("true") }, "10 was delivered in between: ${l.lossByPath}")
    }

    @Test fun persistentCongestionSpanIsBetweenAckElicitingPackets() {
        // RFC 9002 section 7.6.2: "two ack-eliciting packets are declared lost"; a padding-only packet counts in flight but cannot end
        // the period
        val (ld, l) = ld()
        ld.handshakeConfirmed = true
        ld.peerAddressValidated = true
        sampleByAck(ld, 0, t0 - 200.milliseconds)
        for (pn in 1L..5L) send(ld, SpaceId.Application, pn, t0 + (pn.toInt() * 100).milliseconds)
        send(ld, SpaceId.Application, 6, t0 + 2000.milliseconds, ackEliciting = false, inFlight = true)
        for (pn in 7L..9L) send(ld, SpaceId.Application, pn, t0 + 2001.milliseconds)
        ld.onAck(SpaceId.Application, ack(9L to 9L), t0 + 2100.milliseconds)
        assertEquals(listOf(1L, 2L, 3L, 4L, 5L, 6L), l.lost)
        assertEquals(listOf("0:false"), l.lossByPath, "ack-eliciting losses span 400 ms only")
    }

    @Test fun persistentCongestionIsJudgedPerPath() {
        // RFC 9000 section 9.4: each path has its own congestion controller; a long loss period on one path does not collapse the
        // window of another whose single packet was lost
        val (ld, l) = ld()
        ld.handshakeConfirmed = true
        ld.peerAddressValidated = true
        sampleByAck(ld, 0, t0 - 200.milliseconds)
        for (pn in 1L..20L) send(ld, SpaceId.Application, pn, t0 + (pn.toInt() * 100).milliseconds, pathId = if (pn == 5L) 1 else 0)
        ld.onAck(SpaceId.Application, ack(20L to 20L), t0 + 2100.milliseconds)
        assertEquals(listOf("0:true", "1:false"), l.lossByPath)
    }

    @Test fun persistentCongestionResetsMinRttToTheNewestSample() {
        // RFC 9002 section 5.2: "Endpoints SHOULD set the min_rtt to the newest RTT sample after persistent congestion is established"
        val (ld, _) = ld()
        ld.handshakeConfirmed = true
        ld.peerAddressValidated = true
        sampleByAck(ld, 0, t0 - 200.milliseconds, rtt = 50.milliseconds)
        assertEquals(50.milliseconds, ld.rtt.min)
        for (pn in 1L..20L) send(ld, SpaceId.Application, pn, t0 + (pn.toInt() * 100).milliseconds)
        ld.onAck(SpaceId.Application, ack(20L to 20L), t0 + 2300.milliseconds) // sample: 300 ms
        assertEquals(300.milliseconds, ld.rtt.min)
    }
}

private fun Int.microsecondsAsDuration(): Duration = kotlin.time.Duration.parse("${this}us")
