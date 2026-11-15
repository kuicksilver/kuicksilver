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
        val ecnValid = ArrayList<Boolean>()
        var frameStarts = 0
        val ecnPaths = ArrayList<String>()
        var rttSamples = 0

        override fun onAckFrameStart() {
            frameStarts++
        }

        override fun onRttSample(
            now: TimeMark,
            latest: Duration,
            min: Duration,
        ) {
            rttSamples++
        }

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
            declaredAt: TimeMark,
        ) {
            spurious += pn
        }

        override fun onLossSettled(
            cc: io.kuicksilver.quic.CongestionController?,
            now: TimeMark,
            declaredAt: TimeMark,
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
            ecnValid += countsValid
            ecnPaths += "$pathId:$newlyAckedMarked"
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

        val discarded = ArrayList<Pair<io.kuicksilver.quic.CongestionController?, Int>>()
        val rtts = HashMap<Int, RttEstimator>()

        override fun rttOf(pathId: Int): RttEstimator? = rtts[pathId]

        override fun onDiscarded(
            cc: io.kuicksilver.quic.CongestionController?,
            bytes: Int,
        ) {
            discarded += cc to bytes
        }
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
        cc: io.kuicksilver.quic.CongestionController? = null,
        flags: Int = 0,
    ) {
        val p = ld.space(space).newSentPacket()
        p.frames.flags = flags
        p.pn = pn
        p.timeSent = at
        p.size = size
        p.ackEliciting = ackEliciting
        p.ecnMarked = marked
        p.inFlight = inFlight
        p.pathId = pathId
        p.cc = cc
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

    /**
     * RFC 9000 section 13.4.2.1, the three ways ECN counts fail validation, each reported to the path's validator as invalid
     * (0.3.0 cross-review: they were implemented, the section 13.4 row cited `EcnTest.*`, and none was tested): a count that went
     * down, an ECT(1) count when we never send ECT(1), and ECT(0) + CE growing by less than the newly acknowledged ECT(0) packets.
     */
    @Test fun negative_ecnCountsFailValidationInEachOfTheThreeWays() {
        fun validity(
            first: LongArray,
            second: LongArray,
        ): List<Boolean> {
            val (ld, l) = ld()
            ld.handshakeConfirmed = true
            for (pn in 0L..3L) send(ld, SpaceId.Application, pn, t0, marked = true)
            ld.onAck(SpaceId.Application, ack(0L to 1L, ecn = first), t0 + 50.milliseconds)
            ld.onAck(SpaceId.Application, ack(0L to 3L, ecn = second), t0 + 60.milliseconds)
            return l.ecnValid
        }
        assertEquals(listOf(true, true), validity(longArrayOf(2, 0, 0), longArrayOf(4, 0, 0)), "consistent counts")
        assertEquals(listOf(true, false), validity(longArrayOf(2, 0, 0), longArrayOf(1, 0, 3)), "ECT(0) decreased")
        assertEquals(listOf(true, false), validity(longArrayOf(2, 0, 0), longArrayOf(3, 1, 0)), "ECT(1) though we send ECT(0) only")
        assertEquals(listOf(true, false), validity(longArrayOf(2, 0, 0), longArrayOf(3, 0, 0)), "2 newly acknowledged ECT(0), 1 counted")
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
        // core review before 0.2.0 (RFC 9000 section 21.6): a peer repeating an ACK over a range already acknowledged must not make every
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

    @Test fun ptoBackoffSaturatesInsteadOfWrapping() {
        // 1 shl 31 is negative and 1 shl 32 is 1: the 31st unanswered PTO fired at once, the 32nd restarted the backoff (with both
        // idle timeouts disabled nothing else ends such a connection)
        val (ld, _) = ld()
        var at = t0
        var gap = Duration.ZERO
        for (pn in 0L..33L) {
            send(ld, SpaceId.Initial, pn, at)
            val next = ld.timeout()
            assertTrue(next - at >= gap, "PTO ${ld.ptoCount}: ${next - at} after the previous $gap")
            gap = next - at
            assertNotNull(ld.onTimeout(next))
            at = next
        }
        assertEquals(34, ld.ptoCount)
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

    @Test fun clientAntiDeadlockPtoWithOnlyZeroRttInFlight() {
        // RFC 9002 section 6.2.2.1: "the client MUST set the PTO timer if the client has not received an acknowledgment for any of
        // its Handshake packets and the handshake is not confirmed ..., even if there are no packets in flight". The server
        // acknowledged the ClientHello, its Handshake flight was lost; the client's 0-RTT packets are in flight, but their
        // acknowledgements come in 1-RTT packets it cannot read yet, and the Application space arms no PTO before confirmation
        val (ld, _) = ld(TlsRole.Client)
        send(ld, SpaceId.Initial, 0, t0)
        for (pn in 0L..2L) send(ld, SpaceId.Application, pn, t0)
        ld.onAck(SpaceId.Initial, ack(0L to 0L), t0 + 50.milliseconds)
        assertNotEquals(TimeMark.NEVER, ld.timeout(), "the anti-deadlock PTO is armed")
        val probe = ld.onTimeout(ld.timeout())
        assertNotNull(probe)
        assertEquals(SpaceId.Initial, probe.space, "no Handshake keys yet: an Initial probe")
        ld.handshakeKeysAvailable = true
        assertEquals(SpaceId.Handshake, assertNotNull(ld.onTimeout(ld.timeout())).space)
        ld.peerAddressValidated = true
        assertEquals(TimeMark.NEVER, ld.timeout(), "once the server validated the address, 0-RTT alone arms nothing before confirmation")
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

    @Test fun discardedBytesLeaveTheControllerThatCountedThem() {
        // RFC 9002 section 6.4 with RFC 9000 section 9.4: bytes of a discarded space leave flight in the controller that counted
        // them; after a migration or a rebinding that need not be the active path's
        val (ld, l) = ld()
        val a = io.kuicksilver.quic.NewReno()
        val b = io.kuicksilver.quic.NewReno()
        send(ld, SpaceId.Handshake, 0, t0, cc = a)
        send(ld, SpaceId.Handshake, 1, t0, size = 900, cc = b)
        send(ld, SpaceId.Handshake, 2, t0, ackEliciting = false, inFlight = false, cc = b)
        ld.discard(SpaceId.Handshake)
        assertEquals(listOf<Pair<Any?, Int>>(a to 1200, b to 900), l.discarded)
        send(ld, SpaceId.Application, 0, t0, cc = b)
        val app = ld.space(SpaceId.Application).sent
        app.at(app.start)!!.zeroRtt = true
        ld.discardZeroRtt {}
        assertEquals(b to 1200, l.discarded.last(), "rejected 0-RTT too")
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
        // BBR review: the rate sampler sees C.delivered of this ACK before the losses it reveals (TCP's order)
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
        // left unacknowledged (ACK-only packets nobody acknowledged) or never used (a skipped number, RFC 9000 section 21.4)
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

    @Test fun aPacketAcknowledgedInAnotherSpaceBreaksPersistentCongestion() {
        // RFC 9002 section 7.6.2: "across all packet number spaces, none of the packets sent between the send times of these two
        // packets are acknowledged". During the handshake a 1-RTT packet sent between two lost Handshake packets and acknowledged
        // shows the path delivered in between; only the Handshake space's own acknowledgements used to count
        fun lossesWith(appAcked: Boolean): Listener {
            val (ld, l) = ld()
            sampleByAck(ld, 0, t0 - 200.milliseconds)
            for (pn in 0L..15L) send(ld, SpaceId.Handshake, pn, t0 + (pn.toInt() * 100).milliseconds)
            send(ld, SpaceId.Application, 1, t0 + 750.milliseconds)
            if (appAcked) ld.onAck(SpaceId.Application, ack(1L to 1L), t0 + 800.milliseconds)
            ld.onAck(SpaceId.Handshake, ack(15L to 15L), t0 + 1600.milliseconds)
            assertEquals((0L..14L).toList(), l.lost)
            return l
        }
        assertEquals(listOf("0:false"), lossesWith(appAcked = true).lossByPath, "the 1-RTT packet sent at 750 ms was acknowledged")
        assertEquals(listOf("0:true"), lossesWith(appAcked = false).lossByPath, "1.4 s of losses, more than the period")
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

    @Test fun persistentCongestionWaitsForTheNewPathsFirstRttSample() {
        // RFC 9002 section 7.6.2: "a prior RTT sample existed when these two packets were sent". After a migration to a new address
        // the new path has its own estimator without a sample: its packets lost before that path's first sample do not establish
        // persistent congestion just because the old path had one (the first-sample time was per connection)
        val (ld, l) = ld()
        ld.handshakeConfirmed = true
        ld.peerAddressValidated = true
        sampleByAck(ld, 0, t0 - 200.milliseconds)
        ld.rtt = RttEstimator(333.milliseconds)
        ld.activePath = 1
        for (pn in 1L..20L) send(ld, SpaceId.Application, pn, t0 + (pn.toInt() * 100).milliseconds, pathId = 1)
        ld.onAck(SpaceId.Application, ack(20L to 20L), t0 + 2100.milliseconds)
        assertEquals(listOf("1:false"), l.lossByPath, "no sample of the new path existed when its lost packets were sent")
    }

    @Test fun persistentCongestionOfAnotherPathIsJudgedByThatPathsRtt() {
        // RFC 9002 section 7.6.1: the duration comes from the RTT estimate; each path has its own (RFC 9000 section 9.4). Path A
        // (100 ms) loses 1.4 s of packets while the connection has moved to path B (400 ms, a 3.7 s period): A's losses are A's
        // persistent congestion, judged by A's estimate, and the restart of the period is A's, not B's. Back on A, its estimate
        // carries it
        val (ld, l) = ld()
        ld.handshakeConfirmed = true
        ld.peerAddressValidated = true
        val a = ld.rtt
        l.rtts[0] = a
        sampleByAck(ld, 0, t0 - 200.milliseconds)
        val b = RttEstimator(333.milliseconds)
        l.rtts[1] = b
        ld.rtt = b
        ld.activePath = 1
        for (pn in 1L..20L) send(ld, SpaceId.Application, pn, t0 + (pn.toInt() * 100).milliseconds, pathId = if (pn == 2L) 1 else 0)
        ld.onAck(SpaceId.Application, ack(2L to 2L), t0 + 600.milliseconds) // B's first sample, 400 ms
        val bFrom = b.persistentCongestionFrom
        assertEquals(t0 + 600.milliseconds, bFrom)
        ld.onAck(SpaceId.Application, ack(20L to 20L), t0 + 2100.milliseconds) // A's packets 3..17 lost
        assertEquals(listOf("0:false", "0:true"), l.lossByPath)
        assertEquals(t0 + 2100.milliseconds, a.persistentCongestionFrom, "A's period restarts")
        assertEquals(bFrom, b.persistentCongestionFrom, "B's does not")
        ld.rtt = a
        ld.activePath = 0
        assertEquals(t0 + 2100.milliseconds, ld.rtt.persistentCongestionFrom)
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

    /**
     * RFC 9000 section 13.4.2.1: "An endpoint MUST NOT fail ECN validation as a result of processing an ACK frame that does not
     * increase the largest acknowledged packet number." An ACK with the same largest that fills a gap below it, carrying older
     * (lower) counts, must not reach validation at all.
     */
    @Test fun negative_ackThatKeepsTheLargestAcknowledgedDoesNotReachEcnValidation() {
        val (ld, l) = ld()
        ld.handshakeConfirmed = true
        for (pn in 0L..3L) send(ld, SpaceId.Application, pn, t0, marked = true)
        ld.onAck(SpaceId.Application, ack(3L to 3L, ecn = longArrayOf(1, 0, 0)), t0 + 50.milliseconds)
        assertEquals(1, l.ecnCalls)
        ld.onAck(SpaceId.Application, ack(3L to 3L, 1L to 1L, ecn = longArrayOf(0, 0, 0)), t0 + 60.milliseconds)
        assertEquals(listOf(1L), l.acked.filter { it == 1L }, "packet 1 is newly acknowledged by the second frame")
        assertEquals(1, l.ecnCalls, "the largest acknowledged did not grow: no validation")
        assertEquals(listOf(true), l.ecnValid)
    }

    /**
     * RFC 9000 section 13.4.2.1: validation fails only "if the sum of the increase in ECT(0) and ECN-CE counts is less than the
     * number of newly acknowledged packets that were originally sent with an ECT(0) marking": every marked packet reported as CE
     * (ECT(0) unchanged) is valid.
     */
    @Test fun ceOnlyGrowthIsValidEcn() {
        val (ld, l) = ld()
        ld.handshakeConfirmed = true
        for (pn in 0L..1L) send(ld, SpaceId.Application, pn, t0, marked = true)
        ld.onAck(SpaceId.Application, ack(0L to 1L, ecn = longArrayOf(0, 0, 2)), t0 + 50.milliseconds)
        assertEquals(listOf(true), l.ecnValid, "two ECT(0) packets, both counted as CE")
    }

    /** RFC 9002 section 6.1: a packet declared lost and acknowledged later is a spurious loss, also when it is the top of a range. */
    @Test fun spuriousLossAtTheTopOfAnAckRangeIsFound() {
        val (ld, l) = ld()
        ld.handshakeConfirmed = true
        ld.peerAddressValidated = true
        for (pn in 0L..4L) send(ld, SpaceId.Application, pn, t0)
        ld.onAck(SpaceId.Application, ack(1L to 4L), t0 + 50.milliseconds)
        assertEquals(listOf(0L), l.lost)
        ld.onAck(SpaceId.Application, ack(1L to 4L, 0L to 0L), t0 + 60.milliseconds)
        assertEquals(listOf(0L), l.spurious, "the late ACK's range [0..0] has the lost packet as its largest")
    }

    /** A loss found spurious is not settled again later: [LossListener.onLossSettled] is for losses that stand. */
    @Test fun negative_spuriousLossIsNotSettledLater() {
        val (ld, l) = ld()
        ld.handshakeConfirmed = true
        ld.peerAddressValidated = true
        for (pn in 0L..4L) send(ld, SpaceId.Application, pn, t0)
        ld.onAck(SpaceId.Application, ack(1L to 4L), t0 + 50.milliseconds)
        ld.onAck(SpaceId.Application, ack(1L to 4L, 0L to 0L), t0 + 60.milliseconds)
        assertEquals(listOf(0L), l.spurious)
        send(ld, SpaceId.Application, 5, t0 + 10.seconds)
        ld.onAck(SpaceId.Application, ack(5L to 5L), t0 + 10.seconds + 50.milliseconds)
        assertEquals(0, l.settled, "the loss of 0 did not stand")
    }

    /** Every ACK frame opens with [LossListener.onAckFrameStart] (the controllers' "before the ACK" state) and an RTT sample is reported. */
    @Test fun eachAckFrameStartsOnceAndReportsItsRttSample() {
        val (ld, l) = ld()
        ld.handshakeConfirmed = true
        send(ld, SpaceId.Application, 0, t0)
        send(ld, SpaceId.Application, 1, t0)
        ld.onAck(SpaceId.Application, ack(0L to 0L), t0 + 50.milliseconds)
        ld.onAck(SpaceId.Application, ack(0L to 1L), t0 + 60.milliseconds)
        assertEquals(2, l.frameStarts)
        assertEquals(2, l.rttSamples)
    }

    /**
     * RFC 9002 section 7.6.2: persistent congestion needs that "across all packet number spaces, none of the packets sent between
     * the send times of these two packets are acknowledged" - any packet, an ACK-only one too, although loss detection does not
     * keep ACK-only packets. Packets 2..9 (ACK-only) acknowledged between the lost 1 and 10 show the path delivered in between;
     * left unacknowledged, the 1.9 s of losses are persistent congestion.
     */
    @Test fun negative_acknowledgedAckOnlyPacketsBetweenTheLostOnesBreakPersistentCongestion() {
        fun lossByPath(ackOnlyAcknowledged: Boolean): List<String> {
            val (ld, l) = ld()
            ld.handshakeConfirmed = true
            ld.peerAddressValidated = true
            sampleByAck(ld, 0, t0 - 200.milliseconds)
            send(ld, SpaceId.Application, 1, t0)
            for (pn in 2L..9L) send(ld, SpaceId.Application, pn, t0 + 100.milliseconds, ackEliciting = false)
            send(ld, SpaceId.Application, 10, t0 + 2000.milliseconds)
            send(ld, SpaceId.Application, 11, t0 + 2100.milliseconds)
            ld.onAck(SpaceId.Application, if (ackOnlyAcknowledged) ack(11L to 11L, 2L to 9L) else ack(11L to 11L), t0 + 2200.milliseconds)
            assertEquals(listOf(1L, 10L), l.lost)
            return l.lossByPath
        }
        assertEquals(listOf("0:false"), lossByPath(ackOnlyAcknowledged = true), "2..9 were acknowledged between 1 and 10")
        assertEquals(listOf("0:true"), lossByPath(ackOnlyAcknowledged = false))
    }

    /**
     * RFC 9002 section 7.6.2 when the acknowledged ranges overflow: more than [ACKED_KEEP] ranges acknowledged above a run of lost
     * packets must not hide the run's persistent congestion. What the check forgets may only err towards declaring it ("This might
     * result in erroneously declaring persistent congestion, but it will not lead to a failure to detect persistent congestion").
     */
    @Test fun negative_moreAckRangesThanKeptAboveALossRunDoNotHidePersistentCongestion() {
        val (ld, l) = ld()
        ld.handshakeConfirmed = true
        ld.peerAddressValidated = true
        sampleByAck(ld, 0, t0 - 200.milliseconds)
        // the run: ack-eliciting 1, 3, .., 39 over 3.8 s, an ACK-only packet (never acknowledged) between each two
        for (pn in 1L..40L) {
            send(ld, SpaceId.Application, pn, t0 + (pn.toInt() * 100).milliseconds, ackEliciting = pn % 2 == 1L)
        }
        for (pn in 41L..140L) send(ld, SpaceId.Application, pn, t0 + 4100.milliseconds)
        val odd = (139L downTo 41L step 2).map { it to it } // 50 ranges, all above the run
        ld.onAck(SpaceId.Application, ack(*odd.toTypedArray()), t0 + 4200.milliseconds)
        assertEquals((1L..39L step 2).toList(), l.lost.filter { it < 40 })
        assertTrue(l.lossByPath.single().endsWith("true"), "nothing between 1 and 39 was acknowledged: ${l.lossByPath}")
    }

    /**
     * RFC 9002 section 5.1: an RTT sample needs that "The largest acknowledged packet number is newly acknowledged". A later ACK
     * that only fills a gap below an already acknowledged largest gives none.
     */
    @Test fun negative_noRttSampleWhenTheLargestAcknowledgedIsNotNew() {
        val (ld, l) = ld()
        ld.handshakeConfirmed = true
        for (pn in 0L..2L) send(ld, SpaceId.Application, pn, t0)
        ld.onAck(SpaceId.Application, ack(2L to 2L), t0 + 50.milliseconds)
        assertEquals(50.milliseconds, ld.rtt.latest)
        ld.onAck(SpaceId.Application, ack(2L to 2L, 0L to 0L), t0 + 55.milliseconds)
        assertEquals(listOf(2L, 0L), l.acked)
        assertEquals(1, l.rttSamples, "the second frame's largest (2) was acknowledged before")
        assertEquals(50.milliseconds, ld.rtt.latest)
    }

    /** RFC 9002 section 5.3: a packet held for its keys is sampled at its arrival, also when it arrived the instant the packet left. */
    @Test fun sampleIsTakenAtArrivalEvenWhenItEqualsTheSendTime() {
        val (ld, _) = ld()
        ld.handshakeConfirmed = true
        send(ld, SpaceId.Application, 0, t0)
        ld.onAck(SpaceId.Application, ack(0L to 0L), t0 + 100.milliseconds, arrivedAt = t0)
        assertEquals(Duration.ZERO, ld.rtt.latest, "sampled at the arrival time, not at processing")
    }

    /**
     * RFC 9000 section 13.4.2.1 per path (the counts of a frame validate every path with newly acknowledged marked packets, and the
     * path of the largest newly acknowledged packet always hears the verdict): which paths `onEcnAck` reaches, with their marked counts.
     */
    @Test fun ecnVerdictReachesExactlyThePathsWithMarkedPacketsAndTheLargestsPath() {
        fun paths(
            marked0: Boolean,
            marked1: Boolean,
        ): List<String> {
            val (ld, l) = ld()
            ld.handshakeConfirmed = true
            send(ld, SpaceId.Application, 0, t0, marked = marked0, pathId = 0)
            send(ld, SpaceId.Application, 1, t0, marked = marked1, pathId = 1)
            ld.onAck(SpaceId.Application, ack(0L to 1L, ecn = longArrayOf(2, 0, 0)), t0 + 50.milliseconds)
            return l.ecnPaths.sorted()
        }
        assertEquals(listOf("0:1", "1:1"), paths(marked0 = true, marked1 = true), "both paths had marked packets")
        assertEquals(listOf("1:0"), paths(marked0 = false, marked1 = false), "nothing marked: only the largest's path")
        assertEquals(listOf("0:1", "1:0"), paths(marked0 = true, marked1 = false), "path 0 marked, path 1 holds the largest")
        assertEquals(listOf("1:1"), paths(marked0 = false, marked1 = true), "path 0 has nothing to validate")
    }

    /** RFC 9000 section 14.4: a lost PMTU probe is no congestion signal, so a path whose only lost packet was a probe sees no loss event. */
    @Test fun negative_lostPmtuProbeAloneRaisesNoLossEventOnItsPath() {
        val (ld, l) = ld()
        ld.handshakeConfirmed = true
        ld.peerAddressValidated = true
        send(ld, SpaceId.Application, 0, t0, pathId = 0)
        send(ld, SpaceId.Application, 1, t0, pathId = 1, flags = SentFrames.PMTU_PROBE)
        for (pn in 2L..4L) send(ld, SpaceId.Application, pn, t0 + 10.milliseconds)
        ld.onAck(SpaceId.Application, ack(4L to 4L), t0 + 60.milliseconds)
        assertEquals(listOf(0L, 1L), l.lost)
        assertEquals(listOf("0:false"), l.lossByPath)
    }

    /** RFC 9002 section 7.6.2: "The persistent congestion period SHOULD NOT start until there is at least one RTT sample." */
    @Test fun negative_noPersistentCongestionWithoutAnyRttSample() {
        val (ld, l) = ld()
        for (pn in 0L..3L) send(ld, SpaceId.Initial, pn, t0 + (pn * 2000).milliseconds)
        send(ld, SpaceId.Initial, 4, t0 + 6100.milliseconds, ackEliciting = false, inFlight = true)
        ld.onAck(SpaceId.Initial, ack(4L to 4L), t0 + 6200.milliseconds) // its largest elicits nothing: no sample
        assertTrue(!ld.rtt.hasSample)
        assertEquals(listOf(0L, 1L), l.lost.take(2))
        assertTrue(l.lossByPath.none { it.endsWith("true") }, "no RTT sample at all: ${l.lossByPath}")
    }

    /**
     * RFC 9002 section 7.6.2 and RFC 9000 section 14.4: the period is spanned by ack-eliciting packets of the path that count for
     * congestion; a lost PMTU probe (no congestion signal) or a packet of another path does not stretch it.
     */
    @Test fun negative_persistentCongestionIsNotStretchedByAProbeOrAnotherPathsPacket() {
        fun lossesWith(
            flags: Int,
            pathId: Int,
        ): List<String> {
            val (ld, l) = ld()
            ld.handshakeConfirmed = true
            ld.peerAddressValidated = true
            sampleByAck(ld, 0, t0 - 200.milliseconds)
            send(ld, SpaceId.Application, 1, t0)
            send(ld, SpaceId.Application, 2, t0 + 100.milliseconds)
            send(ld, SpaceId.Application, 3, t0 + 2000.milliseconds, pathId = pathId, flags = flags)
            for (pn in 4L..6L) send(ld, SpaceId.Application, pn, t0 + 2050.milliseconds)
            ld.onAck(SpaceId.Application, ack(6L to 6L), t0 + 2100.milliseconds)
            assertEquals(listOf(1L, 2L, 3L), l.lost)
            return l.lossByPath
        }
        assertEquals(listOf("0:false"), lossesWith(SentFrames.PMTU_PROBE, 0), "the 2 s probe does not count")
        assertEquals(listOf("0:false", "1:false"), lossesWith(0, 1), "path 1's packet is not part of path 0's period")
    }

    /** RFC 9002 section 7.6.2: persistent congestion needs a duration that "exceeds the persistent congestion duration": equal is not enough. */
    @Test fun negative_lossSpanEqualToTheDurationIsNotPersistentCongestion() {
        val (ld, l) = ld()
        ld.handshakeConfirmed = true
        ld.peerAddressValidated = true
        sampleByAck(ld, 0, t0 - 200.milliseconds)
        val d = ld.persistentCongestionDuration()
        send(ld, SpaceId.Application, 1, t0)
        send(ld, SpaceId.Application, 2, t0 + d)
        // ACK-less padding: the frame's largest elicits nothing, so no new sample changes the duration
        for (pn in 3L..5L) send(ld, SpaceId.Application, pn, t0 + d + 1.milliseconds, ackEliciting = false, inFlight = true)
        ld.onAck(SpaceId.Application, ack(5L to 5L), t0 + d + 2.milliseconds)
        assertEquals(d, ld.persistentCongestionDuration())
        assertEquals(listOf(1L, 2L), l.lost)
        assertEquals(listOf("0:false"), l.lossByPath, "a span of exactly $d")
    }

    /** RFC 9002 section 6.2.2.1 (anti-deadlock): the client's PTO with nothing ack-eliciting in flight is armed a PTO after the last send. */
    @Test fun antiDeadlockPtoIsArmedInTheFuture() {
        val (ld, _) = ld()
        send(ld, SpaceId.Initial, 0, t0, ackEliciting = false, inFlight = true)
        assertEquals(t0 + ld.rtt.smoothed + ld.rtt.rttVar * 4, ld.timeout())
    }

    /** RFC 9002 appendix A.8, GetPtoTimeAndSpace(): "if (no ack-eliciting packets in flight in space): continue;". */
    @Test fun negative_ptoIgnoresASpaceWithNothingAckElicitingInFlight() {
        val (ld, _) = ld()
        send(ld, SpaceId.Initial, 0, t0)
        ld.onAck(SpaceId.Initial, ack(0L to 0L), t0 + 50.milliseconds)
        send(ld, SpaceId.Handshake, 0, t0 + 1.seconds)
        val pto = ld.rtt.smoothed + maxOf(ld.rtt.rttVar * 4, 1.milliseconds)
        assertEquals(t0 + 1.seconds + pto, ld.timeout(), "the Handshake packet's PTO, not one from the acknowledged Initial")
    }

    /**
     * A PTO takes at most the [n] packets it asked for (RFC 9002 section 6.2.4: "An endpoint MAY send up to two full-sized datagrams
     * containing ack-eliciting packets").
     */
    @Test fun negative_takeForProbeTakesAtMostN() {
        val (ld, _) = ld()
        for (pn in 0L..3L) send(ld, SpaceId.Application, pn, t0, flags = SentFrames.HANDSHAKE_DONE)
        val out = ArrayList<SentPacket>()
        ld.takeForProbe(SpaceId.Application, 1, out)
        assertEquals(listOf(0L), out.map { it.pn })
    }

    /** Successive PTOs cycle through the outstanding packets (`takeForProbe`): a packet a probe took is not taken again. */
    @Test fun successiveProbesTakeDifferentPackets() {
        val (ld, _) = ld()
        for (pn in 0L..3L) send(ld, SpaceId.Application, pn, t0, flags = SentFrames.HANDSHAKE_DONE)
        val first = ArrayList<SentPacket>()
        ld.takeForProbe(SpaceId.Application, 1, first)
        val second = ArrayList<SentPacket>()
        ld.takeForProbe(SpaceId.Application, 1, second)
        assertEquals(listOf(0L), first.map { it.pn })
        assertEquals(listOf(1L), second.map { it.pn })
    }

    /** Discarding a space settles each remembered loss once; a loss settled earlier is not settled again. */
    @Test fun negative_discardSettlesNoLossTwice() {
        val (ld, l) = ld()
        for (pn in 0L..3L) send(ld, SpaceId.Initial, pn, t0)
        ld.onAck(SpaceId.Initial, ack(3L to 3L), t0 + 50.milliseconds) // 0 is lost (packet threshold)
        assertEquals(listOf(0L), l.lost)
        send(ld, SpaceId.Initial, 4, t0 + 10.seconds)
        ld.onAck(SpaceId.Initial, ack(1L to 4L), t0 + 10.seconds + 50.milliseconds) // the loss of 0 settles, nothing else is lost
        assertEquals(1, l.settled)
        ld.discard(SpaceId.Initial, t0 + 11.seconds)
        assertEquals(1, l.settled, "nothing left to settle")
    }

    /**
     * RFC 9002 section 7.6.2 across spaces, with the times kept as the KDoc of `keepAckedTimes` says: a discarded space's acknowledged
     * send times go with it, while the Application space's stay until both the Initial and the Handshake space are gone.
     */
    @Test fun ackedSendTimesFollowTheirSpaceOnDiscard() {
        fun lossByPath(discardFirst: SpaceId?): List<String> {
            val (ld, l) = ld()
            sampleByAck(ld, 0, t0 - 200.milliseconds)
            for (pn in 0L..15L) send(ld, SpaceId.Handshake, pn, t0 + (pn.toInt() * 100).milliseconds)
            send(ld, SpaceId.Application, 1, t0 + 750.milliseconds)
            ld.onAck(SpaceId.Application, ack(1L to 1L), t0 + 800.milliseconds)
            if (discardFirst != null) ld.discard(discardFirst, t0 + 801.milliseconds)
            ld.onAck(SpaceId.Handshake, ack(15L to 15L), t0 + 1600.milliseconds)
            return l.lossByPath
        }
        assertEquals(listOf("0:false"), lossByPath(SpaceId.Initial), "the Application time stays while the Handshake space lives")
        val (ld, l) = ld()
        sampleByAck(ld, 0, t0 - 200.milliseconds)
        for (pn in 0L..15L) send(ld, SpaceId.Application, pn + 1, t0 + (pn.toInt() * 100).milliseconds)
        send(ld, SpaceId.Handshake, 0, t0 + 750.milliseconds)
        ld.onAck(SpaceId.Handshake, ack(0L to 0L), t0 + 800.milliseconds)
        ld.discard(SpaceId.Handshake, t0 + 801.milliseconds)
        ld.handshakeConfirmed = true
        ld.onAck(SpaceId.Application, ack(16L to 16L), t0 + 1600.milliseconds)
        assertEquals(listOf("0:true"), l.lossByPath, "the discarded Handshake space's acknowledged time went with it")
    }
}

private fun Int.microsecondsAsDuration(): Duration = kotlin.time.Duration.parse("${this}us")
