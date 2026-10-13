// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.recovery

import io.kuicksilver.quic.TimeMark
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds

/** Delivery-rate sampling of draft-ietf-ccwg-bbr section 4.1. */
class DeliveryRateSamplerTest {
    private val t0 = TimeMark(1_000_000_000L)
    private var inflight = 0L

    private fun send(
        s: DeliveryRateSampler,
        at: TimeMark,
        size: Int = 1000,
    ): SentPacket =
        SentPacket().also {
            it.timeSent = at
            it.size = size
            it.inFlight = true
            inflight += size
            s.onSent(it, at, inflight)
        }

    private fun ack(
        s: DeliveryRateSampler,
        at: TimeMark,
        minRtt: Duration,
        vararg ps: SentPacket,
    ): Boolean {
        s.begin()
        for (p in ps) {
            inflight -= p.size
            s.onAcked(p, at)
        }
        return s.generate(minRtt.inWholeNanoseconds)
    }

    @Test fun aSteadyFlowSamplesItsRate() {
        val s = DeliveryRateSampler()
        // 1000 bytes every 1 ms (1 MB/s), each acknowledged 50 ms after it left
        val sent = ArrayList<SentPacket>()
        for (i in 0 until 200) {
            val at = t0 + i.milliseconds
            while (sent.isNotEmpty() &&
                sent[0].timeSent + 50.milliseconds <= at
            ) {
                ack(s, sent[0].timeSent + 50.milliseconds, 50.milliseconds, sent.removeAt(0))
            }
            sent += send(s, at)
        }
        assertTrue(s.hasData)
        assertEquals(1_000_000.0, s.deliveryRate.toDouble(), 30_000.0, "rate ${s.deliveryRate}")
        assertEquals(50.milliseconds.inWholeNanoseconds, s.sampleRttNanos)
        assertFalse(s.sampleAppLimited)
    }

    @Test fun theNewestAcknowledgedPacketMakesTheSampleAndTheLongerIntervalWins() {
        val s = DeliveryRateSampler()
        val a = send(s, t0)
        val b = send(s, t0 + 10.milliseconds)
        // both acknowledged together after 40 ms: the snapshot of b (sent last) counts; its send interval is 10 ms, its ACK interval 50 ms
        assertTrue(ack(s, t0 + 50.milliseconds, 1.milliseconds, b, a))
        assertEquals(2000, s.sampleDelivered)
        assertEquals(50.milliseconds.inWholeNanoseconds, s.intervalNanos)
        assertEquals(40_000, s.deliveryRate) // 2000 bytes / 50 ms
        assertEquals(2000, s.newlyAcked)
    }

    @Test fun anIntervalShorterThanMinRttGivesNoRate() {
        val s = DeliveryRateSampler()
        val a = send(s, t0)
        assertTrue(ack(s, t0 + 5.milliseconds, 20.milliseconds, a))
        assertEquals(0, s.deliveryRate) // ACK compression could make it look arbitrarily fast
        assertEquals(1000, s.sampleDelivered)
    }

    @Test fun anAckOfNothingStampedIsNoSample() {
        val s = DeliveryRateSampler()
        s.begin()
        s.onAcked(SentPacket(), t0)
        assertFalse(s.generate(0))
    }

    @Test fun appLimitedPacketsMarkTheirSamplesUntilTheBubbleIsAcknowledged() {
        val s = DeliveryRateSampler()
        val a = send(s, t0)
        s.markAppLimited(inflight) // the application has nothing more: 1000 bytes in flight
        val b = send(s, t0 + 1.milliseconds)
        assertTrue(b.rsAppLimited)
        ack(s, t0 + 40.milliseconds, 1.milliseconds, a)
        assertFalse(s.sampleAppLimited)
        assertTrue(s.appLimited != 0L, "the bubble ends with the delivery of b")
        ack(s, t0 + 41.milliseconds, 1.milliseconds, b)
        assertTrue(s.sampleAppLimited)
        assertEquals(0, s.appLimited) // delivered passed the mark: no longer application-limited
        val c = send(s, t0 + 42.milliseconds)
        assertFalse(c.rsAppLimited)
    }

    @Test fun lossesSinceAPacketLeftAreCounted() {
        val s = DeliveryRateSampler()
        val a = send(s, t0)
        val b = send(s, t0 + 1.milliseconds)
        val c = send(s, t0 + 2.milliseconds)
        inflight -= b.size
        s.onLost(b)
        ack(s, t0 + 40.milliseconds, 1.milliseconds, c)
        assertEquals(1000, s.sampleLost)
        assertEquals(3000, s.sampleTxInFlight)
        ack(s, t0 + 41.milliseconds, 1.milliseconds, a)
        assertEquals(1000, s.sampleLost) // b was lost after a left too
    }

    @Test fun anIdleStartBeginsTheIntervalAtTheSend() {
        val s = DeliveryRateSampler()
        val a = send(s, t0)
        ack(s, t0 + 30.milliseconds, 1.milliseconds, a)
        val b = send(s, t0 + 1000.milliseconds) // nothing in flight: the interval starts now, not at the last ACK
        assertEquals(t0 + 1000.milliseconds, b.rsDeliveredTime)
        assertEquals(t0 + 1000.milliseconds, b.rsFirstSentTime)
    }
}
