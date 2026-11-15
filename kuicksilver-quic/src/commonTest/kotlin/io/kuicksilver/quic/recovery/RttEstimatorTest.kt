// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.recovery

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds

class RttEstimatorTest {
    private val max = 25.milliseconds

    @Test fun initialValues() {
        val r = RttEstimator(333.milliseconds)
        assertEquals(333.milliseconds, r.smoothed)
        assertEquals(166.5.milliseconds, r.rttVar)
        assertFalse(r.hasSample)
    }

    @Test fun firstSample100ms() {
        val r = RttEstimator(333.milliseconds)
        r.onSample(100.milliseconds, 0.milliseconds, true, max)
        assertEquals(100.milliseconds, r.smoothed)
        assertEquals(50.milliseconds, r.rttVar)
        assertEquals(100.milliseconds, r.min)
        assertTrue(r.hasSample)
    }

    @Test fun secondSampleWithAckDelay() {
        val r = RttEstimator(333.milliseconds)
        r.onSample(100.milliseconds, 0.milliseconds, true, max)
        r.onSample(140.milliseconds, 20.milliseconds, true, max)
        assertEquals(102.5.milliseconds, r.smoothed)
        assertEquals(42.5.milliseconds, r.rttVar)
        assertEquals(140.milliseconds, r.latest)
        assertEquals(100.milliseconds, r.min)
    }

    @Test fun ackDelayNotClampedBeforeHandshakeConfirmed() {
        // RFC 9002 section 5.3: ack_delay is limited by max_ack_delay only once the handshake is confirmed
        val r = RttEstimator(333.milliseconds)
        r.onSample(100.milliseconds, 0.milliseconds, false, max)
        r.onSample(180.milliseconds, 40.milliseconds, false, max)
        assertEquals(105.milliseconds, r.smoothed) // adjusted 140
    }

    @Test fun ackDelayClampedToMaxAckDelay() {
        val r = RttEstimator(333.milliseconds)
        r.onSample(100.milliseconds, 0.milliseconds, true, max)
        r.onSample(180.milliseconds, 40.milliseconds, true, max)
        assertEquals(106.875.milliseconds, r.smoothed) // adjusted 155 = 180 - 25
    }

    @Test fun adjustedNeverBelowMinRtt() {
        val r = RttEstimator(333.milliseconds)
        r.onSample(100.milliseconds, 0.milliseconds, true, max)
        r.onSample(110.milliseconds, 20.milliseconds, true, max)
        assertEquals(101.25.milliseconds, r.smoothed) // 110 < min + 20: adjusted stays 110
    }

    /**
     * RFC 9002 section 5.3: "if (latest_rtt >= min_rtt + ack_delay): adjusted_rtt = latest_rtt - ack_delay". At equality the delay
     * is subtracted: a 60 ms sample with 10 ms of ack delay over a 50 ms minimum is a 50 ms sample.
     */
    @Test fun negative_ackDelayIsSubtractedWhenTheSampleEqualsMinPlusDelay() {
        val r = RttEstimator(333.milliseconds)
        r.onSample(50.milliseconds, 0.milliseconds, true, max)
        r.onSample(60.milliseconds, 10.milliseconds, true, max)
        assertEquals(50.milliseconds, r.smoothed)
        assertEquals(18.75.milliseconds, r.rttVar)
    }
}
