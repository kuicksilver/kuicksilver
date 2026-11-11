// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.recovery

import kotlin.time.Duration
import kotlin.time.Duration.Companion.nanoseconds

/** RTT estimation (RFC 9002 section 5). */
internal class RttEstimator(
    initial: Duration,
) {
    var latest: Duration = initial
        private set
    var smoothed: Duration = initial
        private set
    var rttVar: Duration = initial / 2
        private set
    var min: Duration = initial
        private set
    var hasSample: Boolean = false
        private set

    /**
     * Lost packets sent before this mark do not count toward persistent congestion (RFC 9002 section 7.6.2: "a prior RTT sample
     * existed when these two packets were sent"): when this path took its first sample, or its newest one once persistent
     * congestion was established. Per path, as the estimator: a new path's packets wait for that path's own first sample.
     */
    var persistentCongestionFrom: io.kuicksilver.quic.TimeMark = io.kuicksilver.quic.TimeMark.NEVER

    /** RFC 9002 section 5.2: after persistent congestion min_rtt restarts from the newest sample. */
    fun onPersistentCongestion() {
        if (hasSample) min = latest
    }

    fun onSample(
        latest: Duration,
        ackDelay: Duration,
        handshakeConfirmed: Boolean,
        maxAckDelay: Duration,
    ) {
        this.latest = latest
        if (!hasSample) {
            hasSample = true
            min = latest
            smoothed = latest
            rttVar = latest / 2
            return
        }
        if (latest < min) min = latest
        var delay = ackDelay
        if (handshakeConfirmed && delay > maxAckDelay) delay = maxAckDelay
        var adjusted = latest
        if (latest >= min + delay) adjusted = latest - delay
        val diff = (smoothed - adjusted).let { if (it.isNegative()) -it else it }
        rttVar = (rttVar.inWholeNanoseconds * 3 / 4 + diff.inWholeNanoseconds / 4).nanoseconds
        smoothed = (smoothed.inWholeNanoseconds * 7 / 8 + adjusted.inWholeNanoseconds / 8).nanoseconds
    }
}
