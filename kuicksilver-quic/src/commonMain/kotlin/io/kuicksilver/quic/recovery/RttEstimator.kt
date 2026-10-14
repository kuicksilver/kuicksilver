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
