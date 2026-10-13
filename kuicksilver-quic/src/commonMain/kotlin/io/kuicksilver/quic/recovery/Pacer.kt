// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.recovery

import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.quic.Bbr
import io.kuicksilver.quic.CongestionController
import io.kuicksilver.quic.TimeMark
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.nanoseconds

/**
 * Token-bucket pacing at the controller's rate (RFC 9002 section 7.7): bursts up to [CongestionController.sendQuantum]. A
 * window-based controller is not paced when the smoothed RTT is below 1 ms; [Bbr] always is, because its pacing rate is its
 * primary control (draft-ietf-ccwg-bbr section 5.6.2) and its send quantum already bounds the timer rate to about one per ms.
 */
@OptIn(ExperimentalKuicksilverApi::class)
internal class Pacer {
    private var credit: Long = -1 // bytes that may be sent now; -1 = full burst on first use
    private var lastRefill: TimeMark = TimeMark(0)

    private fun refill(
        now: TimeMark,
        cc: CongestionController,
        srtt: Duration,
    ) {
        val burst = cc.sendQuantum.toLong()
        if (credit < 0) {
            credit = burst
            lastRefill = now
            return
        }
        val elapsed = (now - lastRefill).inWholeNanoseconds
        if (elapsed <= 0) return
        val rate = maxOf(cc.pacingRate(srtt), 1L)
        // the time that fills the bucket bounds the product: rate x a long idle gap would overflow (10 Gbit/s x 7.4 s) and stall
        val fill = (burst - minOf(credit, burst)) * 1_000_000_000L / rate + 1
        val add = rate * minOf(elapsed, fill) / 1_000_000_000L
        if (add <= 0) return // too little time for a whole byte: keep accumulating from lastRefill (no truncation drift)
        credit = minOf(burst, credit + add)
        lastRefill = now
    }

    /** When [bytes] may leave: null for now, else the time the bucket holds enough credit. */
    fun nextSendTime(
        now: TimeMark,
        bytes: Int,
        cc: CongestionController,
        smoothedRtt: Duration,
    ): TimeMark {
        if (smoothedRtt < 1.milliseconds && cc !is Bbr) return TimeMark.NEVER
        refill(now, cc, smoothedRtt)
        if (credit >= bytes) return TimeMark.NEVER
        val rate = maxOf(cc.pacingRate(smoothedRtt), 1L)
        return now + ((bytes - credit) * 1_000_000_000L / rate).nanoseconds
    }

    fun onSent(
        now: TimeMark,
        bytes: Int,
    ) {
        if (credit < 0) credit = 0
        credit -= bytes
        if (credit < 0) credit = 0
    }
}
