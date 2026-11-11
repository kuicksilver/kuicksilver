// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.recovery

import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.quic.Bbr
import io.kuicksilver.quic.CongestionController
import io.kuicksilver.quic.TimeMark
import kotlin.time.Duration
import kotlin.time.Duration.Companion.nanoseconds

/**
 * Token-bucket pacing at the controller's rate (RFC 9002 section 7.7: "A sender SHOULD pace sending of all in-flight packets";
 * "Senders MUST either use pacing or limit such bursts"), at every smoothed RTT: bursts up to
 * [CongestionController.sendQuantum], which for [io.kuicksilver.quic.NewReno] and [io.kuicksilver.quic.Cubic] is the initial
 * window ("Senders SHOULD limit bursts to the initial congestion window") and for [Bbr] its own quantum (draft-ietf-ccwg-bbr
 * section 5.6.3). Below 1 ms of RTT the window-based rate, 1.25 x cwnd / sRTT, refills a burst within microseconds.
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
        // past the time that fills the bucket it is simply full: rate x elapsed would overflow after a long gap (a minute at
        // 100 MB/s, 10 Gbit/s x 7.4 s), and a refill that came out negative left the sender waiting for credit that never came
        val missing = burst - credit
        if (missing <= 0 || elapsed >= (missing * 1_000_000_000L + rate - 1) / rate) {
            credit = burst
            lastRefill = now
            return
        }
        val add = rate * elapsed / 1_000_000_000L // elapsed < the fill time: at most missing x 10^9 + rate, no overflow
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
