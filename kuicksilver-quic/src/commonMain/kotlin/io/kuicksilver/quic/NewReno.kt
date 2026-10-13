// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import kotlin.time.Duration

/**
 * NewReno congestion control (RFC 9002 section 7, appendix B): slow start, halving on a congestion event, one datagram
 * of growth per window in congestion avoidance, collapse to the minimum window on persistent congestion.
 */
@OptIn(ExperimentalKuicksilverApi::class)
public class NewReno(
    maxDatagramSize: Int = 1200,
) : CongestionController {
    private var maxDatagramSize: Int = maxDatagramSize
    private var minWindow: Long = 2L * maxDatagramSize
    override var cwnd: Long = initialWindow(maxDatagramSize)
        private set
    override var bytesInFlight: Long = 0
        private set

    /** Slow start threshold; infinite until the first congestion event. */
    public var ssthresh: Long = Long.MAX_VALUE
        private set
    private var recoveryStart: TimeMark? = null

    /** Bytes acknowledged in congestion avoidance not yet turned into growth: max_datagram_size x bytes / cwnd in whole bytes. */
    private var caAcked: Long = 0

    private fun initialWindow(mtu: Int): Long = minOf(10L * mtu, maxOf(14720L, 2L * mtu))

    override fun onPacketSent(
        now: TimeMark,
        bytes: Int,
    ) {
        bytesInFlight += bytes
    }

    override fun onAck(
        now: TimeMark,
        sentTime: TimeMark,
        bytes: Int,
        smoothedRtt: Duration,
        appLimited: Boolean,
    ) {
        bytesInFlight -= bytes
        if (appLimited) return
        val rs = recoveryStart
        if (rs != null && sentTime <= rs) return // acknowledged packet was sent before recovery started
        if (cwnd < ssthresh) {
            cwnd += bytes
        } else {
            // RFC 9002 section 7.3.3 (appendix B.5: max_datagram_size x acked / cwnd) with the remainder carried over: in integer bytes
            // the quotient alone is 0 for every packet once cwnd exceeds max_datagram_size squared (1.44 MB at 1200)
            caAcked += maxDatagramSize.toLong() * bytes
            if (caAcked >= cwnd) {
                val grow = caAcked / cwnd
                caAcked -= grow * cwnd
                cwnd += grow
            }
        }
    }

    private fun congestionEvent(
        now: TimeMark,
        sentTime: TimeMark,
    ) {
        val rs = recoveryStart
        if (rs != null && sentTime <= rs) return
        recoveryStart = now
        caAcked = 0
        cwnd = maxOf(cwnd / 2, minWindow)
        ssthresh = cwnd
    }

    override fun onLoss(
        now: TimeMark,
        lostBytes: Int,
        largestLostSentTime: TimeMark,
        persistentCongestion: Boolean,
    ) {
        bytesInFlight -= lostBytes
        congestionEvent(now, largestLostSentTime)
        if (persistentCongestion) {
            cwnd = minWindow
            recoveryStart = null
        }
    }

    override fun onEcnCe(
        now: TimeMark,
        sentTime: TimeMark,
    ) {
        congestionEvent(now, sentTime)
    }

    override fun onDiscarded(bytes: Int) {
        bytesInFlight -= bytes
    }

    override fun onMtuUpdate(maxDatagramSize: Int) {
        this.maxDatagramSize = maxDatagramSize
        minWindow = 2L * maxDatagramSize
    }

    /** 1.25 × cwnd per smoothed RTT (RFC 9002 section 7.7). */
    override fun pacingRate(smoothedRtt: Duration): Long {
        val nanos = maxOf(smoothedRtt.inWholeNanoseconds, 1L)
        return cwnd * 5 / 4 *
            1_000_000_000L /
            nanos
    }

    override val sendQuantum: Int get() = minOf(65_536, 10 * maxDatagramSize)
}
