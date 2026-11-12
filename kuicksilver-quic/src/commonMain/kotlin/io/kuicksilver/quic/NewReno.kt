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

    /**
     * RFC 9002 section 7.2: the initial window is recalculated with the new size, and a window still at the initial one (slow
     * start, never grown or reduced) shrinks with a smaller size. A larger size never raises the window in bytes (RFC 8899
     * section 3 item 7: "An update to the PLPMTU (or MPS) MUST NOT increase the congestion window measured in bytes").
     */
    override fun onMtuUpdate(maxDatagramSize: Int) {
        val initial = cwnd == initialWindow(this.maxDatagramSize) && ssthresh == Long.MAX_VALUE
        this.maxDatagramSize = maxDatagramSize
        minWindow = 2L * maxDatagramSize
        if (initial) cwnd = minOf(cwnd, initialWindow(maxDatagramSize))
    }

    /** 1.25 × cwnd per smoothed RTT (RFC 9002 section 7.7). */
    override fun pacingRate(smoothedRtt: Duration): Long = windowPacingRate(cwnd, smoothedRtt)

    /** The initial window (RFC 9002 section 7.7: "Senders SHOULD limit bursts to the initial congestion window"), at most 64 KiB or one datagram. */
    override val sendQuantum: Int get() = minOf(initialWindow(maxDatagramSize), maxOf(65_536L, maxDatagramSize.toLong())).toInt()
}

/**
 * 1.25 x [cwnd] per [smoothedRtt] in bytes a second (RFC 9002 section 7.7), at least 1 ns of RTT. Exact in Long arithmetic up to a
 * window of about 7.4 GB; above that cwnd x 5 / 4 x 10^9 would overflow (and the pacer then waited hours for a negative rate), so
 * the rate is computed in Double and saturates at Long.MAX_VALUE.
 */
internal fun windowPacingRate(
    cwnd: Long,
    smoothedRtt: Duration,
): Long {
    val nanos = maxOf(smoothedRtt.inWholeNanoseconds, 1L)
    if (cwnd <= EXACT_PACING_WINDOW) return cwnd * 5 / 4 * 1_000_000_000L / nanos
    val r = cwnd * 1.25e9 / nanos
    return if (r >= Long.MAX_VALUE.toDouble()) Long.MAX_VALUE else r.toLong()
}

/** The largest window whose cwnd x 5 / 4 x 10^9 fits a Long. */
private const val EXACT_PACING_WINDOW: Long = Long.MAX_VALUE / 1_000_000_000L * 4 / 5
