// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import kotlin.math.cbrt
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds

/**
 * CUBIC congestion control (RFC 9438) with HyStart++ (RFC 9406), the default controller. Byte arithmetic throughout:
 * C = 0.4, beta = 0.7, fast convergence, and the Reno-friendly region (alpha = 3(1 - beta)/(1 + beta)) so a short-RTT
 * flow never grows slower than Reno. Slow start ends by HyStart++ (an RTT increase enters Conservative Slow Start, five
 * CSS rounds end slow start, an RTT drop returns to slow start) or by the first congestion event. Pacing and the send
 * quantum are those of [NewReno]. Nothing here allocates after construction.
 */
@OptIn(ExperimentalKuicksilverApi::class)
public class Cubic(
    maxDatagramSize: Int = 1200,
    private val hystart: Boolean = true,
) : CongestionController {
    private var mss: Int = maxDatagramSize
    private var minWindow: Long = 2L * maxDatagramSize
    override var cwnd: Long = initialWindow(maxDatagramSize)
        private set
    override var bytesInFlight: Long = 0
        private set

    /** Slow start threshold; infinite until slow start ends. */
    public var ssthresh: Long = Long.MAX_VALUE
        private set

    /** The window at the last congestion event (after fast convergence), the plateau the cubic curve returns to. */
    public var wMax: Long = 0
        private set
    private var k: Double = 0.0 // seconds from the epoch start to W_max
    private var epochStart: TimeMark = TimeMark.NEVER
    private var wEst: Double = 0.0 // Reno-friendly estimate (bytes)
    private var alpha: Double = ALPHA // alpha_cubic of the Reno-friendly estimate (section 4.3)
    private var cwndPrior: Long = 0 // the window just before the last reduction
    private var recoveryStart: TimeMark = TimeMark.NEVER
    private var lastSent: TimeMark = TimeMark(0)

    /**
     * RFC 9438 section 4.2: "The elapsed time t in Figure 1 MUST NOT include periods during which cwnd has not been updated due to
     * application-limited behavior". Two such periods move the epoch forward by their length: from an ACK that arrived
     * application-limited to the next one that did not ([pausedSince]), and from the moment nothing was left in flight to the
     * next send ([drainedAt], as Linux's tcp_cubic does on CA_EVENT_TX_START; quic-go restarts the epoch instead).
     */
    private var pausedSince: TimeMark = TimeMark.NEVER
    private var drainedAt: TimeMark = TimeMark.NEVER

    // HyStart++ (RFC 9406 section 4): rounds end on the ACK of a packet sent after the round began
    private var roundEndSent: TimeMark = TimeMark.NEVER
    private var roundSamples = 0
    private var currRttMin: Duration = Duration.INFINITE
    private var lastRttMin: Duration = Duration.INFINITE
    private var cssBaseline: Duration = Duration.INFINITE
    private var cssRounds = 0

    /** True while HyStart++ holds the flow in Conservative Slow Start. */
    public var inConservativeSlowStart: Boolean = false
        private set

    private fun initialWindow(mtu: Int): Long = minOf(10L * mtu, maxOf(14720L, 2L * mtu))

    private val inSlowStart: Boolean get() = cwnd < ssthresh

    override fun onPacketSent(
        now: TimeMark,
        bytes: Int,
    ) {
        if (bytesInFlight == 0L && drainedAt != TimeMark.NEVER) {
            if (pausedSince == TimeMark.NEVER && epochStart != TimeMark.NEVER && now > drainedAt) epochStart += now - drainedAt
            drainedAt = TimeMark.NEVER
        } // idle with nothing in flight (an application-limited pause already covers that time)
        bytesInFlight += bytes
        lastSent = now
    }

    /** The sample of the ACK being processed; it belongs to the round of the packets that ACK acknowledges, so it is consumed in [onAck]. */
    private var pendingSample: Duration = Duration.INFINITE

    override fun onRttSample(
        now: TimeMark,
        latest: Duration,
        min: Duration,
    ) {
        if (hystart && inSlowStart) pendingSample = latest
    }

    private fun consumeSample() {
        val s = pendingSample
        if (s == Duration.INFINITE) return
        pendingSample = Duration.INFINITE
        if (roundSamples < N_RTT_SAMPLE) {
            roundSamples++
            if (s < currRttMin) currRttMin = s
        }
        if (roundSamples == N_RTT_SAMPLE && lastRttMin != Duration.INFINITE && !inConservativeSlowStart) {
            val thresh = (lastRttMin / MIN_RTT_DIVISOR).coerceIn(MIN_RTT_THRESH, MAX_RTT_THRESH)
            if (currRttMin >= lastRttMin + thresh) {
                inConservativeSlowStart = true
                cssBaseline = lastRttMin
                cssRounds = 0
            } // section 4.2: the RTT rose, approach the limit carefully
        }
    }

    private fun endRound() {
        if (inConservativeSlowStart) {
            if (currRttMin < cssBaseline) {
                inConservativeSlowStart = false
                cssRounds = 0
            } // the increase was spurious: back to plain slow start
            else if (++cssRounds >= CSS_ROUNDS) {
                ssthresh = cwnd
                inConservativeSlowStart = false
            } // section 4.2: five CSS rounds end slow start
        }
        lastRttMin = currRttMin
        currRttMin = Duration.INFINITE
        roundSamples = 0
    }

    override fun onAck(
        now: TimeMark,
        sentTime: TimeMark,
        bytes: Int,
        smoothedRtt: Duration,
        appLimited: Boolean,
    ) {
        bytesInFlight -= bytes
        if (hystart &&
            inSlowStart
        ) {
            if (roundEndSent == TimeMark.NEVER ||
                sentTime > roundEndSent
            ) {
                if (roundEndSent != TimeMark.NEVER) endRound()
                roundEndSent = lastSent
            }
            consumeSample()
        }
        grow(now, sentTime, bytes, smoothedRtt, appLimited)
        if (bytesInFlight == 0L) drainedAt = now
    }

    private fun grow(
        now: TimeMark,
        sentTime: TimeMark,
        bytes: Int,
        smoothedRtt: Duration,
        appLimited: Boolean,
    ) {
        if (appLimited) {
            pause(now)
            return
        }
        if (recoveryStart != TimeMark.NEVER && sentTime <= recoveryStart) return
        if (inSlowStart) {
            cwnd += if (inConservativeSlowStart) (bytes / CSS_GROWTH_DIVISOR).toLong() else bytes.toLong()
            return
        }
        // congestion avoidance (RFC 9438 section 4.2): the cubic target one RTT ahead, clamped to [cwnd, 1.5 cwnd]
        if (epochStart == TimeMark.NEVER) {
            epochStart = now
            wMax = cwnd
            k = 0.0
            wEst = cwnd.toDouble()
        } else if (pausedSince != TimeMark.NEVER && pausedSince < now) {
            epochStart += now - pausedSince
        } // the application-limited ACKs since then did not move the window
        pausedSince = TimeMark.NEVER
        val t = (now - epochStart + smoothedRtt).inWholeNanoseconds / 1e9
        val d = t - k
        var target = wMax + (C * d * d * d * mss).toLong()
        if (target < cwnd) {
            target = cwnd
        } else if (target > cwnd * 3 / 2) {
            target = cwnd * 3 / 2
        }
        cwnd += (target - cwnd) * bytes / cwnd
        // Reno-friendly region (section 4.3): W_est grows alpha segments per RTT, cwnd never falls behind it; once W_est is back at
        // the window before the reduction, alpha is 1 ("the sender SHOULD set alpha_cubic to 1"): Reno's own rate from there on
        wEst += alpha * bytes.toDouble() * mss / cwnd
        if (alpha < 1.0 && wEst >= cwndPrior) alpha = 1.0
        if (wEst > cwnd) cwnd = wEst.toLong()
    }

    private fun congestionEvent(
        now: TimeMark,
        sentTime: TimeMark,
    ) {
        if (recoveryStart != TimeMark.NEVER && sentTime <= recoveryStart) return
        recoveryStart = now
        cwndPrior = cwnd
        alpha = ALPHA
        // fast convergence (section 4.6): W_max = cwnd (1 + beta) / 2
        wMax = if (cwnd < wMax) cwnd * (BETA_DEN + BETA_NUM) / (2 * BETA_DEN) else cwnd
        cwnd = maxOf(cwnd * BETA_NUM / BETA_DEN, minWindow)
        ssthresh = cwnd
        epochStart = now
        pausedSince = TimeMark.NEVER
        k = cbrt((wMax - cwnd).toDouble() / mss / C)
        wEst = cwnd.toDouble()
        inConservativeSlowStart = false
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
            recoveryStart = TimeMark.NEVER
            epochStart = TimeMark.NEVER
        }
        if (bytesInFlight == 0L) drainedAt = now
    }

    private fun pause(now: TimeMark) {
        if (pausedSince == TimeMark.NEVER) pausedSince = now
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
        mss = maxDatagramSize
        minWindow = 2L * maxDatagramSize
    }

    /** 1.25 x cwnd per smoothed RTT (RFC 9002 section 7.7). */
    override fun pacingRate(smoothedRtt: Duration): Long {
        val nanos = maxOf(smoothedRtt.inWholeNanoseconds, 1L)
        return cwnd * 5 / 4 *
            1_000_000_000L /
            nanos
    }

    override val sendQuantum: Int get() = minOf(65_536, 10 * mss)

    private companion object {
        const val C = 0.4 // RFC 9438 section 5
        const val BETA_NUM = 7L
        const val BETA_DEN = 10L // beta = 0.7
        const val ALPHA = 3.0 * (1 - 0.7) / (1 + 0.7) // section 4.3
        val MIN_RTT_THRESH = 4.milliseconds
        val MAX_RTT_THRESH = 16.milliseconds
        const val MIN_RTT_DIVISOR = 8
        const val N_RTT_SAMPLE = 8
        const val CSS_GROWTH_DIVISOR = 4
        const val CSS_ROUNDS = 5 // RFC 9406 section 4.3
    }
}
