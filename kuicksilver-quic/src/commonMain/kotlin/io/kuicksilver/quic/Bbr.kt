// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.quic.recovery.DeliveryRateSampler
import io.kuicksilver.quic.recovery.SentPacket
import io.kuicksilver.quic.recovery.WindowedMaxFilter
import kotlin.random.Random
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

/**
 * BBR congestion control as specified by draft-ietf-ccwg-bbr (BBRv3): a model-based controller that paces at its estimate of
 * the bottleneck bandwidth and keeps about one bandwidth-delay product in flight, instead of reacting to every loss.
 *
 * The model is a windowed maximum of delivery-rate samples (two ProbeBW cycles) and a windowed minimum RTT (10 s, refreshed by
 * ProbeRTT every 5 s), bounded by loss: a probe that loses more than 2 % of what it had in flight caps the long-term inflight
 * (`inflight_longterm`), and every round with loss outside a probe scales the short-term bounds (`bw_shortterm`,
 * `inflight_shortterm`) by 0.7. The state machine is Startup, Drain, ProbeBW (Down, Cruise, Refill, Up) and ProbeRTT. ECN-CE
 * counts as loss for the round (the draft leaves the ECN response open but requires CE to be treated as congestion), and a
 * CE mark while probing ends the probe as excess loss would.
 *
 * Experimental and opt-in: `quicConfig { congestionController = { Bbr() } }`. BBR tolerates random loss far better than
 * [Cubic] and keeps the bottleneck queue short, but it shares a bottleneck with loss-based flows less predictably (it can take
 * more or less than its share depending on the buffer size). Not implemented: undo after a spurious loss (the core has no
 * spurious-loss signal). Nothing here allocates after construction.
 *
 * [random] desynchronises the bandwidth probes of flows sharing a bottleneck (the 2-3 s probe wait); without one the jitter is
 * derived from the send and ACK times, which differ between flows.
 */
@ExperimentalKuicksilverApi
@OptIn(ExperimentalKuicksilverApi::class)
public class Bbr(
    maxDatagramSize: Int = 1200,
    private val random: Random? = null,
) : CongestionController {
    internal enum class State { Startup, Drain, ProbeBwDown, ProbeBwCruise, ProbeBwRefill, ProbeBwUp, ProbeRtt }

    private enum class AckPhase { Init, Refilling, ProbeStarting, ProbeFeedback, ProbeStopping }

    internal val sampler = DeliveryRateSampler()
    private var mss: Int = maxDatagramSize
    private val initialCwnd: Long = minOf(10L * maxDatagramSize, maxOf(14720L, 2L * maxDatagramSize))

    override var cwnd: Long = initialCwnd
        private set
    override var bytesInFlight: Long = 0
        private set

    /** C.pacing_rate in bytes per second; 0 until the first ACK (then `2.77 x initial window / RTT`). */
    private var pacingRateBps: Long = 0
    private var quantum: Int = minOf(65_536, 10 * maxDatagramSize)

    internal var state: State = State.Startup
        private set
    private var pacingGain: Double = STARTUP_PACING_GAIN
    private var cwndGain: Double = DEFAULT_CWND_GAIN

    // round counting (section 5.5.1)
    internal var roundCount: Long = 0
        private set
    private var roundStart = false
    private var nextRoundDelivered: Long = 0

    // Startup (section 5.3.1)
    internal var fullBwReached: Boolean = false
        private set
    private var fullBwNow = false
    private var fullBw: Long = 0
    private var fullBwCount = 0
    private var lossEventsInRound = 0
    private var lastLostId: Long = -2

    // the model (sections 2.9, 5.5)
    private val maxBwFilter = WindowedMaxFilter(MAX_BW_FILTER_CYCLES - 1)
    private var cycleCount: Long = 0

    /** BBR.max_bw, BBR.bw and BBR.bw_shortterm in bytes per second (Long.MAX_VALUE: no short-term bound). */
    internal var maxBw: Long = 0
        private set
    internal var bw: Long = 0
        private set
    internal var bwShortterm: Long = Long.MAX_VALUE
        private set

    /** BBR.min_rtt in nanoseconds (Long.MAX_VALUE until the first sample) and C.min_rtt over the lifetime. */
    internal var minRttNanos: Long = Long.MAX_VALUE
        private set
    private var minRttStamp: TimeMark = TimeMark.NEVER
    private var lifetimeMinRttNanos: Long = Long.MAX_VALUE
    private var bdp: Long = 0
    private var maxInflight: Long = 0
    private val extraAckedFilter = WindowedMaxFilter(EXTRA_ACKED_FILTER_ROUNDS)
    private var extraAcked: Long = 0
    private var extraAckedIntervalStart: TimeMark = TimeMark.NEVER
    private var extraAckedDelivered: Long = 0

    /** BBR.inflight_longterm and BBR.inflight_shortterm in bytes (Long.MAX_VALUE: unbounded). */
    internal var inflightLongterm: Long = Long.MAX_VALUE
        private set
    internal var inflightShortterm: Long = Long.MAX_VALUE
        private set

    // congestion signals (section 5.5.10)
    private var bwLatest: Long = 0
    private var inflightLatest: Long = 0
    private var isLossInRound = false
    private var lossRoundDelivered: Long = 0
    private var lossRoundStart = false

    // ProbeBW (section 5.3.3)
    private var ackPhase = AckPhase.Init
    private var isBwProbeSample = false
    private var bwProbeUpAcked: Long = 0
    private var probeUpAckedPerInc: Long = Long.MAX_VALUE
    private var bwProbeUpRounds = 0
    private var roundsSinceProbeUp: Long = 0
    private var bwProbeWaitNanos: Long = 0
    private var cycleStamp: TimeMark = TimeMark.NEVER
    private var prevProbeTooHigh = false
    private var prevProbePrecautionary = false
    private var drainStartRound: Long = 0

    // ProbeRTT (section 5.3.4)
    private var probeRttMinDelay: Long = Long.MAX_VALUE
    private var probeRttMinStamp: TimeMark = TimeMark.NEVER
    private var probeRttExpired = false
    private var probeRttDoneStamp: TimeMark = TimeMark.NEVER
    private var probeRttRoundDone = false
    private var idleRestart = false
    private var priorCwnd: Long = 0

    // loss recovery (section 5.6.4.4) and C.is_cwnd_limited over the last round
    private var inRecovery = false
    private var recoveryStart: TimeMark = TimeMark.NEVER
    private var cwndLimitedThisRound = false
    private var cwndLimitedLastRound = false
    private var ackPending = false
    private var jitter: Long = 0x9E3779B97F4A7C15uL.toLong()

    private val minPipeCwnd: Long get() = 4L * mss
    private val isCwndLimited: Boolean get() = cwndLimitedThisRound || cwndLimitedLastRound
    private val inProbeBw: Boolean
        get() = state == State.ProbeBwDown || state == State.ProbeBwCruise || state == State.ProbeBwRefill || state == State.ProbeBwUp
    private val isProbingBw: Boolean get() = state == State.Startup || state == State.ProbeBwRefill || state == State.ProbeBwUp

    override fun onPacketSent(
        now: TimeMark,
        bytes: Int,
    ) {
        if (bytesInFlight == 0L && sampler.appLimited != 0L) handleRestartFromIdle(now)
        bytesInFlight += bytes
        if (bytesInFlight >= cwnd) cwndLimitedThisRound = true
    }

    /** Stamps [p] (already counted by [onPacketSent]) with the delivery state for its later rate sample. */
    internal fun onPacketStamped(
        p: SentPacket,
        now: TimeMark,
    ) {
        sampler.onSent(p, now, bytesInFlight)
    }

    /** One packet of the ACK being processed; the model moves once per ACK, in [onAckProcessed]. */
    internal fun onPacketAcked(
        p: SentPacket,
        now: TimeMark,
    ) {
        if (p.rsId < 0) return
        if (!ackPending) {
            sampler.begin()
            ackPending = true
        }
        sampler.onAcked(p, now)
        if (inRecovery && p.timeSent > recoveryStart) {
            inRecovery = false
            restoreCwnd()
        } // a packet sent after recovery began was acknowledged: recovery is over
    }

    override fun onAck(
        now: TimeMark,
        sentTime: TimeMark,
        bytes: Int,
        smoothedRtt: Duration,
        appLimited: Boolean,
    ) {
        bytesInFlight -= bytes
    }

    /** The end of one ACK frame: UpdateOnACK (section 5.2.3) with the rate sample of the packets it acknowledged. */
    internal fun onAckProcessed(now: TimeMark) {
        if (!ackPending) return
        ackPending = false
        val rtt = sampler.sampleRttNanos
        if (rtt in 0 until lifetimeMinRttNanos) lifetimeMinRttNanos = rtt
        if (!sampler.generate(lifetimeMinRttNanos)) return
        if (pacingRateBps == 0L && rtt > 0) pacingRateBps = (STARTUP_PACING_GAIN * initialCwnd * 1e9 / rtt).toLong()
        if (extraAckedIntervalStart == TimeMark.NEVER) extraAckedIntervalStart = now
        if (minRttStamp == TimeMark.NEVER) {
            minRttStamp = now
            probeRttMinStamp = now
        }
        updateModelAndState(now)
        updateControlParameters()
    }

    /** One lost packet (HandleLostPacket, section 5.5.10.2); the window itself follows in [onLoss]. */
    internal fun onPacketLost(
        p: SentPacket,
        now: TimeMark,
    ) {
        if (p.rsId < 0) return
        sampler.onLost(p)
        if (p.rsId != lastLostId + 1) lossEventsInRound++ // a new discontiguous lost range
        lastLostId = p.rsId
        noteLoss()
        if (!isBwProbeSample) return
        val lost = sampler.lost - p.rsLost
        if (isInflightTooHigh(
                lost,
                p.rsTxInFlight,
            )
        ) {
            handleInflightTooHigh(inflightAtLoss(p.size.toLong(), p.rsTxInFlight, lost), p.rsAppLimited, now)
        }
    }

    override fun onLoss(
        now: TimeMark,
        lostBytes: Int,
        largestLostSentTime: TimeMark,
        persistentCongestion: Boolean,
    ) {
        bytesInFlight -= lostBytes
        if (persistentCongestion) {
            saveCwnd()
            cwnd = maxOf(bytesInFlight + mss, minPipeCwnd)
            inRecovery = false
            recoveryStart = TimeMark.NEVER
            return
        } // OnEnterRTO (section 5.6.4.4)
        if (!inRecovery && (recoveryStart == TimeMark.NEVER || largestLostSentTime > recoveryStart)) {
            saveCwnd()
            inRecovery = true
            recoveryStart = now
        } // OnEnterFastRecovery: remember the last good window
    }

    override fun onEcnCe(
        now: TimeMark,
        sentTime: TimeMark,
    ) {
        noteLoss()
        if (isBwProbeSample) handleInflightTooHigh(bytesInFlight, false, now)
    }

    /** The sender ran out of data with room in the window: what is in flight now is application-limited (section 4.1.2.4). */
    internal fun onAppLimited() {
        if (bytesInFlight < cwnd) sampler.markAppLimited(bytesInFlight)
    }

    override fun onDiscarded(bytes: Int) {
        bytesInFlight -= bytes
    }

    override fun onMtuUpdate(maxDatagramSize: Int) {
        mss = maxDatagramSize
    }

    override fun pacingRate(smoothedRtt: Duration): Long {
        if (pacingRateBps > 0) return pacingRateBps
        val nanos = maxOf(smoothedRtt.inWholeNanoseconds, 1_000_000L)
        return (STARTUP_PACING_GAIN * initialCwnd * 1e9 / nanos).toLong() // InitPacingRate (section 5.6.2)
    }

    override val sendQuantum: Int get() = quantum

    private fun updateModelAndState(now: TimeMark) {
        updateLatestDeliverySignals()
        updateCongestionSignals()
        updateAckAggregation(now)
        checkFullBwReached()
        checkStartupDone()
        checkDrainDone(now)
        updateProbeBwCyclePhase(now)
        updateMinRtt(now)
        checkProbeRtt(now)
        advanceLatestDeliverySignals()
        bw = minOf(maxBw, bwShortterm) // BoundBWForModel
    }

    private fun updateControlParameters() {
        setPacingRateWithGain(pacingGain)
        quantum = (pacingRateBps / 1000).coerceIn(2L * mss, 65_536L).toInt() // 1 ms at the pacing rate
        setCwnd()
    }

    private fun updateLatestDeliverySignals() {
        lossRoundStart = false
        bwLatest = maxOf(bwLatest, sampler.deliveryRate)
        inflightLatest = maxOf(inflightLatest, sampler.sampleDelivered)
        if (sampler.priorDelivered >= lossRoundDelivered) {
            lossRoundDelivered = sampler.delivered
            lossRoundStart = true
        }
    }

    private fun advanceLatestDeliverySignals() {
        if (lossRoundStart) {
            bwLatest = sampler.deliveryRate
            inflightLatest = sampler.sampleDelivered
        }
    }

    private fun updateCongestionSignals() {
        updateRound()
        val rate = sampler.deliveryRate
        if (rate > 0 && (rate >= maxBw || !sampler.sampleAppLimited)) maxBw = maxBwFilter.update(rate, cycleCount)
        if (!lossRoundStart) return
        if (!isProbingBw && isLossInRound) {
            if (bwShortterm == Long.MAX_VALUE) bwShortterm = maxBw
            if (inflightShortterm == Long.MAX_VALUE) inflightShortterm = cwnd
            bwShortterm = maxOf(bwLatest, (bwShortterm * BETA).toLong())
            inflightShortterm = maxOf(inflightLatest, (inflightShortterm * BETA).toLong())
        } // once per round with loss: the short-term model backs off by beta
        isLossInRound = false
    }

    private fun updateRound() {
        if (sampler.priorDelivered >= nextRoundDelivered) {
            startRound()
            roundCount++
            roundsSinceProbeUp++
            roundStart = true
            lossEventsInRound = 0
            cwndLimitedLastRound = cwndLimitedThisRound
            cwndLimitedThisRound = false
        } else {
            roundStart = false
        }
    }

    private fun startRound() {
        nextRoundDelivered = sampler.delivered
    }

    private fun updateAckAggregation(now: TimeMark) {
        val interval = (now - extraAckedIntervalStart).inWholeNanoseconds
        var expected = (bw.toDouble() * interval / 1e9).toLong()
        if (extraAckedDelivered <= expected) {
            extraAckedDelivered = 0
            extraAckedIntervalStart = now
            expected = 0
        } // the ACK rate fell to the estimate: a new aggregation interval
        extraAckedDelivered += sampler.newlyAcked
        val extra = if (extraAckedDelivered > expected) minOf(extraAckedDelivered - expected, cwnd) else 0L
        extraAckedFilter.window = if (fullBwReached) EXTRA_ACKED_FILTER_ROUNDS else 1L
        extraAcked = extraAckedFilter.update(extra, roundCount)
    }

    private fun checkFullBwReached() {
        val rate = sampler.deliveryRate
        if (fullBwNow || !roundStart || sampler.sampleAppLimited || rate == 0L) return
        if (rate >= fullBw + fullBw / 4) {
            resetFullBw()
            fullBw = rate
            return
        } // still growing by 25 % per round
        fullBwCount++
        fullBwNow = fullBwCount >= FULL_BW_ROUNDS
        if (fullBwNow) fullBwReached = true
    }

    private fun resetFullBw() {
        fullBw = 0
        fullBwCount = 0
        fullBwNow = false
    }

    private fun checkStartupDone() {
        if (state == State.Startup && !fullBwReached && lossEventsInRound >= STARTUP_FULL_LOSS_COUNT &&
            isInflightTooHigh(sampler.sampleLost, sampler.sampleTxInFlight)
        ) {
            fullBwReached = true
            inflightLongterm = maxOf(bdpMultiple(1.0), inflightLatest)
        } // CheckStartupHighLoss (section 5.3.1.3): sustained loss above 2 % ends Startup too
        if (state == State.Startup && fullBwReached) {
            state = State.Drain
            pacingGain = DRAIN_PACING_GAIN
            cwndGain = DEFAULT_CWND_GAIN
            drainStartRound = roundCount
        }
    }

    private fun checkDrainDone(now: TimeMark) {
        if (state == State.Drain && (bytesInFlight <= inflight(1.0) || roundCount > drainStartRound + MAX_DRAIN_ROUNDS)) {
            cwndGain = DEFAULT_CWND_GAIN
            startProbeBwDown(now)
        }
    }

    private fun startProbeBwDown(now: TimeMark) {
        isLossInRound = false
        bwLatest = 0
        inflightLatest = 0 // ResetCongestionSignals
        probeUpAckedPerInc = Long.MAX_VALUE
        pickProbeWait(now)
        cycleStamp = now
        ackPhase = AckPhase.ProbeStopping
        startRound()
        state = State.ProbeBwDown
        pacingGain = PROBE_DOWN_PACING_GAIN
        cwndGain = DEFAULT_CWND_GAIN
    }

    private fun startProbeBwCruise() {
        state = State.ProbeBwCruise
        pacingGain = 1.0
        cwndGain = DEFAULT_CWND_GAIN
    }

    private fun startProbeBwRefill() {
        resetShortTermModel()
        bwProbeUpRounds = 0
        bwProbeUpAcked = 0
        prevProbePrecautionary = false
        ackPhase = AckPhase.Refilling
        startRound()
        state = State.ProbeBwRefill
        pacingGain = 1.0
        cwndGain = DEFAULT_CWND_GAIN
    }

    private fun startProbeBwUp() {
        ackPhase = AckPhase.ProbeStarting
        startRound()
        resetFullBw()
        fullBw = sampler.deliveryRate
        state = State.ProbeBwUp
        pacingGain = PROBE_UP_PACING_GAIN
        cwndGain = PROBE_UP_CWND_GAIN
        raiseInflightLongtermSlope()
    }

    private fun resetShortTermModel() {
        bwShortterm = Long.MAX_VALUE
        inflightShortterm = Long.MAX_VALUE
    }

    private fun updateProbeBwCyclePhase(now: TimeMark) {
        if (!fullBwReached) return
        if (adaptLongTermModel(now)) return
        when (state) {
            State.ProbeBwDown -> {
                if (isTimeToProbeBw(now)) return
                if (bytesInFlight <= minOf(inflightWithHeadroom(), inflight(1.0))) startProbeBwCruise()
            }

            State.ProbeBwCruise -> {
                isTimeToProbeBw(now)
            }

            State.ProbeBwRefill -> {
                if (roundStart) {
                    isBwProbeSample = true
                    startProbeBwUp()
                } // one round of refill, then probe
            }

            State.ProbeBwUp -> {
                if (isTimeToGoDown()) {
                    prevProbeTooHigh = false
                    startProbeBwDown(now)
                }
            }

            else -> {}
        }
    }

    private fun isTimeToGoDown(): Boolean {
        if (prevProbeTooHigh && bytesInFlight >= inflightLongterm) {
            prevProbePrecautionary = true
            return true
        } // precautionary deceleration at the level that lost too much last time
        if (isCwndLimited && cwnd >= inflightLongterm) {
            resetFullBw()
            fullBw = sampler.deliveryRate
            return false
        } // limited by inflight_longterm: the plateau test would be meaningless
        return fullBwNow
    }

    private fun isTimeToProbeBw(now: TimeMark): Boolean {
        val renoRounds = minOf(targetInflight() / mss, RENO_ROUNDS_CAP)
        if (now.nanos - cycleStamp.nanos > bwProbeWaitNanos || roundsSinceProbeUp >= renoRounds) {
            startProbeBwRefill()
            return true
        }
        return false
    }

    private fun pickProbeWait(now: TimeMark) {
        roundsSinceProbeUp = nextRandom(now, 2)
        bwProbeWaitNanos = PROBE_WAIT_BASE_NANOS + nextRandom(now, PROBE_WAIT_JITTER_NANOS + 1)
    }

    /** Uniform in `0 until bound`: from [random], or splitmix64 over the time of the call when the caller gave none. */
    private fun nextRandom(
        now: TimeMark,
        bound: Long,
    ): Long {
        random?.let { return it.nextLong(bound) }
        jitter += now.nanos + -0x61c8864680b583ebL
        var z = jitter
        z = (z xor (z ushr 30)) * -0x40a7b892e31b1a47L
        z = (z xor (z ushr 27)) * -0x6b2fb644ecceee15L
        z = z xor (z ushr 31)
        return (z ushr 1) % bound
    }

    private fun adaptLongTermModel(now: TimeMark): Boolean {
        if (ackPhase == AckPhase.ProbeStarting && roundStart) ackPhase = AckPhase.ProbeFeedback
        if (ackPhase == AckPhase.ProbeStopping && roundStart) {
            isBwProbeSample = false
            ackPhase = AckPhase.Init
            if (inProbeBw && !sampler.sampleAppLimited) cycleCount++ // AdvanceMaxBwFilter
            if (inProbeBw && prevProbePrecautionary && !prevProbeTooHigh) {
                startProbeBwRefill()
                return true
            } // the cautious probe stopped short without excess loss: probe again at once
        } // the last probe's feedback is complete
        if (isInflightTooHigh(sampler.sampleLost, sampler.sampleTxInFlight)) {
            if (isBwProbeSample) handleInflightTooHigh(sampler.sampleTxInFlight, sampler.sampleAppLimited, now)
            return false
        }
        if (inflightLongterm == Long.MAX_VALUE) return false
        if (sampler.sampleTxInFlight > inflightLongterm) inflightLongterm = sampler.sampleTxInFlight
        if (state == State.ProbeBwUp) probeInflightLongtermUpward()
        return false
    }

    private fun probeInflightLongtermUpward() {
        if (!isCwndLimited || cwnd < inflightLongterm) return
        bwProbeUpAcked += sampler.newlyAcked
        if (bwProbeUpAcked >= probeUpAckedPerInc) {
            val delta = bwProbeUpAcked / probeUpAckedPerInc
            bwProbeUpAcked -= delta * probeUpAckedPerInc
            inflightLongterm += delta * mss
        }
        if (roundStart) raiseInflightLongtermSlope()
    }

    private fun raiseInflightLongtermSlope() {
        val growthThisRound = 1L shl bwProbeUpRounds
        bwProbeUpRounds = minOf(bwProbeUpRounds + 1, 30)
        probeUpAckedPerInc = maxOf(cwnd / growthThisRound, mss.toLong())
    }

    private fun isInflightTooHigh(
        lost: Long,
        txInFlight: Long,
    ): Boolean = lost * LOSS_THRESH_DEN > txInFlight * LOSS_THRESH_NUM

    private fun handleInflightTooHigh(
        txInFlight: Long,
        appLimited: Boolean,
        now: TimeMark,
    ) {
        prevProbeTooHigh = true
        isBwProbeSample = false // one reaction per probe
        if (!appLimited) inflightLongterm = maxOf(txInFlight, (targetInflight() * BETA).toLong())
        if (state == State.ProbeBwUp) startProbeBwDown(now)
    }

    /** The inflight at which the losses of [size]-byte packet crossed 2 % (InflightAtLoss, section 5.5.10.2). */
    private fun inflightAtLoss(
        size: Long,
        txInFlight: Long,
        lost: Long,
    ): Long {
        val inflightPrev = maxOf(txInFlight - size, 0L)
        val lostPrev = maxOf(lost - size, 0L)
        if (inflightPrev * LOSS_THRESH_NUM < lostPrev * LOSS_THRESH_DEN) return inflightPrev
        val lostPrefix = (inflightPrev * LOSS_THRESH_NUM - lostPrev * LOSS_THRESH_DEN) / (LOSS_THRESH_DEN - LOSS_THRESH_NUM)
        return inflightPrev + lostPrefix
    }

    private fun noteLoss() {
        if (!isLossInRound) {
            lossRoundDelivered = sampler.delivered
            saveCwnd()
        } // SaveStateUponLoss: only the window is kept (no spurious-loss undo)
        isLossInRound = true
    }

    private fun targetInflight(): Long = minOf(bdp, cwnd)

    private fun updateMinRtt(now: TimeMark) {
        val rtt = sampler.sampleRttNanos
        probeRttExpired = now > probeRttMinStamp + PROBE_RTT_INTERVAL
        if (rtt >= 0 && (rtt < probeRttMinDelay || probeRttExpired)) {
            probeRttMinDelay = rtt
            probeRttMinStamp = now
        }
        if (probeRttMinDelay < minRttNanos || now > minRttStamp + MIN_RTT_FILTER) {
            minRttNanos = probeRttMinDelay
            minRttStamp = probeRttMinStamp
        }
    }

    private fun checkProbeRtt(now: TimeMark) {
        if (state != State.ProbeRtt && probeRttExpired && !idleRestart) {
            state = State.ProbeRtt
            pacingGain = 1.0
            cwndGain = PROBE_RTT_CWND_GAIN
            saveCwnd()
            probeRttDoneStamp = TimeMark.NEVER
            ackPhase = AckPhase.ProbeStopping
            startRound()
        }
        if (state == State.ProbeRtt) handleProbeRtt(now)
        if (sampler.sampleDelivered > 0) idleRestart = false
    }

    private fun handleProbeRtt(now: TimeMark) {
        sampler.markAppLimited(bytesInFlight) // low rate samples of ProbeRTT never lower the model
        if (probeRttDoneStamp == TimeMark.NEVER && bytesInFlight <= probeRttCwnd()) {
            probeRttDoneStamp = now + PROBE_RTT_DURATION
            probeRttRoundDone = false
            startRound()
        } else if (probeRttDoneStamp != TimeMark.NEVER) {
            if (roundStart) probeRttRoundDone = true
            if (probeRttRoundDone) checkProbeRttDone(now)
        } // hold the small window for 200 ms and at least one round
    }

    private fun checkProbeRttDone(now: TimeMark) {
        if (probeRttDoneStamp != TimeMark.NEVER && now > probeRttDoneStamp) {
            probeRttMinStamp = now // the next ProbeRTT is due in 5 s
            restoreCwnd()
            resetShortTermModel()
            if (fullBwReached) {
                startProbeBwDown(now)
                startProbeBwCruise()
            } else {
                state = State.Startup
                pacingGain = STARTUP_PACING_GAIN
                cwndGain = DEFAULT_CWND_GAIN
            }
        }
    }

    private fun handleRestartFromIdle(now: TimeMark) {
        idleRestart = true
        extraAckedIntervalStart = now
        if (inProbeBw) {
            setPacingRateWithGain(1.0)
        } else if (state == State.ProbeRtt) {
            checkProbeRttDone(now)
        }
    }

    private fun setPacingRateWithGain(gain: Double) {
        if (bw == 0L) return
        val rate = (gain * bw * (100 - PACING_MARGIN_PERCENT) / 100).toLong()
        if (fullBwReached || rate > pacingRateBps) pacingRateBps = rate
    }

    private fun bdpMultiple(gain: Double): Long {
        if (minRttNanos == Long.MAX_VALUE) return initialCwnd
        bdp = (bw.toDouble() * minRttNanos / 1e9).toLong()
        return (gain * bdp).toLong()
    }

    /** QuantizationBudget (section 5.6.4.2): room for the offload bursts and pipelining, plus 2 datagrams while probing up. */
    private fun quantizationBudget(inflight: Long): Long {
        var v = maxOf(inflight, 3L * quantum, minPipeCwnd)
        if (state == State.ProbeBwUp) v += 2L * mss
        return v
    }

    private fun inflight(gain: Double): Long = quantizationBudget(bdpMultiple(gain))

    private fun inflightWithHeadroom(): Long {
        if (inflightLongterm == Long.MAX_VALUE) return Long.MAX_VALUE
        val headroom = maxOf(mss.toLong(), (inflightLongterm * HEADROOM).toLong())
        return maxOf(inflightLongterm - headroom, minPipeCwnd)
    }

    private fun probeRttCwnd(): Long = maxOf(bdpMultiple(PROBE_RTT_CWND_GAIN), minPipeCwnd)

    private fun saveCwnd() {
        priorCwnd = if (!inRecovery && state != State.ProbeRtt) cwnd else maxOf(priorCwnd, cwnd)
    }

    private fun restoreCwnd() {
        cwnd = maxOf(cwnd, priorCwnd)
    }

    private fun setCwnd() {
        maxInflight = quantizationBudget(bdpMultiple(cwndGain) + extraAcked)
        val acked = sampler.newlyAcked
        if (fullBwReached) {
            cwnd = minOf(cwnd + acked, maxInflight)
        } else if (cwnd < maxInflight || sampler.delivered < initialCwnd) {
            cwnd += acked
        }
        cwnd = maxOf(cwnd, minPipeCwnd)
        if (state == State.ProbeRtt) cwnd = minOf(cwnd, probeRttCwnd())
        // BoundCwndForModel (section 5.6.4.7)
        var cap = Long.MAX_VALUE
        if (inProbeBw && state != State.ProbeBwCruise) {
            cap = inflightLongterm
        } else if (state == State.ProbeRtt || state == State.ProbeBwCruise) {
            cap = inflightWithHeadroom()
        }
        cap = maxOf(minOf(cap, inflightShortterm), minPipeCwnd)
        cwnd = minOf(cwnd, cap)
    }

    private companion object {
        const val STARTUP_PACING_GAIN = 2.77 // 4 ln 2 (section 2.5)
        const val DRAIN_PACING_GAIN = 0.5
        const val DEFAULT_CWND_GAIN = 2.0
        const val PROBE_DOWN_PACING_GAIN = 0.9
        const val PROBE_UP_PACING_GAIN = 1.25
        const val PROBE_UP_CWND_GAIN = 2.25
        const val PROBE_RTT_CWND_GAIN = 0.5
        const val PACING_MARGIN_PERCENT = 1
        const val BETA = 0.7
        const val HEADROOM = 0.15
        const val LOSS_THRESH_NUM = 2L
        const val LOSS_THRESH_DEN = 100L // 2 %
        const val FULL_BW_ROUNDS = 3
        const val STARTUP_FULL_LOSS_COUNT = 6
        const val MAX_DRAIN_ROUNDS = 3
        const val MAX_BW_FILTER_CYCLES = 2L
        const val EXTRA_ACKED_FILTER_ROUNDS = 10L
        const val RENO_ROUNDS_CAP = 63L
        const val PROBE_WAIT_BASE_NANOS = 2_000_000_000L
        const val PROBE_WAIT_JITTER_NANOS = 1_000_000_000L
        val PROBE_RTT_INTERVAL = 5.seconds
        val MIN_RTT_FILTER = 10.seconds
        val PROBE_RTT_DURATION = 200.milliseconds
    }
}
