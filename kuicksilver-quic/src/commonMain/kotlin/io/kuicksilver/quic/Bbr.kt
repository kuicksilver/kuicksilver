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
 * more or less than its share depending on the buffer size). A loss episode whose every lost packet is acknowledged later
 * (reordering, a delay spike) is undone (section 5.5.11). Sizes are bytes, rates bytes per second, times nanoseconds; the
 * arithmetic saturates instead of wrapping. Nothing here allocates after construction.
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
    private var mss: Int = maxOf(maxDatagramSize, 1)

    /** RFC 9002 section 7.2 but at least BBR.MinPipeCwnd (14 720 bytes is less than 4 datagrams above 3 680), recomputed with the size. */
    private var initialCwnd: Long = initialWindow(mss)

    override var cwnd: Long = initialCwnd
        private set
    override var bytesInFlight: Long = 0
        private set

    /** C.pacing_rate in bytes per second; 0 until the first ACK (then `2.77 x initial window / RTT`). */
    private var pacingRateBps: Long = 0
    private var quantum: Int = maxOf(minOf(65_536, 10 * mss), 2 * mss)

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

    /** Discontiguous lost ranges in the current loss round (CheckStartupHighLoss counts them over one round in recovery). */
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

    // spurious-loss undo (section 5.5.11): the model saved at the first loss of a round, and the episode's lost packets the
    // core still remembers ([lossesPending]); when every one of them was acknowledged after all, the episode was spurious
    internal var undoState: State? = null
        private set
    private var undoBwShortterm: Long = Long.MAX_VALUE
    private var undoInflightShortterm: Long = Long.MAX_VALUE
    private var undoInflightLongterm: Long = Long.MAX_VALUE
    internal var lossesPending: Long = 0
        private set
    private var spuriousInEpisode = false
    private var realLossInEpisode = false
    internal var spuriousUndos: Int = 0
        private set

    /** An ECN-CE report of the ACK being processed, acted on in [onAckProcessed] once the ACK's packets left the flight. */
    private var cePending = false
    private var ceInRound = false

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

    /** BBR.MinPipeCwnd: 4 datagrams (section 5.6.4.3). */
    internal val minPipeCwnd: Long get() = 4L * mss

    /** kMinimumWindow (RFC 9002 section 7.2: "The RECOMMENDED value is 2 * max_datagram_size"), the window after persistent congestion. */
    private val minimumWindow: Long get() = 2L * mss
    internal val isCwndLimited: Boolean get() = cwndLimitedThisRound || cwndLimitedLastRound

    /** The current pacing rate in bytes per second (0 before the first ACK) and BBR.MaxPipeCwnd-style limits, for the tests. */
    internal val pacingRateForTest: Long get() = pacingRateBps
    private val inProbeBw: Boolean
        get() = state == State.ProbeBwDown || state == State.ProbeBwCruise || state == State.ProbeBwRefill || state == State.ProbeBwUp
    private val isProbingBw: Boolean get() = state == State.Startup || state == State.ProbeBwRefill || state == State.ProbeBwUp

    override fun onPacketSent(
        now: TimeMark,
        bytes: Int,
    ) {
        if (bytesInFlight == 0L && sampler.appLimited != 0L) handleRestartFromIdle(now)
        val before = bytesInFlight
        bytesInFlight += bytes
        // C.is_cwnd_limited: this packet filled the window; a PTO probe sent past a full window is not the window's doing
        if (before < cwnd && bytesInFlight >= cwnd) cwndLimitedThisRound = true
    }

    /** Stamps [p] (already counted by [onPacketSent]) with the delivery state for its later rate sample. */
    internal fun onPacketStamped(
        p: SentPacket,
        now: TimeMark,
    ) {
        sampler.onSent(p, now, bytesInFlight)
    }

    /**
     * One packet of the ACK being processed, reported before the ACK's loss detection (TCP's order: C.delivered first, so a loss
     * round never closes on the ACK that opened it); the model moves once per ACK, in [onAckProcessed].
     */
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
        if (cePending) {
            cePending = false
            noteLoss()
            // draft-06 section 3.7: CE marks are congestion. One report is one congestion event of the round, like a discontiguous
            // lost range, and it stands for queueing the loss rate cannot measure: CheckStartupHighLoss counts it without the 2 % test
            if (lossEventsInRound < Int.MAX_VALUE) lossEventsInRound++
            ceInRound = true
            if (isBwProbeSample) handleInflightTooHigh(if (ackPending) sampler.sampleTxInFlight else bytesInFlight, false, now)
        } // ECN-CE as loss (section 5.5.10), measured against what was in flight when the newest acknowledged packet left
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
        if (lossesPending == 0L) saveStateUponLoss() // a new loss episode: what an undo would restore
        lossesPending++ // the core remembers it until it is acknowledged after all ([onSpuriousLoss]) or settles ([onLossSettled])
        if (p.rsId < 0) return
        sampler.onLost(p)
        if (p.rsId != lastLostId + 1 && lossEventsInRound < Int.MAX_VALUE) lossEventsInRound++ // a new discontiguous lost range
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
            // RFC 9002 section 7.6.2: "the sender's congestion window MUST be reduced to the minimum congestion window", 2 datagrams
            // (section 7.2); BBR's 4-datagram pipelining floor ([minPipeCwnd]) applies again when its model next sets the window
            cwnd = minimumWindow
            inRecovery = false
            recoveryStart = TimeMark.NEVER
            return
        } // OnEnterRTO (section 5.6.4.4)
        if (!inRecovery && (recoveryStart == TimeMark.NEVER || largestLostSentTime > recoveryStart)) {
            saveCwnd()
            inRecovery = true
            recoveryStart = now
        } // OnEnterFastRecovery: remember the last good window (the model was saved when the loss episode began)
    }

    /** A packet declared lost was acknowledged after all (RFC 9002 section 6.1 reordering, a delay spike). */
    internal fun onSpuriousLoss(now: TimeMark) {
        if (lossesPending > 0) lossesPending--
        spuriousInEpisode = true
        settleEpisode(now)
    }

    /** A packet declared lost was not acknowledged within the time the core remembers it: the loss stands. */
    internal fun onLossSettled(now: TimeMark) {
        if (lossesPending > 0) lossesPending--
        realLossInEpisode = true
        settleEpisode(now)
    }

    private fun settleEpisode(now: TimeMark) {
        if (lossesPending != 0L) return
        if (spuriousInEpisode && !realLossInEpisode) handleSpuriousLossDetection(now)
        spuriousInEpisode = false
        realLossInEpisode = false
    }

    /** HandleSpuriousLossDetection (section 5.5.11.2): every loss of the episode was spurious, back to the state before it. */
    private fun handleSpuriousLossDetection(now: TimeMark) {
        spuriousUndos++
        inRecovery = false
        recoveryStart = TimeMark.NEVER
        restoreCwnd()
        isLossInRound = false
        resetFullBw()
        bwShortterm = maxOf(bwShortterm, undoBwShortterm)
        inflightShortterm = maxOf(inflightShortterm, undoInflightShortterm)
        inflightLongterm = maxOf(inflightLongterm, undoInflightLongterm)
        if (undoState == State.Startup && state != State.Startup) {
            fullBwReached = false
            if (state != State.ProbeRtt) enterStartup()
        } else if (undoState == State.ProbeBwUp && state != State.ProbeBwUp) {
            if (state != State.ProbeRtt) startProbeBwRefill()
        } // the loss ended a bandwidth probe: probe again
        undoState = null
    }

    private fun enterStartup() {
        state = State.Startup
        pacingGain = STARTUP_PACING_GAIN
        cwndGain = DEFAULT_CWND_GAIN
    }

    override fun onEcnCe(
        now: TimeMark,
        sentTime: TimeMark,
    ) {
        cePending = true
        if (!ackPending) onAckProcessed(now) // not inside an ACK (a caller other than the core): act now
    }

    /** The sender ran out of data with room in the window: what is in flight now is application-limited (section 4.1.2.4). */
    internal fun onAppLimited() {
        if (bytesInFlight < cwnd) sampler.markAppLimited(bytesInFlight)
    }

    override fun onDiscarded(bytes: Int) {
        bytesInFlight -= bytes
    }

    /**
     * DPLPMTUD moved the datagram size (C.SMSS): the model stays in bytes, the floors in datagrams follow it: the 4-datagram
     * pipelining minimum, the send quantum's 2 datagrams and, before the first ACK, the initial window (RFC 9002 section 7.2)
     * when that shrinks. RFC 8899 section 3 item 7: "An update to the PLPMTU (or MPS) MUST NOT increase the congestion window
     * measured in bytes", so the window itself only ever comes down here.
     */
    override fun onMtuUpdate(maxDatagramSize: Int) {
        mss = maxOf(maxDatagramSize, 1)
        initialCwnd = initialWindow(mss)
        if (sampler.delivered == 0L && pacingRateBps == 0L && initialCwnd < cwnd) cwnd = initialCwnd
        updateQuantum()
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
        updateQuantum()
        setCwnd()
    }

    /** SetSendQuantum (section 5.6.3): 1 ms at the pacing rate, at most 64 KiB, at least 2 datagrams (which wins for jumbo datagrams). */
    private fun updateQuantum() {
        quantum = maxOf(minOf(pacingRateBps / 1000, 65_536L), 2L * mss).toInt()
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
        checkStartupHighLoss()
        lossEventsInRound = 0
        ceInRound = false
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

    /**
     * CheckStartupHighLoss (section 5.3.1.3), at the end of a loss round (as Linux does): the round that just ended began with its
     * first loss, so the flow was in recovery for that whole round; with at least 6 discontiguous lost ranges in it and more than
     * 2 % lost, Startup ends at a safe inflight.
     */
    private fun checkStartupHighLoss() {
        if (state != State.Startup || fullBwReached || !isLossInRound || lossEventsInRound < STARTUP_FULL_LOSS_COUNT) return
        if (!ceInRound && !isInflightTooHigh(sampler.sampleLost, sampler.sampleTxInFlight)) return
        undoState = State.Startup
        fullBwReached = true
        inflightLongterm = maxOf(bdpMultiple(bw, 1.0), inflightLatest, minPipeCwnd)
    }

    private fun checkStartupDone() {
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
                if (bytesInFlight <= minOf(inflightWithHeadroom(), inflight(maxBw, 1.0))) startProbeBwCruise() // IsTimeToCruise
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
            inflightLongterm = sat(inflightLongterm, delta * mss)
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
    ): Boolean = lost.toDouble() * LOSS_THRESH_DEN > txInFlight.toDouble() * LOSS_THRESH_NUM // in doubles: lost is cumulative

    private fun handleInflightTooHigh(
        txInFlight: Long,
        appLimited: Boolean,
        now: TimeMark,
    ) {
        prevProbeTooHigh = true
        isBwProbeSample = false // one reaction per probe
        // never below the pipelining minimum: with no BDP estimate yet (or nothing in flight on a CE report) the bound would be 0
        if (!appLimited) inflightLongterm = maxOf(txInFlight, (targetInflight() * BETA).toLong(), minPipeCwnd)
        if (state == State.ProbeBwUp) {
            undoState = State.ProbeBwUp
            startProbeBwDown(now)
        }
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
        }
        isLossInRound = true
    }

    /**
     * SaveStateUponLoss (section 5.5.11.1): what an undo restores if the episode turns out spurious. Taken when a loss episode
     * begins (the first loss with none pending, as Linux's bbr_ssthresh does at recovery entry), not at the first loss of every
     * round as the draft's NoteLoss does: a probe's later losses in the same episode come after StartProbeBW_DOWN cleared the
     * round's loss flag and would overwrite the state the undo must restore.
     */
    private fun saveStateUponLoss() {
        saveCwnd()
        undoState = null
        undoBwShortterm = bwShortterm
        undoInflightShortterm = inflightShortterm
        undoInflightLongterm = inflightLongterm
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
                enterStartup()
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
        val rate = maxOf((gain * bw * (100 - PACING_MARGIN_PERCENT) / 100).toLong(), 1L)
        if (fullBwReached || rate > pacingRateBps) pacingRateBps = rate
    }

    /** BDPMultiple (section 5.6.4.2) of [rate] (BBR.bw unless stated), in bytes; Double products saturate at Long.MAX_VALUE. */
    private fun bdpMultiple(
        rate: Long,
        gain: Double,
    ): Long {
        if (minRttNanos == Long.MAX_VALUE) return initialCwnd
        bdp = (rate.toDouble() * minRttNanos / 1e9).toLong()
        return (gain * bdp).toLong()
    }

    private fun bdpMultiple(gain: Double): Long = bdpMultiple(bw, gain)

    /** QuantizationBudget (section 5.6.4.2): room for the offload bursts and pipelining, plus 2 datagrams while probing up. */
    private fun quantizationBudget(inflight: Long): Long {
        var v = maxOf(inflight, 3L * quantum, minPipeCwnd)
        if (state == State.ProbeBwUp) v = sat(v, 2L * mss)
        return v
    }

    private fun inflight(gain: Double): Long = quantizationBudget(bdpMultiple(gain))

    private fun inflight(
        rate: Long,
        gain: Double,
    ): Long = quantizationBudget(bdpMultiple(rate, gain))

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
        maxInflight = quantizationBudget(sat(bdpMultiple(cwndGain), extraAcked))
        val acked = sampler.newlyAcked
        if (fullBwReached) {
            cwnd = minOf(sat(cwnd, acked), maxInflight)
        } else if (cwnd < maxInflight || sampler.delivered < initialCwnd) {
            cwnd = sat(cwnd, acked)
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
        /** RFC 9002 section 7.2, min(10 datagrams, max(14 720 bytes, 2 datagrams)), raised to BBR.MinPipeCwnd. */
        fun initialWindow(mss: Int): Long = maxOf(minOf(10L * mss, maxOf(14720L, 2L * mss)), 4L * mss)

        /** [a] + [b] for non-negative [b], saturating at Long.MAX_VALUE. */
        fun sat(
            a: Long,
            b: Long,
        ): Long = if (b > 0 && a > Long.MAX_VALUE - b) Long.MAX_VALUE else a + b

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
