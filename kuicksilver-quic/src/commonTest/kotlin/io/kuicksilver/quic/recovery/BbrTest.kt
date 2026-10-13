// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.recovery

import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.quic.Bbr
import io.kuicksilver.quic.TimeMark
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.nanoseconds
import kotlin.time.Duration.Companion.seconds

/**
 * BBR (draft-ietf-ccwg-bbr) against a synthetic bottleneck: a FIFO link of [rate] bytes per second and [baseRtt] of propagation,
 * every packet acknowledged on its own as it arrives, losses and CE marks chosen per packet. Calls the controller as the core does:
 * send while the flight is below the window (a datagram may cross it), stamp; per ACK the acknowledged packets' delivery, the
 * spurious losses, the CE report, the losses, the window updates, the end of the ACK. A lost packet is remembered for 3 RTTs and
 * then settled, as the core's spurious-loss memory does.
 */
@OptIn(ExperimentalKuicksilverApi::class)
internal class Bottleneck(
    val cc: Bbr,
    val rate: Long,
    val baseRtt: Duration,
    var mss: Int = 1200,
) {
    var now = TimeMark(1_000_000_000L)
    private var linkFree = now
    private var nextSend = now
    private var pn = 0L
    private val queue = ArrayDeque<SentPacket>()
    private val arrival = ArrayDeque<TimeMark>()
    private val lateAcks = ArrayList<TimeMark>() // acknowledgements of packets declared lost (spurious losses), by arrival
    private val lostAt = ArrayDeque<TimeMark>() // lost packets still remembered, by declaration time

    /** Packets (by number) the link drops, those it marks CE, and those declared lost whose ACK then comes [spuriousDelay] late. */
    var drop: (Long) -> Boolean = { false }
    var ce: (Long) -> Boolean = { false }
    var spurious: (Long) -> Boolean = { false }
    var spuriousDelay: Duration = 5.milliseconds

    /** Bytes the application still has; [Long.MAX_VALUE]: always more. */
    var appBytes = Long.MAX_VALUE
    val states = ArrayList<Pair<TimeMark, Bbr.State>>()
    var maxRtt: Duration = Duration.ZERO
    var delivered = 0L
    var sentBytes = 0L
    var maxCwndInProbeRtt = 0L

    /** Called after every send with the time and size: tests watch the pacing. */
    var onSend: (TimeMark, Int) -> Unit = { _, _ -> }

    val nextPn: Long get() = pn

    fun run(
        d: Duration,
        each: () -> Unit = {},
    ) {
        val end = now + d
        record()
        while (now < end) {
            while (cc.bytesInFlight < cc.cwnd && nextSend <= now && appBytes > 0) send()
            if (appBytes <= 0) cc.onAppLimited()
            var next = end
            if (arrival.isNotEmpty() && arrival.first() < next) next = arrival.first()
            lateAcks.minByOrNull { it.nanos }?.let { if (it < next) next = it }
            if (cc.bytesInFlight < cc.cwnd && appBytes > 0 && nextSend > now && nextSend < next) next = nextSend
            if (next <= now) next = now + 1.nanoseconds
            now = next
            if ((arrival.isNotEmpty() && arrival.first() <= now) || lateAcks.any { it <= now }) ackDue()
            each()
            record()
        }
    }

    private fun record() {
        if (states.isEmpty() || states.last().second != cc.state) states += now to cc.state
        if (cc.state == Bbr.State.ProbeRtt) maxCwndInProbeRtt = maxOf(maxCwndInProbeRtt, cc.cwnd)
    }

    private fun send() {
        val p = SentPacket()
        p.pn = pn++
        p.timeSent = now
        p.size = mss
        p.inFlight = true
        cc.onPacketSent(now, mss)
        cc.onPacketStamped(p, now)
        sentBytes += mss
        onSend(now, mss)
        if (appBytes != Long.MAX_VALUE) appBytes -= mss
        val start = if (linkFree > now) linkFree else now
        linkFree = start + (mss * 1_000_000_000L / rate).nanoseconds
        queue += p
        arrival += linkFree + baseRtt
        val r = cc.pacingRate(baseRtt)
        nextSend = (if (nextSend > now) nextSend else now) + (mss * 1_000_000_000L / maxOf(r, 1L)).nanoseconds
    }

    private fun ackDue() {
        var lostBytes = 0
        var largestLost = TimeMark(0)
        var anyCe = false
        var ceSent = TimeMark(0)
        val acked = ArrayList<SentPacket>()
        val lost = ArrayList<SentPacket>()
        while (arrival.isNotEmpty() && arrival.first() <= now) {
            arrival.removeFirst()
            val p = queue.removeFirst()
            if (drop(p.pn) || spurious(p.pn)) {
                lost += p
                if (spurious(p.pn) && !drop(p.pn)) lateAcks += now + spuriousDelay
            } else {
                if (ce(p.pn)) {
                    anyCe = true
                    ceSent = p.timeSent
                }
                acked += p
            }
        }
        for (p in acked) cc.onPacketAcked(p, now)
        while (lostAt.isNotEmpty() && lostAt.first() + baseRtt * 3 < now) {
            lostAt.removeFirst()
            cc.onLossSettled(now)
        }
        val late = lateAcks.count { it <= now }
        lateAcks.removeAll { it <= now }
        repeat(late) {
            lostAt.removeFirstOrNull()
            cc.onSpuriousLoss(now)
        }
        if (anyCe) cc.onEcnCe(now, ceSent)
        for (p in lost) {
            cc.onPacketLost(p, now)
            lostAt += now
            lostBytes += p.size
            largestLost = p.timeSent
        }
        if (lostBytes > 0) cc.onLoss(now, lostBytes, largestLost, false)
        for (p in acked) {
            cc.onAck(now, p.timeSent, p.size, baseRtt, false)
            delivered += p.size
            val rtt = now - p.timeSent
            if (rtt > maxRtt) maxRtt = rtt
        }
        cc.onAckProcessed(now)
    }

    fun seen(s: Bbr.State): Boolean = states.any { it.second == s }
}

@OptIn(ExperimentalKuicksilverApi::class)
class BbrTest {
    private val rate = 1_250_000L // 10 Mbit/s
    private val rtt = 40.milliseconds
    private val bdp = rate * 40 / 1000 // 50 000 bytes

    private fun bbr() = Bbr(1200, Random(7))

    @Test fun startupFillsThePipeThenDrainsIntoProbeBw() {
        val b = Bottleneck(bbr(), rate, rtt)
        b.run(3.seconds)
        val cc = b.cc
        assertTrue(cc.fullBwReached, "states ${b.states}")
        assertEquals(listOf(Bbr.State.Startup, Bbr.State.Drain), b.states.take(2).map { it.second })
        assertTrue(
            b.states[2]
                .second.name
                .startsWith("ProbeBw"),
            "${b.states}",
        ) // Down, or Cruise at once when Drain emptied the queue
        assertTrue(cc.state.name.startsWith("ProbeBw"), "${cc.state}")
        assertEquals(rate.toDouble(), cc.maxBw.toDouble(), rate * 0.05, "max_bw ${cc.maxBw}")
        assertEquals(rtt.inWholeNanoseconds.toDouble(), cc.minRttNanos.toDouble(), 2e6, "min_rtt ${cc.minRttNanos}")
        assertTrue(b.delivered >= rate * 2, "delivered ${b.delivered} in 3 s")
    }

    @Test fun steadyStateKeepsTheQueueShort() {
        val b = Bottleneck(bbr(), rate, rtt)
        b.run(2.seconds)
        b.maxRtt = Duration.ZERO
        val before = b.delivered
        b.run(8.seconds)
        val goodput = (b.delivered - before) / 8
        assertTrue(goodput >= rate * 0.9, "goodput $goodput of $rate")
        // ProbeBW_UP may queue 1.25 x BDP for a round, the cwnd cap is 2 x BDP: the RTT stays well under twice the base
        assertTrue(b.maxRtt < rtt * 2, "max RTT ${b.maxRtt}")
        assertTrue(b.cc.cwnd <= 3 * bdp, "cwnd ${b.cc.cwnd}")
    }

    @Test fun probeRttRefreshesMinRttEveryFiveSecondsWithAHalfBdpWindow() {
        val b = Bottleneck(bbr(), rate, rtt)
        b.run(12.seconds)
        val entries = b.states.filter { it.second == Bbr.State.ProbeRtt }
        assertTrue(entries.isNotEmpty(), "no ProbeRTT in ${b.states}")
        assertTrue(entries.first().first - TimeMark(1_000_000_000L) >= 5.seconds, "ProbeRTT too early: ${entries.first().first}")
        assertTrue(b.maxCwndInProbeRtt <= maxOf(bdp / 2 + 2400, 4L * 1200), "ProbeRTT window ${b.maxCwndInProbeRtt} (BDP $bdp)")
        val i = b.states.indexOfFirst { it.second == Bbr.State.ProbeRtt }
        val exit = b.states[i + 1]
        assertTrue(exit.second == Bbr.State.ProbeBwCruise || exit.second == Bbr.State.ProbeBwDown, "exit to ${exit.second}")
        val held = exit.first - b.states[i].first
        assertTrue(held >= 200.milliseconds && held < 200.milliseconds + rtt * 4, "held ProbeRTT for $held")
    }

    @Test fun appLimitedSamplesDoNotLowerTheBandwidthEstimate() {
        val b = Bottleneck(bbr(), rate, rtt)
        b.run(3.seconds)
        val estimate = b.cc.maxBw
        // a trickle: 12 kB per 100 ms is a tenth of the link
        var nextTop = b.now
        b.appBytes = 0
        b.run(2.seconds) {
            if (b.now >= nextTop) {
                b.appBytes += 12_000
                nextTop = b.now + 100.milliseconds
            }
        }
        assertTrue(b.cc.maxBw >= estimate * 9 / 10, "max_bw fell from $estimate to ${b.cc.maxBw} on application-limited samples")
    }

    @Test fun randomLossBelowTheThresholdKeepsTheRate() {
        val b = Bottleneck(bbr(), rate, rtt)
        val r = Random(3)
        b.drop = { r.nextDouble() < 0.01 }
        b.run(2.seconds)
        val before = b.delivered
        b.run(8.seconds)
        val goodput = (b.delivered - before) / 8
        // BBRv3 gives up about the loss rate plus the pacing margin per lossy round between probes (draft section 5.3.3.8.3) and
        // reprobes within min(BDP in datagrams, 63) rounds: about 70 % here, where a loss-based flow keeps a fraction
        assertTrue(goodput >= rate * 0.6, "goodput $goodput of $rate with 1 % loss")
    }

    @Test fun heavyLossWhileProbingCapsInflightLongterm() {
        val b = Bottleneck(bbr(), rate, rtt)
        b.run(3.seconds)
        assertEquals(Long.MAX_VALUE, b.cc.inflightLongterm, "no loss yet")
        var lossy = false
        b.drop = { lossy && it % 10 == 0L } // 10 % while probing up
        var sawUp = false
        b.run(6.seconds) {
            if (b.cc.state == Bbr.State.ProbeBwUp) {
                sawUp = true
                lossy = true
            }
        }
        assertTrue(sawUp, "never probed up: ${b.states}")
        assertTrue(b.cc.inflightLongterm < Long.MAX_VALUE, "inflight_longterm unbounded")
        assertTrue(b.cc.inflightLongterm <= 3 * bdp, "inflight_longterm ${b.cc.inflightLongterm}")
        assertTrue(b.cc.cwnd <= b.cc.inflightLongterm || b.cc.state == Bbr.State.ProbeBwCruise || b.cc.state == Bbr.State.ProbeRtt)
    }

    @Test fun lossOutsideProbingBacksTheShortTermModelOffByBeta() {
        val b = Bottleneck(bbr(), rate, rtt)
        b.run(3.seconds)
        while (b.cc.state != Bbr.State.ProbeBwCruise) b.run(10.milliseconds)
        val maxBw = b.cc.maxBw
        b.drop = { it % 20 == 0L } // 5 % for a few rounds
        b.run(rtt * 3)
        assertTrue(b.cc.bwShortterm < maxBw, "bw_shortterm ${b.cc.bwShortterm} vs max_bw $maxBw")
        assertTrue(b.cc.bwShortterm >= (maxBw * 0.7 * 0.7 * 0.7).toLong(), "at most one beta per round: ${b.cc.bwShortterm}")
        assertTrue(b.cc.inflightShortterm < Long.MAX_VALUE)
        assertTrue(b.cc.bw <= b.cc.bwShortterm)
    }

    @Test fun ecnCeCountsAsCongestion() {
        val b = Bottleneck(bbr(), rate, rtt)
        b.run(3.seconds)
        while (b.cc.state != Bbr.State.ProbeBwCruise) b.run(10.milliseconds)
        b.ce = { it % 20 == 0L }
        b.run(rtt * 3)
        assertTrue(b.cc.bwShortterm < b.cc.maxBw, "CE left bw_shortterm at ${b.cc.bwShortterm}")
    }

    @Test fun startupEndsOnSustainedHighLoss() {
        val b = Bottleneck(bbr(), rate * 100, rtt) // a pipe Startup would not fill for a long time
        b.drop = { it > 200 && it % 15 == 0L } // 6.7 % in discontiguous single losses
        b.run(2.seconds)
        assertTrue(b.cc.fullBwReached, "states ${b.states}")
        assertTrue(b.cc.inflightLongterm < Long.MAX_VALUE)
        assertTrue(b.seen(Bbr.State.Drain))
    }

    @Test fun persistentCongestionCollapsesTheWindowToWhatIsInFlight() {
        val cc = bbr()
        val t = TimeMark(1_000_000_000L)
        repeat(10) {
            val p = SentPacket()
            p.size = 1200
            p.timeSent = t
            p.inFlight = true
            cc.onPacketSent(t, 1200)
            cc.onPacketStamped(p, t)
        }
        cc.onLoss(t + 1.seconds, 9 * 1200, t, persistentCongestion = true)
        assertEquals(4L * 1200, cc.cwnd) // max(inflight + 1 datagram, the 4-datagram pipelining minimum)
    }

    @Test fun pacesTheInitialWindowAtTheStartupGainBeforeTheFirstAck() {
        val cc = bbr()
        assertEquals(332_400.0, cc.pacingRate(100.milliseconds).toDouble(), 2.0) // 2.77 x 12 000 bytes per 100 ms
        assertEquals(12_000, cc.cwnd)
    }

    @Test fun aSpuriousLossThatEndedTheProbeIsUndone() {
        // draft section 5.5.11 and appendix A.18: reordering makes a probe look lossy; once the "lost" packets are acknowledged,
        // inflight_longterm and the probe come back
        val b = Bottleneck(bbr(), rate, rtt)
        b.run(3.seconds)
        var lossyFrom = -1L
        var lossyAt = TimeMark.NEVER
        b.spurious = { lossyFrom >= 0 && it in lossyFrom until lossyFrom + 8 } // 8 in a row: well above 2 % of the flight
        b.run(8.seconds) {
            if (lossyFrom < 0 && b.cc.state == Bbr.State.ProbeBwUp) {
                lossyFrom = b.nextPn
                lossyAt = b.now
            }
        }
        assertTrue(lossyFrom >= 0, "never probed up: ${b.states}")
        assertTrue(b.cc.spuriousUndos >= 1, "no undo; states ${b.states}")
        val after = b.states.filter { it.first >= lossyAt }
        val down = after.first { it.second == Bbr.State.ProbeBwDown }
        val refill = after.first { it.first > down.first && it.second == Bbr.State.ProbeBwRefill }
        assertTrue(refill.first - down.first <= rtt * 2, "the undo restarts the probe at once: $after")
        assertTrue(after.takeWhile { it !== refill }.none { it.second == Bbr.State.ProbeRtt }, "$after")
        assertEquals(Long.MAX_VALUE, b.cc.inflightLongterm, "the cap from the spurious losses was undone")
        assertEquals(0L, b.cc.lossesPending)
    }

    @Test fun aRealLossThatEndedTheProbeStands() {
        val b = Bottleneck(bbr(), rate, rtt)
        b.run(3.seconds)
        var lossyFrom = -1L
        b.drop = { lossyFrom >= 0 && it in lossyFrom until lossyFrom + 3 }
        b.run(8.seconds) {
            if (lossyFrom < 0 && b.cc.state == Bbr.State.ProbeBwUp) lossyFrom = b.nextPn
        }
        assertEquals(0, b.cc.spuriousUndos)
        assertTrue(b.cc.inflightLongterm < Long.MAX_VALUE, "the probe's loss bounds inflight_longterm")
    }

    @Test fun aSpuriousLossInStartupReturnsToStartup() {
        val cc = bbr()
        val b = Bottleneck(cc, rate * 100, rtt) // Startup lasts
        b.spurious = { it in 300L until 340L && it % 3 == 0L } // 14 discontiguous "losses", all acknowledged 2 RTTs late
        b.spuriousDelay = rtt * 2 // after the loss round ended Startup
        b.run(rtt * 12)
        assertTrue(cc.spuriousUndos >= 1, "no undo: ${b.states}")
        val seq = b.states.map { it.second }
        val drain = seq.indexOf(Bbr.State.Drain)
        assertTrue(drain > 0 && seq.lastIndexOf(Bbr.State.Startup) > drain, "high loss ended Startup, the undo resumed it: $seq")
        assertEquals(Long.MAX_VALUE, cc.inflightLongterm)
    }

    @Test fun startupDoesNotEndOnABurstOfLossBeforeAFullRoundInRecovery() {
        // review of k7/bbr (section 5.3.1.3): the high-loss exit needs a whole round in recovery, judged at the end of the loss round;
        // a one-off burst whose round ends clean keeps Startup going
        val b = Bottleneck(bbr(), rate * 100, rtt)
        b.drop = { it in 100L until 120L && it % 2 == 0L } // 10 discontiguous losses on one ACK, then none
        var exitedAt = -1L
        b.run(rtt * 4) { if (exitedAt < 0 && b.cc.inflightLongterm != Long.MAX_VALUE) exitedAt = b.nextPn }
        assertEquals(-1L, exitedAt, "Startup ended on loss: ${b.states}")
    }

    @Test fun aPtoProbePastAFullWindowIsNotCwndLimited() {
        // review of k7/bbr: probes bypass the window; they must not let inflight_longterm grow as if the window limited the flow
        val cc = bbr()
        val t = TimeMark(1_000_000_000L)
        repeat(9) { cc.onPacketSent(t, 1200) } // 10 800 of 12 000
        assertTrue(!cc.isCwndLimited)
        cc.onMtuUpdate(1000) // before any ACK the initial window follows the datagram size: 10 000, below the flight
        assertEquals(10_000L, cc.cwnd)
        cc.onPacketSent(t, 1200) // a probe: the window was already full
        assertTrue(!cc.isCwndLimited, "a probe past a full window set C.is_cwnd_limited")
        val d = bbr()
        repeat(10) { d.onPacketSent(t, 1200) }
        assertTrue(d.isCwndLimited, "the 10th datagram filled the window")
    }

    @Test fun theInitialWindowFollowsTheDatagramSizeBeforeTheFirstAck() {
        val cc = bbr()
        cc.onMtuUpdate(1452)
        assertEquals(14_520L, cc.cwnd) // min(10 x 1452, max(14 720, 2 x 1452))
        assertEquals(4L * 1452, cc.minPipeCwnd)
    }

    @Test fun jumboDatagramsKeepTwoInTheSendQuantum() {
        // review of k7/bbr: coerceIn(2 x mss, 64 KiB) threw once 2 datagrams exceeded 64 KiB (loopback PMTUD reaches ~65 K)
        val b = Bottleneck(Bbr(60_000, Random(7)), 125_000_000L, 2.milliseconds, mss = 60_000)
        b.run(1.seconds)
        assertTrue(b.cc.sendQuantum >= 120_000, "quantum ${b.cc.sendQuantum}")
        assertTrue(b.cc.cwnd >= 240_000, "cwnd ${b.cc.cwnd}")
        assertTrue(b.delivered >= 125_000_000L / 2, "delivered ${b.delivered} in 1 s at 1 Gbit/s")
    }

    @Test fun aDatagramSizeChangeMidFlowKeepsTheModelInBytes() {
        val b = Bottleneck(bbr(), rate, rtt)
        b.run(3.seconds)
        val bw = b.cc.maxBw
        b.mss = 1452
        b.cc.onMtuUpdate(1452)
        assertTrue(b.cc.cwnd >= 4L * 1452)
        val before = b.delivered
        b.run(4.seconds)
        assertEquals(bw.toDouble(), b.cc.maxBw.toDouble(), bw * 0.1, "max_bw in bytes per second is unchanged by the datagram size")
        assertTrue((b.delivered - before) / 4 >= rate * 0.85, "goodput ${(b.delivered - before) / 4}")
        b.mss = 1200
        b.cc.onMtuUpdate(1200) // a black hole lowers it again
        b.run(2.seconds)
        assertTrue(b.cc.cwnd >= 4L * 1200 && b.cc.minPipeCwnd == 4800L)
        assertEquals(bw.toDouble(), b.cc.maxBw.toDouble(), bw * 0.1)
    }

    @Test fun restartingFromIdleInProbeBwPacesAtTheEstimateWithoutProbeRtt() {
        // draft section 5.4: no slow start and no line-rate burst after a quiet period, pacing at exactly BBR.bw (less the 1 % margin)
        val b = Bottleneck(bbr(), rate, rtt)
        b.run(3.seconds)
        b.appBytes = 0
        b.run(6.seconds) // idle past the 5 s ProbeRTT interval
        assertEquals(0L, b.cc.bytesInFlight)
        val bw = b.cc.bw
        val restart = b.now
        var firstRate = -1L
        var sentFirstRtt = 0L
        b.onSend = { t, n ->
            if (firstRate < 0) firstRate = b.cc.pacingRateForTest
            if (t - restart < rtt) sentFirstRtt += n
        }
        b.appBytes = Long.MAX_VALUE
        b.run(rtt * 3)
        assertEquals(bw * 0.99, firstRate.toDouble(), 1.0, "pacing at restart")
        // the first RTT carries at most one BDP at that rate plus one send quantum: no burst of the whole window
        assertTrue(sentFirstRtt <= bdp + b.cc.sendQuantum + 1200, "sent $sentFirstRtt in the first RTT (BDP $bdp)")
        val restartStates = b.states.filter { it.first >= restart }.map { it.second }
        assertTrue(Bbr.State.ProbeRtt !in restartStates, "ProbeRTT right after the restart: $restartStates")
    }

    @Test fun restartingFromIdleEndsAProbeRttThatIsDone() {
        val b = Bottleneck(bbr(), rate, rtt)
        b.run(12.seconds) { if (b.cc.state == Bbr.State.ProbeRtt && b.appBytes != 0L) b.appBytes = 0 }
        assertEquals(Bbr.State.ProbeRtt, b.cc.state, "went idle in ProbeRTT: ${b.states}")
        assertEquals(0L, b.cc.bytesInFlight)
        b.appBytes = Long.MAX_VALUE
        var stateAtFirstSend: Bbr.State? = null
        b.onSend = { _, _ -> if (stateAtFirstSend == null) stateAtFirstSend = b.cc.state }
        b.run(1.milliseconds)
        assertTrue(stateAtFirstSend != null && stateAtFirstSend != Bbr.State.ProbeRtt, "restart left ProbeRTT: $stateAtFirstSend")
    }
}
