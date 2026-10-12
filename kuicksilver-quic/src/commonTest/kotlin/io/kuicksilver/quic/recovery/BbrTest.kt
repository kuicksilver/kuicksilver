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
 * send, stamp; per ACK the CE report, the losses, the acknowledged packets, the end of the ACK.
 */
@OptIn(ExperimentalKuicksilverApi::class)
private class Bottleneck(
    val cc: Bbr,
    val rate: Long,
    val baseRtt: Duration,
) {
    val mss = 1200
    var now = TimeMark(1_000_000_000L)
    private var linkFree = now
    private var nextSend = now
    private var pn = 0L
    private val queue = ArrayDeque<SentPacket>()
    private val arrival = ArrayDeque<TimeMark>()

    /** Packets (by number) the link drops, and those it marks CE. */
    var drop: (Long) -> Boolean = { false }
    var ce: (Long) -> Boolean = { false }

    /** Bytes the application still has; [Long.MAX_VALUE]: always more. */
    var appBytes = Long.MAX_VALUE
    val states = ArrayList<Pair<TimeMark, Bbr.State>>()
    var maxRtt: Duration = Duration.ZERO
    var delivered = 0L
    var maxCwndInProbeRtt = 0L

    fun run(
        d: Duration,
        each: () -> Unit = {},
    ) {
        val end = now + d
        record()
        while (now < end) {
            while (cc.bytesInFlight + mss <= cc.cwnd && nextSend <= now && appBytes > 0) send()
            if (appBytes <= 0) cc.onAppLimited()
            var next = end
            if (arrival.isNotEmpty() && arrival.first() < next) next = arrival.first()
            if (cc.bytesInFlight + mss <= cc.cwnd && appBytes > 0 && nextSend > now && nextSend < next) next = nextSend
            if (next <= now) next = now + 1.nanoseconds
            now = next
            if (arrival.isNotEmpty() && arrival.first() <= now) ackDue()
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
        while (arrival.isNotEmpty() && arrival.first() <= now) {
            arrival.removeFirst()
            val p = queue.removeFirst()
            if (drop(p.pn)) {
                cc.onPacketLost(p, now)
                lostBytes += p.size
                largestLost = p.timeSent
            } else {
                if (ce(p.pn)) {
                    anyCe = true
                    ceSent = p.timeSent
                }
                acked += p
            }
        }
        if (anyCe) cc.onEcnCe(now, ceSent)
        if (lostBytes > 0) cc.onLoss(now, lostBytes, largestLost, false)
        for (p in acked) {
            cc.onPacketAcked(p, now)
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
}
