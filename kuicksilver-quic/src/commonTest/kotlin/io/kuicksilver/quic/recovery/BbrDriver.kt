// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.recovery

import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.quic.Bbr
import io.kuicksilver.quic.TimeMark
import kotlin.random.Random
import kotlin.time.Duration.Companion.nanoseconds

/**
 * Drives one [Bbr] with an arbitrary stream of operations, calling it as the core does (send and stamp; per ACK the delivered
 * packets, the spurious losses, the CE report, the losses, the window updates, the end of the ACK; timeouts; MTU changes;
 * application-limited phases; settled losses), and checks the controller's invariants after every operation. Shared by the
 * property tests and the Jazzer target `bbrInvariants`. Each operation reads its arguments from [next] (any values: the driver
 * folds them into range), so a byte stream and a random generator drive it alike.
 */
@OptIn(ExperimentalKuicksilverApi::class)
internal class BbrDriver(
    seed: Long,
    mss: Int,
) {
    val cc = Bbr(mss.coerceIn(1200, 65_527), Random(seed))
    private var mss = mss.coerceIn(1200, 65_527)
    private var now = TimeMark(1_000_000_000L)
    private var pn = 0L
    private val outstanding = ArrayDeque<SentPacket>()
    private var lostRemembered = 0 // lost packets the "core" still remembers (each later spurious or settled)
    var ops = 0
        private set
    private var lastState = cc.state

    /** One operation: [op] picks it, [arg] supplies its parameters. */
    fun step(
        op: Int,
        arg: () -> Int,
    ) {
        ops++
        when ((op and 0x7fffffff) % 10) {
            0 -> send(1 + (arg() and 0x3f), probe = false)
            1 -> ack(arg(), arg(), arg())
            2 -> advance(arg(), arg())
            3 -> cc.onAppLimited()
            4 -> mtu(arg())
            5 -> timeoutLoss(1 + (arg() and 0x1f), persistent = arg() and 7 == 0)
            6 -> settle(1 + (arg() and 0xf))
            7 -> cc.onEcnCe(now, now)
            8 -> send(1 + (arg() and 3), probe = true)
            else -> discard(1 + (arg() and 0xf))
        }
        check()
    }

    private fun send(
        n: Int,
        probe: Boolean,
    ) {
        repeat(n) {
            if (!probe && cc.bytesInFlight >= cc.cwnd) return // the core's rule; a PTO probe goes regardless
            val p = SentPacket()
            p.pn = pn++
            p.timeSent = now
            p.size = mss
            p.inFlight = true
            cc.onPacketSent(now, p.size)
            cc.onPacketStamped(p, now)
            outstanding += p
        }
    }

    /** Time moves on: [scale] picks nanoseconds to seconds, [v] the amount (up to about 10 s of idleness). */
    private fun advance(
        scale: Int,
        v: Int,
    ) {
        val amount = (v and 0xffff).toLong()
        val d =
            when ((scale and 0x7fffffff) % 5) {
                0 -> amount

                // ns
                1 -> amount * 1_000

                // up to 65 ms
                2 -> amount * 30_000

                // up to 2 s
                3 -> amount * 150_000

                // up to 10 s
                else -> 0L
            }
        now += d.nanoseconds
    }

    /**
     * An ACK frame: of the outstanding packets (oldest first) it acknowledges a run of [count] starting at [skip] (the ones it
     * skips past by 3 or more are lost, as the packet threshold says), and [flags] picks spurious losses and a CE report.
     */
    private fun ack(
        skip: Int,
        count: Int,
        flags: Int,
    ) {
        if (outstanding.isEmpty() && lostRemembered == 0) return
        val from = if (outstanding.isEmpty()) 0 else (skip and 0x7fffffff) % minOf(outstanding.size, 8)
        val n = if (outstanding.isEmpty()) 0 else minOf(1 + (count and 0x7fffffff) % 64, outstanding.size - from)
        val acked = ArrayList<SentPacket>(n)
        for (i in 0 until n) acked += outstanding[from + i]
        for (p in acked) cc.onPacketAcked(p, now)
        val spurious = minOf(lostRemembered, (flags ushr 4) and 3)
        repeat(spurious) {
            lostRemembered--
            cc.onSpuriousLoss(now)
        }
        if (flags and 1 != 0) cc.onEcnCe(now, now)
        // packets 3 or more below the largest acknowledged are lost (RFC 9002 section 6.1.1)
        val lost = ArrayList<SentPacket>()
        if (n > 0) {
            val largest = acked.last().pn
            for (k in 0 until from) if (outstanding[k].pn + 3 <= largest) lost += outstanding[k]
        }
        outstanding.removeAll { p -> acked.any { it === p } || lost.any { it === p } }
        declareLost(lost, persistent = flags and 2 != 0 && lost.size >= 2)
        for (p in acked) cc.onAck(now, p.timeSent, p.size, (now - p.timeSent), false)
        cc.onAckProcessed(now)
    }

    private fun timeoutLoss(
        n: Int,
        persistent: Boolean,
    ) {
        val lost = ArrayList<SentPacket>()
        repeat(minOf(n, outstanding.size)) { lost += outstanding.removeFirst() }
        declareLost(lost, persistent)
    }

    private fun declareLost(
        lost: List<SentPacket>,
        persistent: Boolean,
    ) {
        if (lost.isEmpty()) return
        var bytes = 0
        for (p in lost) {
            cc.onPacketLost(p, now)
            lostRemembered++
            bytes += p.size
        }
        cc.onLoss(now, bytes, lost.last().timeSent, persistent)
    }

    private fun settle(n: Int) {
        repeat(minOf(n, lostRemembered)) {
            lostRemembered--
            cc.onLossSettled(now)
        }
    }

    private fun discard(n: Int) {
        var bytes = 0
        repeat(minOf(n, outstanding.size)) { bytes += outstanding.removeFirst().size }
        if (bytes > 0) cc.onDiscarded(bytes)
    }

    /**
     * The 4-datagram floor from before the last larger datagram size, while the window is still below the new one: RFC 8899
     * forbids the size update itself to raise the window, the controller lifts it to the new floor when it next sets it.
     */
    private var oldFloor = Long.MAX_VALUE

    private fun mtu(v: Int) {
        val floor = cc.minPipeCwnd
        mss = 1200 + (v and 0x7fffffff) % (65_527 - 1200 + 1)
        cc.onMtuUpdate(mss)
        if (cc.minPipeCwnd > floor) oldFloor = minOf(oldFloor, floor)
    }

    /** The invariants: violated ones throw [IllegalStateException] with the operation count. */
    fun check() {
        val flight = outstanding.sumOf { it.size.toLong() }
        check(cc.bytesInFlight == flight) { "op $ops: bytes in flight ${cc.bytesInFlight}, outstanding $flight" }
        // the minimum congestion window is 2 datagrams (RFC 9002 section 7.2; persistent congestion sets it), half BBR's pipelining floor
        if (cc.cwnd >= cc.minPipeCwnd / 2) oldFloor = Long.MAX_VALUE
        check(
            cc.cwnd >= minOf(cc.minPipeCwnd, oldFloor) / 2,
        ) { "op $ops: cwnd ${cc.cwnd} below the 2-datagram minimum ${cc.minPipeCwnd / 2}" }
        for (srtt in SRTTS) {
            val r = cc.pacingRate(srtt.nanoseconds)
            check(r > 0) { "op $ops: pacing rate $r at srtt $srtt ns" }
        }
        val q = cc.sendQuantum
        check(q >= 2 * mss && q <= maxOf(65_536, 2 * mss)) { "op $ops: send quantum $q with datagrams of $mss" }
        check(cc.maxBw >= 0 && cc.bw >= 0 && cc.bw <= cc.maxBw) { "op $ops: max_bw ${cc.maxBw} bw ${cc.bw}" }
        check(cc.bwShortterm >= 0) { "op $ops: bw_shortterm ${cc.bwShortterm}" }
        check(cc.minRttNanos >= 0) { "op $ops: min_rtt ${cc.minRttNanos}" }
        check(cc.inflightLongterm > 0 && cc.inflightShortterm >= 0) {
            "op $ops: inflight_longterm ${cc.inflightLongterm} inflight_shortterm ${cc.inflightShortterm}"
        }
        check(cc.lossesPending >= 0)
        val s = cc.sampler
        check(s.delivered >= 0 && s.lost >= 0 && s.deliveryRate >= 0) { "op $ops: sampler ${s.delivered} ${s.lost} ${s.deliveryRate}" }
        val st = cc.state
        if (st != lastState) {
            check(st in LEGAL.getValue(lastState)) { "op $ops: illegal transition $lastState -> $st" }
            lastState = st
        }
    }

    companion object {
        private val SRTTS = longArrayOf(0, 1, 100_000, 1_000_000, 40_000_000, 2_000_000_000, 60_000_000_000)

        /**
         * The transitions one call may show (draft section 4.3 state machine; one ACK can pass through Drain or ProbeBW_DOWN and
         * land further on); Startup and ProbeBW_REFILL are reachable from elsewhere only through a spurious-loss undo.
         */
        val LEGAL: Map<Bbr.State, Set<Bbr.State>> =
            mapOf(
                Bbr.State.Startup to
                    setOf(Bbr.State.Drain, Bbr.State.ProbeBwDown, Bbr.State.ProbeBwCruise, Bbr.State.ProbeBwRefill, Bbr.State.ProbeRtt),
                Bbr.State.Drain to
                    setOf(Bbr.State.ProbeBwDown, Bbr.State.ProbeBwCruise, Bbr.State.ProbeBwRefill, Bbr.State.ProbeRtt, Bbr.State.Startup),
                Bbr.State.ProbeBwDown to setOf(Bbr.State.ProbeBwCruise, Bbr.State.ProbeBwRefill, Bbr.State.ProbeRtt, Bbr.State.Startup),
                Bbr.State.ProbeBwCruise to setOf(Bbr.State.ProbeBwRefill, Bbr.State.ProbeRtt, Bbr.State.Startup),
                Bbr.State.ProbeBwRefill to setOf(Bbr.State.ProbeBwUp, Bbr.State.ProbeRtt, Bbr.State.Startup),
                Bbr.State.ProbeBwUp to
                    setOf(Bbr.State.ProbeBwDown, Bbr.State.ProbeBwCruise, Bbr.State.ProbeBwRefill, Bbr.State.ProbeRtt, Bbr.State.Startup),
                Bbr.State.ProbeRtt to setOf(Bbr.State.ProbeBwDown, Bbr.State.ProbeBwCruise, Bbr.State.Startup),
            )
    }
}
