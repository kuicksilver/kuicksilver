// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.testing

import io.kuicksilver.quic.Ecn
import io.kuicksilver.quic.TimeMark
import kotlin.random.Random
import kotlin.time.Duration
import kotlin.time.Duration.Companion.nanoseconds

/** A datagram travelling over a [SimLink]. */
internal class InFlight(
    val bytes: ByteArray,
    var arrival: TimeMark,
    val ecn: Ecn = Ecn.NotEct,
    /** Which flow the datagram belongs to, for links several flows share (`SharedBottleneck`). */
    val tag: Int = 0,
)

/** One direction of the link: applies loss, reordering, duplication, corruption, serialization and delay. */
internal class SimLink(
    private val params: LinkParams,
    private val random: Random,
    private val name: String,
) {
    private val queue = ArrayList<InFlight>()
    private var linkFree = TimeMark(0)
    var index = 0
        private set
    var delivered = 0L
        private set
    var dropped = 0L
        private set

    /** Set by scenarios to drop the next datagram regardless of the parameters. */
    var dropNext = false

    /** Current MTU of this direction (changeable mid-run: a black hole that appears during a transfer). */
    var mtu: Int? = params.mtu

    /** How long the last datagram sent waited for the link (0 without a bandwidth limit), and the datagrams the full buffer dropped. */
    var lastQueueDelay: Duration = Duration.ZERO
        private set
    var tailDropped = 0L
        private set

    /** The bottleneck rate, changeable mid-run (a link rate step); starts at the parameters' rate. */
    var bandwidth: Long? = params.bandwidthBitsPerSecond

    /** Everything sent is dropped while set (a blackhole, both directions when the scenario sets both links). */
    var blackhole = false

    /** A reordered datagram (with [LinkParams.reorderRate]) is held back this long instead of swapping places with its predecessor. */
    var reorderDelay: Duration = Duration.ZERO

    /** Arrivals are released in batches at multiples of this interval (Wi-Fi-like aggregation of ACKs); zero: no batching. */
    var aggregation: Duration = Duration.ZERO

    /** Extra one-way delay per flow tag (RTT unfairness on a shared bottleneck); null: none. */
    var extraDelayByTag: ((Int) -> Duration)? = null

    /** ECT datagrams that wait longer than this for the link are marked CE (a step-marking AQM); null: no marking. */
    var ceMarkAbove: Duration? = null

    /** When the bottleneck finishes what it holds; the scenario integrates the queueing delay over time from it. */
    val busyUntil: TimeMark get() = linkFree

    fun send(
        bytes: ByteArray,
        ecn: Ecn,
        now: TimeMark,
        tag: Int = 0,
    ) {
        val i = index++
        val tooBig = mtu?.let { bytes.size > it } ?: false
        val drop =
            blackhole || dropNext || tooBig || i in params.lossMask ||
                (params.burstLoss?.let { i >= it.startIndex && i < it.startIndex + it.length } ?: false) ||
                (params.lossRate > 0 && random.nextDouble() < params.lossRate)
        dropNext = false
        if (drop) {
            dropped++
            return
        }
        var payload = bytes
        if (params.corruptRate > 0 &&
            random.nextDouble() < params.corruptRate
        ) {
            payload = bytes.copyOf()
            val k = random.nextInt(payload.size)
            payload[k] =
                (payload[k].toInt() xor (1 + random.nextInt(255))).toByte()
        }
        var arrival =
            now + params.delay +
                (if (params.jitter.isPositive()) (random.nextLong(params.jitter.inWholeNanoseconds)).nanoseconds else 0.nanoseconds)
        extraDelayByTag?.let { arrival += it(tag) }
        var aqmMark = false
        bandwidth?.let { bw ->
            val waiting = if (linkFree > now) ((linkFree - now).inWholeNanoseconds.toDouble() * bw / 8e9).toLong() else 0L
            val limit = params.queueLimitBytes
            if (limit != null && waiting + payload.size > limit) {
                dropped++
                tailDropped++
                return
            } // the bottleneck buffer is full
            lastQueueDelay = if (linkFree > now) linkFree - now else Duration.ZERO
            ceMarkAbove?.let { if (lastQueueDelay > it) aqmMark = true }
            val start =
                if (linkFree >
                    now
                ) {
                    linkFree
                } else {
                    now
                }
            ; val tx = (payload.size * 8L * 1_000_000_000L / bw).nanoseconds
            linkFree = start + tx
            arrival =
                linkFree + params.delay + (extraDelayByTag?.invoke(tag) ?: Duration.ZERO)
        }
        if (aggregation.isPositive()) {
            val q = aggregation.inWholeNanoseconds
            arrival = TimeMark((arrival.nanos + q - 1) / q * q)
        }
        val marked =
            if (aqmMark && (ecn == Ecn.Ect0 || ecn == Ecn.Ect1)) {
                Ecn.Ce
            } else {
                when (val m = params.ecn) {
                    EcnMarking.Pass -> {
                        ecn
                    }

                    EcnMarking.Bleach -> {
                        Ecn.NotEct
                    }

                    is EcnMarking.CeRate -> {
                        if ((
                                ecn ==
                                    Ecn.Ect0 ||
                                    ecn == Ecn.Ect1
                            ) &&
                            random.nextDouble() < m.rate
                        ) {
                            Ecn.Ce
                        } else {
                            ecn
                        }
                    }
                }
            }
        if (reorderDelay.isPositive() && params.reorderRate > 0 && random.nextDouble() < params.reorderRate) {
            arrival += reorderDelay
        }
        queue += InFlight(payload, arrival, marked, tag)
        if (!reorderDelay.isPositive() && params.reorderRate > 0 && queue.size >= 2 &&
            random.nextDouble() < params.reorderRate
        ) {
            val a = queue[queue.size - 1]
            val b = queue[queue.size - 2]
            val t = a.arrival
            a.arrival =
                b.arrival
            b.arrival = t
        }
        if (params.duplicateRate > 0 &&
            random.nextDouble() < params.duplicateRate
        ) {
            queue += InFlight(payload, arrival + 1.nanoseconds, marked, tag)
        }
    }

    fun nextArrival(): TimeMark? = queue.minByOrNull { it.arrival.nanos }?.arrival

    /** Removes and returns every datagram due at or before [now], in arrival order. */
    fun due(now: TimeMark): List<InFlight> {
        val d = queue.filter { it.arrival <= now }.sortedBy { it.arrival.nanos }
        queue.removeAll(d)
        delivered +=
            d.size
        return d
    }

    val pending: Int get() = queue.size
}
