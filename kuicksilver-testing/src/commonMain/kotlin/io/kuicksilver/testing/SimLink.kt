// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.testing

import io.kuicksilver.quic.Ecn
import io.kuicksilver.quic.TimeMark
import kotlin.random.Random
import kotlin.time.Duration.Companion.nanoseconds

/** A datagram travelling over a [SimLink]. */
internal class InFlight(
    val bytes: ByteArray,
    var arrival: TimeMark,
    val ecn: Ecn = Ecn.NotEct,
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

    fun send(
        bytes: ByteArray,
        ecn: Ecn,
        now: TimeMark,
    ) {
        val i = index++
        val tooBig = mtu?.let { bytes.size > it } ?: false
        val drop =
            dropNext || tooBig || i in params.lossMask ||
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
        params.bandwidthBitsPerSecond?.let { bw ->
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
                linkFree + params.delay
        }
        val marked =
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
        queue += InFlight(payload, arrival, marked)
        if (params.reorderRate > 0 && queue.size >= 2 &&
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
            queue += InFlight(payload, arrival + 1.nanoseconds, marked)
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
