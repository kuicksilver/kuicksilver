// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.core

import io.kuicksilver.quic.TimeMark
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

/**
 * Datagram Packetization Layer PMTU Discovery of one path (RFC 8899; RFC 9000 section 14.3): a binary
 * search between the 1200-byte base and [upperBound] with PING+PADDING probes of [step]-byte granularity, [maxProbes]
 * attempts per size, one final probe of the top of the range; the search repeats every [research]; three lost packets
 * larger than the base with no full-size packet sent after the first of them acknowledged mean a black hole: back to
 * 1200 and no probe for [blackHolePause]. The verdict waits for [takeBlackHole], after the whole ACK was processed:
 * loss detection reports the losses of an ACK before its newly acknowledged packets, and a congestion burst is exactly
 * full-size packets lost while later full-size ones arrive. Probes are ack-eliciting but outside congestion control, and their loss is
 * not a congestion signal (section 14.4). The core has no ICMP input (threat-model 3.16).
 */
internal class Pmtud(
    private val base: Int = 1200,
    upperBound: Int,
    private val step: Int = 20,
    private val maxProbes: Int = 3,
    private val research: Duration = 600.seconds,
    private val blackHolePause: Duration = 60.seconds,
) {
    var upperBound: Int = upperBound
        private set
    var current: Int = base
        private set
    private var low = base
    private var high = upperBound
    private var probeSize = 0
    private var probeLosses = 0
    private var probeInFlight = false
    private var finalProbe = false
    var searchDone: Boolean = false
        private set
    private var pausedUntil: TimeMark = TimeMark.NEVER
    private var researchAt: TimeMark = TimeMark.NEVER

    /** Lost packets above the base since the last reset, the lowest packet number among them, the highest acknowledged full-size packet number. */
    private var bigLost = 0
    private var firstBigLostPn = -1L
    private var largestBigAckedPn = -1L

    /** The peer's `max_udp_payload_size` lowers the range (RFC 9000 section 14.3). */
    fun limitUpperBound(peerMax: Int) {
        if (peerMax < upperBound) {
            upperBound = peerMax
            if (high > upperBound) high = upperBound
        }
    }

    /** The size of the probe to send now, 0 when none is due (one in flight, search done, or paused). */
    fun nextProbeSize(now: TimeMark): Int {
        if (probeInFlight || searchDone) return 0
        if (pausedUntil != TimeMark.NEVER) {
            if (now < pausedUntil) return 0
            pausedUntil = TimeMark.NEVER
        }
        val size =
            if (high - low >=
                step
            ) {
                low + ((high - low) / 2 / step) * step
            } else if (high > current) {
                finalProbe = true
                high
            } else {
                finish(now)
                return 0
            }
        probeSize = if (size <= low) low + step else size
        if (probeSize > high) probeSize = high
        probeInFlight = true
        return probeSize
    }

    fun onProbeAcked(
        size: Int,
        now: TimeMark,
    ) {
        probeInFlight = false
        probeLosses = 0
        if (size > current) current = size
        low = maxOf(low, size)
        if (finalProbe || (high - low < step && high <= current)) {
            finish(now)
        } else if (high - low < step && high > current) {
        } // one more try at the top
    }

    fun onProbeLost(
        size: Int,
        now: TimeMark,
    ) {
        probeInFlight = false
        probeLosses++
        if (probeLosses < maxProbes) return
        probeLosses = 0
        if (finalProbe) {
            finish(now)
            return
        }
        high = size - 1
        if (high - low < step && high <= current) finish(now)
    }

    /** A regular (non-probe) packet [pn] of [size] bytes was acknowledged: a full-size one sent after the lost ones proves the path carries the MTU. */
    fun onPacketAcked(
        size: Int,
        pn: Long,
    ) {
        if (size < current) return
        if (pn > largestBigAckedPn) largestBigAckedPn = pn
        if (bigLost > 0 && pn > firstBigLostPn) {
            bigLost = 0
            firstBigLostPn = -1L
        }
    }

    /** A regular packet [pn] of [size] bytes was lost; counted unless a later full-size packet already arrived. */
    fun onPacketLost(
        size: Int,
        pn: Long,
    ) {
        if (size <= base || pn < largestBigAckedPn) return
        if (bigLost == 0 || pn < firstBigLostPn) firstBigLostPn = pn
        bigLost++
    }

    /** After an ACK or a loss timer was processed: true (and back to the base) when three large packets were lost with none acknowledged after them, a black hole (RFC 8899 section 4.3). */
    fun takeBlackHole(now: TimeMark): Boolean {
        if (bigLost < 3) return false
        onBlackHole(now)
        return true
    }

    /** Back to the base size with a pause before probing again: also the answer to repeated PTOs while sending above the base, when nothing comes back for loss detection to work with. */
    fun onBlackHole(now: TimeMark) {
        bigLost = 0
        firstBigLostPn = -1L
        current = base
        low = base
        high = upperBound
        searchDone = false
        probeInFlight = false
        probeLosses =
            0
        finalProbe = false
        pausedUntil = now + blackHolePause
        researchAt = TimeMark.NEVER
    }

    /** When the core must call [onTimeout]: the end of a pause or the re-search time. */
    fun timeout(): TimeMark = if (pausedUntil != TimeMark.NEVER) pausedUntil else researchAt

    fun onTimeout(now: TimeMark) {
        // also on a path that is no longer active: its deadline must not stay in the past
        if (pausedUntil != TimeMark.NEVER && pausedUntil <= now) pausedUntil = TimeMark.NEVER
        if (searchDone && researchAt != TimeMark.NEVER &&
            researchAt <= now
        ) {
            searchDone = false
            finalProbe = false
            low = current
            high = upperBound
            researchAt = TimeMark.NEVER
        }
    }

    private fun finish(now: TimeMark) {
        searchDone = true
        finalProbe = false
        researchAt = now + research
    }
}
