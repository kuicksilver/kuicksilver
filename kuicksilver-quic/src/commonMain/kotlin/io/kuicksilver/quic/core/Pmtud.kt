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
 * full-size packets lost while later full-size ones arrive. A verdict is undone when a full-size packet sent after the
 * packets it rested on is acknowledged later on (the path carried it: a peer that stalled for a few PTOs, delayed ACKs),
 * see [onPacketAcked]. Probes are ack-eliciting but outside congestion control, and their loss is
 * not a congestion signal (section 14.4).
 *
 * ICMP Packet Too Big and a local EMSGSIZE are hints, never facts (RFC 8899 section 4.6, RFC 9000 section 14.2.1; threat-model
 * 3.16): the caller validates the message first ([onPtb]). A size reported above [current] only ends the probes above it at once;
 * one below [current] starts a confirmation (probes of [current]): an acknowledged one forgets the hint, [maxProbes] lost ones lower
 * [current] to the reported size (never below the base, no pause). Nothing else of this class trusts ICMP.
 */
internal class Pmtud(
    private val base: Int = 1200,
    upperBound: Int,
    private val step: Int = 20,
    private val maxProbes: Int = 3,
    private val research: Duration = 600.seconds,
    private val blackHolePause: Duration = 60.seconds,
    /** The size in use at the start: the base, or the MTU a NAT-rebound path inherited (black-hole detection covers it, RFC 8899 section 4.3). */
    start: Int = base,
) {
    var upperBound: Int = upperBound
        private set
    var current: Int = start
        private set
    private var low = start
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

    /** The search state before the last black-hole verdict (0: none to undo) and the packet number after which a full-size acknowledged packet disproves it. */
    private var undoCurrent = 0
    private var undoLow = 0
    private var undoHigh = 0
    private var undoSearchDone = false
    private var undoResearchAt: TimeMark = TimeMark.NEVER
    private var undoAfterPn = -1L

    /** A PTB below [current] being confirmed: the payload it reported (0: none), and the confirmation probes lost so far. */
    private var confirmPtb = 0
    private var confirmLosses = 0
    private var confirming = false

    internal val probeInFlightForTest: Int get() = if (probeInFlight) probeSize else 0
    internal val confirmingForTest: Int get() = confirmPtb
    internal val pausedForTest: Boolean get() = pausedUntil != TimeMark.NEVER

    /**
     * A validated Packet Too Big reporting [payload] bytes of UDP payload (already at least the base: the caller drops smaller
     * ones). At or above [current]: the probes above it are settled at once (RFC 8899 section 4.6.2), the one in flight included.
     * Below [current]: nothing is lowered; probes of [current] confirm the size ([onProbeAcked], [onProbeLost]).
     */
    fun onPtb(
        payload: Int,
        now: TimeMark,
    ) {
        if (payload < base) return
        if (payload >= current) {
            if (payload < high) high = payload
            if (probeInFlight && !confirming && probeSize > payload) {
                // the probe in flight is too large: settled now, not after maxProbes x PTO; its late loss or ACK is still handled
                probeInFlight = false
                probeLosses = 0
            }
            if (high - low < step && high <= current) finish(now)
            return
        }
        if (confirmPtb == 0 || payload < confirmPtb) confirmPtb = payload
    }

    /**
     * The kernel refused a datagram of [size] bytes as larger than the MTU it knows (EMSGSIZE): when it was the probe in flight, that
     * size is settled at once, as if lost [maxProbes] times. Local, so not spoofable; still only about probes, never [current].
     */
    fun onEmsgsize(
        size: Int,
        now: TimeMark,
    ) {
        if (!probeInFlight || confirming || size != probeSize || size <= current) return
        probeInFlight = false
        probeLosses = 0
        if (finalProbe) {
            finish(now)
            return
        }
        high = size - 1
        if (high - low < step && high <= current) finish(now)
    }

    /** The peer's `max_udp_payload_size` lowers the range (RFC 9000 section 14.3). */
    fun limitUpperBound(peerMax: Int) {
        if (peerMax < upperBound) {
            upperBound = peerMax
            if (high > upperBound) high = upperBound
        }
    }

    /** The size of the probe to send now, 0 when none is due (one in flight, search done, or paused). */
    fun nextProbeSize(now: TimeMark): Int {
        if (probeInFlight) return 0
        if (confirmPtb > 0) {
            // a PTB below the size in use: a probe of that size, before anything else and whatever the search state
            confirming = true
            probeSize = current
            probeInFlight = true
            return current
        }
        if (searchDone) return 0
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
        if (confirming && size == probeSize) {
            // the size in use still gets through: the PTB was wrong (or stale)
            confirming = false
            probeInFlight = false
            confirmPtb = 0
            confirmLosses = 0
            return
        }
        if (size > high) high = size // an ACK outweighs any hint that said this size could not pass
        if (probeInFlight && size != probeSize) {
            // the ACK of a probe a hint already settled: it proves its size, the probe in flight stays in flight
            if (size > current) current = size
            low = maxOf(low, size)
            return
        }
        probeInFlight = false
        probeLosses = 0
        if (size > current) current = size
        low = maxOf(low, size)
        if (finalProbe || (high - low < step && high <= current)) {
            finish(now)
        } else if (high - low < step && high > current) {
        } // one more try at the top
    }

    /** A probe of [size] was lost; true when [current] changed (a confirmed PTB lowered it). */
    fun onProbeLost(
        size: Int,
        now: TimeMark,
    ): Boolean {
        if (confirming && size == probeSize) {
            probeInFlight = false
            confirming = false
            if (++confirmLosses < maxProbes) return false
            // maxProbes probes of the size in use lost after a PTB: the path carries no more than the PTB said (RFC 8899 section
            // 4.6.2); to its size, a multiple of the step above the base, and the search goes on from there without a pause
            val to = maxOf(base, base + (confirmPtb - base) / step * step)
            confirmPtb = 0
            confirmLosses = 0
            if (to >= current) return false
            current = to
            low = to
            high = maxOf(to, minOf(high, to + step - 1).coerceAtMost(upperBound))
            searchDone = false
            finalProbe = false
            probeLosses = 0
            return true
        }
        // a probe a hint settled, or one that is not the probe in flight: its loss is already accounted
        if (!probeInFlight || size != probeSize) return false
        probeInFlight = false
        probeLosses++
        if (probeLosses < maxProbes) return false
        probeLosses = 0
        if (finalProbe) {
            finish(now)
            return false
        }
        high = size - 1
        if (high - low < step && high <= current) finish(now)
        return false
    }

    /**
     * A regular (non-probe) packet [pn] of [size] bytes was acknowledged: a full-size one sent after the lost ones proves the path
     * carries the MTU. One larger than [current], sent before a black-hole verdict and after the packets that verdict rested on,
     * proves the verdict wrong (RFC 8899 section 4.1: an acknowledged packet confirms its size): the search state from before it
     * comes back, without a pause. Returns true when [current] changed so.
     */
    fun onPacketAcked(
        size: Int,
        pn: Long,
    ): Boolean {
        if (size < current) return false
        val undone = size > current && undoCurrent > 0 && pn > undoAfterPn
        if (undone) {
            if (size >= undoCurrent) {
                current = undoCurrent
                low = undoLow
                high = undoHigh
                searchDone = undoSearchDone
                researchAt = undoResearchAt
            } else {
                current = size
                low = size
                high = undoHigh
                searchDone = false
                researchAt = TimeMark.NEVER
            }
            finalProbe = false
            probeInFlight = false
            probeLosses = 0
            pausedUntil = TimeMark.NEVER
            undoCurrent = 0
        }
        if (pn > largestBigAckedPn) largestBigAckedPn = pn
        if (bigLost > 0 && pn > firstBigLostPn) {
            bigLost = 0
            firstBigLostPn = -1L
        }
        return undone
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
        fallBack(now, firstBigLostPn)
        return true
    }

    /**
     * Back to the base size with a pause before probing again: also the answer to repeated PTOs while sending above the base, when
     * nothing comes back for loss detection to work with. A full-size packet newer than every one acknowledged so far that is
     * acknowledged after all undoes it (a peer that only stalled).
     */
    fun onBlackHole(now: TimeMark) = fallBack(now, largestBigAckedPn)

    private fun fallBack(
        now: TimeMark,
        disprovedAfterPn: Long,
    ) {
        if (current > base) {
            undoCurrent = current
            undoLow = low
            undoHigh = high
            undoSearchDone = searchDone
            undoResearchAt = researchAt
            undoAfterPn = disprovedAfterPn
        }
        bigLost = 0
        firstBigLostPn = -1L
        confirmPtb = 0
        confirmLosses = 0
        confirming = false
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
