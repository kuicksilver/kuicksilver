// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.core

import io.kuicksilver.quic.TimeMark
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

/**
 * Datagram Packetization Layer PMTU Discovery of one path (RFC 8899; RFC 9000 section 14.3): a binary
 * search between the 1200-byte base and [upperBound] with PING+PADDING probes of [step]-byte granularity, [maxProbes]
 * attempts per size, one final probe of the top of the range; the search repeats every [research]. A probe fails when QUIC's
 * loss detection declares it lost (RFC 9000 section 14.3: "DPLPMTUD relies on tracking loss or acknowledgment of QUIC packets
 * that are carried in PMTU probes"), but never before [minProbeTimer] after it was sent (RFC 8899 section 5.1.1: PROBE_TIMER
 * "MUST NOT be smaller than 1 second"), or when [probeTimer] passed with neither verdict; only then does the next probe go
 * (section 5.2). The SHOULD of the same section ("larger than 15 seconds") is not followed for the loss-detection verdict:
 * docs/spec/rfc/8899.md records why. An acknowledgment that comes after all still confirms the size. Three lost packets
 * larger than the base with no full-size packet acknowledged from the first of them on mean a black hole: back to
 * 1200 and no probe for [blackHolePause]. The verdict waits for [takeBlackHole], after the whole ACK was processed:
 * loss detection reports the losses of an ACK before its newly acknowledged packets, and a congestion burst is exactly
 * full-size packets lost while later full-size ones arrive. A verdict is undone when a full-size packet from the first of
 * those it rested on is acknowledged later on, one of them included (the path carried it: a loss declared spuriously, a peer
 * that stalled for a few PTOs, delayed ACKs),
 * see [onPacketAcked]. Probes are ack-eliciting and count in flight inside the congestion window ("PMTU probes consume
 * congestion window"), but their loss is not a congestion signal (section 14.4).
 *
 * ICMP Packet Too Big and a local EMSGSIZE are hints, never facts (RFC 8899 section 4.6, RFC 9000 section 14.2.1; threat-model
 * 3.16): the caller validates the message first ([onPtb]). A size reported above [current] only ends the probes above it at once.
 * One below [current] drops [current] to the base at once (RFC 8899 section 4.6.2: "The PLPMTU SHOULD be set to BASE_PLPMTU"), but
 * provisionally (RFC 9000 section 14.2.1: "Any reduction ... MAY be provisional"): one probe of the old size goes first, and its
 * acknowledgment restores the old size and search state; once loss detection fails it, the search starts from the base with the
 * reported size as its first point ("can be used to initialize a search algorithm"). A probe of the old size acknowledged at any time
 * after such a drop suspends Packet Too Big processing for [ptbSuspend] (RFC 8899 section 8: "a PL sender could therefore suspend
 * processing of PTB messages (e.g., in a robustness mode after detecting that subsequent probes actually confirm that a size larger
 * than the PTB_SIZE is supported by a path)"), so forged messages cost about one probe round trip at the base per [ptbSuspend] (the probe goes once the congestion window has room). Only probes sent after the drop count: one sent before it is about the path before the PTB. The
 * black-hole detector never relies on a Packet Too Big. Nothing else of this class trusts ICMP.
 */
internal class Pmtud(
    private val base: Int = 1200,
    upperBound: Int,
    private val step: Int = 20,
    private val maxProbes: Int = 3,
    private val research: Duration = 600.seconds,
    private val blackHolePause: Duration = 60.seconds,
    /** RFC 8899 section 5.1.1 PROBE_TIMER for a probe loss detection never judged (at least 3 PTO, see [nextProbeSize]). */
    private val probeTimer: Duration = PROBE_TIMER,
    /** The earliest a probe may fail after it was sent, whatever loss detection says (RFC 8899 section 5.1.1: at least 1 s). */
    private val minProbeTimer: Duration = MIN_PROBE_TIMER,
    /** How long Packet Too Big messages are ignored after a probe disproved one (RFC 8899 section 8 robustness mode). */
    private val ptbSuspend: Duration = research,
    /** The size in use at the start: the base, or the MTU a NAT-rebound path inherited (black-hole detection covers it, RFC 8899 section 4.3). */
    start: Int = base,
    /**
     * The largest packet number sent before this instance (-1: none): probes up to it were another instance's, sent by a search this
     * one replaced (to an address the path no longer has, or before its capabilities changed), and their acknowledgments change nothing.
     */
    sentAfterPn: Long = -1L,
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
    private var probeDeadline: TimeMark = TimeMark.NEVER // when the probe in flight has failed unless acknowledged before
    private var probeSentAt: TimeMark = TimeMark.NEVER
    private var probePn = -1L // the packet number of the probe in flight, once sent

    /**
     * The packet numbers and sizes of the last [SENT_PROBES] probes sent ([onProbeSent]), and which of them loss detection declared
     * lost ([onProbeDeclaredLost]), so an acknowledgment that comes after all is known ([takeLostProbeIn]).
     */
    private val sentPn = LongArray(SENT_PROBES) { -1L }
    private val sentSize = IntArray(SENT_PROBES)
    private val sentLost = BooleanArray(SENT_PROBES)
    private var sentNext = 0
    private var lostProbes = 0

    /** Some probe of the last [SENT_PROBES] was declared lost and not acknowledged since. */
    val hasLostProbes: Boolean get() = lostProbes > 0
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

    /**
     * A validated PTB below the size in use dropped [current] to the base provisionally: the size before it (0: none) and the search
     * state that an acknowledged probe of it restores. [confirming]: the probe in flight is that probe.
     */
    private var ptbFrom = 0
    private var ptbLow = 0
    private var ptbHigh = 0
    private var ptbSearchDone = false
    private var ptbResearchAt: TimeMark = TimeMark.NEVER
    private var confirming = false

    /** The PTB's size on the step grid: the first point of the search after the drop (0: none). */
    private var ptbHint = 0

    /** The size before a drop that stands (the probe of it failed): a late acknowledgment of a probe that large still disproves the PTB. */
    private var ptbDisproveSize = 0

    /** The largest probe packet number sent so far, and that number when the last PTB drop happened: probes up to it were sent before. */
    private var lastProbePn = sentAfterPn
    private var ptbAfterPn = sentAfterPn

    /** Until when Packet Too Big messages are not processed (RFC 8899 section 8 robustness mode); [TimeMark.NEVER]: they are. */
    private var ptbSuspendedUntil: TimeMark = TimeMark.NEVER

    internal val probeInFlightForTest: Int get() = if (probeInFlight) probeSize else 0
    internal val confirmingForTest: Int get() = ptbFrom
    internal val ptbSuspendedForTest: Boolean get() = ptbSuspendedUntil != TimeMark.NEVER
    internal val pausedForTest: Boolean get() = pausedUntil != TimeMark.NEVER

    /**
     * A validated Packet Too Big reporting [payload] bytes of UDP payload (already at least the base: the caller drops smaller
     * ones). At or above [current]: the probes above it are settled at once (RFC 8899 section 4.6.2), the one in flight included.
     * Below [current] (RFC 8899 section 4.6.2 "BASE_PLPMTU <= PL_PTB_SIZE < PLPMTU"): [current] drops to the base provisionally and
     * a search starts at [payload]; not while Packet Too Big processing is suspended. True when [current] changed.
     */
    fun onPtb(
        payload: Int,
        now: TimeMark,
    ): Boolean {
        if (payload < base) return false
        // payload == current: the size in use passes by the message's own account, so it only caps the search; a probe in flight that
        // is not larger than payload is unaffected (the message concerned another, larger datagram)
        if (payload >= current) {
            if (payload < high) high = payload
            if (probeInFlight && !confirming && probeSize > payload) {
                // the probe in flight is too large: settled now, not after maxProbes x PTO; its late loss or ACK is still handled
                probeInFlight = false
                probeLosses = 0
            }
            if (high - low < step && high <= current) finish(now)
            return false
        }
        if (ptbSuspendedUntil != TimeMark.NEVER) {
            if (now < ptbSuspendedUntil) return false
            ptbSuspendedUntil = TimeMark.NEVER
        }
        // "This could be an indication of a black hole. The PLPMTU SHOULD be set to BASE_PLPMTU": provisional (RFC 9000 section 14.2.1)
        // until the probe of the old size fails; a black-hole verdict from before says nothing about the size the PTB disputes
        ptbFrom = current
        ptbLow = low
        ptbHigh = high
        ptbSearchDone = searchDone
        ptbResearchAt = researchAt
        ptbDisproveSize = 0
        ptbHint = base + (payload - base) / step * step
        // probes sent up to now went out before the drop: their acknowledgments, late or not, are about the path before the PTB
        // (RFC 8899 section 8 trusts "subsequent probes"), so they neither overturn it nor raise the size
        ptbAfterPn = lastProbePn
        for (i in 0 until SENT_PROBES) sentLost[i] = false
        lostProbes = 0
        undoCurrent = 0
        bigLost = 0
        firstBigLostPn = -1L
        current = base
        low = base
        high = minOf(upperBound, ptbFrom)
        searchDone = false
        finalProbe = false
        probeInFlight = false // a probe in flight is settled: its late acknowledgment still counts ([onProbeAcked])
        probeLosses = 0
        confirming = false
        researchAt = TimeMark.NEVER
        return true
    }

    /**
     * The kernel refused a datagram of [size] bytes as larger than the MTU it knows (EMSGSIZE): when it was the probe in flight, that
     * size is settled at once, as if lost [maxProbes] times. Not proof: on Linux a forged Packet Too Big sets the socket error the next
     * send meets, so ksl reports EMSGSIZE only when the retried send fails the same way, and a kernel may have cached a forged path
     * MTU. Hence only about the probe in flight, never [current].
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

    /**
     * The peer's `max_udp_payload_size` lowers the range (RFC 9000 section 14.3; [peerMax] is at least the base, RFC 9000 section 18.2).
     * A [current] above it, a configured start the peer cannot take, comes down to it, and so does every state that could raise
     * [current] again (a black-hole verdict to undo, a size a Packet Too Big disputed).
     */
    fun limitUpperBound(peerMax: Int) {
        if (peerMax >= upperBound) return
        upperBound = peerMax
        if (high > upperBound) high = upperBound
        if (current > upperBound) current = upperBound
        if (low > upperBound) low = upperBound
        if (undoCurrent > upperBound) undoCurrent = upperBound
        if (undoLow > upperBound) undoLow = upperBound
        if (undoHigh > upperBound) undoHigh = upperBound
        if (ptbFrom > upperBound) ptbFrom = upperBound
        if (ptbLow > upperBound) ptbLow = upperBound
        if (ptbHigh > upperBound) ptbHigh = upperBound
        if (ptbDisproveSize > upperBound) ptbDisproveSize = upperBound
        if (probeInFlight && probeSize > upperBound) {
            probeInFlight = false // its acknowledgment still counts: the datagram did get through
            probeLosses = 0
        }
    }

    /**
     * The probe [nextProbeSize] just gave could not go yet (the congestion window or the pacer held it, RFC 9000 section 14.4):
     * it is asked for again at the next send opportunity, with the same size.
     */
    fun deferProbe() {
        probeInFlight = false
        probeDeadline = TimeMark.NEVER
    }

    /**
     * The size of the probe to send now, 0 when none is due (one in flight, search done, or paused). Its PROBE_TIMER runs from [now]
     * for [probeTimer], or 3 x [pto] when that is longer.
     */
    fun nextProbeSize(
        now: TimeMark,
        pto: Duration = Duration.ZERO,
    ): Int {
        if (probeInFlight) return 0
        if (ptbFrom > 0) {
            // a PTB dropped the size provisionally: a probe of the old size, before anything else and whatever the search state
            confirming = true
            probeSize = ptbFrom
            startProbe(now, pto)
            return ptbFrom
        }
        if (searchDone) return 0
        if (pausedUntil != TimeMark.NEVER) {
            if (now < pausedUntil) return 0
            pausedUntil = TimeMark.NEVER
        }
        if (ptbHint > 0) {
            // RFC 8899 section 4.6.2: "The PL_PTB_SIZE reported in the PTB message can be used to initialize a search algorithm"
            val hint = ptbHint
            ptbHint = 0
            if (hint > low && hint <= high) {
                probeSize = hint
                startProbe(now, pto)
                return hint
            }
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
        startProbe(now, pto)
        return probeSize
    }

    private fun startProbe(
        now: TimeMark,
        pto: Duration,
    ) {
        probeInFlight = true
        probeSentAt = now
        probePn = -1L
        probeDeadline = now + maxOf(probeTimer, pto * 3)
    }

    /** The probe sent as packet [pn] of [size] bytes was acknowledged at [now]; one sent before the last PTB drop changes nothing. */
    fun onProbeAcked(
        ackedSize: Int,
        pn: Long,
        now: TimeMark,
    ) {
        if (pn <= ptbAfterPn) return
        // a datagram the path carried, but never a size above the range: the peer's limit may have come down since
        val size = minOf(ackedSize, upperBound)
        val disputed = if (ptbFrom > 0) ptbFrom else ptbDisproveSize
        if (disputed > 0 && size >= disputed) {
            // the size the PTB disputed gets through: the PTB was wrong (forged or stale); PTBs are not processed for a while
            ptbSuspendedUntil = now + ptbSuspend
            ptbDisproveSize = 0
            ptbHint = 0
            if (ptbFrom > 0) {
                current = ptbFrom
                low = ptbLow
                high = maxOf(ptbHigh, size)
                searchDone = ptbSearchDone
                researchAt = ptbResearchAt
                ptbFrom = 0
                confirming = false
                probeInFlight = false
                probeLosses = 0
                finalProbe = false
                if (size > current) current = size
                low = maxOf(low, size)
                if (high - low < step && high <= current && !searchDone) finish(now)
                return
            }
        }
        if (size > high) high = size // an ACK outweighs any hint that said this size could not pass
        if (probeInFlight && size != probeSize) {
            // the ACK of a probe a hint already settled: it proves its size, the probe in flight stays in flight unless it is no larger
            if (size > current) current = size
            low = maxOf(low, size)
            if (probeSize <= current) {
                probeInFlight = false
                probeLosses = 0
            }
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

    /** The probe [nextProbeSize] gave went out as 1-RTT packet [pn] of [size] bytes. */
    fun onProbeSent(
        pn: Long,
        size: Int,
    ) {
        if (probeInFlight && size == probeSize) probePn = pn
        if (pn > lastProbePn) lastProbePn = pn
        if (sentLost[sentNext]) lostProbes--
        sentPn[sentNext] = pn
        sentSize[sentNext] = size
        sentLost[sentNext] = false
        sentNext = (sentNext + 1) % SENT_PROBES
    }

    /**
     * Loss detection declared the probe sent as packet [pn] lost at [now]: the probe in flight fails then, or [minProbeTimer] after it
     * was sent when that is later ([onTimeout]); an acknowledgment may still come and confirm its size ([takeLostProbeIn]).
     */
    fun onProbeDeclaredLost(
        pn: Long,
        now: TimeMark,
    ) {
        if (probeInFlight && pn == probePn) {
            val floor = probeSentAt + minProbeTimer
            val at = if (floor > now) floor else now
            if (at < probeDeadline) probeDeadline = at
        }
        for (i in 0 until SENT_PROBES) {
            if (sentPn[i] == pn && !sentLost[i]) {
                sentLost[i] = true
                lostProbes++
            }
        }
    }

    /**
     * The size of a probe declared lost whose packet number is in [smallest]..[largest] (an ACK range), forgotten as lost; 0 when
     * there is none. A probe declared lost leaves the sent-packet history, but its acknowledgment after all (RFC 9002 section 6.1)
     * confirms its size ([onProbeAcked]): RFC 8899 section 5.2 fails only a probe "not acknowledged within the period of the
     * PROBE_TIMER".
     */
    fun takeLostProbeIn(
        smallest: Long,
        largest: Long,
    ): Int {
        for (i in 0 until SENT_PROBES) {
            if (sentLost[i] && sentPn[i] in smallest..largest) {
                sentLost[i] = false
                lostProbes--
                return sentSize[i]
            }
        }
        return 0
    }

    /**
     * Each probe declared lost whose packet number is in [smallest]..[largest] is acknowledged after all ([takeLostProbeIn],
     * [onProbeAcked]); false when there was none.
     */
    fun ackLostProbesIn(
        smallest: Long,
        largest: Long,
        now: TimeMark,
    ): Boolean {
        var any = false
        while (hasLostProbes) {
            var pn = -1L
            for (i in 0 until SENT_PROBES) if (sentLost[i] && sentPn[i] in smallest..largest) pn = sentPn[i]
            if (pn < 0) break
            onProbeAcked(takeLostProbeIn(pn, pn), pn, now)
            any = true
        }
        return any
    }

    /**
     * The PROBE_TIMER of the probe in flight expired before it was acknowledged (RFC 8899 section 5.2: "When a probe packet is sent and
     * not acknowledged within the period of the PROBE_TIMER, the PROBE_COUNT is incremented").
     */
    private fun onProbeTimerExpired(now: TimeMark) {
        val size = probeSize
        probeDeadline = TimeMark.NEVER
        if (confirming) {
            // the probe of the size before the PTB failed: the drop stands (RFC 9000 section 14.2.1: provisional "until QUIC's loss
            // detection algorithm determines that the quoted packet has actually been lost") and the search goes on from the base, its
            // range still up to the old size; a late acknowledgment of that probe still disproves the PTB
            probeInFlight = false
            confirming = false
            ptbDisproveSize = ptbFrom
            ptbFrom = 0
            return
        }
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

    /**
     * A regular (non-probe) packet [pn] of [size] bytes was acknowledged: a full-size one from the first lost one on (that one
     * included: its loss was spurious) proves the path carries the MTU. One larger than [current], sent before a black-hole verdict
     * and no earlier than the first packet that verdict rested on, proves the verdict wrong (RFC 8899 section 4.1: an acknowledged packet confirms its size): the search state from before it
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
                current = minOf(size, upperBound)
                low = current
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
        if (bigLost > 0 && pn >= firstBigLostPn) {
            bigLost = 0
            firstBigLostPn = -1L
        }
        return undone
    }

    /**
     * A regular packet [pn] of [size] bytes was lost; counted unless a later full-size packet already arrived. A packet larger than
     * [current] was sent before a drop and says nothing about the size in use.
     */
    fun onPacketLost(
        size: Int,
        pn: Long,
    ) {
        if (size <= base || size > current || pn < largestBigAckedPn) return
        if (bigLost == 0 || pn < firstBigLostPn) firstBigLostPn = pn
        bigLost++
    }

    /** After an ACK or a loss timer was processed: true (and back to the base) when three large packets were lost with none acknowledged after them, a black hole (RFC 8899 section 4.3). */
    fun takeBlackHole(now: TimeMark): Boolean {
        if (bigLost < 3) return false
        fallBack(now, firstBigLostPn - 1) // the first lost packet itself, acknowledged after all, disproves it too
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
        // probes declared lost before the verdict: a late acknowledgment of one is about the path before it (as onPacketAcked takes a
        // late full-size packet only after the packets the verdict rested on), so it raises nothing ([takeLostProbeIn])
        for (i in 0 until SENT_PROBES) sentLost[i] = false
        lostProbes = 0
        ptbHint = 0
        ptbDisproveSize = 0
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

    /** When the core must call [onTimeout]: the PROBE_TIMER of the probe in flight, the end of a pause or the re-search time. */
    fun timeout(): TimeMark {
        val t = if (pausedUntil != TimeMark.NEVER) pausedUntil else researchAt
        return if (probeInFlight && probeDeadline < t) probeDeadline else t
    }

    /** Runs the timers due at [now]; they never change [current]. */
    fun onTimeout(now: TimeMark) {
        if (probeInFlight && probeDeadline <= now) onProbeTimerExpired(now)
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

/** Probes whose packet numbers [Pmtud] keeps for their late acknowledgments: more than are sent within a PROBE_TIMER after one fails. */
private const val SENT_PROBES = 4

/** RFC 8899 section 5.1.1: PROBE_TIMER "MUST NOT be smaller than 1 second and SHOULD be larger than 15 seconds". */
private val PROBE_TIMER: Duration = 16.seconds

/** RFC 8899 section 5.1.1's floor: no probe fails earlier than this after it was sent. */
private val MIN_PROBE_TIMER: Duration = 1.seconds
