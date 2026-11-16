// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.core

import io.kuicksilver.quic.TimeMark
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

/**
 * [Pmtud]'s state machine on its own (RFC 8899 sections 4.6, 5.1, 5.2 and 5.3; RFC 9000 section 14): the binary search between the
 * 1200-byte base and the upper bound in 20-byte steps (first probe of a 1200..1500 range: 1340), PROBE_TIMER and MAX_PROBES, validated
 * Packet Too Big hints, EMSGSIZE, black-hole detection and its undo. The connection-level behaviour is in [PmtudTest].
 */
class PmtudSearchTest {
    private val t0 = TimeMark(1_000_000_000L)

    private fun at(d: Duration) = t0 + d

    /** A search over 1200..[upper] whose first probe (1340 for 1500) was acknowledged: the size in use is that probe's. */
    private fun raised(upper: Int = 1500): Pmtud {
        val m = Pmtud(upperBound = upper)
        val s = m.nextProbeSize(t0)
        m.onProbeSent(1, s)
        m.onProbeAcked(s, 1, t0)
        assertEquals(s, m.current)
        return m
    }

    /**
     * RFC 8899 section 5.2: the search ends when "a validated PTB is received that corresponds to the last successfully probed size
     * (PL_PTB_SIZE = PLPMTU)". A Packet Too Big reporting the base while the base is in use ends it; one below the base is ignored
     * (section 4.6.2: a PL_PTB_SIZE below the minimum is not used).
     */
    @Test fun negative_packetTooBigAtTheBaseEndsTheSearch() {
        val m = Pmtud(upperBound = 1500)
        m.onPtb(1199, t0)
        assertFalse(m.searchDone, "below the base: ignored")
        m.onPtb(1200, t0)
        assertTrue(m.searchDone, "PL_PTB_SIZE = PLPMTU")
        assertEquals(0, m.nextProbeSize(t0))
        assertEquals(t0 + 600.seconds, m.timeout(), "the next search is due after the raise timer")
        m.onTimeout(t0 + 600.seconds)
        assertEquals(1340, m.nextProbeSize(t0 + 600.seconds), "the new search starts over the whole range")
        m.onProbeSent(1, 1340)
        m.onProbeAcked(1340, 1, t0 + 600.seconds)
        assertFalse(m.searchDone, "its first probe is an ordinary one, not a final probe")
    }

    /**
     * RFC 8899 section 4.6.2: a validated PTB above the PLPMTU and below the probed size settles the probe in flight at once (it is
     * "too large"); one that reports the probe's own size says that size passes and leaves the probe in flight.
     */
    @Test fun negative_packetTooBigSettlesOnlyALargerProbe() {
        val m = Pmtud(upperBound = 1500)
        assertEquals(1340, m.nextProbeSize(t0))
        m.onProbeSent(1, 1340)
        m.onPtb(1340, t0)
        assertEquals(1340, m.probeInFlightForTest, "the probe's own size: still in flight")
        assertEquals(0, m.nextProbeSize(t0))
        val above = raised()
        above.onPtb(1350, t0)
        assertFalse(above.searchDone, "1340..1350 is left: one final probe of 1350")
        assertEquals(1350, above.nextProbeSize(t0))
        m.onPtb(1300, t0)
        assertEquals(0, m.probeInFlightForTest, "larger than the reported size: settled")
        assertEquals(1240, m.nextProbeSize(t0), "the search goes on below the reported size")
        assertEquals(1200, m.current, "a hint above the size in use never raises it")
        val capped = Pmtud(upperBound = 1500)
        capped.nextProbeSize(t0)
        capped.onProbeSent(1, 1340)
        capped.onPtb(1340, t0)
        capped.onProbeAcked(1340, 1, t0)
        assertTrue(capped.searchDone, "the probe of the size the PTB reported passed: nothing above it to search")
        assertEquals(t0 + 600.seconds, capped.timeout())
    }

    /**
     * RFC 8899 section 4.6.2, "BASE_PLPMTU <= PL_PTB_SIZE < PLPMTU": "The PLPMTU SHOULD be set to BASE_PLPMTU", provisionally (RFC
     * 9000 section 14.2.1: "Any reduction in the QUIC maximum packet size in response to ICMP messages MAY be provisional until QUIC's
     * loss detection algorithm determines that the quoted packet has actually been lost"). A probe of the old size goes first: its
     * acknowledgment restores the old size and suspends PTB processing (section 8); its failure lets the drop stand, and the search
     * starts at the reported size ("can be used to initialize a search algorithm"). A late acknowledgment of that probe still
     * disproves the PTB.
     */
    @Test fun negative_packetTooBigBelowTheSizeInUseDropsToTheBaseProvisionally() {
        val ok = raised()
        assertTrue(ok.onPtb(1305, t0))
        assertEquals(1200, ok.current, "dropped to the base at once")
        assertEquals(1340, ok.confirmingForTest, "the size the PTB disputes")
        assertEquals(1340, ok.nextProbeSize(t0), "a probe of the old size goes first")
        ok.onProbeSent(2, 1340)
        ok.onProbeAcked(1340, 2, t0)
        assertEquals(1340, ok.current, "it got through: the PTB was wrong")
        assertEquals(0, ok.confirmingForTest)
        assertTrue(ok.ptbSuspendedForTest)
        assertFalse(ok.onPtb(1300, t0), "PTB processing is suspended for a while")
        assertEquals(1340, ok.current)
        assertEquals(1420, ok.nextProbeSize(t0), "the search goes on above, with ordinary probes")
        ok.onProbeSent(3, 1420)
        ok.onProbeAcked(1420, 3, t0)
        assertEquals(1420, ok.current)

        val lost = raised()
        assertTrue(lost.onPtb(1305, t0))
        assertEquals(1340, lost.nextProbeSize(t0))
        lost.onProbeSent(2, 1340)
        val t = lost.timeout()
        lost.onTimeout(t)
        assertEquals(1200, lost.current, "the probe failed: the drop stands")
        assertEquals(0, lost.confirmingForTest)
        assertEquals(1300, lost.nextProbeSize(t), "the search starts at the reported size, on the step grid")
        lost.onProbeSent(3, 1300)
        lost.onProbeAcked(1300, 3, t)
        assertEquals(1300, lost.current)
        lost.onProbeAcked(1340, 2, t)
        assertEquals(1340, lost.current, "a late acknowledgment of the old size still disproves the PTB")
        assertTrue(lost.ptbSuspendedForTest)
    }

    /** An EMSGSIZE about the probe in flight settles that size at once (as MAX_PROBES losses); about any other size it is ignored. */
    @Test fun negative_emsgsizeSettlesOnlyTheProbeInFlight() {
        val m = Pmtud(upperBound = 1500)
        m.onEmsgsize(1340, t0)
        assertEquals(1340, m.nextProbeSize(t0), "no probe in flight yet: nothing to settle")
        m.onEmsgsize(1300, t0)
        assertEquals(1340, m.probeInFlightForTest, "another size: ignored")
        m.onEmsgsize(1340, t0)
        assertEquals(0, m.probeInFlightForTest)
        assertEquals(1260, m.nextProbeSize(t0), "the range ends below the refused size")
        val narrow = Pmtud(upperBound = 1220)
        assertEquals(1220, narrow.nextProbeSize(t0))
        narrow.onEmsgsize(1220, t0)
        assertEquals(1219, narrow.nextProbeSize(t0), "never the refused size again")
        assertEquals(1200, m.current)
        val deferred = Pmtud(upperBound = 1500)
        assertEquals(1340, deferred.nextProbeSize(t0))
        deferred.deferProbe()
        deferred.onEmsgsize(1340, t0)
        assertEquals(1340, deferred.nextProbeSize(t0), "a deferred probe is not in flight: nothing it says about the size")
        val top = Pmtud(upperBound = 1215)
        assertEquals(1215, top.nextProbeSize(t0))
        top.onEmsgsize(1215, t0)
        assertTrue(top.searchDone, "the final probe refused: the search is done")
        assertEquals(0, top.nextProbeSize(t0))
    }

    /** RFC 9000 section 14.3: the peer's max_udp_payload_size lowers the range; a larger one changes nothing. */
    @Test fun negative_peerMaxUdpPayloadSizeOnlyLowersTheRange() {
        val m = Pmtud(upperBound = 1500)
        m.limitUpperBound(1600)
        assertEquals(1500, m.upperBound)
        m.limitUpperBound(1300)
        assertEquals(1300, m.upperBound)
        assertEquals(1240, m.nextProbeSize(t0))
    }

    /**
     * RFC 8899 section 5.1.1: PROBE_TIMER "MUST NOT be smaller than 1 second"; it runs for 16 s or 3 x PTO when that is longer. A
     * probe loss detection declares lost fails then, never sooner than 1 s after it was sent; a loss of another packet changes nothing.
     */
    @Test fun negative_probeTimerAndItsFloor() {
        val m = Pmtud(upperBound = 1500)
        m.nextProbeSize(t0, pto = 10.seconds)
        assertEquals(t0 + 30.seconds, m.timeout(), "3 x PTO")
        m.onProbeSent(5, 1340)
        m.onProbeDeclaredLost(6, at(100.milliseconds))
        assertEquals(t0 + 30.seconds, m.timeout(), "another packet")
        m.onProbeDeclaredLost(5, at(100.milliseconds))
        assertEquals(t0 + 1.seconds, m.timeout(), "declared lost early: fails at the 1 s floor")
        val late = Pmtud(upperBound = 1500)
        late.nextProbeSize(t0, pto = 1.seconds)
        assertEquals(t0 + 16.seconds, late.timeout())
        late.onProbeSent(5, 1340)
        late.onProbeDeclaredLost(5, at(5.seconds))
        assertEquals(t0 + 5.seconds, late.timeout(), "declared lost after the floor: fails then")
        late.onTimeout(at(4.seconds)) // not yet
        assertEquals(1340, late.probeInFlightForTest)
    }

    /**
     * RFC 8899 section 5.2: a probe not acknowledged within PROBE_TIMER increments PROBE_COUNT and is sent again; at MAX_PROBES (3)
     * the size is given up and the search goes on below it. A deferred probe (window full) is asked for again at the same size.
     */
    @Test fun negative_maxProbesLostEndsThatSize() {
        val m = Pmtud(upperBound = 1500)
        var t = t0
        for (i in 1..2) {
            assertEquals(1340, m.nextProbeSize(t))
            t = m.timeout()
            m.onTimeout(t)
        }
        assertEquals(1340, m.nextProbeSize(t), "two lost: the same size once more")
        m.deferProbe()
        assertEquals(TimeMark.NEVER, m.timeout(), "a deferred probe runs no timer")
        assertEquals(1340, m.nextProbeSize(t), "deferred: the same size")
        t = m.timeout()
        m.onTimeout(t)
        assertEquals(1260, m.nextProbeSize(t), "three lost: below 1340")
    }

    /**
     * RFC 8899 section 5.2: an acknowledged probe of the top of the range (MAX_PLPMTU) ends the search; the remaining sub-step range
     * is tried once more with a final probe of its top, and the search is done whatever becomes of it.
     */
    @Test fun negative_finalProbeOfTheTopEndsTheSearch() {
        val m = Pmtud(upperBound = 1215)
        assertEquals(1215, m.nextProbeSize(t0), "a range smaller than a step: one probe of its top")
        m.onProbeSent(1, 1215)
        m.onProbeAcked(1215, 1, t0)
        assertEquals(1215, m.current)
        assertTrue(m.searchDone)
        val lost = Pmtud(upperBound = 1215)
        var t = t0
        repeat(3) {
            assertEquals(1215, lost.nextProbeSize(t))
            t = lost.timeout()
            lost.onTimeout(t)
        }
        assertTrue(lost.searchDone, "the final probe failed: done at the base")
        assertEquals(1200, lost.current)
        assertEquals(t + 600.seconds, lost.timeout())
        lost.onTimeout(t + 600.seconds)
        assertFalse(lost.searchDone, "the raise timer starts a new search")
        assertEquals(1215, lost.nextProbeSize(t + 600.seconds))
    }

    /**
     * A range exactly one step wide (1200..1220) is probed at its top; that probe lost MAX_PROBES times leaves 1200..1219, whose top
     * is tried once more before the search ends.
     */
    @Test fun negative_aOneStepRangeIsNarrowedNotAbandoned() {
        val m = Pmtud(upperBound = 1220)
        var t = t0
        repeat(3) {
            assertEquals(1220, m.nextProbeSize(t))
            t = m.timeout()
            m.onTimeout(t)
        }
        assertFalse(m.searchDone)
        assertEquals(1219, m.nextProbeSize(t), "the final probe of what is left")
    }

    /** A range with nothing above the size in use (upper bound at the base) ends the search at once; it is searched again later. */
    @Test fun negative_anEmptyRangeEndsTheSearch() {
        val m = Pmtud(upperBound = 1200)
        assertEquals(0, m.nextProbeSize(t0))
        assertTrue(m.searchDone)
        assertEquals(t0 + 600.seconds, m.timeout(), "the raise timer runs")
    }

    /**
     * An acknowledged probe of a size a hint had settled proves that size; a probe in flight no larger than the size now proven says
     * nothing more and is settled too.
     */
    @Test fun negative_lateAckOfASettledProbeRaisesTheSize() {
        val m = Pmtud(upperBound = 1500)
        m.nextProbeSize(t0)
        m.onProbeSent(1, 1340)
        m.onPtb(1300, t0)
        assertEquals(1240, m.nextProbeSize(t0))
        m.onProbeSent(2, 1240)
        m.onProbeAcked(1340, 1, t0)
        assertEquals(1340, m.current, "the acknowledgement outweighs the hint")
        assertEquals(0, m.probeInFlightForTest, "the 1240-byte probe proves nothing more")
    }

    /**
     * RFC 8899 section 4.3 (black-hole detection): three packets above the base lost with no full-size packet acknowledged after the
     * first of them fall back to the base and pause the search; small packets, packets older than an acknowledged one and an
     * acknowledgement of a packet sent before the losses do not count.
     */
    @Test fun negative_blackHoleCounting() {
        val m = raised()
        m.onPacketLost(1200, 1)
        m.onPacketLost(1200, 2)
        m.onPacketLost(1200, 3)
        assertFalse(m.takeBlackHole(t0), "packets of the base size cannot vanish in a black hole")
        m.onPacketLost(1400, 4)
        m.onPacketLost(1400, 5)
        m.onPacketLost(1400, 6)
        assertFalse(m.takeBlackHole(t0), "larger than the size in use: sent before a drop, says nothing about it")
        m.onPacketLost(1340, 10)
        assertTrue(m.onPacketAcked(1340, 8).not())
        m.onPacketLost(1340, 11)
        assertFalse(m.takeBlackHole(t0), "two")
        m.onPacketLost(1340, 12)
        assertTrue(m.takeBlackHole(t0), "an acknowledgement of a packet sent before the first loss proves nothing")
        val reset = raised()
        reset.onPacketLost(1340, 10)
        reset.onPacketLost(1340, 11)
        reset.onPacketAcked(1340, 12)
        reset.onPacketLost(1340, 9)
        reset.onPacketLost(1340, 13)
        assertFalse(reset.takeBlackHole(t0), "a full-size packet after the losses arrived; packet 9 is older than it")
        reset.onPacketLost(1340, 14)
        reset.onPacketLost(1340, 15)
        assertTrue(reset.takeBlackHole(t0))
        assertEquals(1200, reset.current)
    }

    /**
     * The black-hole verdict falls back to the base and pauses the search for 60 s; a full-size packet sent after the packets it
     * rested on and acknowledged later disproves it (RFC 8899 section 4.1: an acknowledged packet confirms its size): the search state
     * comes back without the pause. A smaller one restores only its own size.
     */
    @Test fun negative_blackHoleVerdictAndItsUndo() {
        val m = raised()
        for (pn in 10L..12L) m.onPacketLost(1340, pn)
        assertTrue(m.takeBlackHole(t0))
        assertEquals(1200, m.current)
        assertTrue(m.pausedForTest)
        assertEquals(0, m.nextProbeSize(at(1.seconds)), "paused")
        assertEquals(t0 + 60.seconds, m.timeout())
        val edge = raised()
        for (pn in 10L..12L) edge.onPacketLost(1340, pn)
        edge.takeBlackHole(t0)
        edge.onTimeout(at(60.seconds))
        assertFalse(edge.pausedForTest, "the pause ends at its time")
        val paused = raised()
        for (pn in 10L..12L) paused.onPacketLost(1340, pn)
        paused.takeBlackHole(t0)
        assertEquals(1340, paused.nextProbeSize(at(60.seconds)), "the pause is over: the search starts again from the base")
        assertFalse(m.onPacketAcked(1340, 9), "sent before the first loss: proves nothing")
        val atBase = Pmtud(upperBound = 1500)
        atBase.onBlackHole(t0) // repeated PTOs while at the base
        assertTrue(atBase.pausedForTest)
        assertFalse(atBase.onPacketAcked(1300, 5), "nothing above the base was in use: nothing to undo")
        assertTrue(atBase.pausedForTest)
        assertTrue(m.onPacketAcked(1340, 13), "sent after: the verdict was wrong")
        assertEquals(1340, m.current)
        assertFalse(m.onPacketAcked(1200, 30), "smaller than the size in use: changes nothing")
        assertFalse(m.pausedForTest)
        assertTrue(m.nextProbeSize(at(1.seconds)) > 1340, "the search goes on above")

        val part = raised()
        for (pn in 10L..12L) part.onPacketLost(1340, pn)
        part.takeBlackHole(t0)
        assertTrue(part.onPacketAcked(1260, 13))
        assertEquals(1260, part.current, "only the acknowledged size")
        assertFalse(part.pausedForTest)
        assertEquals(1380, part.nextProbeSize(t0), "the search goes on between that size and the top it had")
        part.onProbeSent(14, 1380)
        part.onProbeAcked(1380, 14, t0)
        assertEquals(1380, part.current)
        assertFalse(part.searchDone, "an ordinary probe of the middle, not the final one")

        val stall = raised()
        stall.onPacketAcked(1340, 20)
        stall.onBlackHole(t0) // repeated PTOs: disproved only by a packet newer than every one acknowledged
        assertFalse(stall.onPacketAcked(1340, 19))
        assertEquals(1200, stall.current)
        assertTrue(stall.onPacketAcked(1340, 21))
        assertEquals(1340, stall.current)
    }

    /**
     * Only probes sent after a PTB drop speak about the path since (RFC 8899 section 8 trusts "subsequent probes"): a late
     * acknowledgment of one sent before neither overturns the drop nor raises the size; likewise for a search that replaced an older
     * one, whose probes up to `sentAfterPn` were the older search's.
     */
    @Test fun negative_aProbeSentBeforeTheDropChangesNothing() {
        val m = raised()
        assertEquals(1420, m.nextProbeSize(t0))
        m.onProbeSent(2, 1420)
        assertTrue(m.onPtb(1300, t0))
        assertEquals(0, m.probeInFlightForTest, "the probe in flight is settled by the drop")
        m.onProbeAcked(1420, 2, t0)
        assertEquals(1200, m.current, "sent before the drop: about the path before it")
        assertEquals(1340, m.confirmingForTest, "the drop is still provisional")
        val replaced = Pmtud(upperBound = 1500, sentAfterPn = 50)
        replaced.onProbeAcked(1340, 40, t0)
        assertEquals(1200, replaced.current, "the old search's probe")
        replaced.onProbeAcked(1340, 51, t0)
        assertEquals(1340, replaced.current)
    }

    /**
     * A second black hole, after the search went above the size of the first verdict, keeps the newer state to undo: a full-size
     * packet acknowledged later restores the size in use just before it, not the older one.
     */
    @Test fun negative_aLaterVerdictKeepsTheNewerStateToUndo() {
        val m = raised()
        for (pn in 10L..12L) m.onPacketLost(1340, pn)
        assertTrue(m.takeBlackHole(t0))
        val t1 = at(60.seconds)
        for ((pn, size) in listOf(13L to 1340, 14L to 1420)) {
            assertEquals(size, m.nextProbeSize(t1))
            m.onProbeSent(pn, size)
            m.onProbeAcked(size, pn, t1)
        }
        assertEquals(1420, m.current)
        for (pn in 20L..22L) m.onPacketLost(1420, pn)
        assertTrue(m.takeBlackHole(t1))
        assertEquals(1200, m.current)
        assertTrue(m.onPacketAcked(1420, 23))
        assertEquals(1420, m.current, "the state just before the newer verdict")
    }

    /** Probes declared lost are remembered for their late acknowledgement, the last four of them; an older entry overwritten is forgotten. */
    @Test fun negative_lostProbeMemory() {
        val m = Pmtud(upperBound = 1500)
        m.onProbeSent(7, 1340)
        m.onProbeDeclaredLost(7, t0)
        m.onProbeDeclaredLost(7, t0)
        assertTrue(m.hasLostProbes)
        assertEquals(0, m.takeLostProbeIn(1, 6))
        assertEquals(1340, m.takeLostProbeIn(5, 9))
        assertFalse(m.hasLostProbes, "counted once, taken once")
        assertEquals(0, m.takeLostProbeIn(5, 9))
        val ring = Pmtud(upperBound = 1500)
        for (pn in 1L..4L) {
            ring.onProbeSent(pn, 1300)
            ring.onProbeDeclaredLost(pn, t0)
        }
        ring.onProbeSent(5, 1300)
        assertEquals(0, ring.takeLostProbeIn(1, 1), "overwritten by the fifth probe")
        for (pn in 2L..4L) assertEquals(1300, ring.takeLostProbeIn(pn, pn))
        assertFalse(ring.hasLostProbes, "the overwritten entry no longer counts")
    }

    /**
     * RFC 8899 section 4.1: an acknowledged packet confirms its size. A late acknowledgment of the first packet a black-hole count or
     * verdict rested on (its loss was spurious) counts as one of the packets after it: the count starts over, and a verdict is undone,
     * as for the second or third of them.
     */
    @Test fun negative_theFirstLostPacketAcknowledgedAfterAllDisprovesTheBlackHole() {
        val count = raised()
        count.onPacketLost(1340, 10)
        count.onPacketLost(1340, 11)
        count.onPacketAcked(1340, 10)
        count.onPacketLost(1340, 12)
        assertFalse(count.takeBlackHole(t0), "the count started over at the acknowledgment")
        val verdict = raised()
        for (pn in 10L..12L) verdict.onPacketLost(1340, pn)
        assertTrue(verdict.takeBlackHole(t0))
        assertTrue(verdict.onPacketAcked(1340, 10), "the first of them got through: the verdict was wrong")
        assertEquals(1340, verdict.current)
        assertFalse(verdict.pausedForTest)
    }
}
