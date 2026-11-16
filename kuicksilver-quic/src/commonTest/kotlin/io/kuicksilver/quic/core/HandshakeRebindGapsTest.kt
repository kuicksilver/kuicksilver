// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.core

import io.ktor.network.sockets.InetSocketAddress
import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.KslLoader
import io.kuicksilver.native.toByteArray
import io.kuicksilver.quic.ConnectionCore
import io.kuicksilver.quic.ConnectionState
import io.kuicksilver.quic.PathId
import io.kuicksilver.quic.PathState
import io.kuicksilver.quic.endpoint.EndpointPair
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

/**
 * The server's handshake-time address changes (RFC 9000 sections 8.1, 8.2, 9.3.2 and 9.3.3), driven on the server's state directly:
 * the mirror of the flight to a second address, the candidate that keeps the address a move left, its adoption and its end. The
 * packet-level scenarios are in [PathTest].
 */
@OptIn(ExperimentalKuicksilverApi::class, DelicateKuicksilverApi::class)
class HandshakeRebindGapsTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private val other = InetSocketAddress("10.0.0.1", 40002)

    /** The server of [p] once the client's first flight arrived: it holds its 1-RTT keys and is still handshaking. */
    private fun midHandshake(p: EndpointPair): ConnectionCore {
        val c = p.connect()
        p.batch.clear()
        val n = c.poll(p.batch, p.now)
        var s: ConnectionCore? = null
        for (i in 0 until n) {
            val d = p.batch.buffer(i).toByteArray(p.batch.length(i))
            if (s == null) s = p.feed(p.server, d, p.clientAddr) else p.feedNoAdmit(p.server, d, p.clientAddr)
        }
        val srv = assertNotNull(s)
        assertEquals(ConnectionState.Handshaking, srv.state)
        assertNotNull(srv.writeKeys[3], "the ClientHello is complete: the server has its 1-RTT keys")
        return srv
    }

    /** An Initial from [other] inside a PTO of the client's last datagram: the flight is mirrored there (a candidate, no move). */
    private fun mirrored(s: ConnectionCore): Path {
        s.onHandshakeAddressChange(PathId.Initial, other, 1200, datagram = 100, initial = true, newest = true)
        val k = assertNotNull(s.handshakeCandidate, "an Initial inside the PTO opens the mirror")
        assertTrue(s.handshakeMirror)
        assertTrue(k.isRemote(other))
        assertTrue(k.handshakeCandidate)
        assertEquals(PathId.Initial, s.paths.active.id)
        assertFalse(s.paths.active.isRemote(other), "the active path did not move")
        return k
    }

    /**
     * Once a Handshake packet shows the client holds its keys, the flight is no longer mirrored. A second address that got nothing of
     * it is dropped; one that got some is validated like any other new address, with a PATH_CHALLENGE (RFC 9000 section 8.2).
     */
    @Test fun negative_theMirrorEndsWithTheClientsHandshakeKeys() {
        val p = EndpointPair()
        try {
            val s = midHandshake(p)
            val k = mirrored(s)
            s.handshakeMirrorDue = true
            s.onClientHandshakeKeys()
            assertFalse(s.handshakeMirror)
            assertFalse(s.handshakeMirrorDue, "no retransmission there is due any more")
            assertNull(s.handshakeCandidate, "nothing went to the second address: it is dropped")
            assertFalse(k.handshakeCandidate)
            s.onHandshakeAddressChange(PathId.Initial, InetSocketAddress("10.0.0.1", 40003), 1200, 200, initial = true, newest = true)
            assertNull(s.handshakeCandidate, "the client has its keys: no flight is mirrored any more")
            assertFalse(k in s.paths.all)
            assertNull(s.handshakeRebindFrom)
        } finally {
            p.close()
        }
        val q = EndpointPair()
        try {
            val s = midHandshake(q)
            val k = mirrored(s)
            s.handshakeMirrorSent = true
            s.handshakeMirrorDue = true
            s.onClientHandshakeKeys()
            assertFalse(s.handshakeMirror, "no more retransmissions there")
            assertFalse(s.handshakeMirrorDue)
            assertSame(k, s.handshakeCandidate, "the client may have read the flight there")
            assertEquals(PathState.Validating, k.state, "validated with a challenge of its own")
            assertTrue(k.challengePending)
        } finally {
            q.close()
        }
    }

    /**
     * A Handshake packet from [other] moves the active path there, led by a PATH_CHALLENGE; the address left becomes the candidate.
     * When the candidate answers its own challenge first, the active path takes its address back, validated, and nothing of the
     * candidate's validation stays: the candidate is gone, the address is validated for amplification (RFC 9000 section 8.1), and its
     * challenge data answers nothing any more.
     */
    @Test fun negative_theCandidateAnsweringFirstTakesThePathBack() {
        val p = EndpointPair()
        try {
            val s = midHandshake(p)
            val a = s.paths.active
            val old = a.remote
            s.onHandshakeAddressChange(PathId.Initial, other, 1200, datagram = 100, initial = false, newest = true)
            assertTrue(a.isRemote(other), "a Handshake packet moves the path at once")
            assertEquals(PathState.Validating, a.state)
            val k = assertNotNull(s.handshakeCandidate)
            assertTrue(k.isRemote(old))
            s.startValidation(k)
            val d = s.newChallengeData(k)
            s.onPathResponse(d)
            assertEquals(PathState.Validated, k.state)
            assertFalse(k.challengePending, "no further PATH_CHALLENGE on the answered address")
            assertTrue(s.candidateAnswered)
            val resends = s.handshakeResendsAtOnceForTest
            s.handshakeFlightElsewhere = true
            s.finishPathResponses()
            assertFalse(s.handshakeFlightElsewhere, "from here on the flight goes to the adopted address only")
            assertEquals(resends + 1, s.handshakeResendsAtOnceForTest, "what went to the other address is resent here at once")
            assertSame(a, s.paths.active)
            assertTrue(a.isRemote(old), "back at the address that answered")
            assertEquals(PathState.Validated, a.state)
            assertTrue(a.amplification.validated)
            assertFalse(a.answers(d), "the validation that ended answers nothing")
            assertEquals(0, a.challengeRetries)
            assertNull(s.handshakeCandidate)
            assertFalse(k in s.paths.all)
            assertTrue(s.handshakeMovesFrozen)
        } finally {
            p.close()
        }
    }

    /** The active address that already answered its own challenge keeps the path: a later answer of the candidate only ends it. */
    @Test fun negative_aValidatedActiveAddressIsNotTakenByTheCandidate() {
        val p = EndpointPair()
        try {
            val s = midHandshake(p)
            val a = s.paths.active
            s.onHandshakeAddressChange(PathId.Initial, other, 1200, datagram = 100, initial = false, newest = true)
            val k = assertNotNull(s.handshakeCandidate)
            s.startValidation(k)
            val d = s.newChallengeData(k)
            a.state = PathState.Validated
            s.onPathResponse(d)
            s.finishPathResponses()
            assertTrue(a.isRemote(other), "the active address stays")
            assertNull(s.handshakeCandidate, "the candidate ends")
            assertFalse(k in s.paths.all)
        } finally {
            p.close()
        }
    }

    /**
     * A candidate dropped after the handshake was confirmed leaves the active address to it: one the handshake did not validate yet
     * counts as validated by its completion (RFC 9000 section 8.1), as it would have at completion.
     */
    @Test fun negative_droppingTheCandidateAfterConfirmationValidatesTheActiveAddress() {
        val p = EndpointPair()
        try {
            val s = midHandshake(p)
            val k = mirrored(s)
            val a = s.paths.active
            a.state = PathState.Unknown
            s.handshakeConfirmedAt = s.now
            s.dropHandshakeCandidate()
            assertFalse(k in s.paths.all)
            assertEquals(PathState.Validated, a.state)
            assertSame(a, s.paths.lastValidated)
        } finally {
            p.close()
        }
    }

    /** A Handshake packet from [to]: the server moves the active path there (see [ConnectionCore.onHandshakeAddressChange]). */
    private fun ConnectionCore.handshakePacketFrom(
        to: InetSocketAddress,
        datagram: Long,
    ) = onHandshakeAddressChange(PathId.Initial, to, 1200, datagram, initial = false, newest = true)

    /**
     * RFC 9000 section 9.3.2: a newer packet from the address an unvalidated move left takes the path back. Nothing showed the client
     * was reached at that address, so it comes back unvalidated, with no challenge of its own while the other address is validated.
     */
    @Test fun negative_aRestoreToAnAddressNothingReachedLeavesItUnvalidated() {
        val p = EndpointPair()
        try {
            val s = midHandshake(p)
            val a = s.paths.active
            val old = a.remote
            assertFalse(a.amplification.validated)
            s.handshakePacketFrom(other, 100)
            val fb = assertNotNull(s.handshakeFallback)
            assertFalse(fb.reached)
            val k = assertNotNull(s.handshakeCandidate)
            val d = s.newChallengeData(k)
            s.handshakeFlightElsewhere = true
            s.handshakePacketFrom(old, 101)
            assertFalse(a.answers(d), "no validation of it is under way any more")
            assertFalse(s.handshakeFlightElsewhere, "the flight goes to this address only from here on")
            assertEquals(1, s.handshakeRestores)
            assertTrue(a.isRemote(old))
            assertNull(s.handshakeFallback)
            assertEquals(PathState.Unknown, a.state, "validated by the client's Handshake packet or acknowledgements from here on")
            assertFalse(a.amplification.validated, "three times what arrived, no more (section 8.1)")
        } finally {
            p.close()
        }
    }

    /**
     * An acknowledgement of a packet sent to the address before the move shows the client was reached there: the restore takes the
     * address as validated for amplification (section 8.1), and while the other address of the rebind is still under validation it
     * answers a PATH_CHALLENGE of its own too, settled as validated if no answer comes (the first address to answer decides).
     */
    @Test fun negative_aRestoreToAnAddressTheClientWasReachedAtConfirmsIt() {
        val p = EndpointPair()
        try {
            val s = midHandshake(p)
            val a = s.paths.active
            val old = a.remote
            s.handshakePacketFrom(other, 100)
            val fb = assertNotNull(s.handshakeFallback)
            s.onHandshakePathAcked(PathId.Initial.value, fb.epoch)
            assertTrue(fb.reached)
            s.handshakePacketFrom(old, 101)
            assertTrue(a.isRemote(old))
            assertTrue(a.amplification.validated)
            assertNotNull(s.handshakeCandidate, "the other address is still being validated")
            assertEquals(PathState.Validating, a.state)
            assertTrue(a.handshakeValidated, "settled as validated at its deadline if unanswered")
        } finally {
            p.close()
        }
    }

    /** The old address was validated before the move: its validation went to the candidate, which holds it while the move lasts. */
    private fun movedFromValidated(s: ConnectionCore): Path {
        val a = s.paths.active
        a.state = PathState.Validated
        a.validatedAt = s.now
        a.amplification.validated = true
        s.paths.lastValidated = a
        s.handshakePacketFrom(other, 100)
        val k = assertNotNull(s.handshakeCandidate)
        assertEquals(PathState.Validating, k.state, "a validated address left is validated again (section 9.3.3)")
        return a
    }

    /**
     * RFC 9000 section 9.3.2, "revert to using the last validated peer address when validation of a new peer address fails": at the
     * move's deadline the path goes back to the address it left, validated as it was, with the time it was validated then.
     */
    @Test fun negative_theRevertAtTheDeadlineRestoresTheValidatedAddress() {
        val p = EndpointPair()
        try {
            val s = midHandshake(p)
            val t0 = s.now
            val a = movedFromValidated(s)
            val fb = assertNotNull(s.handshakeFallback)
            s.now = fb.deadline + s.pto()
            s.revertHandshakeMove(fb)
            assertTrue(a.isRemote(fb.remote))
            assertEquals(PathState.Validated, a.state)
            assertEquals(t0, a.validatedAt, "validated when it was, not now")
            assertTrue(s.handshakeMovesFrozen, "no further handshake-time move")
            assertFalse(a.challengePending)
            assertNull(s.handshakeCandidate)
        } finally {
            p.close()
        }
    }

    /**
     * A newer packet from the validated address the move left, after the candidate's challenge to it expired unanswered: the address
     * is confirmed with a fresh validation period, never left validating with a deadline in the past.
     */
    @Test fun negative_aRestoreAfterTheCandidatesDeadlineStartsAFreshValidation() {
        val p = EndpointPair()
        try {
            val s = midHandshake(p)
            val a = movedFromValidated(s)
            val fb = assertNotNull(s.handshakeFallback)
            s.now = s.handshakeCandidate!!.challengeDeadline + s.pto()
            s.handshakePacketFrom(fb.remote, 101)
            assertTrue(a.isRemote(fb.remote))
            assertEquals(PathState.Validating, a.state)
            assertTrue(a.challengeDeadline > s.now, "a validation period from now")
            assertTrue(a.handshakeValidated)
        } finally {
            p.close()
        }
    }

    /**
     * A revert while the handshake is still running: the flight went only to the old address, but nothing shows the client read it
     * there (the handshake did not complete), so the address comes back unvalidated.
     */
    @Test fun negative_aRevertDuringTheHandshakeDoesNotTakeTheFlightAsProof() {
        val p = EndpointPair()
        try {
            val s = midHandshake(p)
            val a = s.paths.active
            s.handshakeFlightTo = a.remote
            s.handshakeFlightElsewhere = false
            s.handshakePacketFrom(other, 100)
            val fb = assertNotNull(s.handshakeFallback)
            assertTrue(fb.flightOnlyThere)
            s.now = fb.deadline
            s.revertHandshakeMove(fb)
            assertTrue(a.isRemote(fb.remote))
            assertFalse(fb.reached)
            assertFalse(a.amplification.validated)
            assertEquals(PathState.Unknown, a.state)
        } finally {
            p.close()
        }
    }

    /**
     * RFC 9000 section 9.4: a change of the peer's address to another IP starts congestion control and RTT over; a newer packet from
     * the candidate's address after the move was validated takes the path there and resets them again.
     */
    @Test fun negative_aMoveBackToTheCandidatesIpStartsCongestionOver() {
        val p = EndpointPair()
        try {
            val s = midHandshake(p)
            val a = s.paths.active
            val old = a.remote
            val elsewhere = InetSocketAddress("10.0.0.9", 40002)
            assertNull(a.pmtud, "no DF on this socket: no DPLPMTUD")
            s.handshakePacketFrom(elsewhere, 100)
            assertNull(a.pmtud, "a new IP does not start DPLPMTUD where the socket cannot run it")
            s.onHandshakePathAcked(PathId.Initial.value, a.addressEpoch) // the new address reached the client
            assertNull(s.handshakeFallback)
            assertNotNull(s.handshakeCandidate)
            val cc = a.cc
            val rtt = a.rtt
            val search = Pmtud(upperBound = 1500, start = 1400)
            a.pmtud = search
            s.handshakePacketFrom(old, 101)
            assertTrue(a.isRemote(old))
            val restarted = assertNotNull(a.pmtud)
            assertTrue(restarted !== search, "DPLPMTUD starts over on the new IP (RFC 9000 section 14)")
            assertEquals(1200, restarted.current)
            assertTrue(a.cc !== cc, "a fresh congestion controller")
            assertTrue(a.rtt !== rtt, "a fresh RTT estimator")
        } finally {
            p.close()
        }
    }

    /**
     * Only the two addresses of the first rebind are ever the candidate: a third address with the port of one of them but another IP
     * is not one of them, so when the path leaves it, it is dropped rather than kept under validation.
     */
    @Test fun negative_aThirdAddressSharingAPortIsNotARebindAddress() {
        val p = EndpointPair()
        try {
            val s = midHandshake(p)
            val a = s.paths.active
            val old = a.remote
            s.handshakePacketFrom(other, 100)
            val third = InetSocketAddress("10.0.0.9", other.port)
            s.handshakePacketFrom(third, 101)
            assertTrue(a.isRemote(third))
            s.handshakePacketFrom(old, 102) // back: the candidate takes the third address the path leaves
            assertTrue(a.isRemote(old))
            assertNull(s.handshakeCandidate, "the third address is dropped")
        } finally {
            p.close()
        }
    }

    /** The active address answering its own challenge decides for it: the candidate goes and no handshake-time move follows. */
    @Test fun negative_theActiveAddressAnsweringFirstFreezesTheMoves() {
        val p = EndpointPair()
        try {
            val s = midHandshake(p)
            val a = s.paths.active
            s.handshakePacketFrom(other, 100)
            val d = s.newChallengeData(a)
            s.onPathResponse(d)
            assertEquals(PathState.Validated, a.state)
            assertNull(s.handshakeCandidate)
            assertTrue(s.handshakeMovesFrozen)
            s.handshakePacketFrom(InetSocketAddress("10.0.0.1", 40004), 101)
            assertTrue(a.isRemote(other), "frozen: the address stays until the handshake completes")
        } finally {
            p.close()
        }
    }

    /** A move whose new address became validated for amplification is not undone at the deadline (RFC 9000 section 9.3.2 needs a failed validation). */
    @Test fun negative_aValidatedMoveIsNotReverted() {
        val p = EndpointPair()
        try {
            val s = midHandshake(p)
            val a = s.paths.active
            s.handshakePacketFrom(other, 100)
            val fb = assertNotNull(s.handshakeFallback)
            a.amplification.validated = true
            s.now = fb.deadline
            s.revertHandshakeMove(fb)
            assertTrue(a.isRemote(other))
            assertFalse(s.handshakeMovesFrozen)
        } finally {
            p.close()
        }
    }

    /**
     * The address left by the first move is validated again when it was validated for amplification (RFC 9000 section 9.3.3), also
     * when the path had not finished a PATH_CHALLENGE there (an address validated by a token or a Retry).
     */
    @Test fun negative_anAddressValidatedForAmplificationIsChallengedWhenLeft() {
        val p = EndpointPair()
        try {
            val s = midHandshake(p)
            val a = s.paths.active
            assertEquals(PathState.Unknown, a.state)
            a.amplification.validated = true
            s.handshakePacketFrom(other, 100)
            val k = assertNotNull(s.handshakeCandidate)
            assertEquals(PathState.Validating, k.state)
            assertTrue(k.challengePending)
            assertFalse(k.handshakeValidated)
        } finally {
            p.close()
        }
    }

    /**
     * Back to the candidate's address after the new one was validated: a validation already under way there goes on with its
     * challenge data (an answer to it still validates), it is not started over.
     */
    @Test fun negative_aMoveBackKeepsTheValidationUnderWayThere() {
        val p = EndpointPair()
        try {
            val s = midHandshake(p)
            val a = movedFromValidated(s)
            val k = assertNotNull(s.handshakeCandidate)
            val d = s.newChallengeData(k)
            s.onHandshakePathAcked(PathId.Initial.value, a.addressEpoch)
            assertNull(s.handshakeFallback)
            val old = k.remote
            s.handshakePacketFrom(old, 101)
            assertTrue(a.isRemote(old))
            assertEquals(PathState.Validating, a.state)
            assertTrue(a.answers(d), "the challenge sent to this address still counts")
        } finally {
            p.close()
        }
    }

    /** Handshake-time moves are for the handshake only: once it completed, a late datagram's completion moves nothing (RFC 9000 section 9). */
    @Test fun negative_noHandshakeMoveAfterTheHandshake() {
        val p = EndpointPair()
        try {
            val c = p.connect()
            assertTrue(p.confirmed(c))
            repeat(5) { p.step() }
            val s = p.server.connections().single()
            val before = s.paths.active.remote
            s.onHandshakeDatagramDone(other)
            assertEquals(before, s.paths.active.remote)
        } finally {
            p.close()
        }
    }

    /**
     * The datagram that completes the ClientHello moves the path without a PATH_CHALLENGE (no ServerHello has left yet): any challenge
     * of the address before is forgotten, and the client's Handshake packet validates the new one. A Handshake packet validates the
     * active address only when the whole flight went there and nowhere else (RFC 9000 section 8.1).
     */
    @Test fun negative_theCompletingDatagramsMoveAndTheFlightRule() {
        val p = EndpointPair()
        try {
            val s = midHandshake(p)
            val a = s.paths.active
            val d = s.newChallengeData(a)
            s.onHandshakeDatagramDone(other)
            assertTrue(a.isRemote(other))
            assertEquals(PathState.Unknown, a.state)
            assertFalse(a.answers(d))
            s.handshakeFlightTo = a.remote
            s.handshakeFlightElsewhere = true
            s.onInitialPathValidated(a.remote)
            assertFalse(a.amplification.validated, "part of the flight went elsewhere")
            s.handshakeFlightElsewhere = false
            s.onInitialPathValidated(a.remote)
            assertTrue(a.amplification.validated)
        } finally {
            p.close()
        }
        val q = EndpointPair()
        try {
            val s = midHandshake(q)
            val a = s.paths.active
            s.handshakeFlightTo = null
            s.handshakeFlightElsewhere = false
            s.onHandshakeFlightSent(a)
            assertEquals(a.remote, s.handshakeFlightTo)
            val k = mirrored(s)
            s.onHandshakeFlightSent(k)
            assertTrue(s.handshakeFlightElsewhere, "the flight went to a second address too")
        } finally {
            q.close()
        }
    }

    /** Bytes received from the address a move left are counted once per datagram (RFC 9000 section 8.1 counts datagrams' bytes). */
    @Test fun negative_theFallbackCreditsEachDatagramOnce() {
        val p = EndpointPair()
        try {
            val s = midHandshake(p)
            s.handshakePacketFrom(other, 100)
            val fb = assertNotNull(s.handshakeFallback)
            fb.credit(5, 100)
            fb.credit(5, 100)
            fb.credit(6, 50)
            assertEquals(150L, fb.receivedSince)
        } finally {
            p.close()
        }
    }

    /**
     * The handshake's validation of the active address while the other address of the rebind is still being validated: having been
     * reached proves the address, not that the client is still there, so it answers a challenge of its own too; at the deadline with
     * no answer it settles as validated and that is reported.
     */
    @Test fun negative_aReachedAddressIsConfirmedThenSettled() {
        val p = EndpointPair()
        try {
            val s = midHandshake(p)
            val a = s.paths.active
            s.onHandshakeDatagramDone(other) // the move with the completing datagram: unvalidated, no challenge
            assertNotNull(s.handshakeCandidate)
            assertEquals(PathState.Unknown, a.state)
            s.onHandshakePathAcked(PathId.Initial.value, a.addressEpoch)
            assertEquals(PathState.Validating, a.state, "a challenge of its own")
            assertTrue(a.handshakeValidated)
            s.settleHandshakeValidated(a)
            assertEquals(PathState.Validated, a.state)
            assertFalse(a.challengePending)
            p.drain(s)
            assertTrue(p.events[s]!!.any { it is io.kuicksilver.quic.ConnectionEvent.PathValidated && it.path == a.id })
        } finally {
            p.close()
        }
    }
}
