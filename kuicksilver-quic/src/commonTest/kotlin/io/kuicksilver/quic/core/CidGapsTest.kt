// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.core

import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.PacketBuffer
import io.kuicksilver.native.of
import io.kuicksilver.quic.TimeMark
import io.kuicksilver.quic.TransportError
import io.kuicksilver.quic.wire.ConnectionId
import io.kuicksilver.quic.wire.QuicWireException
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/** [ConnectionIdManager] edges (RFC 9000 sections 5.1, 9.5, 19.15, 19.16) the connection-level tests leave open. */
@OptIn(ExperimentalKuicksilverApi::class)
class CidGapsTest {
    private val t0 = TimeMark(1_000_000_000L)

    private fun manager(
        limit: Int = 4,
        retiredCap: Int = 32,
    ) = ConnectionIdManager(localLimit = limit, retiredCap = retiredCap, cidLength = 8, random = Random(1), registrar = NoopRegistrar)

    private fun cid(b: Int) = ConnectionId(ByteArray(8) { b.toByte() })

    private fun newCid(
        m: ConnectionIdManager,
        seq: Long,
        retire: Long = 0,
        cidByte: Int = 0x40 + seq.toInt(),
    ): Boolean {
        val b = PacketBuffer.of(ByteArray(8) { cidByte.toByte() } + ByteArray(16) { seq.toByte() })
        try {
            return m.onNewConnectionId(seq, retire, b, 0, 8, 8)
        } finally {
            b.close()
        }
    }

    private fun sendAll(m: ConnectionIdManager) {
        while (true) m.nextNewCidToSend()?.let { it.sent = true } ?: break
    }

    /**
     * RFC 9000 section 7.2: "A client MUST change the Destination Connection ID it uses for sending packets in response to only
     * the first received Initial or Retry packet." The peer's handshake ID, taken from its first Initial, is never replaced by
     * a later one: not while it is the only one and has no reset token yet (until 0.3.0 it was, for msquic's provisional
     * SCID), not once it has a token, not once a second ID exists.
     */
    @Test fun negative_initialPeerCidIsNeverReplaced() {
        val m = manager()
        m.adoptInitialPeerCid(cid(1))
        m.adoptInitialPeerCid(cid(2))
        assertEquals(cid(1), m.activePeerCid(), "the only ID, without a token: kept")
        assertEquals(listOf(0L), m.peerSeqsForTest())
        m.setPeerResetToken(0, ByteArray(16) { 7 })
        m.adoptInitialPeerCid(cid(3))
        assertEquals(cid(1), m.activePeerCid(), "it has a reset token now: kept")
        val n = manager()
        n.adoptInitialPeerCid(cid(1))
        newCid(n, 1)
        n.adoptInitialPeerCid(cid(3))
        assertEquals(cid(1), n.activePeerCid(), "a second ID exists: kept")
        assertEquals(listOf(0L, 1L), n.peerSeqsForTest())
    }

    /**
     * RFC 9000 section 5.1.1: "If the preferred_address transport parameter is sent, the sequence number of the supplied connection
     * ID is 1"; section 18.2: active_connection_id_limit is "the maximum number of connection IDs from the peer that an endpoint is
     * willing to store. This value includes ... that received in the preferred_address transport parameter". It is adopted once,
     * and only within our limit.
     */
    @Test fun negative_preferredAddressCidIsAdoptedOnceWithinTheLimit() {
        val m = manager(limit = 2)
        m.adoptInitialPeerCid(cid(1))
        m.adoptPreferredAddressCid(cid(2), ByteArray(16) { 2 })
        assertEquals(listOf(0L, 1L), m.peerSeqsForTest(), "two of two")
        m.adoptPreferredAddressCid(cid(3), ByteArray(16) { 3 })
        assertEquals(listOf(0L, 1L), m.peerSeqsForTest(), "sequence 1 is known already")
        // hand-built: the transport parameters arrive before any NEW_CONNECTION_ID, so a connection never reaches this order; it pins
        // that the adoption itself respects the limit whatever was stored before
        val full = manager(limit = 2)
        full.adoptInitialPeerCid(cid(1))
        newCid(full, 2)
        full.adoptPreferredAddressCid(cid(3), ByteArray(16) { 3 })
        assertEquals(listOf(0L, 2L), full.peerSeqsForTest(), "the limit is reached: not adopted")
    }

    /** The server's `preferred_address` ID travels in the transport parameters: no NEW_CONNECTION_ID frame repeats it. */
    @Test fun negative_preferredAddressLocalCidIsNotSentAgainInAFrame() {
        val m = manager()
        m.adoptInitialLocalCid(cid(9))
        val l = m.preferredAddressLocal()!!
        assertEquals(1L, l.seq)
        assertNull(m.nextNewCidToSend())
    }

    /**
     * RFC 9000 section 9.5: "an endpoint MUST NOT reuse a connection ID when sending to more than one destination address". When
     * retire_prior_to removes the ID in use, the replacement is not the ID a probing path holds.
     */
    @Test fun negative_replacementOfARetiredCurrentIdIsNotAPathsId() {
        val m = manager(limit = 8)
        m.adoptInitialPeerCid(cid(1))
        for (s in 1L..3L) newCid(m, s)
        val held = m.takePathPeer()!!
        assertEquals(1L, held.seq)
        newCid(m, 4, retire = 1)
        val now = m.activePeerCid()
        assertNotEquals(held.cid, now, "the probing path's ID")
        assertEquals(cid(0x42), now, "the lowest active ID no path holds (sequence 2)")
        val reordered = manager(limit = 8)
        reordered.adoptInitialPeerCid(cid(1))
        for (s in listOf(1L, 3L, 2L)) newCid(reordered, s) // 2 arrives after 3
        reordered.takePathPeer()
        newCid(reordered, 4, retire = 1)
        assertEquals(cid(0x42), reordered.activePeerCid(), "the lowest, whatever the arrival order")
    }

    /**
     * RFC 9000 section 19.15 / 10.3.2: a new ID of ours never repeats one that still routes, a retired one in its grace period
     * included (the same ID under a new sequence number is a PROTOCOL_VIOLATION a peer may raise).
     */
    @Test fun negative_newLocalIdNeverRepeatsARetiredOneStillRouting() {
        val m = manager()
        val draws = ArrayDeque(listOf(cid(5), cid(5), cid(6), cid(7), cid(8)))
        m.generator = { draws.removeFirstOrNull() }
        m.adoptInitialLocalCid(cid(4))
        m.setPeerLimit(2)
        sendAll(m)
        m.onPeerRetired(1, t0)
        val issued = (0L..3L).mapNotNull { m.localForTest(it)?.cid }
        assertEquals(listOf(cid(4), cid(6)), issued, "5 still routes after its retirement")
    }

    /** A configuration that allows several IDs again issues up to the peer's limit (load-balancers draft section 3.2). */
    @Test fun negative_allowMultipleIssuesUpToThePeerLimit() {
        val m = manager()
        m.adoptInitialLocalCid(cid(4))
        m.limitToSingle()
        m.allowMultiple()
        m.setPeerLimit(4)
        assertEquals(4, m.localCount)
        assertFalse(m.singleCid)
    }

    /** No configuration change was requested: nothing is reissued on a receive batch or on a lost NEW_CONNECTION_ID. */
    @Test fun negative_noReissueWithoutARequest() {
        val m = manager()
        var calls = 0
        m.reissueSource = {
            calls++
            cid(0x33)
        }
        m.adoptInitialLocalCid(cid(4))
        m.setPeerLimit(2)
        sendAll(m)
        assertFalse(m.retryPendingReissue())
        m.issueRetiringOlder() // sequence 2 asks the peer to retire 0 and 1
        sendAll(m)
        m.onPeerRetired(0, t0)
        m.onNewCidLost(1, t0) // the last retirement outstanding goes: nothing was requested, so nothing is reissued
        assertFalse(m.retryPendingReissue())
        assertEquals(0, calls, "reissue source asked without a request")
    }

    /**
     * RFC 9000 section 13.3: a lost NEW_CONNECTION_ID is sent again, whatever its place in the list and also when it carries
     * Retire Prior To.
     */
    @Test fun negative_lostNewConnectionIdIsResent() {
        val m = manager()
        m.adoptInitialLocalCid(cid(4))
        m.setPeerLimit(3)
        sendAll(m)
        m.onPeerRetired(0, t0) // sequence 1 is first in the list now
        sendAll(m)
        m.onNewCidLost(1, t0)
        assertEquals(1L, m.nextNewCidToSend()?.seq, "the first one in the list")
        sendAll(m)
        m.issueRetiringOlder()
        val retiring = m.nextNewCidToSend()!!
        retiring.sent = true
        m.onNewCidLost(retiring.seq, t0)
        assertEquals(retiring.seq, m.nextNewCidToSend()?.seq, "the frame carrying Retire Prior To itself")
    }

    /**
     * RFC 9000 section 5.1.2: a new Retire Prior To goes out only once the peer retired what the previous one asked for: a requested
     * configuration change waits while any of those retirements is outstanding, also when one of them leaves through a lost frame.
     * Our IDs are replaced as they go.
     */
    @Test fun negative_reissueWaitsForEveryOutstandingRetirement() {
        val m = manager()
        var calls = 0
        m.reissueSource = {
            calls++
            cid(0x50 + calls)
        }
        m.adoptInitialLocalCid(cid(4))
        m.setPeerLimit(3)
        sendAll(m)
        m.issueRetiringOlder() // sequence 3 asks the peer to retire 0, 1 and 2
        sendAll(m)
        m.requestReissue()
        assertEquals(0, calls)
        m.onNewCidLost(1, t0)
        assertEquals(0, calls, "0 and 2 are still outstanding")
        m.onPeerRetired(0, t0)
        assertEquals(0, calls, "2 is still outstanding")
        m.onPeerRetired(2, t0)
        assertEquals(1, calls, "every retirement arrived")
        val replace = manager()
        replace.adoptInitialLocalCid(cid(4))
        replace.setPeerLimit(2)
        sendAll(replace)
        replace.issueRetiringOlder()
        sendAll(replace)
        replace.onPeerRetired(0, t0)
        replace.onNewCidLost(1, t0)
        assertEquals(2, replace.localCount, "the lost one is replaced up to the peer's limit")
    }

    /**
     * RFC 9000 section 19.16: "Receipt of a RETIRE_CONNECTION_ID frame containing a sequence number greater than any previously sent
     * to the peer MUST be treated as a connection error of type PROTOCOL_VIOLATION"; one for an ID issued but never sent likewise,
     * also when that ID is first in the list. A retirement of an ID already gone is a glitch (false).
     */
    @Test fun negative_retireConnectionIdChecks() {
        val m = manager()
        m.adoptInitialLocalCid(cid(4))
        m.setPeerLimit(2) // sequence 1 issued, not sent
        assertEquals(0x19L, assertFailsWith<QuicWireException> { m.onPeerRetired(2, t0) }.frameType)
        m.onPeerRetired(0, t0)
        assertFailsWith<QuicWireException> { m.onPeerRetired(1, t0) } // first in the list now, never sent
        m.expireRetired(t0)
        assertFalse(m.onPeerRetired(0, t0), "already gone: a glitch")
    }

    /** At most retiredCap of our retired IDs keep routing; the oldest leaves the registry early (RFC 9000 section 10.3.1). */
    @Test fun negative_retiredLocalIdsLeaveTheRegistryAtTheCap() {
        val removed = ArrayList<ConnectionId>()
        val registrar =
            object : CidRegistrar {
                override fun add(
                    cid: ConnectionId,
                    core: io.kuicksilver.quic.ConnectionCore,
                ) {}

                override fun remove(cid: ConnectionId) {
                    removed += cid
                }
            }
        val m = ConnectionIdManager(localLimit = 4, retiredCap = 2, cidLength = 8, random = Random(1), registrar = registrar)
        m.adoptInitialLocalCid(cid(4))
        m.setPeerLimit(2)
        for (seq in 0L..3L) {
            sendAll(m)
            m.onPeerRetired(seq, t0 + 10.seconds)
        }
        assertEquals(2, m.sizesForTest()[2], "retired IDs still routing")
        assertEquals(2, m.sizesForTest()[3])
        assertEquals(2, removed.size, "two left the registry early")
    }

    /**
     * RFC 9000 section 9.5 / 19.16: a path's peer ID is given back with one RETIRE_CONNECTION_ID, never the ID in use, never one
     * retire_prior_to already retired; a retransmitted NEW_CONNECTION_ID for it does not bring it back.
     */
    @Test fun negative_releasedPathPeerIsRetiredOnce() {
        val m = manager(limit = 8)
        m.adoptInitialPeerCid(cid(1))
        m.activePeerCid()
        for (s in 1L..3L) newCid(m, s)
        m.releasePathPeer(m.currentPeer!!)
        assertEquals(listOf(0L, 1L, 2L, 3L), m.peerSeqsForTest(), "the ID in use stays")
        val held = m.takePathPeer()!!
        m.releasePathPeer(held)
        assertEquals(listOf(held.seq), m.takeRetireFrames())
        assertTrue(newCid(m, held.seq), "a retransmission of a retired ID")
        assertFalse(held.seq in m.peerSeqsForTest(), "not brought back")
        val second = m.takePathPeer()!!
        newCid(m, 4, retire = 3) // retires 0 and 2: the path's ID among them
        val queued = m.takeRetireFrames()
        m.releasePathPeer(second)
        assertEquals(queued.count { it == second.seq }, 1)
        assertTrue(m.takeRetireFrames().isEmpty(), "no second RETIRE_CONNECTION_ID for ${second.seq}")
    }

    /** The backlog of unacknowledged retirements is retiredCap: rotation, giving a path ID back and new retirements respect it exactly. */
    @Test fun negative_retirementBacklogBoundary() {
        val m = manager(limit = 8, retiredCap = 2)
        m.adoptInitialPeerCid(cid(1))
        m.activePeerCid()
        for (s in 1L..5L) newCid(m, s)
        assertTrue(m.canRetireOneMore())
        assertTrue(m.rotatePeerCid(), "one outstanding after it: fits")
        assertTrue(m.canRetireOneMore(), "one of two used")
        assertTrue(m.rotatePeerCid(), "two of two")
        assertFalse(m.canRetireOneMore())
        m.takeRetireFrames() // both unacknowledged now
        assertFalse(m.canRetireOneMore())
        assertFalse(m.rotatePeerCid(), "the backlog is full")
        val held = m.takePathPeer()!!
        m.releasePathPeer(held)
        assertTrue(m.takeRetireFrames().isEmpty(), "no room: the path's ID stays")
        assertFalse(held.heldByPath, "no path holds it any more: it stays used, never a spare")
        assertEquals(
            TransportError.CONNECTION_ID_LIMIT_ERROR,
            assertFailsWith<QuicWireException> { newCid(m, 6, retire = 6) }.code,
            "retire_prior_to needs more retirements than the backlog holds",
        )
        val one = manager(limit = 8, retiredCap = 2)
        one.adoptInitialPeerCid(cid(1))
        one.activePeerCid()
        for (s in 1L..5L) newCid(one, s)
        assertTrue(one.rotatePeerCid()) // one retirement outstanding
        val path = one.takePathPeer()!!
        one.releasePathPeer(path)
        assertEquals(listOf(0L, path.seq), one.takeRetireFrames(), "the second of two fits")
        assertEquals(
            TransportError.CONNECTION_ID_LIMIT_ERROR,
            assertFailsWith<QuicWireException> { newCid(one, 6, retire = 2) }.code,
            "a third outstanding retirement (sequence 1) does not fit",
        )
    }

    /**
     * RFC 9000 section 19.15: "An endpoint that receives a NEW_CONNECTION_ID frame with a sequence number smaller than the Retire Prior
     * To field of a previously received NEW_CONNECTION_ID frame MUST send a corresponding RETIRE_CONNECTION_ID frame that retires the
     * newly received connection ID". A late frame above everything retired is kept.
     */
    @Test fun negative_lateNewConnectionIdBelowRetirePriorToIsRetired() {
        val m = manager(limit = 8)
        m.adoptInitialPeerCid(cid(1))
        newCid(m, 1)
        newCid(m, 3)
        newCid(m, 4, retire = 3)
        assertEquals(listOf(0L, 1L), m.takeRetireFrames().sorted())
        assertFalse(newCid(m, 2), "a new sequence number, not a repeat")
        assertFalse(2L in m.peerSeqsForTest())
        assertEquals(listOf(2L), m.takeRetireFrames())
    }

    /**
     * A sequence number above the retired-sequence memory's floor is a new ID: kept, not retired. With a memory of two, giving back
     * path IDs 1, 3 and 4 forgets 1 (floor 2); sequence 2, delayed, then arrives.
     */
    @Test fun negative_sequenceAtTheRetiredFloorIsKept() {
        val m = manager(limit = 8, retiredCap = 2)
        m.adoptInitialPeerCid(cid(1))
        m.activePeerCid()
        for (s in listOf(1L, 3L, 4L, 5L)) newCid(m, s)
        for (expected in listOf(1L, 3L, 4L)) {
            val p = m.takePathPeer()!!
            assertEquals(expected, p.seq)
            m.releasePathPeer(p)
            for (seq in m.takeRetireFrames()) m.onRetireAcked(seq)
        }
        assertFalse(newCid(m, 2))
        assertTrue(2L in m.peerSeqsForTest(), "2 is not below the floor")
        assertFalse(newCid(m, 1), "a retransmission of forgotten sequence 1")
        assertFalse(1L in m.peerSeqsForTest(), "below the floor: retired again, never brought back")
    }

    /** RFC 9000 section 10.3: every peer reset token kept is reported to the endpoint's reset routing, those of NEW_CONNECTION_ID too. */
    @Test fun negative_peerTokensFromNewConnectionIdAreReported() {
        val m = manager()
        val added = ArrayList<Byte>()
        m.peerTokens =
            object : PeerTokenSink {
                override fun added(token: ByteArray) {
                    added += token[0]
                }

                override fun removed(token: ByteArray) {}
            }
        m.adoptInitialPeerCid(cid(1))
        newCid(m, 1)
        newCid(m, 2)
        assertEquals(listOf<Byte>(1, 2), added)
    }

    /**
     * RFC 9000 section 19.15: "if a sequence number is used for different connection IDs, the endpoint MAY treat that receipt as a
     * connection error of type PROTOCOL_VIOLATION"; we do.
     */
    @Test fun negative_sequenceNumberReusedForAnotherIdIsProtocolViolation() {
        val m = manager()
        m.adoptInitialPeerCid(cid(1))
        newCid(m, 1)
        assertTrue(newCid(m, 1), "the same ID again: a retransmission")
        assertEquals(TransportError.PROTOCOL_VIOLATION, assertFailsWith<QuicWireException> { newCid(m, 1, cidByte = 0x77) }.code)
    }

    /**
     * RFC 9000 section 9.5: "An endpoint MUST NOT reuse a connection ID when sending to more than one destination address". An ID a path
     * probed with that becomes the active one's is used; once the active path moves on to another, it is never handed to a new path as
     * a spare.
     */
    @Test fun negative_anIdMadeCurrentIsNeverASpareAgain() {
        val m = manager(limit = 8)
        m.adoptInitialPeerCid(cid(1))
        m.activePeerCid()
        newCid(m, 1)
        newCid(m, 2)
        val probed = m.takePathPeer()!!
        assertEquals(1L, probed.seq)
        m.makeCurrent(probed)
        assertTrue(m.rotatePeerCid(retireOld = false))
        assertEquals(2L, m.currentPeer!!.seq)
        assertNull(m.takePathPeer(), "0, 1 and 2 all went somewhere: no spare")
        assertFalse(m.hasSparePeer())
        assertFalse(probed.heldByPath, "the active path's ID is no other path's")
        assertFalse(m.rotatePeerCid(retireOld = false), "no spare to rotate to")
        val r = manager(limit = 8)
        r.adoptInitialPeerCid(cid(1))
        r.activePeerCid()
        for (seq in 1L..3L) newCid(r, seq)
        assertTrue(r.rotatePeerCid(retireOld = false))
        assertTrue(r.rotatePeerCid(retireOld = false))
        assertEquals(2L, r.currentPeer!!.seq)
        assertEquals(3L, r.takePathPeer()?.seq, "1 carried our packets after the first rotation: never a spare again")
    }

    /**
     * RFC 9000 section 10.3.1: a peer's reset token counts for "the connection IDs and remote addresses for datagrams it has recently
     * sent". Our packets name an ID by value: a copy of it (another instance, as a packet header gives) marks that ID used and sent
     * to the address, and no other one.
     */
    @Test fun negative_aPeerIdIsMatchedByValueForItsResetToken() {
        val m = manager()
        m.adoptInitialPeerCid(cid(1))
        newCid(m, 1)
        val copy = ConnectionId(ByteArray(8) { 0x41 })
        val to =
            io.ktor.network.sockets
                .InetSocketAddress("10.0.0.2", 443)
        m.noteLongHeaderSent(copy)
        m.noteSentTowards(ConnectionId(ByteArray(8) { 0x41 }), AddressClass.ipKey(to), to.port)
        val datagram = PacketBuffer.of(ByteArray(24) { 0x40 } + ByteArray(16) { 1 })
        try {
            assertTrue(m.matchesPeerToken(datagram, 40, to), "sequence 1's token from where its ID went")
            assertFalse(
                m.matchesPeerToken(
                    datagram,
                    40,
                    io.ktor.network.sockets
                        .InetSocketAddress("10.0.0.3", 443),
                ),
                "not from another address",
            )
        } finally {
            datagram.close()
        }
    }

    /**
     * A NEW_CONNECTION_ID retransmitted for a sequence number we retired, whose RETIRE_CONNECTION_ID is still unacknowledged but which
     * the retired-sequence memory already forgot, needs no second RETIRE_CONNECTION_ID: it is not queued again, so it costs no room
     * in the backlog (no CONNECTION_ID_LIMIT_ERROR for a benign retransmission).
     */
    @Test fun negative_aRetirementInFlightIsNotQueuedTwice() {
        val m = manager(limit = 8, retiredCap = 2)
        m.adoptInitialPeerCid(cid(1))
        m.activePeerCid()
        for (seq in 1L..4L) newCid(m, seq)
        repeat(2) { m.releasePathPeer(m.takePathPeer()!!) }
        assertEquals(listOf(1L, 2L), m.takeRetireFrames())
        m.onRetireAcked(2)
        m.releasePathPeer(m.takePathPeer()!!) // sequence 3; the memory of retired sequences forgets 1
        newCid(m, 1) // the peer's retransmission
        assertEquals(listOf(3L), m.takeRetireFrames(), "1 is in flight already")
    }
}
