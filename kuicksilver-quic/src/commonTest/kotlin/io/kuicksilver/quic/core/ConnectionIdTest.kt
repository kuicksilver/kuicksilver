// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.core

import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.PacketBuffer
import io.kuicksilver.native.of
import io.kuicksilver.quic.CorePair
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.TimeMark
import io.kuicksilver.quic.wire.ConnectionId
import io.kuicksilver.quic.wire.QuicWireException
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds

@OptIn(ExperimentalKuicksilverApi::class, DelicateKuicksilverApi::class)
class ConnectionIdTest {
    private fun manager(limit: Int = 4) =
        ConnectionIdManager(localLimit = limit, retiredCap = 32, cidLength = 8, random = Random(1), registrar = NoopRegistrar)

    private fun newCid(
        m: ConnectionIdManager,
        seq: Long,
        retire: Long = 0,
        cidByte: Byte = seq.toByte(),
        tokenByte: Byte = 0,
    ) {
        val b =
            PacketBuffer.of(ByteArray(8) { cidByte } + ByteArray(16) { tokenByte })
        ; try {
            m.onNewConnectionId(seq, retire, b, 0, 8, 8)
        } finally {
            b.close()
        }
    }

    @Test fun issuesMinOfPeerLimitAndEight() {
        val p = CorePair()
        p.use { _ ->
            assertTrue(p.handshake())
            p.runUntil(limit = 300.milliseconds) { p.server!!.peerCidCount >= 4 && p.client.peerCidCount >= 4 }
            assertEquals(4, p.server!!.peerCidCount, "peer limit 4 -> 4 connection IDs in total")
            assertEquals(4, p.client.peerCidCount)
            val m = manager()
            m.setPeerLimit(100)
            assertEquals(8, m.localCount, "never more than 8")
        }
    }

    @Test fun lostNewCidBelowOwnRetirePriorToIsNotResent() {
        // RFC 9000 sections 5.1.2 and 19.15: once we asked the peer to retire every ID below retire_prior_to, a lost NEW_CONNECTION_ID
        // for one of those IDs is not retransmitted (the peer would only retire it again)
        val m = manager()
        m.setPeerLimit(3)
        while (true) m.nextNewCidToSend()?.let { it.sent = true } ?: break
        m.issueRetiringOlder()
        while (true) m.nextNewCidToSend()?.let { it.sent = true } ?: break
        m.onNewCidLost(1, TimeMark(1_000_000_000L))
        assertNull(m.nextNewCidToSend(), "sequence 1 is below our own retire_prior_to: not resent")
    }

    @Test fun suppressedNewCidIsDroppedLocallyAfterThreePto() {
        // core review before 0.2.0, RFC 9000 section 5.1.2: a lost NEW_CONNECTION_ID below our retire_prior_to is not resent, so the peer
        // may never learn (and never retire) that ID; it stops routing 3 x PTO after the loss instead of staying registered forever
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
        val m = ConnectionIdManager(localLimit = 4, retiredCap = 32, cidLength = 8, random = Random(1), registrar = registrar)
        m.setPeerLimit(3)
        while (true) m.nextNewCidToSend()?.let { it.sent = true } ?: break
        m.issueRetiringOlder()
        while (true) m.nextNewCidToSend()?.let { it.sent = true } ?: break
        val cid = m.localForTest(1)!!.cid
        val t = TimeMark(1_000_000_000L)
        val dropAt = t + 300.milliseconds // 3 x PTO after the loss
        m.onNewCidLost(1, dropAt)
        assertNull(m.nextNewCidToSend(), "sequence 1 is still not resent")
        val bytes = PacketBuffer.of(cid.toByteArray())
        assertTrue(m.localMatches(bytes, 0, cid.length), "packets already in flight still route during the grace period")
        assertEquals(dropAt, m.nextRetiredExpiry())
        assertTrue(m.onPeerRetired(1, dropAt), "a RETIRE_CONNECTION_ID for it (the frame was not lost after all) costs no glitch")
        m.expireRetired(dropAt)
        assertTrue(!m.localMatches(bytes, 0, cid.length), "the ID no longer routes after 3 x PTO")
        assertTrue(removed.any { it == cid }, "the registrar entry is removed")
    }

    /**
     * Found by the stateful connection fuzzer (`connectionNull`): every ID the peer retired stayed registered for 3 x PTO and was
     * replaced at once, so a peer retiring each new ID as it arrived grew the retired set (and the endpoint's routing table)
     * without a fixed bound. 0.3.0 cross-review: it also made us draw a new ID, a QUIC-LB nonce of a space the process shares,
     * for every 2-byte RETIRE_CONNECTION_ID. Up to 2 x the issued count retired within 3 x PTO are replaced at once; past that a
     * retirement costs a glitch token and its replacement waits until a retired ID leaves (RFC 9000 section 5.1.1 sets no time).
     */
    @Test fun negative_retiredLocalIdsStayBounded() {
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
        val m = ConnectionIdManager(localLimit = 4, retiredCap = 32, cidLength = 8, random = Random(1), registrar = registrar)
        m.setPeerLimit(3)
        val until = TimeMark(1_000_000_000L)
        var seq = 0L
        val answers = ArrayList<Boolean>()
        repeat(100) {
            while (true) m.nextNewCidToSend()?.let { it.sent = true } ?: break
            if (m.localForTest(seq) == null) return@repeat // nothing left to retire: the peer has to wait as well
            answers += m.onPeerRetired(seq++, until)
        }
        assertEquals(List(6) { true } + List(3) { false }, answers, "6 replaced at once, then glitches")
        val sizes = m.sizesForTest()
        assertEquals(9, sizes[2], "retired IDs still routing")
        assertEquals(0, m.localCount, "the replacements wait")
        assertEquals(9L, seq)
        m.expireRetired(until)
        assertEquals(9, removed.size, "the retired IDs left the registry at their deadline")
        assertEquals(3, m.localCount, "and the replacements were issued then")
    }

    /**
     * The cap on retired IDs that keep routing ([QuicLimits.retiredConnectionIds]) on its own: since replacements are rationed (at
     * most [ConnectionIdManager.REPLACEMENT_WINDOW] times the issued IDs retired within 3 x PTO) the rationing bounds the set first with
     * the default cap, and the fuzzer's reproducer of the original finding (crash-retired-cids-unbounded) no longer reaches the cap.
     * With a cap below the rationing bound the oldest retired ID leaves the registry early and the set never exceeds the cap.
     */
    @Test fun negative_retiredIdsThatKeepRoutingNeverExceedTheCap() {
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
        val m = ConnectionIdManager(localLimit = 4, retiredCap = 4, cidLength = 8, random = Random(1), registrar = registrar)
        m.setPeerLimit(3)
        val until = TimeMark(1_000_000_000L)
        var seq = 0L
        repeat(100) {
            while (true) m.nextNewCidToSend()?.let { it.sent = true } ?: break
            if (m.localForTest(seq) == null) return@repeat
            m.onPeerRetired(seq++, until)
            assertTrue(m.sizesForTest()[2] <= 4, "retired IDs still routing: ${m.sizesForTest()[2]} > the cap of 4")
        }
        assertTrue(seq > 4, "more retirements than the cap: $seq")
        assertEquals((seq - 4).toInt(), removed.size, "the oldest left the registry early")
    }

    /**
     * 0.3.0 cross-review: the periodic rotation retired the old peer ID with no room left in the retirement backlog and threw
     * CONNECTION_ID_LIMIT_ERROR out of poll(), mid-packet. With the backlog full it now waits.
     */
    @Test fun negative_rotationWithAFullRetirementBacklogWaits() {
        val m = manager(limit = 40)
        for (seq in 0L..35L) newCid(m, seq)
        newCid(m, 36, retire = 32) // 32 retirements outstanding, none acknowledged: the backlog (32) is full
        val before = m.activePeerCid()
        assertTrue(m.hasSparePeer())
        assertEquals(false, m.rotatePeerCid(), "no room to retire the ID in use: no rotation")
        assertEquals(before, m.activePeerCid(), "the ID in use stays")
        m.takeRetireFrames().forEach(m::onRetireAcked)
        assertTrue(m.rotatePeerCid(), "it rotates once the peer acknowledged the retirements")
    }

    /**
     * 0.3.0 cross-review, RFC 9000 section 5.1.2: "An endpoint SHOULD allow for sending and tracking a number of
     * RETIRE_CONNECTION_ID frames of at least twice the value of the active_connection_id_limit transport parameter". With a limit
     * of 20 an honest peer that rotates all 20 IDs twice before our retirements are acknowledged left 40 outstanding against a
     * fixed backlog of 32: CONNECTION_ID_LIMIT_ERROR.
     */
    @Test fun retirementBacklogIsTwiceOurActiveConnectionIdLimit() {
        val p =
            CorePair(
                clientQuic =
                    io.kuicksilver.quic.QuicConfig
                        .Builder()
                        .apply { expert { activeConnectionIdLimit = 20 } }
                        .build(),
            )
        p.use { _ ->
            val m = p.client.cids
            m.adoptInitialPeerCid(ConnectionId(ByteArray(8) { 0x7f }))
            for (seq in 1L..19L) newCid(m, seq)
            newCid(m, 20, retire = 20) // 0..19 retired
            for (seq in 21L..39L) newCid(m, seq)
            newCid(m, 40, retire = 40) // 20..39 retired: 40 outstanding, none acknowledged
            assertEquals(40, m.takeRetireFrames().size)
        }
    }

    /**
     * 0.3.0 cross-review, RFC 9000 sections 10.3.2 and 19.15: a new ID of ours is never one the endpoint already routes (another
     * connection's, whose packets and reset token it would take) nor one of this connection's live or retired IDs (the same ID
     * under a new sequence number).
     */
    @Test fun negative_newLocalIdNeverRepeatsOneInUse() {
        val taken = ConnectionId(ByteArray(8) { 0x11 })
        val registrar =
            object : CidRegistrar {
                override fun add(
                    cid: ConnectionId,
                    core: io.kuicksilver.quic.ConnectionCore,
                ) {}

                override fun remove(cid: ConnectionId) {}

                override fun contains(cid: ConnectionId): Boolean = cid == taken
            }
        val m = ConnectionIdManager(localLimit = 4, retiredCap = 32, cidLength = 8, random = Random(1), registrar = registrar)
        val own = ConnectionId(ByteArray(8) { 0x22 })
        m.adoptInitialLocalCid(own)
        val script = ArrayDeque(listOf(taken, own, taken, ConnectionId(ByteArray(8) { 0x33 }), ConnectionId(ByteArray(8) { 0x44 })))
        m.generator = { script.removeFirst() }
        m.setPeerLimit(3)
        assertEquals(
            listOf(
                own,
                ConnectionId(
                    ByteArray(8) {
                        0x33
                    },
                ),
                ConnectionId(ByteArray(8) { 0x44 }),
            ),
            (0L..2L).map { m.localForTest(it)!!.cid },
        )
        assertTrue(script.isEmpty())
        // every draw collides: nothing is issued now, nothing fails
        m.generator = { taken }
        while (true) m.nextNewCidToSend()?.let { it.sent = true } ?: break
        m.onPeerRetired(1, TimeMark(1_000_000_000L))
        assertEquals(2, m.localCount)
    }

    @Test fun lostNewCidRetiredByPeerIsNotResent() {
        val m = manager()
        m.setPeerLimit(3)
        while (true) m.nextNewCidToSend()?.let { it.sent = true } ?: break
        m.onPeerRetired(1, TimeMark(1_000_000_000L))
        while (true) m.nextNewCidToSend()?.let { it.sent = true } ?: break
        m.onNewCidLost(1, TimeMark(1_000_000_000L))
        assertNull(m.nextNewCidToSend(), "an ID the peer already retired is not resent")
    }

    @Test fun negative_cidLimit() {
        val m = manager(limit = 4)
        m.adoptInitialPeerCid(ConnectionId(ByteArray(8)))
        for (seq in 1L..3L) newCid(m, seq)
        assertEquals(4, m.peerCount)
        val e = assertFailsWith<QuicWireException> { newCid(m, 4) }
        assertEquals(0x09L, e.code)
        val p = CorePair()
        p.use { _ ->
            assertTrue(p.handshake())
            p.client.testInjectNewCids = 5
            p.runUntil(limit = 300.milliseconds) {
                p.closedReason(p.serverEvents) !=
                    null
            }
            val r = p.closedReason(p.serverEvents)
            assertIs<QuicException.ConnectionLost.TransportClosed>(r)
            assertEquals(0x09L, r.code)
        }
    }

    @Test fun newConnectionIdIdempotent() {
        val m = manager()
        m.adoptInitialPeerCid(ConnectionId(ByteArray(8)))
        newCid(m, 1)
        newCid(m, 1)
        newCid(m, 1)
        assertEquals(2, m.peerCount)
    }

    /**
     * RFC 9000 section 19.15: "If an endpoint receives a NEW_CONNECTION_ID frame that repeats a previously issued connection ID with a
     * different Stateless Reset Token field value or a different Sequence Number field value, or if a sequence number is used for
     * different connection IDs, the endpoint MAY treat that receipt as a connection error of type PROTOCOL_VIOLATION" (quic-go,
     * picoquic). A repeat of the same frame stays legal ("MUST NOT be treated as a connection error").
     */
    @Test fun negative_newCidSameSequenceOtherTokenIsProtocolViolation() {
        val m = manager()
        m.adoptInitialPeerCid(ConnectionId(ByteArray(8)))
        newCid(m, 1, tokenByte = 1)
        newCid(m, 1, tokenByte = 1) // the same frame again
        val e = assertFailsWith<QuicWireException> { newCid(m, 1, tokenByte = 2) }
        assertEquals(0x0aL, e.code)
        assertEquals(0x18L, e.frameType)
    }

    @Test fun negative_newCidSameIdOtherSequenceIsProtocolViolation() {
        val m = manager()
        m.adoptInitialPeerCid(ConnectionId(ByteArray(8)))
        newCid(m, 1, cidByte = 7)
        val e = assertFailsWith<QuicWireException> { newCid(m, 2, cidByte = 7) }
        assertEquals(0x0aL, e.code)
        assertEquals(0x18L, e.frameType)
        assertEquals(2, m.peerCount, "the conflicting ID was not added")
    }

    /** The handshake's ID (sequence 0) counts as issued: a NEW_CONNECTION_ID repeating it under another sequence is refused. */
    @Test fun negative_newCidRepeatingTheHandshakeIdIsProtocolViolation() {
        val m = manager()
        m.adoptInitialPeerCid(ConnectionId(ByteArray(8)))
        val e = assertFailsWith<QuicWireException> { newCid(m, 1, cidByte = 0) }
        assertEquals(0x0aL, e.code)
    }

    /** The check runs before Retire Prior To: an ID that this very frame retires is still a repeat under another sequence. */
    @Test fun negative_newCidRepeatingAnIdItRetiresIsProtocolViolation() {
        val m = manager()
        m.adoptInitialPeerCid(ConnectionId(ByteArray(8)))
        newCid(m, 1, cidByte = 7)
        val e = assertFailsWith<QuicWireException> { newCid(m, 2, retire = 2, cidByte = 7) }
        assertEquals(0x0aL, e.code)
    }

    /**
     * RFC 9000 section 19.16: "The sequence number specified in a RETIRE_CONNECTION_ID frame MUST NOT refer to the Destination
     * Connection ID field of the packet in which the frame is contained. The peer MAY treat this as a connection error of type
     * PROTOCOL_VIOLATION" (ngtcp2, quic-go, picoquic).
     */
    @Test fun negative_retireOfThePacketsOwnDcidIsProtocolViolation() {
        val p = CorePair()
        p.use { _ ->
            assertTrue(p.handshake())
            val seq =
                p.client.cids.currentPeer!!
                    .seq
            p.client.testInjectFrames += 3 to byteArrayOf(0x19, seq.toByte())
            p.runUntil(limit = 300.milliseconds) { p.closedReason(p.serverEvents) != null }
            val r = p.closedReason(p.serverEvents)
            assertIs<QuicException.ConnectionLost.TransportClosed>(r)
            assertEquals(0x0aL, r.code)
            assertEquals(0x19L, r.frameType)
        }
    }

    /** The positive control: a rotation retires the old ID in a packet sent to the new one, which the server accepts. */
    @Test fun retireOfAnotherIdThanThePacketsDcidIsAccepted() {
        val p = CorePair()
        p.use { _ ->
            assertTrue(p.handshake())
            p.runUntil(limit = 300.milliseconds) { p.client.peerCidCount >= 2 }
            assertTrue(p.client.cids.rotatePeerCid())
            p.client.remoteCid = p.client.cids.activePeerCid()
            p.client.testInjectFrames += 3 to byteArrayOf(0x01) // a PING, so a packet goes out at once with the RETIRE
            p.runUntil(limit = 300.milliseconds) { p.server!!.retiredByPeer >= 1 || p.closedReason(p.serverEvents) != null }
            assertNull(p.closedReason(p.serverEvents), "the server keeps the connection")
            assertNull(p.closedReason(p.clientEvents), "the client keeps the connection")
            assertTrue(p.server!!.retiredByPeer >= 1, "the server took the retirement")
        }
    }

    @Test fun retirePriorToRetiresOldOnes() {
        val m = manager()
        m.adoptInitialPeerCid(ConnectionId(ByteArray(8)))
        newCid(m, 1)
        newCid(m, 2, retire = 2)
        assertEquals(listOf(0L, 1L), m.takeRetireFrames())
        assertEquals(1, m.peerCount)
        assertNull(m.takeRetireFrames().firstOrNull())
        val p = CorePair()
        p.use { _ ->
            assertTrue(p.handshake())
            p.runUntil(limit = 300.milliseconds) { p.client.peerCidCount >= 4 }
            p.client.testRetirePriorTo = true
            p.runUntil(limit = 300.milliseconds) { p.client.retiredByPeer > 0 }
            assertTrue(p.client.retiredByPeer >= 1, "the server retired our old IDs and we replaced them")
            assertNull(p.closedReason(p.serverEvents))
        }
    }

    /**
     * Review finding 5, RFC 9000 section 19.15 ("Receipt of the same frame multiple times MUST NOT be treated as a connection
     * error"): a retransmitted NEW_CONNECTION_ID for an ID we rotated away from and retired used to be added again, as a fresh
     * unused ID (whose stateless reset the peer may now send) or past our limit as CONNECTION_ID_LIMIT_ERROR.
     */
    @Test fun retransmittedNewCidForSelfRetiredIdIsIgnored() {
        val m = manager(limit = 4)
        m.adoptInitialPeerCid(ConnectionId(ByteArray(8)))
        for (seq in 1L..3L) newCid(m, seq)
        assertTrue(m.rotatePeerCid())
        assertEquals(listOf(0L), m.takeRetireFrames())
        m.onRetireAcked(0)
        newCid(m, 4) // the peer replaces the retired ID
        assertTrue(m.rotatePeerCid())
        assertEquals(listOf(1L), m.takeRetireFrames())
        newCid(m, 1) // the peer's retransmission of NEW_CONNECTION_ID(1) crosses our RETIRE_CONNECTION_ID(1)
        assertEquals(3, m.peerCount, "the retired ID is not added again")
        assertEquals(listOf(2L, 3L, 4L), m.peerSeqsForTest())
        newCid(m, 5)
        newCid(m, 0) // and a very late copy of the first replacement after our limit is full again
        newCid(m, 1)
        assertEquals(4, m.peerCount, "no CONNECTION_ID_LIMIT_ERROR, nothing re-added")
        assertNull(m.takeRetireFrames().firstOrNull(), "the RETIRE frames already went out once")
    }

    /** Review finding 5: copies of a NEW_CONNECTION_ID below retire_prior_to queue one RETIRE_CONNECTION_ID, not one per copy. */
    @Test fun duplicateNewCidBelowRetirePriorToQueuesOneRetire() {
        val m = manager(limit = 2)
        m.adoptInitialPeerCid(ConnectionId(ByteArray(8)))
        newCid(m, 1, retire = 1)
        assertEquals(listOf(0L), m.takeRetireFrames())
        newCid(m, 2) // never seen before, already below retire_prior_to after the next frame
        newCid(m, 3, retire = 3)
        assertEquals(listOf(1L, 2L), m.takeRetireFrames())
        repeat(40) {
            newCid(m, 0)
            newCid(m, 2)
        }
        assertNull(m.takeRetireFrames().firstOrNull(), "the unacknowledged RETIRE frames cover every copy")
        m.onRetireAcked(0)
        m.onRetireAcked(1)
        m.onRetireAcked(2)
        repeat(40) { newCid(m, 1) }
        assertNull(m.takeRetireFrames().firstOrNull(), "an ID retired and acknowledged is remembered, not retired again")
        assertEquals(1, m.peerCount)
    }

    /** Review finding 5: the memory of retired sequence numbers is bounded; older ones are retired again rather than re-added. */
    @Test fun retiredSequenceMemoryIsBounded() {
        val m = manager(limit = 2)
        m.adoptInitialPeerCid(ConnectionId(ByteArray(8)))
        for (seq in 1L..100L) {
            newCid(m, seq, retire = seq)
            m.takeRetireFrames().forEach { m.onRetireAcked(it) }
        }
        assertTrue(m.retiredSeqMemoryForTest() <= 32, "remembered ${m.retiredSeqMemoryForTest()}")
        newCid(m, 3)
        assertEquals(listOf(100L), m.peerSeqsForTest(), "a forgotten retired ID is still not re-added")
        assertEquals(listOf(3L), m.takeRetireFrames(), "it is retired again instead")
    }

    /**
     * Review finding 13, RFC 9000 section 19.15: "An endpoint that is sending packets with a zero-length Destination Connection ID
     * MUST treat receipt of a NEW_CONNECTION_ID frame as a connection error of type PROTOCOL_VIOLATION."
     */
    @Test fun negative_newCidFromZeroLengthCidPeer() {
        val m = manager()
        m.adoptInitialPeerCid(ConnectionId.EMPTY)
        val e = assertFailsWith<QuicWireException> { newCid(m, 1) }
        assertEquals(0x0aL, e.code)
        assertEquals(0x18L, e.frameType)
    }

    /**
     * Review finding 22, RFC 9000 section 19.16: "Receipt of a RETIRE_CONNECTION_ID frame containing a sequence number greater than
     * any previously sent to the peer MUST be treated as a connection error of type PROTOCOL_VIOLATION." An ID we issued but whose
     * NEW_CONNECTION_ID has not gone out yet was accepted.
     */
    @Test fun negative_retireOfIssuedButUnsentId() {
        val m = manager()
        m.adoptInitialLocalCid(ConnectionId(ByteArray(8)))
        m.setPeerLimit(3)
        m.nextNewCidToSend()!!.sent = true // sequence 1 goes out, 2 waits
        val e = assertFailsWith<QuicWireException> { m.onPeerRetired(2, TimeMark(1_000_000_000L)) }
        assertEquals(0x0aL, e.code)
        assertTrue(m.onPeerRetired(1, TimeMark(1_000_000_000L)), "sequence 1 was sent")
        m.nextNewCidToSend()!!.sent = true // sequence 2
        m.nextNewCidToSend()!!.let {
            // sequence 3, the replacement of 1, is lost after it was sent once
            it.sent = true
            m.onNewCidLost(it.seq, TimeMark(1_000_000_000L))
        }
        assertTrue(m.onPeerRetired(3, TimeMark(1_000_000_000L)), "a sequence sent once may be retired while its frame is resent")
    }

    /** Review finding 14, RFC 9000 section 5.1.2: the preferred_address ID (sequence 1) is retired by retire_prior_to, not forgotten. */
    @Test fun preferredAddressIdIsRetiredNotForgotten() {
        val m = manager()
        m.adoptInitialPeerCid(ConnectionId(ByteArray(8)))
        m.adoptPreferredAddressCid(ConnectionId(ByteArray(8) { 1 }), ByteArray(16))
        newCid(m, 2, retire = 2)
        assertEquals(listOf(0L, 1L), m.takeRetireFrames())
        assertEquals(listOf(2L), m.peerSeqsForTest())
    }

    @Test fun retiredBacklogAbove32IsCidLimitError() {
        val m = manager(limit = 2)
        m.adoptInitialPeerCid(ConnectionId(ByteArray(8)))
        var seq = 1L
        val e =
            assertFailsWith<QuicWireException> {
                repeat(40) {
                    newCid(m, seq, retire = seq)
                    seq++
                }
            } // each frame retires the previous one; nothing acknowledges our RETIRE frames
        assertEquals(0x09L, e.code)
        assertTrue(seq - 1 >= 32)
    }
}
