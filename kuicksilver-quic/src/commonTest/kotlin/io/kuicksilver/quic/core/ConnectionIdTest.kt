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
    ) {
        val b =
            PacketBuffer.of(ByteArray(8) { seq.toByte() } + ByteArray(16))
        ; try {
            m.onNewConnectionId(seq, retire, b, 0, 8, 8)
        } finally {
            b.close()
        }
    }

    @Test fun issuesMinOfPeerLimitAndEight() {
        val p = CorePair()
        try {
            assertTrue(p.handshake())
            p.runUntil(limit = 300.milliseconds) { p.server!!.peerCidCount >= 4 && p.client.peerCidCount >= 4 }
            assertEquals(4, p.server!!.peerCidCount, "peer limit 4 -> 4 connection IDs in total")
            assertEquals(4, p.client.peerCidCount)
            val m = manager()
            m.setPeerLimit(100)
            assertEquals(8, m.localCount, "never more than 8")
        } finally {
            p.close()
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
        // review of k7/f1-core, RFC 9000 section 5.1.2: a lost NEW_CONNECTION_ID below our retire_prior_to is not resent, so the peer
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
     * without a fixed bound. At most `retiredCap` retired IDs keep routing; the oldest leaves early (a stateless reset for a
     * retired ID is ignored by the peer, RFC 9000 section 10.3.1).
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
        repeat(100) {
            while (true) m.nextNewCidToSend()?.let { it.sent = true } ?: break
            m.onPeerRetired(seq++, until)
        }
        val sizes = m.sizesForTest()
        assertTrue(sizes[2] <= 32 && sizes[3] <= 32, "retired IDs still routing: ${sizes[2]} (deadlines ${sizes[3]})")
        assertEquals(100 - 32, removed.size, "the oldest retired IDs left the registry early")
        assertEquals(3, m.localCount, "every retired ID was replaced")
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
        try {
            assertTrue(p.handshake())
            p.client.testInjectNewCids = 5
            p.runUntil(limit = 300.milliseconds) {
                p.closedReason(p.serverEvents) !=
                    null
            }
            val r = p.closedReason(p.serverEvents)
            assertIs<QuicException.ConnectionLost.TransportClosed>(r)
            assertEquals(0x09L, r.code)
        } finally {
            p.close()
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

    @Test fun retirePriorToRetiresOldOnes() {
        val m = manager()
        m.adoptInitialPeerCid(ConnectionId(ByteArray(8)))
        newCid(m, 1)
        newCid(m, 2, retire = 2)
        assertEquals(listOf(0L, 1L), m.takeRetireFrames())
        assertEquals(1, m.peerCount)
        assertNull(m.takeRetireFrames().firstOrNull())
        val p = CorePair()
        try {
            assertTrue(p.handshake())
            p.runUntil(limit = 300.milliseconds) { p.client.peerCidCount >= 4 }
            p.client.testRetirePriorTo = true
            p.runUntil(limit = 300.milliseconds) { p.client.retiredByPeer > 0 }
            assertTrue(p.client.retiredByPeer >= 1, "the server retired our old IDs and we replaced them")
            assertNull(p.closedReason(p.serverEvents))
        } finally {
            p.close()
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
