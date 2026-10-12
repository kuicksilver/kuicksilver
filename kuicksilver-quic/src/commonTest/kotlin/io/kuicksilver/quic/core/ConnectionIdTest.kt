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
        m.onNewCidLost(1)
        assertNull(m.nextNewCidToSend(), "sequence 1 is below our own retire_prior_to: not resent")
    }

    @Test fun lostNewCidRetiredByPeerIsNotResent() {
        val m = manager()
        m.setPeerLimit(3)
        while (true) m.nextNewCidToSend()?.let { it.sent = true } ?: break
        m.onPeerRetired(1, TimeMark(1_000_000_000L))
        while (true) m.nextNewCidToSend()?.let { it.sent = true } ?: break
        m.onNewCidLost(1)
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
