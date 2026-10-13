// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.core

import io.ktor.network.sockets.InetSocketAddress
import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.ConnectionCore
import io.kuicksilver.quic.ConnectionEvent
import io.kuicksilver.quic.ConnectionState
import io.kuicksilver.quic.NullCryptoProvider
import io.kuicksilver.quic.PathFailureReason
import io.kuicksilver.quic.PathState
import io.kuicksilver.quic.TestFrame
import io.kuicksilver.quic.endpoint.EndpointPair
import io.kuicksilver.quic.nullOneRttFrames
import io.kuicksilver.tls.KslQuicCrypto
import io.kuicksilver.tls.QuicCrypto
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Migration in the first moments of a connection (RFC 9000 sections 5.1.1 and 9.5): the server's spare connection IDs come with its
 * first 1-RTT flight, and a client probe that finds none waits for a NEW_CONNECTION_ID instead of failing as an unanswered path.
 */
@OptIn(ExperimentalKuicksilverApi::class, DelicateKuicksilverApi::class)
class EarlyMigrationTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private val other = InetSocketAddress("10.0.0.7", 40000)

    private fun EndpointPair.server(): ConnectionCore = server.connections().single()

    private fun firstFlightCids(crypto: QuicCrypto) {
        val p = EndpointPair(crypto = crypto)
        try {
            val c = p.connect()
            assertTrue(p.runUntil { c.state == ConnectionState.Confirmed }, "confirmed")
            // RFC 9000 section 5.1.1: the server issues up to the client's active_connection_id_limit (4 by default) at once, so the
            // client holds them by the time HANDSHAKE_DONE confirms the handshake and a migration becomes possible
            assertEquals(4, c.cids.peerCount, "the server's IDs arrived with its first 1-RTT flight (${crypto::class.simpleName})")
            assertTrue(c.cids.hasSparePeer())
        } finally {
            p.close()
        }
    }

    @Test fun serverIssuesConnectionIdsInItsFirstPostHandshakeFlight() {
        firstFlightCids(NullCryptoProvider)
        firstFlightCids(KslQuicCrypto)
    }

    /** A pair whose server holds its NEW_CONNECTION_ID frames, confirmed; the client has no spare ID of the server. */
    private fun heldPair(): Pair<EndpointPair, ConnectionCore> {
        val p = EndpointPair()
        p.server.testHoldNewConnectionIds = true
        val c = p.connect()
        assertTrue(p.confirmed(c))
        assertEquals(1, c.cids.peerCount, "no NEW_CONNECTION_ID reached the client")
        assertFalse(c.cids.hasSparePeer())
        return p to c
    }

    @Test fun migrationRightAfterHandshakeCompletesOnceTheConnectionIdArrives() {
        val (p, c) = heldPair()
        try {
            val s = p.server()
            val probes = ArrayList<ByteArray>()
            p.filterToServer =
                { _, b ->
                    if (nullOneRttFrames(b)?.any { it is TestFrame.PathChallenge } == true) probes += b
                    true
                }
            val id = c.addPath(p.serverAddr, p.now)
            p.clientSocketSources[id] = other
            p.clientListens += other
            c.probePath(id, p.now)
            val start = p.now
            val release = start + c.validationTimeout() * 0.9
            while (p.now < release) p.step()
            assertEquals(PathState.Validating, c.pathState(id), "still waiting for an ID, not failed")
            assertTrue(probes.isEmpty(), "no PATH_CHALLENGE reusing the active path's ID (RFC 9000 section 9.5)")
            s.cids.holdNewCidsForTest = false
            val released = p.now
            assertTrue(p.runUntil { c.pathState(id) == PathState.Validated }, "validated: ${c.pathState(id)}")
            assertTrue(
                p.now - released <= c.pto() * 2,
                "the probe goes out as soon as the ID arrives, not at the next backed-off repeat: ${p.now - released}",
            )
            c.switchPath(id, p.now)
            val sid = c.openStream(true)
            c.writeStream(sid, ByteArray(100) { 0x41 }, 0, 100, true)
            repeat(5) { p.step() }
            assertEquals(other, s.remoteAddressForTest, "the server follows the client to the new address")
            assertNull(p.closed(c))
            assertNull(p.closed(s))
        } finally {
            p.close()
        }
    }

    @Test fun probeWithoutSpareConnectionIdFailsWithNoSpareConnectionId() {
        val (p, c) = heldPair()
        try {
            val id = c.addPath(p.serverAddr, p.now)
            p.clientSocketSources[id] = other
            p.clientListens += other
            c.probePath(id, p.now)
            assertTrue(p.runUntil { c.pathState(id) == PathState.Failed }, "gave up: ${c.pathState(id)}")
            val failed = p.events[c]!!.filterIsInstance<ConnectionEvent.PathFailed>().single()
            assertEquals(PathFailureReason.NoSpareConnectionId, failed.reason)
            assertNull(p.closed(c), "the connection stays on its path")
            assertEquals(io.kuicksilver.quic.PathId.Initial, c.path.id)
        } finally {
            p.close()
        }
    }
}
