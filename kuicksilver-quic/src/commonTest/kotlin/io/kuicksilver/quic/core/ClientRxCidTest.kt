// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.core

import io.ktor.network.sockets.InetSocketAddress
import io.kuicksilver.native.KslLoader
import io.kuicksilver.native.PacketBuffer
import io.kuicksilver.quic.NewReno
import io.kuicksilver.quic.QuicConfig
import io.kuicksilver.quic.endpoint.EndpointPair
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds

/**
 * Which of a client's connection IDs the server's packets carry, per path (`ConnectionInfo.paths`): several paths can share
 * a socket (a probe of the server's preferred address leaves from the active path's, RFC 9000 section 9.6.3), so a packet
 * is credited to the path of its socket and its peer address, never to another path on that socket.
 */
class ClientRxCidTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    @Test fun aPacketFromAnotherAddressOnTheSameSocketIsCreditedToItsOwnPath() {
        val p = EndpointPair()
        val c = p.connect(QuicConfig.Default)
        p.use { _ ->
            assertTrue(p.confirmed(c))
            val first = c.paths.active
            val before = c.localCidSeqOn(first)
            val probe = assertNotNull(c.paths.add(first.socket, InetSocketAddress("10.9.9.9", 4433), NewReno(), 333.milliseconds))
            val other = assertNotNull(c.cids.localCidOf(1), "the client issued a second ID")
            val buf = PacketBuffer.allocate(other.length)
            other.copyTo(buf, 0)
            c.noteClientRxCid(first.socket, probe.remote, buf, 0, other.length)
            assertEquals(1L, probe.clientRxCidSeq, "the probe's path")
            assertEquals(before, c.localCidSeqOn(first), "the path the connection started on is untouched")
            assertNotEquals(1L, first.clientRxCidSeq)
            // a packet from an address no path has changes nothing
            c.noteClientRxCid(first.socket, InetSocketAddress("10.8.8.8", 1), buf, 0, other.length)
            assertEquals(before, c.localCidSeqOn(first))
            buf.close()
        }
    }
}
