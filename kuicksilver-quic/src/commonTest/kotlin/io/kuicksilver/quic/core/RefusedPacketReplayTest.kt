// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.core

import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.ConnectionState
import io.kuicksilver.quic.CoreFixtures
import io.kuicksilver.quic.CorePair
import io.kuicksilver.quic.Dgram
import io.kuicksilver.quic.QuicLimits
import io.kuicksilver.quic.StreamPriority
import io.kuicksilver.quic.quicConfig
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * Review h-quic: a packet whose STREAM frame is refused with ReassemblyFull is dropped unacknowledged, after the frames ahead of
 * it in the packet were applied. It was not recorded as received either, so a network duplicate or an on-path replay of it was
 * processed again: its DATAGRAM frame reached the application twice. RFC 9000 section 12.3: "A receiver MUST discard a newly
 * unprotected packet unless it is certain that it has not processed another packet with the same packet number".
 */
@OptIn(ExperimentalKuicksilverApi::class, DelicateKuicksilverApi::class)
class RefusedPacketReplayTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    @Test fun negative_aReplayedRefusedPacketIsNotProcessedTwice() {
        // one reassembly range per stream: a second hole refuses the packet that would open it
        val p = CorePair(serverQuic = quicConfig { limits = QuicLimits(reassemblyRangesPerStream = 1) })
        try {
            assertTrue(p.handshake())
            assertTrue(
                p.runUntil(2.seconds) { p.client.state == ConnectionState.Confirmed && p.server!!.state == ConnectionState.Confirmed },
            )
            val server = p.server!!
            val id = p.client.openStream(bidi = true, StreamPriority.Default)
            val size = 6000
            val data = ByteArray(size + 100) { (it * 7).toByte() }
            val captured = ArrayList<ByteArray>()
            p.filterToServer = { _, bytes ->
                if (bytes[0].toInt() and 0x80 == 0) captured += bytes
                false
            }
            assertEquals(size, p.client.writeStream(id, data, 0, size, false))
            p.poll(p.client, p.toServer, CoreFixtures.clientAddr, toServer = true)
            assertTrue(captured.size >= 3, "stream data spread over ${captured.size} datagrams")
            // the second datagram only: one buffered range past a hole
            p.toServer += Dgram(captured[1], CoreFixtures.clientAddr)
            p.deliver(server, p.toServer)
            assertEquals(1, server.stats.reassemblyRanges)
            // a DATAGRAM frame ahead of a STREAM frame that opens a second range: refused after the DATAGRAM was taken
            captured.clear()
            p.client.testInjectDatagramBytes = 10
            assertEquals(100, p.client.writeStream(id, data, size, 100, true))
            p.poll(p.client, p.toServer, CoreFixtures.clientAddr, toServer = true)
            assertEquals(1, captured.size)
            val refused = captured[0]
            val duplicatesBefore = server.stats.duplicatesDropped
            repeat(2) { p.toServer += Dgram(refused, CoreFixtures.clientAddr) } // the packet and a network duplicate
            p.deliver(server, p.toServer)
            val buf = ByteArray(2048)
            var datagrams = 0
            while (server.readDatagram(buf, 0) >= 0) datagrams++
            assertEquals(1, datagrams, "the DATAGRAM frame of a refused packet reached the application again through its duplicate")
            assertEquals(duplicatesBefore + 1, server.stats.duplicatesDropped)
            // the refused packet was not acknowledged: the client resends its stream data and the transfer completes
            p.filterToServer = { _, _ -> true }
            var read = 0
            val got = ByteArray(size + 100)
            assertTrue(
                p.runUntil(10.seconds) {
                    while (true) {
                        val n = server.readStream(id, got, read, got.size - read)
                        if (n <= 0) break
                        read += n
                    }
                    read == size + 100
                },
                "read $read of ${size + 100}",
            )
            assertTrue(got.contentEquals(data))
            assertNull(p.closedReason(p.serverEvents))
        } finally {
            p.close()
        }
    }
}
