// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.core

import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.KslLoader
import io.kuicksilver.native.PacketBuffer
import io.kuicksilver.native.of
import io.kuicksilver.native.toByteArray
import io.kuicksilver.quic.ConnectionCore
import io.kuicksilver.quic.ConnectionEvent
import io.kuicksilver.quic.ConnectionState
import io.kuicksilver.quic.CoreFixtures
import io.kuicksilver.quic.CorePair
import io.kuicksilver.quic.Dgram
import io.kuicksilver.quic.Ecn
import io.kuicksilver.quic.PacketBatch
import io.kuicksilver.quic.PathId
import io.kuicksilver.quic.QuicConfig
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.VersionProfile
import io.kuicksilver.quic.ksl
import io.kuicksilver.quic.quicConfig
import io.kuicksilver.quic.recovery.SpaceId
import io.kuicksilver.quic.server
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds

@OptIn(ExperimentalKuicksilverApi::class, DelicateKuicksilverApi::class)
class ReceivePathTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private fun isLong(b: ByteArray) = b[0].toInt() and 0x80 != 0

    private fun longType(
        b: ByteArray,
        v: VersionProfile = VersionProfile.V1,
    ): Int = (b[0].toInt() and 0x30) ushr 4

    @Test fun coalescedPacketBufferedUntilKeys() {
        // the server's first datagram (Initial + Handshake) is held back until two later Handshake datagrams arrived: those packets wait for their keys
        val p = CorePair(crypto = ksl)
        var held: ByteArray? = null
        var maxBuffered = 0
        p.filterToClient =
            {
                i,
                b,
                ->
                when {
                    i == 0 -> {
                        held = b
                        false
                    }

                    i == 2 -> {
                        p.toClient.addLast(Dgram(held!!, CoreFixtures.serverAddr))
                        true
                    }

                    else -> {
                        true
                    }
                }
            }
        try {
            assertTrue(
                p.runUntil {
                    maxBuffered = maxOf(maxBuffered, p.client.stats.undecryptableBuffered)
                    p.clientEvents.any { it is ConnectionEvent.HandshakeCompleted } &&
                        p.serverEvents.any { it is ConnectionEvent.HandshakeCompleted }
                },
                "client=${p.closedReason(p.clientEvents)}",
            )
            assertTrue(maxBuffered >= 1, "Handshake packets were buffered until the keys arrived")
            assertEquals(0L, p.client.stats.datagramsDropped, "dropped")
            assertEquals(0L, p.client.stats.lostPackets, "lost")
        } finally {
            p.close()
        }
    }

    @Test fun replayedPacketKeepsItsOwnEcn() {
        // RFC 9000 section 13.4.1: a Handshake packet held for its keys arrived in a datagram marked ECT(0); when it is fed again after the
        // (unmarked) datagram that brought the keys, it must be counted with its own mark, not the replaying datagram's
        val p = CorePair(crypto = ksl)
        var held: ByteArray? = null
        var maxEct0 = 0L
        p.filterToClient =
            { i, b ->
                when (i) {
                    0 -> {
                        held = b
                        false
                    }

                    1 -> {
                        p.toClient.addLast(Dgram(b, CoreFixtures.serverAddr, Ecn.Ect0))
                        false
                    }

                    2 -> {
                        p.toClient.addLast(Dgram(held!!, CoreFixtures.serverAddr))
                        true
                    }

                    else -> {
                        true
                    }
                }
            }
        try {
            assertTrue(
                p.runUntil {
                    maxEct0 =
                        maxOf(
                            maxEct0,
                            p.client.loss
                                .space(SpaceId.Handshake)
                                .ack.ecnCounts
                                ?.get(0) ?: 0L,
                        )
                    p.clientEvents.any { it is ConnectionEvent.HandshakeCompleted } &&
                        p.serverEvents.any { it is ConnectionEvent.HandshakeCompleted }
                },
                "client=${p.closedReason(p.clientEvents)}",
            )
            assertTrue(maxEct0 >= 1, "the replayed Handshake packet counted as ECT(0): $maxEct0")
        } finally {
            p.close()
        }
    }

    @Test fun undecryptableBufferCap32() {
        val p = CorePair(crypto = ksl)
        try {
            val junk = ByteArray(1200) { 0x5a }
            junk[0] = 0xe0.toByte()
            junk[1] = 0
            junk[2] = 0
            junk[3] = 0
            junk[4] = 1
            junk[5] = 8
            junk[14] =
                0
            junk[15] = 0x44
            // Handshake-type long header, v1, 8-byte DCID, empty SCID, Length 1183 (one packet per datagram); no keys yet
            junk[16] = 0x9f.toByte()
            p.client.testCidForBuffering(junk, 6)
            repeat(33) {
                val b = PacketBuffer.of(junk)
                try {
                    p.client.handleDatagram(b, junk.size, CoreFixtures.serverAddr, Ecn.NotEct, p.now)
                } finally {
                    b.close()
                }
            }
            assertEquals(32, p.client.stats.undecryptableBuffered)
            assertEquals(1L, p.client.stats.datagramsDropped)
        } finally {
            p.close()
        }
    }

    @Test fun initialKeysDiscardedOnFirstHandshakePacket() {
        val p = CorePair(crypto = ksl)
        try {
            assertTrue(p.runUntil { p.client.hasHandshakeKeys })
            p.runUntil(limit = 50.milliseconds) { false }
            assertFalse(p.client.hasInitialKeys, "client drops Initial keys after sending its first Handshake packet")
            assertFalse(p.server!!.hasInitialKeys, "server drops them after receiving one")
        } finally {
            p.close()
        }
    }

    @Test fun handshakeKeysDiscardedAfterWholePacket() {
        val p = CorePair(crypto = ksl)
        try {
            assertTrue(p.handshake())
            assertTrue(p.runUntil { p.client.state == ConnectionState.Confirmed })
            assertFalse(p.client.hasHandshakeKeys)
            assertNull(p.closedReason(p.clientEvents))
        } finally {
            p.close()
        }
    }

    @Test fun negative_handshakeDoneFromClient() {
        val p = CorePair()
        try {
            assertTrue(p.handshake())
            p.client.testInjectHandshakeDone = true
            p.runUntil(limit = 200.milliseconds) {
                p.closedReason(p.serverEvents) !=
                    null
            }
            val r = p.closedReason(p.serverEvents)
            assertIs<QuicException.ConnectionLost.TransportClosed>(r)
            assertEquals(0x0aL, r.code)
        } finally {
            p.close()
        }
    }

    @Test fun negative_duplicatePacketNumberAfterAead() {
        val p = CorePair(crypto = ksl)
        val captured = ArrayList<ByteArray>()
        p.filterToClient = { _, b ->
            if (!isLong(b)) captured += b
            true
        }
        try {
            assertTrue(p.handshake())
            assertTrue(p.runUntil { captured.isNotEmpty() })
            val dup = captured.first()
            val before = p.client.stats.packetsReceived
            val corrupt = dup.copyOf()
            corrupt[corrupt.size - 1] = (corrupt[corrupt.size - 1].toInt() xor 1).toByte()
            val b1 = PacketBuffer.of(corrupt)
            try {
                p.client.handleDatagram(b1, corrupt.size, CoreFixtures.serverAddr, Ecn.NotEct, p.now)
            } finally {
                b1.close()
            }
            assertEquals(before, p.client.stats.packetsReceived, "AEAD failure: dropped, not counted as a duplicate")
            val b2 = PacketBuffer.of(dup)
            try {
                p.client.handleDatagram(b2, dup.size, CoreFixtures.serverAddr, Ecn.NotEct, p.now)
            } finally {
                b2.close()
            }
            assertEquals(before, p.client.stats.packetsReceived, "a replayed packet is discarded after AEAD")
            assertEquals(1L, p.client.stats.duplicatesDropped)
            assertNull(p.closedReason(p.clientEvents))
        } finally {
            p.close()
        }
    }

    @Test fun datagramFrameWithoutSupportIsProtocolViolation() {
        val p = CorePair(serverQuic = io.kuicksilver.quic.quicConfig { maxDatagramFrameSize = 0 })
        try {
            assertTrue(p.handshake())
            p.client.testInjectDatagramFrame =
                true
            p.runUntil(limit = 200.milliseconds) { p.closedReason(p.serverEvents) != null }
            val r = p.closedReason(p.serverEvents)
            assertIs<QuicException.ConnectionLost.TransportClosed>(r)
            assertEquals(0x0aL, r.code)
        } finally {
            p.close()
        }
    }

    @Test fun greaseFixedBitOnlyWhenPeerAdvertised() {
        fun traffic(
            p: CorePair,
            n: Int,
        ): Boolean {
            val id = p.client.openStream(true)
            var sent = 0
            return p.runUntil(limit = 2000.milliseconds) {
                if (sent <
                    n
                ) {
                    p.client.writeStream(id, ByteArray(100), 0, 100, false)
                    sent++
                }
                ; p.sentToServer > n
            }
        }
        val cleared = ArrayList<Boolean>()
        val p = CorePair(crypto = ksl, serverQuic = quicConfig { greaseQuicBit = false })
        p.filterToServer =
            { _, b ->
                if (!isLong(b)) cleared += (b[0].toInt() and 0x40 == 0)
                true
            }
        try {
            assertTrue(p.handshake())
            traffic(p, 40)
            assertTrue(cleared.size > 20 && cleared.none { it }, "the server did not advertise grease_quic_bit: $cleared")
        } finally {
            p.close()
        }
        val cleared2 = ArrayList<Boolean>()
        val q = CorePair(crypto = ksl)
        q.filterToServer =
            { _, b ->
                if (!isLong(b)) cleared2 += (b[0].toInt() and 0x40 == 0)
                true
            }
        try {
            assertTrue(q.handshake())
            traffic(q, 40)
            assertTrue(cleared2.any { it } && cleared2.any { !it }, "random fixed bit when advertised: $cleared2")
        } finally {
            q.close()
        }
    }

    @Test fun clientIgnoresPreferredAddress() {
        val p = CorePair(serverTls = CoreFixtures.server(), crypto = ksl)
        p.onServerCreated = { it.testAdvertisePreferredAddress = true }
        try {
            assertTrue(p.handshake())
            assertEquals(PathId.Initial, p.client.stats.currentPath)
            assertNull(p.closedReason(p.clientEvents))
        } finally {
            p.close()
        }
    }

    /** RFC 9000 section 7.2: once the client took the server's Source Connection ID from its first Initial, packets with another SCID are discarded (msquic answers a retransmitted Initial from a second connection instance). */
    @Test fun clientDiscardsLongHeaderWithDifferentScid() {
        val p = CorePair(crypto = ksl)
        var injected = false
        p.filterToClient = { i, _ ->
            if (i == 1 &&
                !injected
            ) { // after the real server's first flight: a second server instance answers the same client Initial with its own SCID
                injected = true
                val init = p.lastClientInitial!!
                val b = PacketBuffer.of(init)
                val other =
                    try {
                        ConnectionCore
                            .server(
                                QuicConfig.Default,
                                CoreFixtures.server(),
                                ksl,
                                CoreFixtures.clientAddr,
                                kotlin.random.Random(77),
                                p.now,
                                b,
                                init.size,
                            )!!
                            .also {
                                it.handleDatagram(b, init.size, CoreFixtures.clientAddr, Ecn.NotEct, p.now)
                            }
                    } finally {
                        b.close()
                    }
                val batch = PacketBatch(8)
                val n = other.poll(batch, p.now)
                for (k in 0 until n) p.toClient.addLast(Dgram(batch.buffer(k).toByteArray(batch.length(k)), CoreFixtures.serverAddr))
                batch.close()
                assertTrue(n > 0, "the stranger produced its first flight")
                other.release()
            }
            true
        }
        try {
            assertTrue(p.handshake(), "the handshake completes with the first server; the stranger's packets are ignored")
            assertTrue(injected)
            assertTrue(
                p.client.stats.datagramsDropped >= 1,
                "the second instance's datagrams were dropped: ${p.client.stats.datagramsDropped}",
            )
        } finally {
            p.close()
        }
    }

    /** msquic acknowledges the first Initial from a packet whose SCID is still the client's DCID and picks its own SCID with the ServerHello: the client follows the SCID of the first Initial that carries CRYPTO (RFC 9000 section 7.2 applies from there). */
    @Test fun clientAdoptsScidOfFirstInitialWithCryptoNotOfAnAckOnlyOne() {
        val p = CorePair(crypto = ksl)
        var injected = false
        var ackOnly = 0
        p.filterToClient = { i, _ ->
            if (i == 0 &&
                !injected
                // before the real server's flight: a stranger created from the first of the two client Initials only acknowledges, its
                // ClientHello being incomplete
            ) {
                injected = true
                val init = p.lastClientInitial!!
                val b = PacketBuffer.of(init)
                val other =
                    try {
                        ConnectionCore.server(
                            QuicConfig.Default,
                            CoreFixtures.server(),
                            ksl,
                            CoreFixtures.clientAddr,
                            kotlin.random.Random(78),
                            p.now,
                            b,
                            init.size,
                        )!!
                    } finally {
                        b.close()
                    }
                // three deliveries of the same half ClientHello: three ACK-only Initials, the last one with packet number 2 (msquic numbers across its instances; a stranger's pn 0 would collide with the real server's)
                val batch = PacketBatch(8)
                var last: ByteArray? = null
                repeat(3) {
                    val bb = PacketBuffer.of(init)
                    try {
                        other.handleDatagram(bb, init.size, CoreFixtures.clientAddr, Ecn.NotEct, p.now)
                    } finally {
                        bb.close()
                    }
                    batch.clear()
                    val n = other.poll(batch, p.now)
                    if (n >
                        0
                    ) {
                        last = batch.buffer(0).toByteArray(batch.length(0))
                    }
                }
                last?.let {
                    p.toClient.addLast(Dgram(it, CoreFixtures.serverAddr))
                    ackOnly++
                }
                batch.close()
                other.release()
            }
            true
        }
        try {
            p.step() // the client's two Initials are queued; lastClientInitial is the second (the first was recorded first)
            assertTrue(p.handshake(), "the handshake completes with the server whose Initial carried the ServerHello")
            assertTrue(injected && ackOnly >= 1, "an ACK-only Initial with a foreign SCID arrived first: $ackOnly")
        } finally {
            p.close()
        }
    }

    private fun feed(
        core: ConnectionCore,
        d: ByteArray,
        from: io.ktor.network.sockets.InetSocketAddress,
        now: io.kuicksilver.quic.TimeMark,
    ) {
        val b = PacketBuffer.of(d)
        try {
            core.handleDatagram(b, d.size, from, Ecn.NotEct, now)
        } finally {
            b.close()
        }
    }

    private fun assertProtocolViolation(
        events: List<ConnectionEvent>,
        who: String,
    ) {
        val r = events.filterIsInstance<ConnectionEvent.Closed>().firstOrNull()?.reason
        assertIs<QuicException.ConnectionLost.TransportClosed>(r, "$who closed: $r")
        assertEquals(io.kuicksilver.quic.TransportError.PROTOCOL_VIOLATION, r.code, "$who: $r")
    }

    /** RFC 9000 sections 17.2 and 17.3.1: reserved bits that are non-zero after removing header protection are a PROTOCOL_VIOLATION, in long and short headers. */
    @Test fun negative_reservedBitsSet() {
        val p = CorePair()
        try {
            // Null crypto: header protection is the identity, so the test sets the bits the peer "sent"
            assertTrue(p.handshake())
            p.runUntil(100.milliseconds) { false }
            p.filterToServer = { _, b ->
                if (!isLong(b)) b[0] = (b[0].toInt() or 0x08).toByte()
                true
            }
            val id = p.client.openStream(true)
            p.client.writeStream(id, ByteArray(10), 0, 10, true)
            assertTrue(p.runUntil(1000.milliseconds) { p.closedReason(p.serverEvents) != null })
            assertProtocolViolation(p.serverEvents, "server (short header)")
        } finally {
            p.close()
        }
        val q = CorePair()
        try {
            var done = false
            q.filterToClient =
                { _, b ->
                    if (!done && isLong(b) && longType(b) == 0) {
                        done = true
                        b[0] = (b[0].toInt() or 0x04).toByte()
                    }
                    true
                }
            assertTrue(q.runUntil(1000.milliseconds) { q.closedReason(q.clientEvents) != null })
            assertProtocolViolation(q.clientEvents, "client (long header)")
        } finally {
            q.close()
        }
    }

    /** RFC 9000 section 17.2.2: a server Initial with a non-zero Token Length is discarded by the client; the retransmitted one completes the handshake. */
    @Test fun negative_serverInitialWithToken() {
        val p = CorePair()
        try {
            var tampered: ByteArray? = null
            p.filterToClient =
                { i, b ->
                    if (i ==
                        0
                    ) {
                        val off =
                            1 + 4 + 1 + (b[5].toInt() and 0xff)
                        val tokenLenOff =
                            off + 1 + (b[off].toInt() and 0xff)
                        tampered =
                            b.copyOfRange(0, tokenLenOff) + byteArrayOf(1, 0x58) + b.copyOfRange(tokenLenOff + 1, b.size)
                        false
                    } else {
                        true
                    }
                }
            while (tampered == null) p.step()
            feed(p.client, tampered!!, CoreFixtures.serverAddr, p.now)
            assertFalse(p.client.anyPeerPacket, "the Initial with a token was discarded")
            assertTrue(p.handshake(), "the server's retransmission completes the handshake")
        } finally {
            p.close()
        }
    }

    /** RFC 9000 section 17.2: a long-header packet with the fixed bit cleared is discarded unless we allowed it with grease_quic_bit. */
    @Test fun negative_longHeaderWithoutFixedBit() {
        val p = CorePair(clientQuic = quicConfig { greaseQuicBit = false })
        try {
            var tampered: ByteArray? = null
            p.filterToClient =
                { i, b ->
                    if (i == 0) {
                        tampered = b.copyOf().also { it[0] = (it[0].toInt() and 0x40.inv()).toByte() }
                        false
                    } else {
                        true
                    }
                }
            while (tampered == null) p.step()
            feed(p.client, tampered!!, CoreFixtures.serverAddr, p.now)
            assertFalse(p.client.anyPeerPacket, "discarded")
            assertTrue(p.handshake())
        } finally {
            p.close()
        }
    }

    /** RFC 9000 section 9: a client discards packets from a server address it does not know: no processing, and a PATH_CHALLENGE from there opens no path. */
    @Test fun negative_clientDropsPacketFromUnknownServerAddress() {
        val p = CorePair()
        try {
            assertTrue(p.handshake())
            p.runUntil(100.milliseconds) { false }
            val s = p.server!!
            val stranger =
                io.ktor.network.sockets
                    .InetSocketAddress("10.0.0.99", 443)
            s.testInjectPathChallenges = 1
            p.batch.clear()
            check(s.poll(p.batch, p.now) >= 1)
            val d = p.batch.buffer(0).toByteArray(p.batch.length(0))
            val received = p.client.stats.packetsReceived
            feed(p.client, d, stranger, p.now)
            assertEquals(received, p.client.stats.packetsReceived, "not processed")
            assertEquals(1, p.client.pathCountForTest, "no path for the stranger")
            assertEquals(0, p.client.paths.responses, "no PATH_RESPONSE queued")
            feed(p.client, d, CoreFixtures.serverAddr, p.now)
            assertEquals(received + 1, p.client.stats.packetsReceived, "the same datagram from the server's address is processed")
        } finally {
            p.close()
        }
    }
}
