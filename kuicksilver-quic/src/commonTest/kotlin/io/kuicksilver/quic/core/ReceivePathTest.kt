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
import io.kuicksilver.quic.wire.PacketHeaderCodec
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

    /**
     * Review finding 18, RFC 9000 section 12.2: "Receivers SHOULD ignore any subsequent packets with a different Destination
     * Connection ID than the first packet in the datagram." Each coalesced packet was matched against all of our IDs on its own.
     * (Null protection ignores the header in its AEAD, so the rewritten DCID still opens.)
     */
    @Test fun coalescedPacketWithOtherDcidIsIgnored() {
        val p = CorePair()
        var held: ByteArray? = null
        val hv =
            io.kuicksilver.quic.wire
                .PacketHeaderView()
        p.filterToServer = { _, b ->
            val buf = PacketBuffer.of(b)
            try {
                if (held == null && isLong(b) && longType(b) == 0 &&
                    io.kuicksilver.quic.wire.PacketHeaderCodec
                        .parse(buf, 0, b.size, 8, hv) && hv.packetEnd < b.size &&
                    p.server != null && isLong(b.copyOfRange(hv.packetEnd, b.size))
                ) {
                    held = b // the client's Initial with its Handshake packet coalesced
                    false
                } else {
                    true
                }
            } finally {
                buf.close()
            }
        }
        try {
            p.runUntil(limit = 300.milliseconds) { held != null }
            val d = held!!
            val s = p.server!!
            val other =
                s.cids
                    .localForTest(1)!!
                    .cid
                    .toByteArray()
            var packets = 0
            val b = PacketBuffer.of(d)
            try {
                var off = 0
                while (off < d.size &&
                    io.kuicksilver.quic.wire.PacketHeaderCodec
                        .parse(b, off, d.size, 8, hv)
                ) {
                    if (packets == 1) {
                        assertEquals(8, hv.dcidLen)
                        other.copyInto(d, hv.dcidOff) // the Handshake packet now names another of the server's IDs
                    }
                    packets++
                    off = hv.packetEnd
                }
            } finally {
                b.close()
            }
            val before = s.stats.packetsReceived
            val heldBefore = s.receiver.bufferedCount
            val m = PacketBuffer.of(d)
            try {
                s.handleDatagram(m, d.size, CoreFixtures.clientAddr, Ecn.NotEct, p.now)
            } finally {
                m.close()
            }
            // a 1-RTT packet behind them waits for the handshake to complete (RFC 9001 section 5.7)
            val held = s.receiver.bufferedCount - heldBefore
            assertEquals(
                packets - 1L,
                s.stats.packetsReceived - before + held,
                "the packet with another DCID is skipped, the rest processed (or held: $held)",
            )
        } finally {
            p.close()
        }
    }

    /**
     * Review finding 21, RFC 9000 section 19.19: the Frame Type of CONNECTION_CLOSE is "the type of frame that triggered the error".
     * Stream-limit and flow-control errors carried 0, and stream errors always STREAM (0x08).
     */
    @Test fun closeNamesTheFrameThatTriggeredTheError() {
        val cases =
            listOf(
                // STREAM with OFF=0, LEN=1 on client bidi stream index 1000 (id 4000), far above the stream limit: STREAM_LIMIT_ERROR
                byteArrayOf(0x0a, 0x4f, 0xa0.toByte(), 0x01, 0x00) to (0x04L to 0x0aL),
                // RESET_STREAM on stream 0 with a final size of 2^40: FLOW_CONTROL_ERROR
                byteArrayOf(0x04, 0x00, 0x00, 0xc0.toByte(), 0, 0, 0x01, 0, 0, 0, 0) to (0x03L to 0x04L),
                // STREAM_DATA_BLOCKED on the server's unopened uni stream 3: STREAM_STATE_ERROR
                byteArrayOf(0x15, 0x03, 0x00) to (0x05L to 0x15L),
            )
        for ((frame, expected) in cases) {
            val p = CorePair()
            try {
                assertTrue(p.handshake())
                p.client.testInjectFrames += 3 to frame
                p.runUntil(limit = 300.milliseconds) { p.closedReason(p.serverEvents) != null }
                val r = p.closedReason(p.serverEvents)
                assertIs<QuicException.ConnectionLost.TransportClosed>(r)
                assertEquals(expected.first, r.code, "error code for frame 0x${frame[0].toString(16)}")
                assertEquals(expected.second, r.frameType, "Frame Type for frame 0x${frame[0].toString(16)}")
            } finally {
                p.close()
            }
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

    /**
     * RFC 9000 section 17.4: with the spin bit disabled (we never spin), "It is RECOMMENDED that endpoints set the spin bit to a
     * random value either chosen independently for each packet or chosen independently for each connection ID." It was always 0.
     * Both directions, from the short headers (Null protection leaves the first byte as sent).
     */
    @Test fun spinBitIsRandomWhileDisabled() {
        val toServer = ArrayList<Boolean>()
        val toClient = ArrayList<Boolean>()
        val p = CorePair()
        p.filterToServer = { _, b ->
            if (!isLong(b)) toServer += b[0].toInt() and 0x20 != 0
            true
        }
        p.filterToClient = { _, b ->
            if (!isLong(b)) toClient += b[0].toInt() and 0x20 != 0
            true
        }
        try {
            assertTrue(p.handshake())
            val id = p.client.openStream(true)
            var sent = 0
            p.runUntil(limit = 2000.milliseconds) {
                if (sent < 40) {
                    p.client.writeStream(id, ByteArray(100), 0, 100, false)
                    sent++
                }
                toServer.size > 40 && toClient.size > 20
            }
            assertTrue(toServer.size > 20 && toServer.any { it } && toServer.any { !it }, "client: $toServer")
            assertTrue(toClient.size > 10 && toClient.any { it } && toClient.any { !it }, "server: $toClient")
        } finally {
            p.close()
        }
    }

    /**
     * RFC 9000 section 12.2: "Senders MUST NOT coalesce QUIC packets with different connection IDs into a single UDP datagram."
     * Every datagram of a handshake (coalesced Initial, Handshake and 1-RTT packets) and of a transfer, in both directions.
     */
    @Test fun coalescedPacketsShareOneConnectionId() {
        val hv =
            io.kuicksilver.quic.wire
                .PacketHeaderView()
        var coalesced = 0
        var datagrams = 0

        fun check(
            b: ByteArray,
            shortDcidLen: Int,
        ) {
            datagrams++
            val buf = PacketBuffer.of(b)
            try {
                var off = 0
                var first: ByteArray? = null
                var packets = 0
                while (off < b.size && PacketHeaderCodec.parse(buf, off, b.size, shortDcidLen, hv)) {
                    val dcid = b.copyOfRange(hv.dcidOff, hv.dcidOff + hv.dcidLen)
                    if (first == null) first = dcid else assertTrue(first.contentEquals(dcid), "packet $packets of a datagram")
                    packets++
                    if (hv.packetEnd <= off) break
                    off = hv.packetEnd
                }
                if (packets > 1) coalesced++
            } finally {
                buf.close()
            }
        }
        val p = CorePair()
        p.filterToServer = { _, b ->
            check(b, 8)
            true
        }
        p.filterToClient = { _, b ->
            check(b, 8)
            true
        }
        try {
            assertTrue(p.handshake())
            val id = p.client.openStream(true)
            var sent = 0
            p.runUntil(limit = 1000.milliseconds) {
                if (sent < 20) {
                    p.client.writeStream(id, ByteArray(500), 0, 500, false)
                    sent++
                }
                false
            }
            assertTrue(coalesced >= 2 && datagrams > 20, "$coalesced coalesced of $datagrams datagrams")
        } finally {
            p.close()
        }
    }

    @Test fun clientIgnoresPreferredAddress() {
        val p = CorePair(serverTls = CoreFixtures.server(), crypto = ksl)
        p.onServerCreated = { it.testAdvertisePreferredAddress = true }
        try {
            assertTrue(p.handshake())
            assertEquals(PathId.Initial, p.client.stats.currentPath)
            assertNull(p.closedReason(p.clientEvents))
            // review finding 14, RFC 9000 sections 5.1.1 and 5.1.2: the preferred_address ID is the server's sequence 1; it is kept
            // (and later retired), not forgotten
            p.runUntil(limit = 300.milliseconds) { p.client.peerCidCount >= 4 }
            assertTrue(1L in p.client.cids.peerSeqsForTest(), "peer IDs ${p.client.cids.peerSeqsForTest()}")
            assertNull(p.closedReason(p.clientEvents))
            assertNull(p.closedReason(p.serverEvents))
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

    /**
     * RFC 9000 section 7.2, msquic: until it has the whole ClientHello its connection sends from the client's own DCID
     * (connection.c, the IsInitial source CID) and takes its real SCID only when the listener accepts (listener.c,
     * QuicConnGenerateNewSourceCid). An Initial with nothing but ACK and PADDING from the DCID the client sends to is processed
     * (its ACK gives an RTT sample) without fixing the SCID; its packet number is not recorded, so the ServerHello's Initial is
     * no duplicate whatever its number. The first Initial with another SCID fixes it.
     */
    @Test fun ackOnlyInitialFromTheClientsOwnDcidDoesNotFixTheScid() {
        val p = CorePair(crypto = ksl)
        try {
            p.filterToClient = { i, _ -> i > 0 } // the real server's answer to half the ClientHello is lost
            p.step()
            val dcid = p.client.remoteCid
            p.advance(20.milliseconds)
            val dropped = p.client.datagramsDropped
            feed(p.client, ackOnlyInitial(p.client, scid = dcid, pn = 0, largestAcked = 0), CoreFixtures.serverAddr, p.now)
            assertEquals(dropped, p.client.datagramsDropped, "the ACK-only Initial is processed")
            assertTrue(p.client.rtt.hasSample, "its ACK counts")
            assertEquals(dcid, p.client.remoteCid, "its SCID, the client's own DCID, is not adopted")
            // the server's next Initial may carry packet number 0 again: not recorded, the provisional one is no duplicate for it
            feed(p.client, ackOnlyInitial(p.client, scid = dcid, pn = 0, largestAcked = 0), CoreFixtures.serverAddr, p.now)
            assertEquals(0L, p.client.duplicatesDropped, "the provisional packet number is not recorded")
            assertTrue(p.handshake(), "the ServerHello's Initial fixes the SCID")
            assertEquals(p.server!!.localCid, p.client.remoteCid)
        } finally {
            p.close()
        }
    }

    /**
     * RFC 9000 section 7.2: "Once a client has received a valid Initial packet from the server, it MUST discard any subsequent
     * packet it receives on that connection with a different Source Connection ID." An ACK-only Initial from any SCID other
     * than the client's own DCID is a valid Initial like any other (quic-go answers half a ClientHello that way, from its real
     * SCID): it fixes the SCID, and a ServerHello from another one is discarded.
     */
    @Test fun negative_ackOnlyInitialFromAnotherScidFixesIt() {
        val p = CorePair(crypto = ksl)
        try {
            p.filterToClient = { _, _ -> false } // nothing of the real server yet
            p.step()
            val init = p.lastClientInitial!!
            val b = PacketBuffer.of(init)
            val other =
                try {
                    ConnectionCore.server(
                        QuicConfig.Default,
                        CoreFixtures.server(),
                        ksl,
                        CoreFixtures.clientAddr,
                        kotlin.random.Random(79),
                        p.now,
                        b,
                        init.size,
                    )!!
                } finally {
                    b.close()
                }
            val bb = PacketBuffer.of(init)
            try {
                other.handleDatagram(bb, init.size, CoreFixtures.clientAddr, Ecn.NotEct, p.now)
            } finally {
                bb.close()
            }
            val batch = PacketBatch(8)
            assertTrue(other.poll(batch, p.now) > 0, "the stranger acknowledges the half ClientHello")
            val ackOnly = batch.buffer(0).toByteArray(batch.length(0))
            batch.close()
            val strangerCid = other.localCid
            other.release()
            p.advance(20.milliseconds)
            val dropped = p.client.datagramsDropped
            feed(p.client, ackOnly, CoreFixtures.serverAddr, p.now)
            assertEquals(dropped, p.client.datagramsDropped, "the ACK-only Initial is taken")
            assertTrue(p.client.rtt.hasSample, "its ACK counts")
            assertEquals(strangerCid, p.client.remoteCid, "its SCID is adopted")
            p.filterToClient = { _, _ -> true }
            p.runUntil(500.milliseconds) { false }
            assertFalse(p.client.hasHandshakeKeys, "the real server's ServerHello, from another SCID, is discarded")
            assertTrue(p.client.datagramsDropped > dropped)
        } finally {
            p.close()
        }
    }

    /** A server Initial from [scid] to [client] with an ACK of [largestAcked] and PADDING, sealed with the server's Initial keys. */
    private fun ackOnlyInitial(
        client: ConnectionCore,
        scid: io.kuicksilver.quic.wire.ConnectionId,
        pn: Long,
        largestAcked: Int,
    ): ByteArray {
        val dcid = client.localCid.toByteArray()
        val s = scid.toByteArray()
        val payload = byteArrayOf(0x02, largestAcked.toByte(), 0, 0, 0) + ByteArray(30)
        val length = 2 + payload.size + 16
        val header =
            byteArrayOf(0xc1.toByte(), 0, 0, 0, 1, dcid.size.toByte()) + dcid + byteArrayOf(s.size.toByte()) + s +
                byteArrayOf(0, (0x40 or (length shr 8)).toByte(), length.toByte())
        val pnOffset = header.size
        val bytes = header + ByteArray(length)
        payload.copyInto(bytes, pnOffset + 2)
        val (r, w) = ksl.initialProtectors(client.initialKeyCid.toByteArray(), client.version.version, io.kuicksilver.tls.TlsRole.Server)
        val buf = PacketBuffer.of(bytes)
        try {
            val end =
                io.kuicksilver.quic.crypto.PacketProtection
                    .protect(buf, 0, pnOffset, 2, pnOffset + 2 + payload.size, pn, w, ByteArray(5))
            assertEquals(bytes.size, end)
            return buf.toByteArray(end)
        } finally {
            buf.close()
            r.close()
            w.close()
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

    /**
     * A long-header v1 packet under Null protection (identity header protection, a 16-byte tag naming the packet number):
     * [type] 0 is Initial, 2 Handshake; [badTag] makes it fail to open. The 4-byte packet number decodes as written.
     */
    private fun nullLongPacket(
        type: Int,
        dcid: ByteArray,
        scid: ByteArray,
        pn: Long,
        payload: ByteArray,
        badTag: Boolean = false,
    ): ByteArray {
        val out = ArrayList<Byte>()
        out += (0xc0 or (type shl 4) or 3).toByte()
        out += listOf<Byte>(0, 0, 0, 1)
        out += dcid.size.toByte()
        out += dcid.toList()
        out += scid.size.toByte()
        out += scid.toList()
        if (type == 0) out += 0.toByte() // no token
        val length = 4 + payload.size + 16
        out += (0x40 or (length ushr 8)).toByte()
        out += length.toByte()
        for (i in 3 downTo 0) out += (pn ushr (8 * i)).toByte()
        out += payload.toList()
        repeat(16) { i -> out += if (i < 8) 0 else (if (badTag) pn + 1 else pn).ushr(8 * (15 - i)).toByte() }
        return out.toByteArray()
    }

    /**
     * RFC 9000 section 14.1: "A server MUST discard an Initial packet that is carried in a UDP datagram with a payload that is
     * smaller than the smallest allowed maximum datagram size of 1200 bytes." Only an Initial first in the datagram was checked;
     * one coalesced after another packet was processed whatever the datagram's size.
     */
    @Test fun negative_coalescedInitialInSmallDatagramIsDiscarded() {
        val p = CorePair()
        try {
            p.step()
            val s = p.server!!
            val dcid = s.localCid.toByteArray()
            val scid = p.client.localCid.toByteArray()
            val ping = byteArrayOf(0x01) + ByteArray(40) // PING, then PADDING so the header-protection sample fits
            // a Handshake packet that does not open: it is not processed, so the Initial space is not discarded by it
            val lead = nullLongPacket(2, dcid, scid, 7, ping, badTag = true)
            val small = lead + nullLongPacket(0, dcid, scid, 50, ping)
            check(small.size < 1200)
            feed(s, small, CoreFixtures.clientAddr, p.now)
            val ack = s.loss.space(SpaceId.Initial).ack
            assertFalse(ack.isDuplicate(50), "the Initial in a ${small.size}-byte datagram was discarded")
            assertNull(p.closedReason(p.serverEvents))
            // the control: the same layout padded to 1200 bytes inside the Initial is processed
            val bigPayload = byteArrayOf(0x01) + ByteArray(1200)
            val big = lead + nullLongPacket(0, dcid, scid, 51, bigPayload)
            feed(s, big, CoreFixtures.clientAddr, p.now)
            assertTrue(ack.isDuplicate(51), "the Initial in a ${big.size}-byte datagram was processed")
        } finally {
            p.close()
        }
    }

    /**
     * RFC 9000 section 10.3.1: "Endpoints MAY skip this check if any packet from a datagram is successfully processed. However,
     * the comparison MUST be performed when the first packet in an incoming datagram either cannot be associated with a
     * connection or cannot be decrypted." An Initial the server discards for the datagram's size (section 14.1) was associated
     * and never tried, so a datagram of only that is no reset candidate (review 2026-10-28, QC-2); one whose first packet does
     * not open is checked even when a later packet of it is processed.
     */
    @Test fun resetCheckFollowsTheFirstPacketOfTheDatagram() {
        val p = CorePair()
        try {
            p.step()
            val s = p.server!!
            val dcid = s.localCid.toByteArray()
            val scid = p.client.localCid.toByteArray()
            val ping = byteArrayOf(0x01) + ByteArray(40)
            val before = s.invalidResets
            val onlyInitial = nullLongPacket(0, dcid, scid, 60, ping)
            check(onlyInitial.size < 1200)
            feed(s, onlyInitial, CoreFixtures.clientAddr, p.now)
            assertEquals(before, s.invalidResets, "a discarded small Initial is no Stateless Reset candidate")
            val lead = nullLongPacket(2, dcid, scid, 8, ping, badTag = true)
            val good = nullLongPacket(0, dcid, scid, 61, byteArrayOf(0x01) + ByteArray(1200))
            feed(s, lead + good, CoreFixtures.clientAddr, p.now)
            val ack = s.loss.space(SpaceId.Initial).ack
            assertTrue(ack.isDuplicate(61), "the second packet was processed")
            assertEquals(before + 1, s.invalidResets, "the first packet did not open: the datagram is checked")
        } finally {
            p.close()
        }
    }

    /**
     * RFC 9000 section 10.3.1 asks for the reset comparison when the first packet "cannot be associated with a connection or
     * cannot be decrypted". A duplicate was decrypted (the check may be skipped), and a packet of a space whose keys are
     * gone is ours but cannot be opened any more (the check runs). Neither is an invalid reset of the peer: a network
     * duplicate or a late retransmission counted in `invalidResets` made the statistic noisy (review 2026-10-28, N4).
     */
    @Test fun aDuplicateOrADiscardedSpaceLeadingTheDatagramIsNoInvalidReset() {
        val p = CorePair()
        try {
            p.step()
            val s = p.server!!
            val dcid = s.localCid.toByteArray()
            val scid = p.client.localCid.toByteArray()
            val big = byteArrayOf(0x01) + ByteArray(1200)
            val before = s.invalidResets
            val initial = nullLongPacket(0, dcid, scid, 80, big)
            feed(s, initial, CoreFixtures.clientAddr, p.now)
            val ack = s.loss.space(SpaceId.Initial).ack
            assertTrue(ack.isDuplicate(80))
            val duplicates = s.duplicatesDropped
            feed(s, initial, CoreFixtures.clientAddr, p.now) // the network duplicated it
            assertEquals(duplicates + 1, s.duplicatesDropped)
            assertEquals(before, s.invalidResets, "a duplicate was decrypted: no invalid reset")
            s.spaceDiscarded[SpaceId.Initial.ordinal] = true // as after the handshake: the Initial keys are gone
            feed(s, nullLongPacket(0, dcid, scid, 81, big), CoreFixtures.clientAddr, p.now)
            assertEquals(before, s.invalidResets, "a packet of a discarded space is ours: no invalid reset")
            feed(s, ByteArray(60) { 0x40 }, CoreFixtures.clientAddr, p.now) // a short header nobody can open
            assertEquals(before + 1, s.invalidResets, "an undecryptable first packet still counts")
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
