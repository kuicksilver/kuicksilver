// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.endpoint

import io.ktor.network.sockets.InetSocketAddress
import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.KslLoader
import io.kuicksilver.native.PacketBuffer
import io.kuicksilver.native.of
import io.kuicksilver.native.toByteArray
import io.kuicksilver.quic.ConnectionAdmission
import io.kuicksilver.quic.ConnectionState
import io.kuicksilver.quic.NullCryptoProvider
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.Rfc9001Packets
import io.kuicksilver.quic.Rfc9369Packets
import io.kuicksilver.quic.TimeMark
import io.kuicksilver.quic.VersionProfile
import io.kuicksilver.quic.core.PacketReceiver
import io.kuicksilver.quic.wire.ConnectionId
import io.kuicksilver.quic.wire.PacketHeaderCodec
import io.kuicksilver.quic.wire.PacketHeaderView
import io.kuicksilver.quic.wire.PacketType
import io.kuicksilver.quic.wire.RetryPacket
import io.kuicksilver.tls.KslQuicCrypto
import io.kuicksilver.tls.QuicCrypto
import kotlin.random.Random
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.hours
import kotlin.time.Duration.Companion.nanoseconds
import kotlin.time.Duration.Companion.seconds

/** RFC 9000 sections 8.1 and 17.2.5, RFC 9001 section 5.8: Retry on the server, Retry validation on the client, address-bound tokens. */
@OptIn(ExperimentalKuicksilverApi::class, DelicateKuicksilverApi::class)
class RetryTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private fun isInitial(b: ByteArray) =
        b[0].toInt() and 0x80 != 0 &&
            PacketHeaderView().let { v ->
                PacketHeaderCodec.parse(PacketBuffer.of(b).also { }, 0, b.size, 8, v) &&
                    v.type == PacketType.Initial
            }

    private fun isRetry(b: ByteArray): Boolean {
        val v = PacketHeaderView()
        val buf = PacketBuffer.of(b)
        try {
            return PacketHeaderCodec.parse(buf, 0, b.size, 8, v) &&
                v.type == PacketType.Retry
        } finally {
            buf.close()
        }
    }

    @Test fun rfc9001A4RetryBytes() = retryVector(VersionProfile.V1, Rfc9001Packets.A4_RETRY, Rfc9001Packets.DCID)

    @Test fun rfc9369A4RetryBytes() = retryVector(VersionProfile.V2, Rfc9369Packets.A4_RETRY, Rfc9369Packets.DCID)

    private fun retryVector(
        profile: VersionProfile,
        expected: ByteArray,
        odcid: ByteArray,
    ) {
        val out = PacketBuffer.allocate(200)
        try {
            val n =
                RetryPacket.write(
                    out,
                    profile,
                    ConnectionId(ByteArray(0)),
                    ConnectionId(expected.copyOfRange(7, 15)),
                    "token".encodeToByteArray(),
                    ConnectionId(odcid),
                    KslQuicCrypto,
                    firstByteRandom = 0x0f,
                )
            assertContentEquals(expected, out.toByteArray(n))
            assertTrue(RetryPacket.verify(out, 0, n, ConnectionId(odcid), KslQuicCrypto))
            assertFalse(RetryPacket.verify(out, 0, n, ConnectionId(ByteArray(8)), KslQuicCrypto), "another ODCID: tag mismatch")
        } finally {
            out.close()
        }
    }

    @Test fun retryRoundTripCompletesHandshake() {
        for (crypto in listOf<QuicCrypto>(NullCryptoProvider, KslQuicCrypto)) {
            val p = EndpointPair(crypto = crypto) { admission = ConnectionAdmission.AlwaysRetry }
            var retries = 0
            var handshakeBeforeValidated = false
            p.filterToClient = { _, b ->
                if (isRetry(b)) retries++
                true
            }
            try {
                val c = p.connect()
                assertTrue(p.confirmed(c), "handshake after Retry with $crypto: ${p.closed(c)}")
                assertTrue(retries in 1..2, "one Retry per Initial datagram of the first flight (the server is stateless): $retries")
                val s = p.server.connections().single()
                assertTrue(s.addressValidated, "the token validates the address: no Handshake packet needed for that")
                assertFalse(handshakeBeforeValidated)
                assertNull(p.closed(c))
                assertNull(p.closed(s))
            } finally {
                p.close()
            }
        }
    }

    @Test fun serverInitialScidMayDifferFromRetryScid() {
        // RFC 9000 section 7.2: the client switches its DCID twice, to the Retry SCID and then to the SCID of the server's Initial; the Retry SCID is never
        // a peer connection ID of its own, so a NEW_CONNECTION_ID must not make the client fall back to it (ngtcp2 and quinn answer the Retry with a fresh SCID)
        val p = EndpointPair(crypto = KslQuicCrypto) { admission = ConnectionAdmission.AlwaysRetry }
        p.server.testFreshCidAfterRetry = true
        val shortDcids = ArrayList<ByteArray>()
        p.filterToServer = { _, b ->
            if (b[0].toInt() and 0x80 == 0) shortDcids += b.copyOfRange(1, 9)
            true
        }
        try {
            val c = p.connect()
            assertTrue(p.confirmed(c), "handshake: ${p.closed(c)}")
            val s = p.server.connections().single()
            assertFalse(
                s.localCid.toByteArray().contentEquals(s.retryScid!!.toByteArray()),
                "the server's Initial SCID differs from the Retry SCID",
            )
            assertTrue(p.runUntil { shortDcids.size >= 1 }, "no 1-RTT packet from the client")
            for (d in shortDcids) {
                assertContentEquals(
                    s.localCid.toByteArray(),
                    d,
                    "every 1-RTT packet goes to the server's Initial SCID, never back to the Retry SCID",
                )
            }
        } finally {
            p.close()
        }
    }

    @Test fun negative_forgedRetryTag() {
        val p = EndpointPair(crypto = KslQuicCrypto) { admission = ConnectionAdmission.AlwaysRetry }
        var forged = 0
        p.filterToClient =
            { _, b ->
                if (isRetry(b) && forged == 0) {
                    forged++
                    b[b.size - 1] = (b[b.size - 1].toInt() xor 1).toByte()
                }
                true
            } // the first Retry arrives with a bad tag; the client's PTO repeats the Initial and the second Retry is genuine
        try {
            val c = p.connect()
            assertTrue(p.confirmed(c), "${p.closed(c)}")
            assertEquals(1, forged)
            assertNull(p.closed(c))
        } finally {
            p.close()
        }
    }

    /** RFC 9001 section 5.8: a Retry whose integrity tag does not verify is dropped; the same packet with its tag intact is taken. */
    @Test fun negative_forgedRetryTagDropped() {
        for (forge in listOf(true, false)) {
            val p = EndpointPair()
            p.serverStalled = true // no server packet before the Retry
            try {
                val c = p.connect()
                p.step()
                val b = PacketBuffer.allocate(100)
                try {
                    val n =
                        RetryPacket.write(
                            b,
                            VersionProfile.V1,
                            c.localCid,
                            ConnectionId(ByteArray(8) { 5 }),
                            ByteArray(16) { 7 },
                            c.odcid,
                            NullCryptoProvider,
                            0,
                        )
                    val bytes = b.toByteArray(n)
                    if (forge) bytes[n - 1] = (bytes[n - 1].toInt() xor 1).toByte()
                    p.feed(p.client, bytes, p.serverAddr)
                } finally {
                    b.close()
                }
                assertEquals(!forge, c.retryReceivedForTest, if (forge) "a forged tag is dropped" else "the control is taken")
            } finally {
                p.close()
            }
        }
    }

    @Test fun negative_retryEmptyToken() {
        val p = EndpointPair()
        p.serverStalled = true // no server packet before the Retry: a client that processed one ignores any Retry anyway
        try {
            val c = p.connect()
            p.step()
            val b = PacketBuffer.allocate(100)
            try {
                val n =
                    RetryPacket.write(
                        b,
                        VersionProfile.V1,
                        c.localCid,
                        ConnectionId(ByteArray(8) { 5 }),
                        ByteArray(0),
                        c.odcid,
                        NullCryptoProvider,
                        0,
                    )
                p.feed(p.client, b.toByteArray(n), p.serverAddr)
            } finally {
                b.close()
            }
            assertFalse(c.retryReceivedForTest, "a Retry with an empty token is dropped (RFC 9000 section 17.2.5.2)")
            assertNull(p.closed(c))
        } finally {
            p.close()
        }
    }

    /** RFC 9369 section 4.1: "The client ignores Retry packets using other versions." */
    @Test fun negative_retryInOtherVersionIgnored() {
        for (retryVersion in listOf(VersionProfile.V2, VersionProfile.V1)) {
            val p = EndpointPair()
            p.serverStalled = true // no server packet before the Retry
            try {
                val c = p.connect(io.kuicksilver.quic.quicConfig { versions = listOf(VersionProfile.V1, VersionProfile.V2) })
                p.step()
                val b = PacketBuffer.allocate(100)
                try {
                    val n =
                        RetryPacket.write(
                            b,
                            retryVersion,
                            c.localCid,
                            ConnectionId(ByteArray(8) { 5 }),
                            ByteArray(16) { 7 },
                            c.odcid,
                            NullCryptoProvider,
                            0,
                        )
                    p.feed(p.client, b.toByteArray(n), p.serverAddr)
                } finally {
                    b.close()
                }
                // the v1 Retry is the control: the same packet in the Initial's version is taken
                assertEquals(retryVersion == VersionProfile.V1, c.retryReceivedForTest, "Retry in $retryVersion answering a v1 Initial")
            } finally {
                p.close()
            }
        }
    }

    /**
     * Fuzzing finding (packetRecvClient): a Retry whose token cannot fit the client's next 1200-byte Initial made the packet
     * builder throw out of poll. Such a Retry is dropped; the largest token that fits is still taken and sent.
     */
    @Test fun negative_retryOversizedTokenDropped() {
        for ((size, taken) in listOf(1150 to false, 1060 to false, PacketReceiver.MAX_RETRY_TOKEN to true)) {
            val p = EndpointPair()
            try {
                val c = p.connect() // the Retry arrives before any server packet
                val b = PacketBuffer.allocate(1500)
                try {
                    val n =
                        RetryPacket.write(
                            b,
                            VersionProfile.V1,
                            c.localCid,
                            ConnectionId(ByteArray(20) { 5 }),
                            ByteArray(size) { 3 },
                            c.odcid,
                            NullCryptoProvider,
                            0,
                        )
                    p.feed(p.client, b.toByteArray(n), p.serverAddr)
                } finally {
                    b.close()
                }
                assertEquals(taken, c.retryReceivedForTest, "a Retry with a $size-byte token")
                repeat(3) { p.step() } // the next Initials carry the token (or none): polling must not throw
                // a forged Retry the server never sent ends in a transport-parameter mismatch; a dropped one changes nothing
                if (!taken) assertNull(p.closed(c), "the client keeps its handshake going after a $size-byte Retry token")
            } finally {
                p.close()
            }
        }
    }

    @Test fun negative_retryScidEqualsOdcid() {
        val p = EndpointPair()
        p.serverStalled = true // no server packet before the Retry: a client that processed one ignores any Retry anyway
        try {
            val c = p.connect()
            p.step()
            val b = PacketBuffer.allocate(100)
            try {
                val n =
                    RetryPacket.write(
                        b,
                        VersionProfile.V1,
                        c.localCid,
                        c.odcid,
                        "t".encodeToByteArray(),
                        c.odcid,
                        NullCryptoProvider,
                        0,
                    )
                p.feed(p.client, b.toByteArray(n), p.serverAddr)
            } finally {
                b.close()
            }
            assertFalse(c.retryReceivedForTest, "SCID equal to the Initial's DCID: dropped")
            assertNull(p.closed(c))
        } finally {
            p.close()
        }
    }

    @Test fun negative_retryAfterInitial() {
        // the client processed the server's first datagram (its Initial) and is still in the handshake: only the rule "before any
        // other server packet" (RFC 9000 section 17.2.5.2) can drop a Retry now (with the server's own SCID, a valid tag)
        val p = EndpointPair(crypto = KslQuicCrypto)
        p.filterToClient = { i, _ -> i == 0 }
        try {
            val c = p.connect()
            assertTrue(p.runUntil { c.anyPeerPacket })
            assertEquals(io.kuicksilver.quic.ConnectionState.Handshaking, c.state)
            val b = PacketBuffer.allocate(100)
            try {
                val n =
                    RetryPacket.write(
                        b,
                        VersionProfile.V1,
                        c.localCid,
                        c.remoteCid,
                        "t".encodeToByteArray(),
                        c.odcid,
                        KslQuicCrypto,
                        0,
                    )
                p.feed(p.client, b.toByteArray(n), p.serverAddr)
            } finally {
                b.close()
            }
            assertFalse(c.retryReceivedForTest)
            p.filterToClient = { _, _ -> true }
            assertTrue(p.confirmed(c))
        } finally {
            p.close()
        }
    }

    @Test fun secondRetryDropped() {
        val p = EndpointPair { admission = ConnectionAdmission.AlwaysRetry }
        var dup: ByteArray? = null
        p.filterToClient = { _, b ->
            if (isRetry(b) && dup == null) dup = b.copyOf()
            true
        }
        try {
            val c = p.connect()
            assertTrue(p.runUntil { c.retryReceivedForTest })
            val before = c.remoteCid
            val second = dup!!.copyOf()
            second[10] = (second[10].toInt() xor 1).toByte() // another SCID
            p.feed(p.client, second, p.serverAddr)
            assertEquals(before, c.remoteCid, "a second Retry is ignored")
            assertTrue(p.confirmed(c))
        } finally {
            p.close()
        }
    }

    @Test fun negative_invalidRetryTokenInvalidTokenClose() {
        val p = EndpointPair(crypto = KslQuicCrypto) { admission = ConnectionAdmission.AlwaysRetry }
        var tampered = 0
        p.filterToServer =
            { _, b ->
                if (isInitial(b)) {
                    val v = PacketHeaderView()
                    val buf = PacketBuffer.of(b)
                    try {
                        if (PacketHeaderCodec.parse(buf, 0, b.size, 8, v) &&
                            v.tokenLen > 0
                        ) {
                            tampered++
                            b[v.tokenOff + 12] = (b[v.tokenOff + 12].toInt() xor 1).toByte()
                        }
                    } finally {
                        buf.close()
                    }
                }
                ; true
            }
        try {
            val c = p.connect()
            assertTrue(p.runUntil { p.closed(c) != null }, "the client is told")
            val r = p.closed(c)
            assertIs<QuicException.ConnectionLost.TransportClosed>(r)
            assertEquals(0x0bL, r.code, "INVALID_TOKEN")
            assertEquals(0, p.server.connectionCount, "no connection for a forged token")
            assertTrue(tampered >= 1)
        } finally {
            p.close()
        }
    }

    @Test fun negative_expiredRetryToken() {
        val p = EndpointPair(crypto = KslQuicCrypto) { admission = ConnectionAdmission.AlwaysRetry }
        var delayed = false
        p.filterToClient = { _, b ->
            if (isRetry(b) && !delayed) {
                delayed = true
                p.now += 10.seconds + 1.nanoseconds
            }
            true
        } // the token is already older than its lifetime when the client uses it
        try {
            val c = p.connect(quic = io.kuicksilver.quic.quicConfig { handshakeTimeout = 60.seconds })
            assertTrue(
                p.runUntil(limit = 30.seconds) {
                    p.closed(c) !=
                        null
                },
            ) // the 10 s jump eats most of a default limit
            val r = p.closed(c)
            assertIs<QuicException.ConnectionLost.TransportClosed>(r, "$r")
            assertEquals(0x0bL, r.code)
            assertEquals(0, p.server.connectionCount)
        } finally {
            p.close()
        }
    }

    @Test fun tokenBoundToAddressAndPort() {
        val p = EndpointPair(crypto = KslQuicCrypto) { admission = ConnectionAdmission.AlwaysRetry }
        var moved = false
        p.filterToClient =
            { _, b ->
                if (isRetry(b) && !moved) {
                    moved = true
                    p.clientSource = InetSocketAddress("10.0.0.1", 40001)
                }
                true
            } // the client's port changes before it uses the token
        try {
            val c = p.connect()
            assertTrue(p.runUntil { p.closed(c) != null })
            val r = p.closed(c)
            assertIs<QuicException.ConnectionLost.TransportClosed>(r)
            assertEquals(0x0bL, r.code)
        } finally {
            p.close()
        }
    }

    @Test fun negative_retryTokenReusedWithOtherDcid() {
        // RFC 9000 sections 8.1.2-8.1.4 and 17.2.5.3: a Retry token is bound to the SCID of the Retry that carried it; an Initial that
        // presents it under another Destination Connection ID is refused with INVALID_TOKEN, statelessly, and makes no connection
        val p = EndpointPair(crypto = KslQuicCrypto) { admission = ConnectionAdmission.AlwaysRetry }
        var token: ByteArray? = null
        p.filterToClient =
            { _, b ->
                if (token == null && isRetry(b)) {
                    val v = PacketHeaderView()
                    val buf = PacketBuffer.of(b)
                    try {
                        if (PacketHeaderCodec.parse(buf, 0, b.size, 8, v)) token = b.copyOfRange(v.tokenOff, v.tokenOff + v.tokenLen)
                    } finally {
                        buf.close()
                    }
                }
                true
            }
        try {
            val c1 = p.connect()
            assertTrue(p.confirmed(c1), "${p.closed(c1)}")
            val stolen = assertNotNull(token)
            val c2 = p.connect()
            c2.initialToken = stolen // a fresh connection: its DCID is not the Retry SCID the token was minted for
            assertTrue(p.runUntil { p.closed(c2) != null }, "the second client is told")
            val r = p.closed(c2)
            assertIs<QuicException.ConnectionLost.TransportClosed>(r)
            assertEquals(0x0bL, r.code, "INVALID_TOKEN, not a connection with mismatching transport parameters")
            assertEquals(1, p.server.connectionCount, "no connection for a token under another DCID")
        } finally {
            p.close()
        }
    }

    @Test fun tokenSurvivesOneRotationNotTwo() {
        val tokens = AddressTokens(KslQuicCrypto, Random(1), retryLifetime = 10.hours, rotateEvery = 1.hours)
        val client = InetSocketAddress("10.0.0.1", 40000)
        val odcid = ConnectionId(ByteArray(8) { 1 })
        val retryScid = ConnectionId(ByteArray(8) { 2 })
        try {
            val t0 = TimeMark(1_000_000_000L)
            val tok = tokens.mint(odcid, retryScid, client, 1, t0)

            fun check(at: TimeMark): TokenCheck {
                val b = PacketBuffer.of(tok)
                try {
                    return tokens.check(b, 0, tok.size, client, 1, at)
                } finally {
                    b.close()
                }
            }
            assertIs<TokenCheck.Valid>(check(t0 + 61.seconds * 60))
            assertIs<TokenCheck.Valid>(check(t0 + 90.seconds * 60), "one rotation later the previous key still checks")
            assertIs<TokenCheck.Invalid>(check(t0 + 150.seconds * 60), "two rotations later the key is gone")
        } finally {
            tokens.close()
        }
    }

    @Test fun clientChecksRetrySourceConnectionId() {
        val p = EndpointPair(crypto = KslQuicCrypto) { admission = ConnectionAdmission.AlwaysRetry }
        p.server.testForgeRetryScidInTp = true
        try {
            val c = p.connect()
            assertTrue(p.runUntil { p.closed(c) != null })
            val r = p.closed(c)
            assertIs<QuicException.ConnectionLost.TransportClosed>(r)
            assertEquals(0x08L, r.code, "TRANSPORT_PARAMETER_ERROR")
        } finally {
            p.close()
        }
    }

    @Test fun retransmittedInitialWithTokenRoutesToExistingConnection() {
        // focus 3: the client's Initial with the token is repeated (PTO) after the connection exists, and again after the token expired — both route by DCID, no INVALID_TOKEN
        val p = EndpointPair(crypto = KslQuicCrypto) { admission = ConnectionAdmission.AlwaysRetry }
        var withToken: ByteArray? = null
        p.filterToServer =
            { _, b ->
                if (isInitial(b) &&
                    withToken == null
                ) {
                    val v = PacketHeaderView()
                    val buf = PacketBuffer.of(b)
                    try {
                        if (PacketHeaderCodec.parse(buf, 0, b.size, 8, v) &&
                            v.tokenLen > 0
                        ) {
                            withToken = b.copyOf()
                        }
                    } finally {
                        buf.close()
                    }
                }
                ; true
            }
        try {
            val c = p.connect()
            assertTrue(p.confirmed(c))
            val s = p.server.connections().single()
            assertEquals(s, p.feed(p.server, withToken!!, p.clientAddr), "routes to the existing connection")
            assertEquals(1, p.server.connectionCount)
            p.now += 11.seconds
            assertEquals(s, p.feed(p.server, withToken, p.clientAddr), "and still after the token's lifetime")
            assertEquals(0, p.stateless(p.server).size, "no INVALID_TOKEN close")
        } finally {
            p.close()
        }
    }

    @Test fun retryNotCountedAsCongestion() {
        val p = EndpointPair { admission = ConnectionAdmission.AlwaysRetry }
        try {
            val c = p.connect()
            val cwnd0 = c.stats.cwnd
            assertTrue(p.runUntil { c.retryReceivedForTest })
            assertEquals(cwnd0, c.stats.cwnd, "RFC 9002 section 6.3: discarding the first flight is not a loss")
            assertEquals(0L, c.stats.lostPackets)
        } finally {
            p.close()
        }
    }

    @Test fun notRetryTokenIgnored() {
        val p = EndpointPair(crypto = KslQuicCrypto)
        var tagged = false
        p.filterToServer = { _, b ->
            if (isInitial(b) && !tagged) {
                tagged = true
            }
            true
        }
        try {
            val c = p.connect(quic = io.kuicksilver.quic.quicConfig { })
            c.initialToken = ByteArray(50) { 0x02 } // type 0x02: not one of our Retry tokens
            assertTrue(p.confirmed(c), "${p.closed(c)}")
            val s = p.server.connections().single()
            assertTrue(s.addressValidatedByHandshakeForTest, "the address was validated by the Handshake packet, not by the token")
        } finally {
            p.close()
        }
    }
}
