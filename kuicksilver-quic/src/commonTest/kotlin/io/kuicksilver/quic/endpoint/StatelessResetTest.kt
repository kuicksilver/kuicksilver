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
import io.kuicksilver.quic.ConnectionCore
import io.kuicksilver.quic.ConnectionEvent
import io.kuicksilver.quic.ConnectionState
import io.kuicksilver.quic.CoreFixtures
import io.kuicksilver.quic.Ecn
import io.kuicksilver.quic.EndpointCore
import io.kuicksilver.quic.NullCryptoProvider
import io.kuicksilver.quic.PacketBatch
import io.kuicksilver.quic.QuicClientConfig
import io.kuicksilver.quic.QuicEndpointConfig
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.QuicServerConfig
import io.kuicksilver.quic.TimeMark
import io.kuicksilver.quic.core.ConnectionIdManager
import io.kuicksilver.quic.core.NoopRegistrar
import io.kuicksilver.quic.wire.ConnectionId
import io.kuicksilver.tls.KslQuicCrypto
import io.kuicksilver.tls.QuicCrypto
import kotlinx.coroutines.runBlocking
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
import kotlin.time.Duration.Companion.milliseconds

/** RFC 9000 section 10.3: stateless reset with keyed tokens, constant-time matching and rate limits (threat-model item 6). */
@OptIn(ExperimentalKuicksilverApi::class, DelicateKuicksilverApi::class)
class StatelessResetTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private val clientAddr = InetSocketAddress("10.0.0.1", 40000)
    private val serverAddr = InetSocketAddress("10.0.0.2", 443)

    /** Two endpoint cores joined in memory under virtual time. */
    private inner class Pair(
        crypto: QuicCrypto = NullCryptoProvider,
        serverSeed: Long = 5,
        loopIndex: Int = 0,
        /** The server's address as the client dials it (and as the server's packets arrive). */
        val serverAddr: InetSocketAddress = this@StatelessResetTest.serverAddr,
    ) {
        var now = TimeMark(1_000_000_000L)
        val server =
            EndpointCore(
                QuicEndpointConfig
                    .Builder()
                    .apply {
                        this.server = QuicServerConfig.Builder(CoreFixtures.server()).build()
                        this.crypto =
                            crypto
                    }.build(),
                Random(serverSeed),
                loopIndex,
            )
        val client = EndpointCore(QuicEndpointConfig.Builder().apply { this.crypto = crypto }.build(), Random(6))
        val events = HashMap<ConnectionCore, MutableList<ConnectionEvent>>()
        val batch = PacketBatch(16)

        fun connect(): ConnectionCore = client.connect(QuicClientConfig.Builder(CoreFixtures.client()).build(), serverAddr, now)

        private fun drain(c: ConnectionCore) {
            val l = events.getOrPut(c) { ArrayList() }
            while (true) {
                val e =
                    c.nextEvent() ?: break
                l += e
                if (e is ConnectionEvent.VerifyRequested) c.resumeVerify(runBlocking { e.session.verifyPeer(e.chain) })
            }
        }

        private fun move(
            from: EndpointCore,
            to: EndpointCore,
            fromAddr: InetSocketAddress,
        ) {
            for (c in from.connections().toList()) {
                batch.clear()
                val n = c.poll(batch, now)
                for (i in 0 until n) {
                    val b = PacketBuffer.of(batch.buffer(i).toByteArray(batch.length(i)))
                    try {
                        to.handleDatagram(b, batch.length(i), fromAddr, Ecn.NotEct, now)
                    } finally {
                        b.close()
                    }
                }
            }
            batch.clear()
            val n = from.pollStateless(batch)
            for (i in 0 until n) {
                val b = PacketBuffer.of(batch.buffer(i).toByteArray(batch.length(i)))
                try {
                    to.handleDatagram(b, batch.length(i), fromAddr, Ecn.NotEct, now)
                } finally {
                    b.close()
                }
            }
            to.processPending(now)
        }

        fun step() {
            now += 10.milliseconds
            for (c in client.connections().toList() + server.connections().toList()) if (c.nextTimeoutOrNever() <= now) c.onTimeout(now)
            move(client, server, clientAddr)
            for (c in server.connections()) drain(c)
            move(server, client, serverAddr)
            for (c in client.connections()) drain(c)
            for (c in server.connections()) drain(c)
        }

        fun handshake(c: ConnectionCore): Boolean {
            repeat(400) {
                step()
                if (c.state == ConnectionState.Confirmed &&
                    server.connections().any { it.state == ConnectionState.Confirmed }
                ) {
                    return true
                }
            }
            return false
        }

        fun closed(c: ConnectionCore): QuicException.ConnectionLost? =
            events[c]?.filterIsInstance<ConnectionEvent.Closed>()?.firstOrNull()?.reason

        fun feed(
            ep: EndpointCore,
            bytes: ByteArray,
            from: InetSocketAddress,
        ): ConnectionCore? {
            val before = ep.connectionCount
            val b = PacketBuffer.of(bytes)
            try {
                ep.handleDatagram(b, bytes.size, from, Ecn.NotEct, now)?.let { return it }
            } finally {
                b.close()
            }
            ep.processPending(now)
            return if (ep.connectionCount >
                before
            ) {
                ep.connections().last()
            } else {
                null
            }
        }

        fun stateless(ep: EndpointCore): List<ByteArray> {
            batch.clear()
            val n = ep.pollStateless(batch)
            return List(n) { batch.buffer(it).toByteArray(batch.length(it)) }
        }

        fun close() {
            batch.close()
            client.close()
            server.close()
        }
    }

    private fun nullToken(cid: ByteArray): ByteArray {
        val out = ByteArray(16)
        val b = PacketBuffer.of(cid)
        try {
            NullCryptoProvider.newResetKey().token(b, 0, cid.size, out, 0)
        } finally {
            b.close()
        }
        return out
    }

    /** A short-header datagram of [size] bytes addressed to [dcid]. */
    private fun shortTo(
        dcid: ByteArray,
        size: Int,
        seed: Int = 1,
    ): ByteArray {
        val r = Random(seed)
        val b = ByteArray(size) { r.nextInt().toByte() }
        b[0] =
            (0x40 or (b[0].toInt() and 0x3f)).toByte()
        dcid.copyInto(b, 1)
        return b
    }

    private fun serverFormatCid(
        routing: Int,
        seed: Int = 1,
    ): ByteArray =
        ByteArray(8) { (it * 17 + seed).toByte() }.also {
            it[0] = 0x01
            it[1] =
                routing.toByte()
        }

    @Test fun serverTransportParametersCarryResetToken() {
        val p = Pair()
        try {
            val c = p.connect()
            assertTrue(p.handshake(c))
            val s = p.server.connections().single()
            assertContentEquals(
                nullToken(s.localCid.toByteArray()),
                c.peerResetTokenForTest(0),
                "stateless_reset_token = ResetKey.token(server SCID)",
            )
        } finally {
            p.close()
        }
    }

    @Test fun newConnectionIdTokensFromResetKey() {
        val p = Pair()
        try {
            val c = p.connect()
            assertTrue(p.handshake(c))
            repeat(20) { p.step() }
            val peers = c.peerCidsForTest()
            assertTrue(peers.size >= 2, "server issued more IDs: ${peers.size}")
            for ((cid, token) in peers) assertContentEquals(nullToken(cid.toByteArray()), token, "token of ${cid.toByteArray().toList()}")
        } finally {
            p.close()
        }
    }

    @Test fun resetSentForUnknownShortHeaderDcid() {
        val p = Pair()
        try {
            val dcid = serverFormatCid(routing = 0)
            assertNull(p.feed(p.server, shortTo(dcid, 100), clientAddr))
            val out = p.stateless(p.server)
            assertEquals(1, out.size)
            val r = out[0]
            assertTrue(r.size in 21..99, "smaller than the trigger, at least 21 bytes: ${r.size}")
            assertEquals(0x40, r[0].toInt() and 0xc0, "fixed bit set, long header bit clear")
            assertContentEquals(nullToken(dcid), r.copyOfRange(r.size - 16, r.size), "the last 16 bytes are the token of the DCID")
        } finally {
            p.close()
        }
    }

    /** Fuzzing finding (endpointRoute, packetRecvServer): a trigger larger than the 1500-byte answer buffer overflowed it. */
    @Test fun negative_resetForJumboDatagramFitsItsBuffer() {
        val p = Pair()
        try {
            val dcid = serverFormatCid(routing = 0)
            for ((i, size) in listOf(1501, 1600, 9000, 65_527).withIndex()) {
                assertNull(p.feed(p.server, shortTo(dcid, size, seed = i), InetSocketAddress("10.0.1.${i + 1}", 7)))
                val out = p.stateless(p.server)
                assertEquals(1, out.size, "a reset for a datagram of $size bytes")
                assertTrue(out[0].size in 21..1500, "the reset fits the answer buffer: ${out[0].size}")
                assertContentEquals(nullToken(dcid), out[0].copyOfRange(out[0].size - 16, out[0].size))
            }
        } finally {
            p.close()
        }
    }

    @Test fun noResetForLongHeader() {
        val p = Pair()
        try {
            val dcid = serverFormatCid(0)
            val b = ByteArray(1300) { 7 }
            b[0] = 0xe0.toByte()
            b[1] = 0
            b[2] = 0
            b[3] = 0
            b[4] = 1
            b[5] =
                8
            dcid.copyInto(b, 6)
            b[14] = 8 // Handshake-type long header
            p.feed(p.server, b, clientAddr)
            assertEquals(0, p.stateless(p.server).size)
        } finally {
            p.close()
        }
    }

    @Test fun noResetForDatagramOf21BytesOrLess() {
        val p = Pair()
        try {
            p.feed(p.server, shortTo(serverFormatCid(0), 21), clientAddr)
            p.feed(p.server, shortTo(serverFormatCid(0), 15), clientAddr)
            assertEquals(0, p.stateless(p.server).size)
        } finally {
            p.close()
        }
    }

    @Test fun resetResponsesRateLimited() {
        val p = Pair()
        try {
            repeat(100) { p.feed(p.server, shortTo(serverFormatCid(0, seed = it), 100, seed = it), clientAddr) }
            assertTrue(p.stateless(p.server).size <= 8, "at most 8 per second per address")
            val other = InetSocketAddress("10.0.0.9", 9)
            p.feed(p.server, shortTo(serverFormatCid(0, 3), 100), other)
            assertEquals(1, p.stateless(p.server).size, "another address has its own budget")
        } finally {
            p.close()
        }
    }

    @Test fun validResetDrainsWithStatelessReset() {
        val p = Pair()
        try {
            val c = p.connect()
            assertTrue(p.handshake(c))
            repeat(5) { p.step() }
            // the server "restarts": a fresh endpoint with the same (deterministic Null) reset key knows nothing about the connection
            val restarted =
                EndpointCore(
                    QuicEndpointConfig
                        .Builder()
                        .apply {
                            server =
                                QuicServerConfig.Builder(CoreFixtures.server()).build()
                            ; crypto = NullCryptoProvider
                        }.build(),
                    Random(99),
                )
            try {
                val id = c.openStream(true)
                c.writeStream(id, ByteArray(100), 0, 100, false)
                p.batch.clear()
                val n = c.poll(p.batch, p.now)
                assertTrue(n >= 1)
                val dg = p.batch.buffer(0).toByteArray(p.batch.length(0))
                assertNull(p.feed(restarted, dg, clientAddr))
                val reset = p.stateless(restarted).single()
                assertNotNull(p.feed(p.client, reset, serverAddr), "the reset is matched to the connection by the peer address and token")
                val r =
                    p.closed(c) ?: run {
                        p.step()
                        p.closed(c)
                    }
                assertIs<QuicException.ConnectionLost.StatelessReset>(r)
                assertEquals(ConnectionState.Draining, c.state)
                p.batch.clear()
                assertEquals(0, c.poll(p.batch, p.now), "draining: no CONNECTION_CLOSE, nothing at all")
            } finally {
                restarted.close()
            }
        } finally {
            p.close()
        }
    }

    @Test fun resetDetectedWhenPeerAddressTextDiffers() {
        // the client dialled "::1"; the reset comes from the same address written out in full: one peer, so the reset is found
        // (Kotlin/Native's InetSocketAddress compares the text, so the reset candidates are keyed by the address bytes)
        val p = Pair(serverAddr = InetSocketAddress("::1", 443))
        try {
            val c = p.connect()
            assertTrue(p.handshake(c))
            repeat(5) { p.step() }
            val restarted =
                EndpointCore(
                    QuicEndpointConfig
                        .Builder()
                        .apply {
                            server = QuicServerConfig.Builder(CoreFixtures.server()).build()
                            crypto = NullCryptoProvider
                        }.build(),
                    Random(99),
                )
            try {
                val id = c.openStream(true)
                c.writeStream(id, ByteArray(100), 0, 100, false)
                p.batch.clear()
                assertTrue(c.poll(p.batch, p.now) >= 1)
                val dg = p.batch.buffer(0).toByteArray(p.batch.length(0))
                assertNull(p.feed(restarted, dg, clientAddr))
                val reset = p.stateless(restarted).single()
                assertNotNull(
                    p.feed(p.client, reset, InetSocketAddress("0:0:0:0:0:0:0:1", 443)),
                    "the reset is matched by the address bytes",
                )
                val r =
                    p.closed(c) ?: run {
                        p.step()
                        p.closed(c)
                    }
                assertIs<QuicException.ConnectionLost.StatelessReset>(r)
            } finally {
                restarted.close()
            }
        } finally {
            p.close()
        }
    }

    @Test fun negative_wrongStatelessResetToken() {
        val p = Pair()
        try {
            val c = p.connect()
            assertTrue(p.handshake(c))
            val bogus = ByteArray(100) { 0x55 }
            bogus[0] = 0x41
            c.localCid.toByteArray().copyInto(bogus, 1) // routes to the client's connection, token is garbage
            p.feed(p.client, bogus, serverAddr)
            assertNull(p.closed(c))
            assertEquals(1L, c.stats.invalidResets)
        } finally {
            p.close()
        }
    }

    @Test fun negative_resetTokenOfRetiredCid() {
        val m =
            ConnectionIdManager(
                localLimit = 4,
                retiredCap = 32,
                cidLength = 8,
                random = Random(1),
                registrar = NoopRegistrar,
                resetKey = null,
            )
        m.adoptInitialPeerCid(ConnectionId(ByteArray(8)))

        fun add(
            seq: Long,
            retire: Long,
            token: Byte,
        ) {
            val b = PacketBuffer.of(ByteArray(8) { seq.toByte() } + ByteArray(16) { token })
            try {
                m.onNewConnectionId(seq, retire, b, 0, 8, 8)
            } finally {
                b.close()
            }
        }
        add(1, 0, 0x11)
        add(2, 2, 0x22) // retire_prior_to = 2 retires sequences 0 and 1
        m.markUsedForTest(1)
        m.markUsedForTest(2)
        val dg1 = PacketBuffer.of(ByteArray(40) { 0x11 })
        val dg2 = PacketBuffer.of(ByteArray(40) { 0x22 })
        try {
            assertFalse(m.matchesPeerToken(dg1, 40), "token of a retired ID never matches")
            assertTrue(m.matchesPeerToken(dg2, 40))
        } finally {
            dg1.close()
            dg2.close()
        }
    }

    @Test fun negative_zeroResetToken() {
        val m =
            ConnectionIdManager(
                localLimit = 4,
                retiredCap = 32,
                cidLength = 8,
                random = Random(1),
                registrar = NoopRegistrar,
                resetKey = null,
            )
        m.adoptInitialPeerCid(ConnectionId(ByteArray(8)))
        m.setPeerResetToken(0, ByteArray(16))
        m.markUsedForTest(0)
        val dg = PacketBuffer.of(ByteArray(40))
        try {
            assertFalse(m.matchesPeerToken(dg, 40), "all-zero token advertised by the peer never matches")
        } finally {
            dg.close()
        }
    }

    @Test fun unusedPeerCidTokenNotChecked() {
        val m =
            ConnectionIdManager(
                localLimit = 4,
                retiredCap = 32,
                cidLength = 8,
                random = Random(1),
                registrar = NoopRegistrar,
                resetKey = null,
            )
        m.adoptInitialPeerCid(ConnectionId(ByteArray(8)))
        m.setPeerResetToken(0, ByteArray(16) { 9 })
        val dg = PacketBuffer.of(ByteArray(40) { 9 })
        try {
            assertFalse(m.matchesPeerToken(dg, 40), "RFC 9000 section 10.3.1: tokens of IDs we never used are not checked")
            m.markUsedForTest(0)
            assertTrue(m.matchesPeerToken(dg, 40))
        } finally {
            dg.close()
        }
    }

    @Test fun negative_resetNotFromOtherLoop() {
        val p = Pair(loopIndex = 1)
        try {
            p.feed(p.server, shortTo(serverFormatCid(routing = 0), 100), clientAddr)
            assertEquals(0, p.stateless(p.server).size, "a DCID of another loop is that loop's business")
        } finally {
            p.close()
        }
    }

    @Test fun negative_resetConstantTime() {
        val token = ByteArray(16) { (it + 1).toByte() }
        val same = PacketBuffer.of(ByteArray(4) + token)
        val first =
            PacketBuffer.of(ByteArray(4) + token.copyOf().also { it[0] = 0 })
        ; val last = PacketBuffer.of(ByteArray(4) + token.copyOf().also { it[15] = 0 })
        try {
            assertTrue(ConstantTime.equals(same, 4, token, 0, 16))
            assertFalse(ConstantTime.equals(first, 4, token, 0, 16))
            assertFalse(ConstantTime.equals(last, 4, token, 0, 16))
        } finally {
            same.close()
            first.close()
            last.close()
        }
    }

    @Test fun tokenNotDerivableFromCidGenerator() {
        val a = Pair(crypto = KslQuicCrypto, serverSeed = 5)
        val b = Pair(crypto = KslQuicCrypto, serverSeed = 5)
        try {
            val dcid = serverFormatCid(0)
            a.feed(a.server, shortTo(dcid, 100), clientAddr)
            b.feed(b.server, shortTo(dcid, 100), clientAddr)
            val ta = a.stateless(a.server).single().takeLast(16)
            val tb = b.stateless(b.server).single().takeLast(16)
            assertFalse(ta == tb, "same CID generator seed, different reset keys: different tokens")
        } finally {
            a.close()
            b.close()
        }
    }
}
