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
import io.kuicksilver.quic.QuicConfig
import io.kuicksilver.quic.QuicEndpointConfig
import io.kuicksilver.quic.QuicLbConfig
import io.kuicksilver.quic.QuicServerConfig
import io.kuicksilver.quic.TimeMark
import io.kuicksilver.quic.VersionProfile
import io.kuicksilver.quic.core.validationTimeout
import io.kuicksilver.quic.quicConfig
import io.kuicksilver.tls.QuicCrypto
import kotlin.random.Random
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

@OptIn(ExperimentalKuicksilverApi::class, DelicateKuicksilverApi::class, kotlin.concurrent.atomics.ExperimentalAtomicApi::class)
class EndpointCoreTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    /** Each test starts with no nonce space of an earlier one (and frees their plaintext keys). */
    @kotlin.test.AfterTest fun forgetNonceSpaces() = QuicLbNonceSpaces.forgetForTest()

    private val now = TimeMark(1_000_000_000L)
    private val a1 = InetSocketAddress("10.0.0.1", 1111)
    private val a2 = InetSocketAddress("10.0.0.2", 2222)

    private fun server(
        quic: QuicConfig = QuicConfig.Default,
        crypto: QuicCrypto = NullCryptoProvider,
        maxConnections: Int = 10_000,
        acceptQueue: Int = 32,
    ): EndpointCore =
        EndpointCore(
            QuicEndpointConfig
                .Builder()
                .apply {
                    this.server =
                        QuicServerConfig.Builder(CoreFixtures.server()).apply { this.quic = quic }.build()
                    ; this.crypto = crypto
                    this.maxConnections =
                        maxConnections
                    this.acceptQueue = acceptQueue
                }.build(),
            Random(5),
        )

    private fun clientEndpoint(crypto: QuicCrypto = NullCryptoProvider) =
        EndpointCore(
            QuicEndpointConfig
                .Builder()
                .apply {
                    this.crypto =
                        crypto
                }.build(),
            Random(6),
        )

    private fun clientConfig(quic: QuicConfig = QuicConfig.Default) =
        QuicClientConfig
            .Builder(CoreFixtures.client())
            .apply {
                this.quic =
                    quic
            }.build()

    /** First datagram of a fresh client core. */
    private fun firstInitial(client: ConnectionCore): ByteArray {
        val b = PacketBatch(4)
        try {
            check(client.poll(b, now) >= 1)
            return b.buffer(0).toByteArray(b.length(0))
        } finally {
            b.close()
        }
    }

    private fun feed(
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

    private fun stateless(ep: EndpointCore): List<ByteArray> {
        val b = PacketBatch(4)
        try {
            val n = ep.pollStateless(b)
            return List(n) { b.buffer(it).toByteArray(b.length(it)) }
        } finally {
            b.close()
        }
    }

    /**
     * RFC 9002 section 6.2.2: the next client connection to a server the endpoint already measured starts from the last smoothed RTT,
     * so its first PTO is about 3 x that RTT instead of 999 ms (interop handshakecorruption against quic-go: probes at 1, 3, 7 s left
     * quic-go's 5 s handshake idle timeout room to drop the half-open connection); another address and a connection without a
     * sample keep the configured value.
     */
    @Test fun nextClientConnectionStartsFromTheLastMeasuredRtt() {
        val cep = clientEndpoint()
        val first = cep.connect(clientConfig(), a2, now)
        assertEquals(333.milliseconds, startRtt(first).smoothed)
        startRtt(first).onSample(40.milliseconds, Duration.ZERO, false, 25.milliseconds)
        cep.remove(first)
        val second = cep.connect(clientConfig(), a2, now)
        assertEquals(40.milliseconds, startRtt(second).smoothed)
        assertTrue(!startRtt(second).hasSample, "a starting value, not a sample")
        val other = cep.connect(clientConfig(), InetSocketAddress("10.0.0.3", 2222), now)
        assertEquals(333.milliseconds, startRtt(other).smoothed)
        cep.remove(second) // no sample of its own: the remembered 40 ms stays
        val third = cep.connect(clientConfig(), a2, now)
        assertEquals(40.milliseconds, startRtt(third).smoothed)
    }

    /**
     * Review finding 9, RFC 9000 section 8.2.4: the validation timeout is three times "the larger of the current PTO or the PTO for the
     * new path (using kInitialRtt ...)". A remembered 4 ms RTT of the first path (a Wi-Fi measurement) used to shrink it to about
     * 24 ms, so a migration to a 150 ms cellular path failed with ValidationTimeout; the memory now only seeds the first path.
     */
    @Test fun rememberedRttDoesNotShrinkPathValidation() {
        val cep = clientEndpoint()
        val first = cep.connect(clientConfig(), a2, now)
        startRtt(first).onSample(4.milliseconds, Duration.ZERO, false, 25.milliseconds)
        cep.remove(first)
        val second = cep.connect(clientConfig(), a2, now)
        assertEquals(4.milliseconds, startRtt(second).smoothed, "the first path still starts from the remembered RTT")
        // the current PTO is about 3 x 4 ms here: the new path's 6 x kInitialRtt decides
        assertEquals(333.milliseconds * 6, second.validationTimeout())
    }

    /** The memory is bounded (256 server addresses, the least recently stored dropped first) and a server endpoint stores nothing. */
    @Test fun negative_rttMemoryBoundedAndClientOnly() {
        val cep = clientEndpoint()
        for (i in 0..256) {
            val c = cep.connect(clientConfig(), InetSocketAddress("10.1.${i / 200}.${i % 200 + 1}", 443), now)
            startRtt(c).onSample(50.milliseconds, Duration.ZERO, false, 25.milliseconds)
            cep.remove(c)
        }
        val oldest = cep.connect(clientConfig(), InetSocketAddress("10.1.0.1", 443), now)
        assertEquals(333.milliseconds, startRtt(oldest).smoothed, "the first address was evicted")
        val newest = cep.connect(clientConfig(), InetSocketAddress("10.1.1.57", 443), now)
        assertEquals(50.milliseconds, startRtt(newest).smoothed)
        val srv = server()
        val s = assertNotNull(feed(srv, firstInitial(cep.connect(clientConfig(), a2, now)), a1))
        startRtt(s).onSample(50.milliseconds, Duration.ZERO, false, 25.milliseconds)
        srv.remove(s)
        val c = srv.connect(clientConfig(), a1, now) // a server endpoint's own client connections do not learn from its server side
        assertEquals(333.milliseconds, startRtt(c).smoothed)
    }

    private fun startRtt(c: ConnectionCore) = c.paths.active.rtt

    @Test fun routesByDcid() {
        val srv = server()
        val cep = clientEndpoint()
        val c1 = cep.connect(clientConfig(), a2, now)
        val c2 = cep.connect(clientConfig(), a2, now)
        val s1 = feed(srv, firstInitial(c1), a1)
        val s2 = feed(srv, firstInitial(c2), InetSocketAddress("10.0.0.3", 3333))
        assertNotNull(s1)
        assertNotNull(s2)
        assertTrue(s1 !== s2)
        assertEquals(2, srv.connectionCount)
        assertEquals(s1, srv.nextAccepted())
        assertEquals(s2, srv.nextAccepted())
        assertNull(srv.nextAccepted())
        // the server's own packets carry its chosen CID: a later client datagram addressed to it routes back to the same core
        val b = PacketBatch(4)
        try {
            s1.poll(b, now)
            val reply = b.buffer(0).toByteArray(b.length(0))
            val replyBuf = PacketBuffer.of(reply)
            try {
                c1.handleDatagram(replyBuf, reply.size, a2, Ecn.NotEct, now)
            } finally {
                replyBuf.close()
            }
        } finally {
            b.close()
        }
        val next = PacketBatch(4)
        try {
            if (c1.poll(next, now) >=
                1
            ) {
                val d = next.buffer(0).toByteArray(next.length(0))
                assertEquals(s1, feed(srv, d, a1))
            }
        } finally {
            next.close()
        }
    }

    /** A (spoofed) Initial from source port 0 would cost the server a reply the kernel refuses (EINVAL); it is dropped regardless of the reflective-port setting. */
    @Test fun initialFromSourcePortZeroDropped() {
        val srv = server()
        val c = clientEndpoint().connect(clientConfig(), a2, now)
        assertNull(feed(srv, firstInitial(c), InetSocketAddress("10.0.0.9", 0)))
        assertEquals(0, srv.connectionCount)
        assertEquals(1L, srv.stats.initialsDropped)
    }

    @Test fun initialDatagramBelow1200Ignored() {
        val srv = server()
        val c = clientEndpoint().connect(clientConfig(), a2, now)
        assertNull(feed(srv, firstInitial(c).copyOf(1100), a1))
        assertEquals(0, srv.connectionCount)
        assertTrue(stateless(srv).isEmpty())
    }

    @Test fun dcidShorterThan8Dropped() {
        val srv = server()
        val c = clientEndpoint().connect(clientConfig(), a2, now)
        val d = firstInitial(c)
        d[5] = 4 // DCID length 4 — our server CIDs are 8 bytes
        assertNull(feed(srv, d, a1))
        assertEquals(0, srv.connectionCount)
    }

    /** A stateless answer leaves from the address the datagram it answers was sent to (RFC 9000 section 9), here Version Negotiation. */
    @Test fun statelessAnswerLeavesFromTheLocalAddress() {
        val srv = server()
        val c = clientEndpoint().connect(clientConfig(), a2, now)
        val d = firstInitial(c)
        for (i in 1..4) d[i] = 0x0a
        val vip = InetSocketAddress("192.0.2.10", 443)
        val buf = PacketBuffer.of(d)
        try {
            assertNull(srv.handleDatagram(buf, d.size, a1, Ecn.NotEct, now, io.kuicksilver.quic.PathId.Initial, vip))
        } finally {
            buf.close()
        }
        val b = PacketBatch(4)
        try {
            assertEquals(1, srv.pollStateless(b))
            assertEquals(a1, b.address(0))
            assertEquals(vip, b.localAddress(0), "Version Negotiation leaves from $vip")
        } finally {
            b.close()
        }
    }

    @Test fun unknownVersionGetsVersionNegotiation() {
        val srv = server()
        val c = clientEndpoint().connect(clientConfig(), a2, now)
        val d = firstInitial(c)
        d[1] = 0x0a
        d[2] = 0x0a
        d[3] =
            0x0a
        d[4] = 0x0a
        assertNull(feed(srv, d, a1))
        val vn = stateless(srv).single()
        assertTrue(vn.size <= d.size)
        assertEquals(
            0x80,
            vn[0].toInt() and 0x80,
        )
        assertEquals(0, vn[1].toInt() or vn[2].toInt() or vn[3].toInt() or vn[4].toInt())
        val dcidLen = d[5].toInt()
        val scidLen = d[6 + dcidLen].toInt()
        assertEquals(scidLen, vn[5].toInt())
        assertEquals(dcidLen, vn[6 + scidLen].toInt()) // CIDs swapped
        val offered =
            vn.copyOfRange(7 + scidLen + dcidLen, vn.size).toList().chunked(4).map {
                (it[0].toInt() and 0xff shl 24) or
                    (it[1].toInt() and 0xff shl 16) or
                    (it[2].toInt() and 0xff shl 8) or
                    (it[3].toInt() and 0xff)
            }
        assertEquals(listOf(1), offered)
        val both = server(quicConfig { this.versions = listOf(VersionProfile.V1, VersionProfile.V2) })
        feed(both, d, a1)
        val vn2 = stateless(both).single()
        assertEquals(
            listOf(1, 0x6b3343cf),
            vn2.copyOfRange(7 + scidLen + dcidLen, vn2.size).toList().chunked(4).map {
                (
                    it[0].toInt() and
                        0xff shl
                        24
                ) or
                    (it[1].toInt() and 0xff shl 16) or
                    (it[2].toInt() and 0xff shl 8) or
                    (it[3].toInt() and 0xff)
            },
        )
    }

    @Test fun v2InitialAcceptedWhenEnabled() {
        val srv = server(quicConfig { versions = listOf(VersionProfile.V2, VersionProfile.V1) })
        val c =
            clientEndpoint().connect(
                clientConfig(
                    quicConfig {
                        versions =
                            listOf(VersionProfile.V2)
                    },
                ),
                a2,
                now,
            )
        ; assertNotNull(feed(srv, firstInitial(c), a1))
    }

    @Test fun v2InitialToV1OnlyServerGetsVersionNegotiation() {
        val srv = server()
        val c =
            clientEndpoint().connect(
                clientConfig(
                    quicConfig {
                        versions =
                            listOf(VersionProfile.V2)
                    },
                ),
                a2,
                now,
            )
        ; assertNull(feed(srv, firstInitial(c), a1))
        assertEquals(1, stateless(srv).size)
    }

    @Test fun noVersionNegotiationForSmallDatagram() {
        val srv = server()
        val c = clientEndpoint().connect(clientConfig(), a2, now)
        val d = firstInitial(c).copyOf(600)
        d[1] =
            0x0a
        assertNull(feed(srv, d, a1))
        assertTrue(stateless(srv).isEmpty())
    }

    @Test fun negative_serverDropsVersionNegotiation() {
        val srv = server()
        val vn =
            byteArrayOf(0x80.toByte(), 0, 0, 0, 0, 8) + ByteArray(8) + byteArrayOf(8) + ByteArray(8) + byteArrayOf(0, 0, 0, 1)
        assertNull(feed(srv, vn, a1))
        assertTrue(stateless(srv).isEmpty())
        assertEquals(0, srv.connectionCount)
    }

    @Test fun shortHeaderUnknownDcidDropped() {
        val srv = server()
        val d = ByteArray(100) { 0x40 }
        assertNull(feed(srv, d, a1))
        assertTrue(stateless(srv).isEmpty())
    }

    @Test fun serverCidFormat() {
        val srv = server()
        val c = clientEndpoint().connect(clientConfig(), a2, now)
        val s = feed(srv, firstInitial(c), a1)!!
        val cid = s.localCid.toByteArray()
        assertEquals(8, cid.size)
        assertEquals(0x01, cid[0].toInt())
        assertEquals(0, cid[1].toInt())
    }

    @Test fun maxConnectionsDropsNewInitials() {
        val srv = server(maxConnections = 1)
        val cep = clientEndpoint()
        assertNotNull(feed(srv, firstInitial(cep.connect(clientConfig(), a2, now)), a1))
        assertNull(feed(srv, firstInitial(cep.connect(clientConfig(), a2, now)), InetSocketAddress("10.0.0.9", 9)))
        assertEquals(1, srv.connectionCount)
        assertTrue(stateless(srv).isEmpty())
    }

    @Test fun acceptQueueCap32() {
        val srv = server(acceptQueue = 2)
        val cep = clientEndpoint()
        repeat(3) {
            feed(
                srv,
                firstInitial(cep.connect(clientConfig(), a2, now)),
                InetSocketAddress(
                    "10.0.0.${it + 1}",
                    1000 + it,
                ),
            )
        }
        assertEquals(2, srv.connectionCount, "the third Initial is refused while the accept queue is full")
        assertNotNull(srv.nextAccepted())
        assertNotNull(srv.nextAccepted())
        assertNull(srv.nextAccepted())
    }

    @Test fun registryEmptyAfterClose() {
        val srv = server()
        val c = clientEndpoint().connect(clientConfig(), a2, now)
        val d = firstInitial(c)
        val s = feed(srv, d, a1)!!
        val cid = s.localCid.toByteArray()
        s.close(0, "", now)
        srv.remove(s)
        assertEquals(0, srv.connectionCount)
        val short = ByteArray(64) { 0x5a }
        short[0] = 0x40
        cid.copyInto(short, 1)
        assertNull(feed(srv, short, a1), "a short-header packet to a removed CID finds no core")
    }

    // ---- final review fix pass ----
    @Test fun undecryptableInitialsLeaveNoConnection() {
        // forged Initials (valid header, garbage payload) must not occupy connection or accept-queue slots (threat-model 3.2; a critical finding of the pre-release review)
        val srv = server()
        val cep = clientEndpoint()
        val good = firstInitial(cep.connect(clientConfig(), a2, now))
        for (k in 0 until 40) {
            val junk = good.copyOf()
            junk[6] = (junk[6].toInt() xor (k + 1)).toByte() // another DCID → a new "connection"
            for (i in 200 until junk.size) junk[i] = (junk[i].toInt() xor 0x5a).toByte() // the payload no longer authenticates
            assertNull(feed(srv, junk, InetSocketAddress("10.0.0.${k + 10}", 4000 + k)))
        }
        assertEquals(0, srv.connectionCount)
        assertNull(srv.nextAccepted())
        assertNotNull(feed(srv, good, a1), "a genuine Initial is still accepted")
        assertEquals(1, srv.connectionCount)
    }

    @Test fun acceptBacklogIsTheApplicationsNotTheLoops() {
        // the accept limit counts connections the application has not taken, as reported by the hook — not every connection ever created
        var backlog = 0
        val srv = server(acceptQueue = 2)
        srv.acceptBacklog = { backlog }
        val cep = clientEndpoint()
        repeat(5) {
            assertNotNull(
                feed(
                    srv,
                    firstInitial(cep.connect(clientConfig(), a2, now)),
                    InetSocketAddress(
                        "10.0.0.${it + 10}",
                        5000 + it,
                    ),
                ),
            )
            ; srv.nextAccepted()
        }
        assertEquals(5, srv.connectionCount)
        backlog = 2
        assertNull(
            feed(srv, firstInitial(cep.connect(clientConfig(), a2, now)), InetSocketAddress("10.0.0.99", 5999)),
            "refused while the application lags",
        )
    }

    @Test fun connectionIdLengthMustMatchTheEndpoint() {
        assertFailsWith<IllegalArgumentException> {
            QuicEndpointConfig
                .Builder()
                .apply {
                    server =
                        QuicServerConfig.Builder(CoreFixtures.server()).apply { quic = quicConfig { connectionIdLength = 12 } }.build()
                }.build()
        }
        val cep = clientEndpoint()
        assertFailsWith<IllegalArgumentException> { cep.connect(clientConfig(quicConfig { connectionIdLength = 4 }), a2, now) }
    }

    @Test fun exceptionInsideOneConnectionClosesOnlyThatConnection() {
        val srv = server()
        val cep = clientEndpoint()
        val c1 = cep.connect(clientConfig(), a2, now)
        val c2 = cep.connect(clientConfig(), a2, now)
        val d1 = firstInitial(c1)
        val s1 = feed(srv, d1, a1)!!
        val s2 = feed(srv, firstInitial(c2), InetSocketAddress("10.0.0.3", 3333))!!
        s1.testInjectFailure = IllegalStateException("boom")
        assertEquals(s1, feed(srv, d1, a1), "the (duplicate) datagram still routes to its connection")
        assertEquals(io.kuicksilver.quic.ConnectionState.Closed, s1.state)
        assertIs<io.kuicksilver.quic.QuicException.ConnectionLost.Internal>(
            generateSequence {
                s1.nextEvent()
            }.filterIsInstance<ConnectionEvent.Closed>().first().reason,
        )
        assertTrue(s2.state != io.kuicksilver.quic.ConnectionState.Closed)
        assertEquals(2, srv.connectionCount)
    }

    // ---- several loops on one port ----
    private fun serverFormatCid(routing: Int): ByteArray =
        ByteArray(8) { (it * 17 + 1).toByte() }.also {
            it[0] = 0x01
            it[1] =
                routing.toByte()
        }

    private fun shortTo(
        dcid: ByteArray,
        size: Int,
    ): ByteArray {
        val r = Random(1)
        val b = ByteArray(size) { r.nextInt().toByte() }
        b[0] =
            (0x40 or (b[0].toInt() and 0x3f)).toByte()
        dcid.copyInto(b, 1)
        return b
    }

    @Test fun ownerLoopFromRoutingByte() {
        val srv = server()

        fun owner(bytes: ByteArray): Int {
            val b = PacketBuffer.of(bytes)
            try {
                return srv.ownerLoop(b, bytes.size)
            } finally {
                b.close()
            }
        }
        assertEquals(5, owner(shortTo(serverFormatCid(5), 100)), "a short header with our CID format names its loop")
        assertEquals(-1, owner(shortTo(ByteArray(8) { 7 }, 100)), "not our format")
        val cep = clientEndpoint()
        assertEquals(
            -1,
            owner(firstInitial(cep.connect(clientConfig(), a2, now))),
            "an Initial is admitted where it lands, never forwarded",
        )
        assertEquals(-1, owner(byteArrayOf(0x40, 1, 2)), "too short to carry a CID")
    }

    /** One loop of a two-loop group (the server config every group has), sans IO. */
    private fun groupLoop(index: Int): EndpointCore =
        EndpointCore(
            QuicEndpointConfig
                .Builder()
                .apply {
                    server = QuicServerConfig.Builder(CoreFixtures.server()).build()
                    crypto = NullCryptoProvider
                    loops = 2
                }.build(),
            Random(10L + index),
            loopIndex = index,
        )

    /** Every datagram [c] has to send now. */
    private fun datagrams(c: ConnectionCore): List<ByteArray> {
        val b = PacketBatch(16)
        try {
            val n = c.poll(b, now)
            return List(n) { b.buffer(it).toByteArray(b.length(it)) }
        } finally {
            b.close()
        }
    }

    private fun owner(
        ep: EndpointCore,
        bytes: ByteArray,
    ): Int {
        val b = PacketBuffer.of(bytes)
        try {
            return ep.ownerLoop(b, bytes.size)
        } finally {
            b.close()
        }
    }

    /**
     * A client connection of a group (`connect` on a multi-loop endpoint) carries its loop's routing byte in its connection
     * IDs, so the server's answers, which the kernel may hash onto another loop's socket, are forwarded to it: the Initial
     * with the ServerHello included (MultiLoopTest.zeroRttTicketsServeEveryLoop timed out in the handshake on Linux when
     * the answer landed on the other loop: a random client CID named no loop and an Initial was never forwarded).
     */
    @Test fun groupClientConnectionAnswersReachItsLoop() {
        val loop0 = groupLoop(0)
        val loop1 = groupLoop(1)
        val peer = server()
        val c = loop0.connect(clientConfig(), a2, now)
        assertEquals(0x01, c.localCid.toByteArray()[0].toInt(), "a group's client CID is in the routing format")
        assertEquals(0, c.localCid.toByteArray()[1].toInt(), "routing byte = the connecting loop")
        val s = assertNotNull(feed(peer, firstInitial(c), a1))
        val answers = datagrams(s)
        assertTrue(answers.isNotEmpty())
        for (d in answers) {
            assertEquals(0, owner(loop1, d), "the other loop names the owner of the server's answer")
            assertNull(feed(loop1, d, a2), "the other loop takes nothing from it")
        }
        assertEquals(0, loop1.connectionCount, "no stranger connection from a server's Initial")
        for (d in answers) assertEquals(c, feed(loop0, d, a2), "the owner takes it")
    }

    /** An Initial whose DCID names another loop of the group goes there whole (its retransmits do too); one naming no loop is admitted where it lands. */
    @Test fun groupInitialRoutedOnlyToALoopThatExists() {
        val loop0 = groupLoop(0)
        val initial = firstInitial(clientEndpoint().connect(clientConfig(), a2, now))

        fun withDcid(routing: Int) =
            initial.copyOf().also {
                it[6] = 0x01
                it[7] = routing.toByte()
            }
        assertEquals(1, owner(loop0, withDcid(1)), "a DCID naming loop 1 belongs to loop 1")
        assertNull(feed(loop0, withDcid(1), a1), "loop 0 admits nothing for loop 1")
        assertEquals(0, loop0.connectionCount)
        assertEquals(-1, owner(loop0, withDcid(0)), "naming this loop: admitted here")
        assertEquals(-1, owner(loop0, withDcid(7)), "naming no loop of the group: admitted here, never dropped")
        assertEquals(-1, owner(server(), withDcid(1)), "a single loop forwards nothing")
    }

    @Test fun cidRoutingByteIsLoopIndex() {
        val srv =
            EndpointCore(
                QuicEndpointConfig
                    .Builder()
                    .apply {
                        server = QuicServerConfig.Builder(CoreFixtures.server()).build()
                        crypto =
                            NullCryptoProvider
                    }.build(),
                Random(3),
                loopIndex = 3,
            )
        val cep = clientEndpoint()
        val s = assertNotNull(feed(srv, firstInitial(cep.connect(clientConfig(), a2, now)), a1))
        assertEquals(0x01, s.localCid.toByteArray()[0].toInt())
        assertEquals(3, s.localCid.toByteArray()[1].toInt(), "routing byte = loop index")
    }

    @Test fun flushVisitsOnlyDirtyConnections() {
        val cep = clientEndpoint()
        val cores = (0 until 1000).map { cep.connect(clientConfig(), InetSocketAddress("10.0.0.2", 2000 + it), now) }
        assertEquals(1000, cep.dirtyConnections.size, "new connections are dirty (their Initial must leave)")
        cep.clearDirty()
        assertEquals(0, cep.dirtyConnections.size)
        val target = cores[500]
        val dg = shortTo(target.localCid.toByteArray(), 60)
        val b = PacketBuffer.of(dg)
        try {
            cep.handleDatagram(b, dg.size, target.remoteAddressForTest, Ecn.NotEct, now)
        } finally {
            b.close()
        }
        assertEquals(listOf(target), cep.dirtyConnections.toList(), "a datagram dirties its connection only")
        cep.markDirty(cores[1])
        assertEquals(2, cep.dirtyConnections.size)
        cep.markDirty(cores[1])
        assertEquals(2, cep.dirtyConnections.size, "idempotent")
    }

    /** Every ID a server issues with NEW_CONNECTION_ID keeps the CID format and the loop's routing byte, else forwarding and stateless reset stop working once the peer rotates. */
    @Test fun issuedConnectionIdsKeepFormatAndRoutingByte() {
        val srv =
            EndpointCore(
                QuicEndpointConfig
                    .Builder()
                    .apply {
                        server = QuicServerConfig.Builder(CoreFixtures.server()).build()
                        crypto =
                            NullCryptoProvider
                    }.build(),
                Random(3),
                loopIndex = 3,
            )
        val cep = clientEndpoint()
        val c = cep.connect(clientConfig(), a2, now)
        var t = now
        val batch = PacketBatch(16)

        fun pump(
            from: EndpointCore,
            to: EndpointCore,
            addr: InetSocketAddress,
        ) {
            for (core in from.connections().toList()) {
                batch.clear()
                val n = core.poll(batch, t)
                for (i in 0 until
                    n) {
                    val bytes = batch.buffer(i).toByteArray(batch.length(i))
                    feed(to, bytes, addr)
                }
            }
        }
        repeat(60) {
            pump(cep, srv, a1)
            pump(srv, cep, a2)
            for (core in cep.connections() + srv.connections()) {
                core.nextTimeout()?.let {
                    if (it <=
                        t
                    ) {
                        core.onTimeout(t)
                    }
                }
                while (core.nextEvent() !=
                    null
                ) {}
            }
            t += 5.milliseconds
            if (c.state == io.kuicksilver.quic.ConnectionState.Confirmed) return@repeat
        }
        batch.close()
        assertEquals(io.kuicksilver.quic.ConnectionState.Confirmed, c.state)
        val s = srv.connections().single()
        val issued =
            (1L..3L).mapNotNull {
                s.cids
                    .localForTest(it)
                    ?.cid
                    ?.toByteArray()
            }
        assertTrue(issued.isNotEmpty(), "ids were issued")
        for (id in issued) {
            assertEquals(0x01, id[0].toInt(), "format byte")
            assertEquals(3, id[1].toInt(), "routing byte = loop index in ${id.toList()}")
        }
    }

    /** An unknown short header is matched against the connections of its source address only, not against every connection. */
    @Test fun unknownShortHeaderChecksOnlyConnectionsOfThatAddress() {
        val cep = clientEndpoint()
        val remotes = listOf(InetSocketAddress("10.0.0.2", 2000), InetSocketAddress("10.0.0.2", 2001), InetSocketAddress("10.0.0.3", 2000))
        for (r in remotes) cep.connect(clientConfig(), r, now)
        val dg = ByteArray(60) { (it * 7).toByte() }
        dg[0] = 0x40

        fun feedFrom(a: InetSocketAddress): Int {
            cep.resetCandidatesExaminedForTest = 0
            val b = PacketBuffer.of(dg)
            try {
                cep.handleDatagram(b, dg.size, a, Ecn.NotEct, now)
            } finally {
                b.close()
            }
            return cep.resetCandidatesExaminedForTest
        }
        assertEquals(0, feedFrom(InetSocketAddress("10.0.0.9", 1)), "a stranger's packet examines no connection")
        assertEquals(1, feedFrom(remotes[2]), "one connection at that address")
        assertEquals(1, feedFrom(remotes[0]))
    }

    /** A deterministic generator that remembers what it handed out, to prove where a value came from. */
    private class RecordingRandom(
        seed: Long,
    ) : Random() {
        private val inner = Random(seed)
        val bytes = ArrayList<ByteArray>()
        val longs = HashSet<Long>()
        var rangedInts = 0

        override fun nextBits(bitCount: Int): Int = inner.nextBits(bitCount)

        override fun nextLong(): Long = inner.nextLong().also { longs += it }

        override fun nextInt(
            from: Int,
            until: Int,
        ): Int = inner.nextInt(from, until).also { rangedInts++ }

        override fun nextBytes(
            array: ByteArray,
            fromIndex: Int,
            toIndex: Int,
        ): ByteArray {
            inner.nextBytes(array, fromIndex, toIndex)
            bytes +=
                array.copyOfRange(fromIndex, toIndex)
            return array
        }

        /** True when [value] (from index [skip] on: the server CID format overwrites its first two bytes) was drawn here. */
        fun drew(
            value: ByteArray,
            skip: Int = 0,
        ): Boolean =
            bytes.any {
                it.size == value.size &&
                    it.copyOfRange(skip, it.size).contentEquals(value.copyOfRange(skip, value.size))
            }
    }

    /** Every random draw of a connection (CIDs, PATH_CHALLENGE data, skipped packet numbers) comes from the endpoint's CSPRNG, not from a child generator with a 64-bit seed an observer can recover. */
    @Test fun connectionRandomnessComesFromTheEndpointSource() {
        val sr = RecordingRandom(5)
        val cr = RecordingRandom(6)
        val p = EndpointPair(serverRandom = sr, clientRandom = cr)
        try {
            val c = p.connect()
            assertTrue(p.confirmed(c))
            repeat(10) { p.step() }
            val s = p.server.connections().single()
            assertTrue(cr.drew(c.odcid.toByteArray()), "client original DCID")
            assertTrue(cr.drew(c.localCid.toByteArray()), "client SCID")
            val clientIds =
                (1L..3L).mapNotNull {
                    c.cids
                        .localForTest(it)
                        ?.cid
                        ?.toByteArray()
                }
            val serverIds =
                (1L..3L).mapNotNull {
                    s.cids
                        .localForTest(it)
                        ?.cid
                        ?.toByteArray()
                }
            assertTrue(clientIds.isNotEmpty() && serverIds.isNotEmpty(), "IDs were issued")
            for (id in clientIds) assertTrue(cr.drew(id), "client NEW_CONNECTION_ID")
            for (id in serverIds) assertTrue(sr.drew(id, skip = 2), "server NEW_CONNECTION_ID")
            assertTrue(
                cr.rangedInts > 0 && sr.rangedInts > 0,
                "the skipped packet numbers are drawn from the endpoint source (client ${cr.rangedInts}, server ${sr.rangedInts})",
            )
            p.clientSource = InetSocketAddress("10.0.0.7", 40000)
            p.clientListens += p.clientSource
            val id = c.openStream(true)
            c.writeStream(id, ByteArray(100), 0, 100, true)
            p.step()
            val challenged = s.paths.all.filter { it.challenge != 0L }
            assertTrue(challenged.isNotEmpty(), "the migration started a validation")
            for (path in challenged) assertTrue(path.challenge in sr.longs, "PATH_CHALLENGE data of $path")
        } finally {
            p.close()
        }
    }

    // ---- preferred_address, server side (RFC 9000 sections 9.6 and 18.2) ----

    private val preferred = io.kuicksilver.quic.PreferredAddress(InetSocketAddress("10.0.0.3", 4433), null)

    @Test fun serverAdvertisesPreferredAddressWithSequenceOneCid() {
        val p = EndpointPair(crypto = io.kuicksilver.tls.KslQuicCrypto, serverPreferred = preferred)
        try {
            val c = p.connect()
            assertTrue(p.confirmed(c), "${p.closed(c)}")
            val s = p.server.connections().single()
            val tp = assertNotNull(c.peerTp)
            assertTrue(tp.preferredAddressPresent)
            assertEquals("10.0.0.3", tp.preferredIpv4!!.hostname)
            assertEquals(4433, tp.preferredIpv4!!.port)
            assertNull(tp.preferredIpv6, "IPv6 not offered: zeros")
            val seq1 = assertNotNull(s.cids.localForTest(1), "the server's sequence 1")
            assertEquals(seq1.cid, tp.preferredAddressCid)
            assertTrue(seq1.token.contentEquals(tp.preferredAddressToken!!), "its reset token")
        } finally {
            p.close()
        }
    }

    /** The client probes the preferred address on its own socket and moves there once validated (what `followPreferredAddress` does by itself). */
    private fun moveClientToPreferred(
        p: EndpointPair,
        c: ConnectionCore,
    ) {
        assertTrue(p.runUntil(5.seconds) { c.cids.hasSparePeerForTest }, "a spare peer ID")
        val id = c.addPath(preferred.ipv4!!, p.now, io.kuicksilver.quic.PathId.Initial)
        c.probePath(id, p.now)
        assertTrue(
            p.runUntil(5.seconds) {
                c.pathState(id) == io.kuicksilver.quic.PathState.Validated
            },
            "the client validated the preferred address",
        )
        c.switchPath(id, p.now)
        val sid = c.openStream(true)
        c.writeStream(sid, ByteArray(100), 0, 100, true) // non-probing packets on the new path
    }

    @Test fun negative_initialOnPreferredSocketIsDropped() {
        // a new connection never starts on the preferred socket, and nothing there answers statelessly (RFC 9000 section 9.6)
        val p = EndpointPair(serverPreferred = preferred)
        try {
            val c = p.connect()
            val b = PacketBatch(4)
            try {
                val n = c.poll(b, p.now)
                assertTrue(n > 0)
                for (i in 0 until n) {
                    val bytes = b.buffer(i).toByteArray(b.length(i))
                    val buf = PacketBuffer.of(bytes)
                    try {
                        p.server.handleDatagram(buf, bytes.size, p.clientAddr, Ecn.NotEct, p.now, io.kuicksilver.quic.PREFERRED_SOCKET)
                    } finally {
                        buf.close()
                    }
                }
            } finally {
                b.close()
            }
            p.server.processPending(p.now)
            assertEquals(0L, p.server.stats.connectionsCreated)
            assertEquals(0, p.stateless(p.server).size, "no stateless answer")
        } finally {
            p.close()
        }
    }

    @Test fun negative_serverSendsNothingNonProbingFromPreferredBeforeValidation() {
        // RFC 9000 section 9.6.1: the server sends non-probing packets from its preferred address only after it validated the
        // client's address there; until then they keep leaving the original socket
        val p = EndpointPair(crypto = io.kuicksilver.tls.KslQuicCrypto, serverPreferred = preferred)
        try {
            val c = p.connect(quicConfig { followPreferredAddress = false }) // moved by hand, step by step
            assertTrue(p.confirmed(c), "${p.closed(c)}")
            val s = p.server.connections().single()
            moveClientToPreferred(p, c)
            var violated = false
            var reason: io.kuicksilver.quic.PathChangeReason? = null
            assertTrue(
                p.runUntil(10.seconds) {
                    val a = s.path
                    if (a.socket == io.kuicksilver.quic.PREFERRED_SOCKET &&
                        a.state != io.kuicksilver.quic.PathState.Validated
                    ) {
                        violated = true
                    }
                    reason =
                        p.events[s]!!
                            .filterIsInstance<ConnectionEvent.PathChanged>()
                            .lastOrNull()
                            ?.reason
                    reason != null
                },
                "the server never moved to its preferred socket",
            )
            assertTrue(!violated, "the active path moved to the preferred socket before its validation")
            assertEquals(io.kuicksilver.quic.PathChangeReason.PreferredAddress, reason)
            assertEquals(io.kuicksilver.quic.PREFERRED_SOCKET, s.path.socket)
            assertEquals(1, s.pathCountForTest, "the original path is closed after the move")
            // from here everything the server sends comes from the preferred address
            val from = p.serverSentFrom.size
            val id = c.openStream(true)
            c.writeStream(id, ByteArray(5000), 0, 5000, true)
            p.runUntil(2.seconds) { false }
            assertTrue(p.serverSentFrom.drop(from).isNotEmpty() && p.serverSentFrom.drop(from).all { it == preferred.ipv4 })
            assertNull(p.closed(c))
        } finally {
            p.close()
        }
    }

    @Test fun preferredMoveAllowedWithAllowMigrationFalse() {
        // the server disabled active migration, yet a move to its preferred address is the client's right (RFC 9000 section 18.2);
        // on the preferred socket only the client's current address is taken, as ngtcp2 does
        val noMigration = quicConfig { allowMigration = false }
        val p = EndpointPair(crypto = io.kuicksilver.tls.KslQuicCrypto, serverPreferred = preferred, serverQuic = noMigration)
        val captured = ArrayList<ByteArray>()
        try {
            val c = p.connect(quicConfig { followPreferredAddress = false })
            assertTrue(p.confirmed(c), "${p.closed(c)}")
            val s = p.server.connections().single()
            p.filterToServer = { _, b ->
                // kept back from the server, so it sees each of them for the first time below (a repeat is a duplicate packet)
                if (b[0].toInt() and 0x80 == 0 && captured.size < 4) {
                    captured += b.copyOf()
                    false
                } else {
                    true
                }
            }
            val id = c.openStream(true)
            c.writeStream(id, ByteArray(6000), 0, 6000, true)
            assertTrue(p.runUntil(2.seconds) { captured.size >= 2 }, "1-RTT datagrams of the client: ${captured.size}")
            p.filterToServer = { _, _ -> true }

            fun feed(
                bytes: ByteArray,
                from: InetSocketAddress,
            ) {
                val b = PacketBuffer.of(bytes)
                try {
                    p.server.handleDatagram(b, bytes.size, from, Ecn.NotEct, p.now, io.kuicksilver.quic.PREFERRED_SOCKET)
                } finally {
                    b.close()
                }
            }
            val paths = s.pathCountForTest
            feed(captured[1], InetSocketAddress("10.0.0.9", 40000))
            assertEquals(paths, s.pathCountForTest, "another IP on the preferred socket: dropped")
            feed(captured[0], p.clientAddr)
            assertEquals(paths + 1, s.pathCountForTest, "the client's own address on the preferred socket: a new path")
        } finally {
            p.close()
        }
    }

    // ---- QUIC-LB server connection IDs (draft-ietf-quic-load-balancers-21) ----

    private fun hexOf(b: ByteArray) = b.joinToString("") { (it.toInt() and 0xff).toString(16).padStart(2, '0') }

    private fun localCids(s: ConnectionCore): List<ByteArray> =
        (0L..40L).mapNotNull {
            s.cids
                .localForTest(it)
                ?.cid
                ?.toByteArray()
        }

    @Test fun quicLbIssuedCidsDecodeToServerId() {
        val cfg = QuicLbFixtures.config(configId = 2)
        val p = LbPair(cfg)
        try {
            val c = p.connect()
            assertTrue(p.handshake(c))
            val s = p.server.connections().single()
            val issued = localCids(s)
            assertTrue(issued.size >= 2, "the handshake ID and NEW_CONNECTION_ID ones: ${issued.size}")
            val more =
                List(100) {
                    p.server.route
                        .newCid(Random(it), client = false)
                        .toByteArray()
                }
            for (cid in issued + more) {
                assertEquals(2, (cid[0].toInt() and 0xff) ushr 5, "config rotation bits: ${hexOf(cid)}")
                assertEquals(7, cid[0].toInt() and 0x1f, "self-encoded length: ${hexOf(cid)}")
                kotlin.test.assertContentEquals(QuicLbFixtures.SID, QuicLbFixtures.decodeSid(cfg, cid), "server ID of ${hexOf(cid)}")
            }
            assertEquals(issued.size + more.size, (issued + more).map { hexOf(it) }.toSet().size, "no ID twice")
            assertTrue(issued.none { hexOf(it).contains("ed793a") }, "the server ID never shows in clear")
        } finally {
            p.close()
        }
    }

    @Test fun quicLbOwnerLoopMatchesIssuingLoop() {
        val cfg = QuicLbFixtures.config()
        val ec = QuicLbFixtures.endpointConfig(cfg, loops = 4)
        val state = QuicLbState(LbNullCrypto, Random(1), cfg, 4, 8)
        val cores = List(4) { EndpointCore(ec, Random(10L + it), it, null, state) }
        try {
            for ((i, core) in cores.withIndex()) {
                val r = Random(100 + i)
                repeat(1000) {
                    val cid = core.route.newCid(r, client = it % 10 == 0).toByteArray()
                    for (other in cores) assertEquals(i, QuicLbFixtures.owner(other, QuicLbFixtures.shortTo(cid)), "owner of ${hexOf(cid)}")
                }
            }
            assertEquals(
                0L,
                cores.sumOf { it.stats.loadBalancerNoncesWasted },
                "IDs drawn for another loop wait for it: no nonce spent unused",
            )
            assertEquals(-1, QuicLbFixtures.owner(cores[0], QuicLbFixtures.shortTo(ByteArray(8) { 0x55 })), "not our format")
        } finally {
            for (c in cores) c.close()
            state.close()
        }
    }

    @Test fun quicLbRotationKeepsOldConnectionsRouting() {
        val p = LbPair(QuicLbFixtures.config(configId = 2))
        try {
            val c = p.connect()
            assertTrue(p.handshake(c))
            val s = p.server.connections().single()
            val old = localCids(s)
            p.server.updateLoadBalancer(QuicLbFixtures.config(configId = 3))
            for (cid in old) assertEquals(s, p.feed(p.server, QuicLbFixtures.shortTo(cid)), "an old ID still routes to its connection")
            val fresh =
                p.server.route
                    .newCid(Random(1), client = false)
                    .toByteArray()
            assertEquals(3, (fresh[0].toInt() and 0xff) ushr 5, "new IDs use the new configuration")
            assertEquals(0, QuicLbFixtures.owner(p.server, QuicLbFixtures.shortTo(old[0])), "the previous configuration still has an owner")
            repeat(30) { p.step() }
            assertEquals(ConnectionState.Confirmed, c.state, "the connection lives on")
            val live = localCids(s)
            assertTrue(
                live.isNotEmpty() &&
                    live.all {
                        (it[0].toInt() and 0xff) ushr 5 == 3
                    },
                "only new-configuration IDs remain: ${live.map { hexOf(it) }}",
            )
            val peer = assertNotNull(c.cids.currentPeer).cid.toByteArray()
            assertEquals(3, (peer[0].toInt() and 0xff) ushr 5, "the client moved to an ID of the new configuration")
            assertTrue(c.openStream(bidi = true) >= 0, "and can still open streams")
        } finally {
            p.close()
        }
    }

    @Test fun quicLbExhaustionGoesUnroutable() {
        val p = LbPair(QuicLbFixtures.config(keyHex = "0f0e0d0c0b0a09080706050403020101")) // a nonce space of its own
        try {
            assertNotNull(p.server.lb)
                .routes.current!!
                .space
                .spendForTest()
            val cid =
                p.server.route
                    .newCid(Random(1), client = false)
                    .toByteArray()
            assertEquals(7, (cid[0].toInt() and 0xff) ushr 5, "unroutable codepoint once the nonces are spent")
            assertEquals(7, cid[0].toInt() and 0x1f, "and it self-encodes its length")
            val c = p.connect()
            assertTrue(p.handshake(c))
            val s = p.server.connections().single()
            assertEquals(7, (s.localCid[0].toInt() and 0xff) ushr 5)
            assertEquals(1, localCids(s).size, "one ID over the life of the connection")
            assertEquals(true, c.peerTp?.disableActiveMigration, "disable_active_migration")
            assertEquals(1L, p.server.stats.loadBalancerNoncesExhausted, "counted once")
        } finally {
            p.close()
        }
    }

    /** Spent nonces under a connection that has its full set: its IDs stay, and no unroutable one goes out in NEW_CONNECTION_ID. */
    @Test fun quicLbExhaustionAfterHandshakeStopsIssuing() {
        val p = LbPair(QuicLbFixtures.config(keyHex = "0f0e0d0c0b0a09080706050403020102"))
        try {
            val c = p.connect()
            assertTrue(p.handshake(c))
            val s = p.server.connections().single()
            assertTrue(localCids(s).size >= 2)
            p.server.lb!!
                .routes.current!!
                .space
                .spendForTest()
            assertTrue(c.cids.rotatePeerCid(), "the client retires the ID it used")
            repeat(20) { p.step() }
            assertTrue(s.retiredByPeer >= 1, "the server saw the retirement")
            val live = localCids(s)
            assertTrue(live.none { (it[0].toInt() and 0xff) ushr 5 == 7 }, "no unroutable ID handed out: ${live.map { hexOf(it) }}")
            assertTrue(s.cids.singleCid, "the connection stopped issuing")
            assertEquals(ConnectionState.Confirmed, c.state)
        } finally {
            p.close()
        }
    }

    /** RFC 9000 section 5.1.2: a second change waits until the peer retired what the first one asked for. */
    @Test fun quicLbBackToBackUpdatesWaitForRetirements() {
        val p = LbPair(QuicLbFixtures.config(configId = 2))
        try {
            val c = p.connect()
            assertTrue(p.handshake(c))
            val s = p.server.connections().single()
            p.server.updateLoadBalancer(QuicLbFixtures.config(configId = 3))
            p.server.updateLoadBalancer(QuicLbFixtures.config(configId = 4))
            assertTrue(s.cids.reissuePendingForTest, "the second change waits")
            assertEquals(1, localCids(s).count { (it[0].toInt() and 0xff) ushr 5 == 3 }, "one ID of the first change so far")
            repeat(40) { p.step() }
            assertFalse(s.cids.reissuePendingForTest, "sent once the client retired the earlier IDs")
            val live = localCids(s)
            assertTrue(live.isNotEmpty() && live.all { (it[0].toInt() and 0xff) ushr 5 == 4 }, live.map { hexOf(it) }.toString())
            assertEquals(ConnectionState.Confirmed, c.state)
        } finally {
            p.close()
        }
    }

    /** An ID two configurations back, still in use, is forwarded to its owner whatever its codepoint. */
    @Test fun quicLbOwnerOfAnOlderConfigurationsId() {
        val a = QuicLbFixtures.config(configId = 1)
        val ec = QuicLbFixtures.endpointConfig(a, loops = 2)
        val state = QuicLbState(LbNullCrypto, Random(1), a, 2, 8)
        val loop0 = EndpointCore(ec, Random(10), 0, null, state)
        val loop1 = EndpointCore(ec, Random(11), 1, null, state)
        try {
            val cid = loop1.route.newCid(Random(1), client = false).toByteArray()
            state.update(QuicLbFixtures.config(configId = 2))
            state.update(QuicLbFixtures.config(configId = 3))
            assertEquals(1, QuicLbFixtures.owner(loop0, QuicLbFixtures.shortTo(cid)), "forwarded to loop 1")
        } finally {
            loop0.close()
            loop1.close()
            state.close()
        }
    }

    @Test fun negative_quicLbGroupCoresWithoutSharedState() {
        assertFailsWith<IllegalArgumentException> {
            EndpointCore(QuicLbFixtures.endpointConfig(QuicLbFixtures.config(), loops = 2), Random(1), 0)
        }
    }

    @Test fun quicLbPlaintextHandsOutOneCid() {
        val p = LbPair(QuicLbFixtures.config(plaintext = true))
        try {
            val c = p.connect()
            assertTrue(p.handshake(c))
            val s = p.server.connections().single()
            assertEquals(1, localCids(s).size, "no NEW_CONNECTION_ID for plaintext IDs")
            kotlin.test.assertNotEquals(true, c.peerTp?.disableActiveMigration)
            // an encrypted configuration (another server ID: section 9.7) brings the full set back
            p.server.updateLoadBalancer(QuicLbFixtures.config(configId = 4, sid = byteArrayOf(1, 2, 3)))
            repeat(30) { p.step() }
            val live = localCids(s)
            assertTrue(live.size >= 2 && live.all { (it[0].toInt() and 0xff) ushr 5 == 4 }, live.map { hexOf(it) }.toString())
        } finally {
            p.close()
        }
    }

    @Test fun quicLbUnroutableUpdateStopsIssuing() {
        val p = LbPair(QuicLbFixtures.config())
        try {
            val c = p.connect()
            assertTrue(p.handshake(c))
            val s = p.server.connections().single()
            val before = localCids(s)
            p.server.updateLoadBalancer(null)
            val cid =
                p.server.route
                    .newCid(Random(1), client = false)
                    .toByteArray()
            assertEquals(7, (cid[0].toInt() and 0xff) ushr 5)
            repeat(10) { p.step() }
            assertEquals(before.map { hexOf(it) }, localCids(s).map { hexOf(it) }, "live connections keep their IDs")
            assertEquals(s, p.feed(p.server, QuicLbFixtures.shortTo(before[0])))
        } finally {
            p.close()
        }
    }

    @Test fun negative_lengthMismatchWithEndpointRejected() {
        fun build(
            lb: QuicLbConfig,
            cidLength: Int = 8,
            server: Boolean = true,
        ) = QuicEndpointConfig
            .Builder()
            .apply {
                if (server) {
                    this.server =
                        QuicServerConfig
                            .Builder(CoreFixtures.server())
                            .apply { quic = quicConfig { connectionIdLength = cidLength } }
                            .build()
                }
                connectionIdLength = cidLength
                loadBalancer = lb
            }.build()
        assertFailsWith<IllegalArgumentException> { build(QuicLbConfig(0, ByteArray(3), 5, null, QuicLbFixtures.plainReservation)) }
        assertFailsWith<IllegalArgumentException> {
            build(
                QuicLbConfig(0, ByteArray(1), 4, null, QuicLbFixtures.plainReservation),
                cidLength = 6,
            )
        }
        assertFailsWith<IllegalArgumentException> { build(QuicLbFixtures.config(), server = false) }
        build(QuicLbFixtures.config())
    }

    @Test fun negative_updateLoadBalancerRefused() {
        val plain = server()
        val p = LbPair(QuicLbFixtures.config(plaintext = true))
        try {
            assertFailsWith<IllegalStateException> { plain.updateLoadBalancer(QuicLbFixtures.config()) }
            assertFailsWith<IllegalArgumentException>("a server ID in clear must not be used encrypted") {
                p.server.updateLoadBalancer(QuicLbFixtures.config(configId = 3))
            }
            assertFailsWith<IllegalArgumentException>("another length") {
                p.server.updateLoadBalancer(QuicLbConfig(3, byteArrayOf(9), 7, null, QuicLbFixtures.plainReservation))
            }
            val q = LbPair(QuicLbFixtures.config(configId = 2))
            try {
                assertFailsWith<IllegalArgumentException>("the codepoint in use with another key") {
                    q.server.updateLoadBalancer(QuicLbFixtures.config(configId = 2, keyHex = "0f0e0d0c0b0a09080706050403020103"))
                }
                q.server.updateLoadBalancer(QuicLbFixtures.config(configId = 2)) // the same configuration again: nothing changes
            } finally {
                q.close()
            }
        } finally {
            plain.close()
            p.close()
        }
    }

    /** A caller that closes a rotated-out key cannot hurt the endpoint: it decrypts with its own copy. */
    @Test fun quicLbOldKeyClosedByTheCallerKeepsTheEndpointAlive() {
        val old =
            io.kuicksilver.tls.KslQuicCrypto
                .newLoadBalancerKey(QuicLbFixtures.hex("0f0e0d0c0b0a09080706050403020104"))
        val oldConfig = QuicLbConfig(2, QuicLbFixtures.SID, 4, old)
        val p = LbPair(oldConfig)
        try {
            val oldCid = QuicLbFixtures.cidOf(oldConfig, byteArrayOf(9, 9, 9, 9))
            val stranger = QuicLbFixtures.cidOf(QuicLbConfig(2, byteArrayOf(1, 1, 1), 4, old), byteArrayOf(9, 9, 9, 9))
            p.server.updateLoadBalancer(QuicLbFixtures.config(configId = 3))
            old.close()
            assertNull(p.feed(p.server, QuicLbFixtures.shortTo(stranger)), "another server ID under the old codepoint")
            assertEquals(0, p.stateless(), "no reset for a stranger")
            assertNull(p.feed(p.server, QuicLbFixtures.shortTo(oldCid)))
            assertEquals(1, p.stateless(), "the previous configuration is still recognised, with the endpoint's own key copy")
            val c = p.connect()
            assertTrue(p.handshake(c), "the endpoint is alive")
        } finally {
            p.close()
        }
    }

    /** Section 9: a connection that had the full set never hands out more than the one plaintext ID of the change. */
    @Test fun quicLbAtMostOnePlaintextIdPerChange() {
        val p = LbPair(QuicLbFixtures.config(configId = 2))
        try {
            val c = p.connect()
            assertTrue(p.handshake(c))
            val s = p.server.connections().single()
            val plaintext = HashSet<String>()

            fun record() = localCids(s).filter { (it[0].toInt() and 0xff) ushr 5 == 4 }.forEach { plaintext += hexOf(it) }
            p.server.updateLoadBalancer(QuicLbFixtures.config(configId = 3))
            p.server.updateLoadBalancer(QuicLbFixtures.config(configId = 4, sid = byteArrayOf(7, 7, 7), plaintext = true))
            assertTrue(c.cids.rotatePeerCid(), "the client retires one ID while the plaintext change waits")
            repeat(40) {
                p.step()
                record()
            }
            assertEquals(1, plaintext.size, "one plaintext ID: $plaintext")
            assertTrue(s.cids.singleCid)
            assertEquals(ConnectionState.Confirmed, c.state)
        } finally {
            p.close()
        }
    }

    /**
     * After a Retry the connection keeps the Retry's SCID as its one server ID (draft sections 3.2 and 9: one ID, plaintext
     * only for the server's Initial), for a plaintext configuration and for an unroutable endpoint.
     */
    @Test fun quicLbRetriedConnectionKeepsTheRetryScid() {
        for (unroutable in listOf(false, true)) {
            val config =
                if (unroutable) {
                    QuicLbFixtures.config(
                        configId = 2,
                    )
                } else {
                    QuicLbFixtures.config(configId = 2, sid = byteArrayOf(5, 5, 5), plaintext = true)
                }
            val p = LbPair(config, admission = io.kuicksilver.quic.ConnectionAdmission.AlwaysRetry)
            try {
                if (unroutable) p.server.updateLoadBalancer(null)
                val c = p.connect()
                assertTrue(p.handshake(c), "unroutable=$unroutable")
                assertEquals(1L, p.server.stats.retriesSent)
                val s = p.server.connections().single()
                assertEquals(assertNotNull(c.retryScid), s.localCid, "the Retry SCID is the connection's ID")
                assertEquals(
                    listOf(s.localCid),
                    localCids(s).map {
                        io.kuicksilver.quic.wire
                            .ConnectionId(it)
                    },
                    "one server ID",
                )
                assertEquals(listOf(0L), c.cids.peerSeqsForTest(), "the client knows one server ID")
                assertEquals(if (unroutable) 7 else 2, (s.localCid[0].toInt() and 0xff) ushr 5)
                assertEquals(unroutable, c.peerTp?.disableActiveMigration == true)
            } finally {
                p.close()
            }
        }
    }

    /**
     * A flood of Retries on one loop of four takes no owner exception (a client that never returns would never release it);
     * ordinary IDs past full pools do, bounded, and drain as the IDs leave.
     */
    @Test fun quicLbOwnerExceptionsStayBoundedAndDrain() {
        val cfg = QuicLbFixtures.config(keyHex = "0f0e0d0c0b0a09080706050403020106")
        val ec = QuicLbFixtures.endpointConfig(cfg, loops = 4, admission = io.kuicksilver.quic.ConnectionAdmission.AlwaysRetry)
        val state = QuicLbState(LbNullCrypto, Random(1), cfg, 4, 8, poolSize = 2, maxExceptions = 8)
        val cores = List(4) { EndpointCore(ec, Random(10L + it), it, null, state) }
        val client = EndpointCore(QuicEndpointConfig.Builder().apply { crypto = NullCryptoProvider }.build(), Random(6))
        try {
            repeat(120) {
                val from = InetSocketAddress("10.1.${it / 200}.${it % 200 + 1}", 4000 + it)
                val b = PacketBuffer.of(firstInitial(client.connect(clientConfig(), a1, now)))
                try {
                    cores[0].handleDatagram(b, b.capacity, from, Ecn.NotEct, now)
                } finally {
                    b.close()
                }
                cores[0].processPending(now)
            }
            // a few client DCIDs hash to another loop (1 in 32 encode our length): the group forwards those, the rest get a Retry here
            assertTrue(cores[0].stats.retriesSent > 100, "${cores[0].stats.retriesSent} Retries")
            assertEquals(0, state.exceptions.size, "Retry SCIDs never take an owner exception")
            val r = Random(3)
            val ids = List(200) { cores[0].route.newCid(r, client = false) }
            assertTrue(state.exceptions.size in 1..8, "bounded: ${state.exceptions.size}")
            for (id in ids) cores[0].route.release(id)
            assertEquals(0, state.exceptions.size, "released with their IDs")
        } finally {
            client.close()
            for (c in cores) c.close()
            state.close()
        }
    }

    private class FlakyReservation : io.kuicksilver.quic.QuicLbNonceReservation {
        var mark = 0L
        var fail = false
        var tries = 0

        override fun load(): Long = mark

        override fun store(mark: Long) {
            tries++
            if (fail) throw kotlinx.io.IOException("disk full")
            this.mark = mark
        }

        override fun secret(): ByteArray = ByteArray(16)
    }

    /** A configuration change that met a failed reservation store goes out once the store works again. */
    @Test fun quicLbPendingChangeRetriedAfterAStoreOutage() {
        val reservation = FlakyReservation()
        val key = QuicLbFixtures.key("0f0e0d0c0b0a09080706050403020107")
        val p = LbPair(QuicLbConfig(2, QuicLbFixtures.SID, 4, key, reservation))
        try {
            val c = p.connect()
            assertTrue(p.handshake(c))
            val s = p.server.connections().single()
            reservation.fail = true
            p.server.lb!!
                .routes.current!!
                .space
                .useUpReservationForTest()
            p.server.updateLoadBalancer(QuicLbConfig(3, QuicLbFixtures.SID, 4, key, reservation))
            assertTrue(s.cids.reissuePendingForTest, "the change waits for a nonce")
            assertTrue(p.server.stats.loadBalancerReservationFailures >= 1)
            assertEquals(0L, p.server.stats.loadBalancerNoncesExhausted, "not exhaustion")
            reservation.fail = false
            repeat(120) { p.step() }
            assertFalse(s.cids.reissuePendingForTest, "sent after the back-off")
            val live = localCids(s)
            assertTrue(live.isNotEmpty() && live.all { (it[0].toInt() and 0xff) ushr 5 == 3 }, live.map { hexOf(it) }.toString())
            assertEquals(ConnectionState.Confirmed, c.state)
        } finally {
            p.close()
        }
    }

    /** A loop that issues far more IDs than the others: their pools fill, then the IDs carry an owner exception; none is wasted. */
    @Test fun quicLbSkewedIssuanceWastesNoNonce() {
        val cfg = QuicLbFixtures.config(keyHex = "0f0e0d0c0b0a09080706050403020105")
        val ec = QuicLbFixtures.endpointConfig(cfg, loops = 4)
        val state = QuicLbState(LbNullCrypto, Random(1), cfg, 4, 8)
        val cores = List(4) { EndpointCore(ec, Random(10L + it), it, null, state) }
        try {
            val r = Random(7)
            val ids = List(6000) { cores[0].route.newCid(r, client = false).toByteArray() }
            assertEquals(0L, cores[0].stats.loadBalancerNoncesWasted)
            for (cid in ids.takeLast(
                200,
            )) {
                assertEquals(0, QuicLbFixtures.owner(cores[2], QuicLbFixtures.shortTo(cid)), "the exception names loop 0")
            }
        } finally {
            for (c in cores) c.close()
            state.close()
        }
    }

    /**
     * Section 3.1: a Retry's SCID of the previous configuration, adopted after the change moved the connections, moves too:
     * one NEW_CONNECTION_ID of the new configuration whose Retire Prior To retires the Retry SCID.
     */
    @Test fun quicLbRetryScidOfThePreviousConfigurationIsRetired() {
        val p = LbPair(QuicLbFixtures.config(configId = 2), admission = io.kuicksilver.quic.ConnectionAdmission.AlwaysRetry)
        try {
            val c = p.connect()
            p.step() // the client's Initial, and the server's Retry back to it
            assertEquals(1L, p.server.stats.retriesSent)
            p.server.updateLoadBalancer(QuicLbFixtures.config(configId = 3))
            assertTrue(p.handshake(c))
            val s = p.server.connections().single()
            assertEquals(assertNotNull(c.retryScid), s.localCid, "the Retry SCID was adopted")
            assertEquals(2, (s.localCid[0].toInt() and 0xff) ushr 5)
            val reissue = assertNotNull(s.cids.localForTest(1) ?: s.cids.localForTest(2))
            assertEquals(3, (reissue.cid[0].toInt() and 0xff) ushr 5, "the change's ID is of the new configuration")
            assertEquals(reissue.seq, reissue.retirePriorTo, "and retires every earlier one, the Retry SCID included")
            repeat(20) { p.step() }
            assertNull(s.cids.localForTest(0), "the client retired the Retry SCID")
            assertTrue(localCids(s).all { (it[0].toInt() and 0xff) ushr 5 == 3 })
        } finally {
            p.close()
        }
    }

    /** A Retry SCID made unroutable only because no nonce was reserved then gets a routable ID once nonces are reserved. */
    @Test fun quicLbTemporaryUnroutableRetryScidIsReplaced() {
        val reservation = FlakyReservation()
        val key = QuicLbFixtures.key("0f0e0d0c0b0a09080706050403020108")
        val p =
            LbPair(
                QuicLbConfig(2, QuicLbFixtures.SID, 4, key, reservation),
                admission = io.kuicksilver.quic.ConnectionAdmission.AlwaysRetry,
            )
        try {
            reservation.fail = true
            p.server.lb!!
                .routes.current!!
                .space
                .useUpReservationForTest()
            val c = p.connect()
            p.step()
            assertEquals(7, (assertNotNull(c.retryScid)[0].toInt() and 0xff) ushr 5, "an unroutable Retry SCID")
            reservation.fail = false
            repeat(16) {
                p.server.lb
                    .routes.current!!
                    .space
                    .tick()
            } // the back-off passes: the store is made
            assertTrue(p.server.route.canIssueRoutable())
            assertTrue(p.handshake(c))
            val s = p.server.connections().single()
            assertEquals(2, (s.localCid[0].toInt() and 0xff) ushr 5, "a routable ID instead")
            assertFalse(s.unroutableCid)
            assertFalse(s.cids.singleCid)
        } finally {
            p.close()
        }
    }

    /**
     * A store outage with many connections waiting for a change: nothing is drawn while nothing is reserved, and the store is
     * tried at most once a receive batch.
     */
    @Test fun quicLbStoreOutageDrawsNothing() {
        val reservation = FlakyReservation()
        val key = QuicLbFixtures.key("0f0e0d0c0b0a09080706050403020109")
        val p = LbPair(QuicLbConfig(2, QuicLbFixtures.SID, 4, key, reservation))
        try {
            val clients = List(5) { p.connect() }
            for (c in clients) assertTrue(p.handshake(c))
            val space =
                p.server.lb!!
                    .routes.current!!
                    .space
            reservation.fail = true
            space.useUpReservationForTest()
            p.server.updateLoadBalancer(QuicLbConfig(3, QuicLbFixtures.SID, 4, key, reservation))
            val drawn = space.drawnForTest
            val tries = reservation.tries
            val batches = 50
            repeat(batches) { p.step() }
            assertEquals(drawn, space.drawnForTest, "nothing drawn during the outage")
            assertTrue(reservation.tries - tries <= batches, "at most one store a batch: ${reservation.tries - tries}")
            assertTrue(p.server.connections().all { it.cids.reissuePendingForTest })
        } finally {
            p.close()
        }
    }

    /** The owner exceptions are full: a new ID that hashes elsewhere is spent unused; every live exception keeps routing. */
    @Test fun quicLbFullOwnerExceptionsNeverDropALiveOne() {
        val cfg = QuicLbFixtures.config(keyHex = "0f0e0d0c0b0a0908070605040302010a")
        val ec = QuicLbFixtures.endpointConfig(cfg, loops = 4)
        val state = QuicLbState(LbNullCrypto, Random(1), cfg, 4, 8, poolSize = 1, maxExceptions = 4)
        val cores = List(4) { EndpointCore(ec, Random(10L + it), it, null, state) }
        try {
            val r = Random(5)
            val ids = List(100) { cores[0].route.newCid(r, client = false).toByteArray() }
            assertEquals(4, state.exceptions.size, "full")
            assertTrue(cores[0].stats.loadBalancerNoncesWasted > 0, "refused, spent unused")
            for (cid in ids) {
                assertEquals(
                    0,
                    QuicLbFixtures.owner(cores[2], QuicLbFixtures.shortTo(cid)),
                    "every issued ID still reaches loop 0",
                )
            }
        } finally {
            for (c in cores) c.close()
            state.close()
        }
    }

    /**
     * Section 3.2: an unroutable Retry SCID whose replacement would be unroutable again (the reservation ran out between the
     * two looks) stays the connection's one server ID: initial_source_connection_id == retry_source_connection_id.
     */
    @Test fun quicLbUnroutableRetryScidStaysWhenNoncesRunOutAgain() {
        val reservation = FlakyReservation()
        val key = QuicLbFixtures.key("0f0e0d0c0b0a0908070605040302010b")
        val p =
            LbPair(
                QuicLbConfig(2, QuicLbFixtures.SID, 4, key, reservation),
                admission = io.kuicksilver.quic.ConnectionAdmission.AlwaysRetry,
            )
        try {
            val space =
                p.server.lb!!
                    .routes.current!!
                    .space
            reservation.fail = true
            space.useUpReservationForTest()
            val c = p.connect()
            p.step()
            val retryScid = assertNotNull(c.retryScid)
            assertEquals(7, (retryScid[0].toInt() and 0xff) ushr 5)
            reservation.fail = false
            p.server.testBetweenRetryChecks = {
                reservation.fail = true
                space.useUpReservationForTest()
                p.server.testBetweenRetryChecks = null
            }
            p.step()
            reservation.fail = false
            assertTrue(p.handshake(c))
            val s = p.server.connections().single()
            assertEquals(retryScid, s.localCid, "the Retry SCID stays")
            assertEquals(c.peerTp?.retrySourceConnectionId, c.peerTp?.initialSourceConnectionId, "one server ID")
        } finally {
            p.close()
        }
    }

    /** A change prepared with an entry another change retired meanwhile is refused as stale; preparing again works. */
    @Test fun quicLbStalePreparedConfigurationIsRefused() {
        val a = QuicLbFixtures.config(configId = 1)
        val state = QuicLbState(LbNullCrypto, Random(1), a, 1, 8)
        try {
            state.update(QuicLbFixtures.config(configId = 2))
            val reusing = state.prepare(a) // the previous configuration's entry
            state.update(QuicLbFixtures.config(configId = 3)) // retires it
            assertFailsWith<QuicLbState.StaleConfiguration> { state.commit(reusing) }
            assertTrue(state.update(a))
            val cid = QuicLbRoute(state, 0).newCid(Random(2), client = false)
            assertEquals(1, (cid[0].toInt() and 0xff) ushr 5, "issues under the configuration prepared again")
        } finally {
            state.close()
        }
    }
}
