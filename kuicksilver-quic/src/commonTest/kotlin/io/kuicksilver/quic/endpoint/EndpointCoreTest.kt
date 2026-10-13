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
import io.kuicksilver.quic.CoreFixtures
import io.kuicksilver.quic.Ecn
import io.kuicksilver.quic.EndpointCore
import io.kuicksilver.quic.NullCryptoProvider
import io.kuicksilver.quic.PacketBatch
import io.kuicksilver.quic.QuicClientConfig
import io.kuicksilver.quic.QuicConfig
import io.kuicksilver.quic.QuicEndpointConfig
import io.kuicksilver.quic.QuicServerConfig
import io.kuicksilver.quic.TimeMark
import io.kuicksilver.quic.VersionProfile
import io.kuicksilver.quic.quicConfig
import io.kuicksilver.tls.QuicCrypto
import kotlin.random.Random
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds

@OptIn(ExperimentalKuicksilverApi::class, DelicateKuicksilverApi::class)
class EndpointCoreTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

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
        // forged Initials (valid header, garbage payload) must not occupy connection or accept-queue slots (threat-model 3.2; K3 final review, Critical 1)
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
}
