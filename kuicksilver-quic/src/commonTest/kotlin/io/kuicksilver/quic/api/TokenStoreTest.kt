// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.api

import io.ktor.network.sockets.InetSocketAddress
import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.KslLoader
import io.kuicksilver.native.PacketBuffer
import io.kuicksilver.native.of
import io.kuicksilver.quic.AdmissionDecision
import io.kuicksilver.quic.ConnectionAdmission
import io.kuicksilver.quic.ConnectionState
import io.kuicksilver.quic.CoreFixtures
import io.kuicksilver.quic.KuicksilverLogger
import io.kuicksilver.quic.LogLevel
import io.kuicksilver.quic.MemoryNetwork
import io.kuicksilver.quic.MemoryTokenStore
import io.kuicksilver.quic.QuicClientConfig
import io.kuicksilver.quic.QuicEndpoint
import io.kuicksilver.quic.QuicEndpointConfig
import io.kuicksilver.quic.QuicServerConfig
import io.kuicksilver.quic.QuicTokenStore
import io.kuicksilver.quic.core.takeReceivedTokens
import io.kuicksilver.quic.endpoint.EndpointPair
import io.kuicksilver.quic.runtime.LoopGroup
import io.kuicksilver.quic.tokenStoreKey
import io.kuicksilver.quic.wire.FrameEncoder
import io.kuicksilver.quic.wire.PacketHeaderCodec
import io.kuicksilver.quic.wire.PacketHeaderView
import io.kuicksilver.quic.wire.PacketType
import io.kuicksilver.quic.wire.WireWriter
import io.kuicksilver.tls.KslQuicCrypto
import kotlinx.coroutines.async
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/** The client keeps NEW_TOKEN tokens in a [QuicTokenStore] and presents them in the Initials of its next connection (RFC 9000 section 8.1.3). */
@OptIn(ExperimentalKuicksilverApi::class, DelicateKuicksilverApi::class)
class TokenStoreTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private val serverAddr = InetSocketAddress("10.0.0.2", 2222)
    private val clientAddr = InetSocketAddress("10.0.0.1", 1111)

    /** A [MemoryTokenStore] whose puts and takes the test can wait for and inspect. */
    private class RecordingStore(
        val inner: QuicTokenStore = MemoryTokenStore(),
        val failTake: Boolean = false,
        val failPut: Boolean = false,
    ) : QuicTokenStore {
        val puts = Channel<Pair<String, ByteArray>>(Channel.UNLIMITED)
        val takes = ArrayList<String>()

        override suspend fun put(
            key: String,
            token: ByteArray,
        ) {
            try {
                if (failPut) throw IllegalStateException("disk full")
                inner.put(key, token)
            } finally {
                puts.trySend(key to token.copyOf()) // after the store has it: a test waiting for the put may connect again at once
            }
        }

        override suspend fun take(key: String): ByteArray? {
            takes += key
            if (failTake) throw IllegalStateException("store unavailable")
            return inner.take(key)
        }
    }

    /** The token of every client Initial seen on the network, in order (null: none). */
    private class InitialTap(
        net: MemoryNetwork,
        client: InetSocketAddress,
    ) {
        val tokens = ArrayList<ByteArray?>()

        init {
            net.lose = { from, _, bytes ->
                if (from == client) tokenOfInitial(bytes)?.let { tokens += it.takeIf { t -> t.isNotEmpty() } }
                false
            }
        }
    }

    private class Setup(
        val net: MemoryNetwork,
        val server: QuicEndpoint,
        val client: QuicEndpoint,
        val warnings: Channel<String> = Channel(Channel.UNLIMITED),
    ) : AutoCloseable {
        override fun close() {
            client.close()
            server.close()
        }
    }

    private suspend fun setup(
        admission: ConnectionAdmission = ConnectionAdmission.AlwaysRetry,
        serverBlock: QuicServerConfig.Builder.() -> Unit = {},
    ): Setup {
        val net = MemoryNetwork()
        val warnings = Channel<String>(Channel.UNLIMITED)
        val logger =
            object : KuicksilverLogger {
                override fun isEnabled(level: LogLevel) = level >= LogLevel.Warn

                override fun log(
                    level: LogLevel,
                    message: String,
                    cause: Throwable?,
                ) {
                    warnings.trySend(message)
                }
            }
        val b = net.open(serverAddr)
        val a = net.open(clientAddr)
        val server =
            QuicEndpoint.bind(
                serverAddr,
                QuicEndpointConfig
                    .Builder()
                    .apply {
                        server = QuicServerConfig.Builder(CoreFixtures.server()).apply(serverBlock).build()
                        crypto = KslQuicCrypto
                        this.admission = admission
                        io = { b }
                    }.build(),
            )
        val client =
            QuicEndpoint.bind(
                clientAddr,
                QuicEndpointConfig
                    .Builder()
                    .apply {
                        crypto = KslQuicCrypto
                        this.logger = logger
                        io = { a }
                    }.build(),
            )
        return Setup(net, server, client, warnings)
    }

    private fun clientConfig(
        store: QuicTokenStore?,
        name: String = "server.test",
    ) = QuicClientConfig
        .Builder(CoreFixtures.client(name = name))
        .apply { tokenStore = store }
        .build()

    /** One full connection through [s]; closed once the server accepted it. */
    private suspend fun connectOnce(
        s: Setup,
        store: QuicTokenStore?,
        name: String = "server.test",
        to: InetSocketAddress = serverAddr,
    ) {
        kotlinx.coroutines.coroutineScope {
            val accepted = async { s.server.accept() }
            val c = s.client.connect(to, clientConfig(store, name))
            accepted.await()
            c.close()
        }
    }

    @Test fun tokenReturnedInEveryInitialOfTheNextConnection(): Unit =
        runBlocking {
            setup().use { s ->
                withTimeout(20.seconds) {
                    val store = RecordingStore()
                    connectOnce(s, store)
                    val (key, token) = store.puts.receive()
                    assertEquals("server.test:2222", key, "keyed by the server name and port")
                    val tap = InitialTap(s.net, clientAddr)
                    val retries = s.server.stats.retriesSent
                    connectOnce(s, store)
                    assertTrue(tap.tokens.isNotEmpty())
                    for (t in tap.tokens) assertContentEquals(token, t, "every Initial of the second connection carries the token")
                    assertEquals(retries, s.server.stats.retriesSent, "no Retry for the token holder")
                    assertEquals(1L, s.server.stats.newTokensAccepted)
                }
            }
        }

    @Test fun tokenReturnedInEveryInitialUntilRetry() {
        // RFC 9000 section 17.2.5.3: the token of a Retry replaces the one the client started with
        // the policy asks the second client for a Retry although its token validated it, until that client has taken the Retry
        var second: io.kuicksilver.quic.ConnectionCore? = null
        val p =
            EndpointPair(crypto = KslQuicCrypto) {
                admission =
                    ConnectionAdmission { a ->
                        val c = second
                        val allow = if (c == null) a.addressValidated else c.retryReceivedForTest
                        if (allow) AdmissionDecision.Allow else AdmissionDecision.Retry
                    }
            }
        try {
            val first = p.connect()
            assertTrue(p.confirmed(first), "${p.closed(first)}")
            val s = p.server.connections().single()
            assertTrue(p.runUntil { s.newTokenSendsForTest.isNotEmpty() })
            val token = s.newTokenSendsForTest[0]
            val seen = ArrayList<ByteArray?>()
            var retried = false
            p.filterToServer = { _, b ->
                tokenOfInitial(b)?.let { seen += it }
                true
            }
            p.filterToClient = { _, b ->
                if (packetType(b) == PacketType.Retry) retried = true
                true
            }
            val c = p.connect()
            c.initialToken = token
            second = c
            assertTrue(p.confirmed(c), "${p.closed(c)}")
            assertTrue(retried, "the policy answered the token holder with a Retry")
            val firstRetryToken = seen.indexOfFirst { !it.contentEquals(token) }
            assertTrue(firstRetryToken > 0, "the first Initials carry the NEW_TOKEN token")
            for (i in 0 until firstRetryToken) assertContentEquals(token, seen[i])
            for (i in firstRetryToken until seen.size) {
                assertEquals(0x01, seen[i]!![0].toInt(), "after the Retry every Initial carries the Retry token")
            }
        } finally {
            p.close()
        }
    }

    @Test fun tokenIsSingleUse(): Unit =
        runBlocking {
            // a server that issues none: the one token the store held goes out once, the third connection has none
            setup(admission = ConnectionAdmission.default(), serverBlock = { newTokenLifetime = null }).use { s ->
                withTimeout(20.seconds) {
                    val store = RecordingStore()
                    val token = ByteArray(33) { 0x02 }
                    store.inner.put("server.test:2222", token)
                    val tap = InitialTap(s.net, clientAddr)
                    connectOnce(s, store)
                    assertTrue(
                        tap.tokens.isNotEmpty() && tap.tokens.all { it.contentEquals(token) },
                        "the stored token goes out: ${tap.tokens.map { it?.size }}",
                    )
                    tap.tokens.clear()
                    connectOnce(s, store)
                    assertTrue(tap.tokens.isNotEmpty() && tap.tokens.all { it == null }, "and only once")
                    assertEquals(0L, s.server.stats.invalidTokens, "a stale NEW_TOKEN token is not refused")
                }
            }
        }

    @Test fun keyedByServerName(): Unit =
        runBlocking {
            // RFC 9000 section 8.1.3: "A client MUST NOT include a token that is not applicable to the server that it is connecting to"
            setup(admission = ConnectionAdmission.default()).use { s ->
                withTimeout(20.seconds) {
                    val store = RecordingStore()
                    connectOnce(s, store, name = "a.wild.test")
                    assertEquals("a.wild.test:2222", store.puts.receive().first)
                    val tap = InitialTap(s.net, clientAddr)
                    connectOnce(s, store, name = "b.wild.test")
                    assertEquals(listOf("a.wild.test:2222", "b.wild.test:2222"), store.takes)
                    assertTrue(tap.tokens.isNotEmpty() && tap.tokens.all { it == null }, "a.wild.test's token does not go to b.wild.test")
                    assertNotNull(store.inner.take("a.wild.test:2222"), "and stays in the store")
                }
            }
        }

    @Test fun keyedByAddressWithoutServerName() {
        assertEquals("10.0.0.2:2222", tokenStoreKey(null, serverAddr))
        assertEquals("[fd00::1]:443", tokenStoreKey(null, InetSocketAddress("fd00::1", 443)))
        assertEquals("server.test:443", tokenStoreKey("server.test", InetSocketAddress("fd00::1", 443)))
    }

    @Test fun negative_oversizedOrFloodedTokensBounded() {
        // a server that floods NEW_TOKEN frames or sends one too large: the client keeps eight per connection, at most 1024 bytes
        // each, and every frame past the eighth spends a glitch token (RFC 9000 section 21.9)
        val p = EndpointPair(crypto = KslQuicCrypto)
        try {
            val c = p.connect()
            assertTrue(p.confirmed(c), "${p.closed(c)}")
            val s = p.server.connections().single()
            p.runUntil(1.seconds) { false }
            c.takeReceivedTokens()
            val glitchesBefore = c.glitchCounts[7]
            s.testInjectFrames += 3 to newTokenFrame(ByteArray(1025) { 1 })
            s.testInjectFrames += 3 to newTokenFrame(ByteArray(1024) { 2 })
            repeat(98) { i -> s.testInjectFrames += 3 to newTokenFrame(ByteArray(40) { (i + 3).toByte() }) }
            assertTrue(p.runUntil { s.testInjectFrames.isEmpty() })
            p.runUntil(1.seconds) { false }
            val kept = c.takeReceivedTokens()
            assertTrue(kept.size <= 8, "at most eight per connection: ${kept.size}")
            assertTrue(kept.none { it.size > 1024 }, "a token over 1024 bytes is not kept")
            assertTrue(kept.any { it.size == 1024 }, "1024 bytes is")
            assertEquals(ConnectionState.Confirmed, c.state, "a flood costs glitch tokens, not the connection (1000 in the bucket)")
            assertTrue(
                c.glitchCounts[7] - glitchesBefore >= 90,
                "every NEW_TOKEN past the eighth spends a glitch token: ${c.glitchCounts[7]}",
            )
        } finally {
            p.close()
        }
    }

    @Test fun memoryStoreIsBounded(): Unit =
        runBlocking {
            val store = MemoryTokenStore(maxServers = 2, tokensPerServer = 4)
            repeat(100) { store.put("a:1", byteArrayOf(it.toByte())) }
            val taken = ArrayList<ByteArray>()
            while (true) taken += store.take("a:1") ?: break
            assertEquals(4, taken.size, "tokensPerServer")
            assertEquals(listOf(99, 98, 97, 96), taken.map { it[0].toInt() }, "newest first")
            store.put("a:1", byteArrayOf(1))
            store.put("b:1", byteArrayOf(2))
            store.take("a:1") // empties a:1
            store.put("a:1", byteArrayOf(3))
            store.put("c:1", byteArrayOf(4)) // b:1 is the least recently used
            assertNull(store.take("b:1"), "maxServers: the least recently used server is evicted")
            assertNotNull(store.take("a:1"))
            assertNotNull(store.take("c:1"))
            assertFailsWith<IllegalArgumentException> { MemoryTokenStore(maxServers = 0) }
            assertFailsWith<IllegalArgumentException> { MemoryTokenStore(tokensPerServer = 0) }
        }

    @Test fun negative_newTokenFromClientIsProtocolViolation() {
        // RFC 9000 section 19.7: "Servers MUST treat receipt of a NEW_TOKEN frame as a connection error of type PROTOCOL_VIOLATION"
        val p = EndpointPair(crypto = KslQuicCrypto)
        try {
            val c = p.connect()
            assertTrue(p.confirmed(c), "${p.closed(c)}")
            val s = p.server.connections().single()
            c.testInjectFrames += 3 to newTokenFrame(ByteArray(16) { 1 })
            assertTrue(p.runUntil { p.closed(s) != null })
            val r = kotlin.test.assertIs<io.kuicksilver.quic.QuicException.ConnectionLost.TransportClosed>(p.closed(s))
            assertEquals(0x0aL, r.code, "PROTOCOL_VIOLATION")
        } finally {
            p.close()
        }
    }

    @Test fun storeFailureDoesNotFailConnect(): Unit =
        runBlocking {
            setup().use { s ->
                withTimeout(20.seconds) {
                    val store = RecordingStore(failTake = true, failPut = true)
                    connectOnce(s, store)
                    store.puts.receive() // the put that throws
                    connectOnce(s, store)
                    val warned = generateSequence { s.warnings.tryReceive().getOrNull() }.toList()
                    assertTrue(warned.any { "token store" in it }, "$warned")
                    assertEquals(0L, s.client.stats.uncaughtFailures)
                }
            }
        }

    @Test fun negative_hangingStoreDoesNotHoldConnect(): Unit =
        runBlocking {
            // a store whose calls never return: connect goes on without a token after the bound, and says so once
            setup(admission = ConnectionAdmission.default()).use { s ->
                withTimeout(20.seconds) {
                    val puts = Channel<Unit>(Channel.UNLIMITED)
                    val store =
                        object : QuicTokenStore {
                            override suspend fun put(
                                key: String,
                                token: ByteArray,
                            ) {
                                try {
                                    kotlinx.coroutines.awaitCancellation()
                                } finally {
                                    puts.trySend(Unit) // cancelled by the bound
                                }
                            }

                            override suspend fun take(key: String): ByteArray? = kotlinx.coroutines.awaitCancellation()
                        }
                    connectOnce(s, store)
                    puts.receive()
                    connectOnce(s, store)
                    val warned = generateSequence { s.warnings.tryReceive().getOrNull() }.toList()
                    assertEquals(1, warned.count { "took more than" in it }, "logged once per endpoint loop: $warned")
                    assertEquals(0L, s.client.stats.uncaughtFailures)
                }
            }
        }

    @Test fun tokenFromOneLoopValidOnAnother(): Unit =
        runBlocking {
            // a group's loops share their token keys: the token loop 0 issued validates the client on loop 1 (another socket)
            val net = MemoryNetwork()
            val otherAddr = InetSocketAddress("10.0.0.3", 2222)
            val config =
                QuicEndpointConfig
                    .Builder()
                    .apply {
                        server = QuicServerConfig.Builder(CoreFixtures.server()).build()
                        crypto = KslQuicCrypto
                        admission = ConnectionAdmission.AlwaysRetry
                        loops = 2
                    }.build()
            val group = LoopGroup.create(config, listOf(net.open(serverAddr), net.open(otherAddr)))
            val client =
                QuicEndpoint.bind(
                    clientAddr,
                    QuicEndpointConfig
                        .Builder()
                        .apply {
                            crypto = KslQuicCrypto
                            val a = net.open(clientAddr)
                            io = { a }
                        }.build(),
                )
            try {
                withTimeout(20.seconds) {
                    val store = RecordingStore()
                    val s = Setup(net, group, client)
                    connectOnce(s, store, to = serverAddr)
                    store.puts.receive()
                    connectOnce(s, store, to = otherAddr)
                    val perLoop = group.statsForTest()
                    assertTrue(perLoop[0].retriesSent >= 1, "loop 0 asked the first client for a Retry")
                    assertEquals(0L, perLoop[1].retriesSent, "loop 1 took the token loop 0 issued")
                    assertEquals(1L, perLoop[1].newTokensAccepted)
                }
            } finally {
                client.close()
                group.close()
            }
        }

    internal companion object {
        fun packetType(b: ByteArray): PacketType? {
            val v = PacketHeaderView()
            val buf = PacketBuffer.of(b)
            try {
                return if (PacketHeaderCodec.parse(buf, 0, b.size, 8, v)) v.type else null
            } finally {
                buf.close()
            }
        }

        /** The token field of a client Initial (empty for none), or null when [b] is not an Initial. */
        fun tokenOfInitial(b: ByteArray): ByteArray? {
            val v = PacketHeaderView()
            val buf = PacketBuffer.of(b)
            try {
                if (!PacketHeaderCodec.parse(buf, 0, b.size, 8, v) || v.type != PacketType.Initial) return null
                return b.copyOfRange(v.tokenOff, v.tokenOff + v.tokenLen)
            } finally {
                buf.close()
            }
        }

        fun newTokenFrame(token: ByteArray): ByteArray {
            val buf = PacketBuffer.allocate(token.size + 16)
            try {
                val w = WireWriter(buf, 0, token.size + 16)
                FrameEncoder.newToken(w, token)
                return ByteArray(w.pos).also { buf.copyTo(it, 0, 0, w.pos) }
            } finally {
                buf.close()
            }
        }
    }
}
