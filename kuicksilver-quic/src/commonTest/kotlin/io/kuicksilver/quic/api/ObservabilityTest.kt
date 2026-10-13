// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.api

import io.ktor.network.sockets.InetSocketAddress
import io.ktor.utils.io.readAvailable
import io.ktor.utils.io.writeFully
import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.AdmissionDecision
import io.kuicksilver.quic.ConnectionAdmission
import io.kuicksilver.quic.ConnectionInfo
import io.kuicksilver.quic.ConnectionListener
import io.kuicksilver.quic.CoreFixtures
import io.kuicksilver.quic.KuicksilverLogger
import io.kuicksilver.quic.LogLevel
import io.kuicksilver.quic.MemoryNetwork
import io.kuicksilver.quic.NullCryptoProvider
import io.kuicksilver.quic.QuicClientConfig
import io.kuicksilver.quic.QuicConnection
import io.kuicksilver.quic.QuicEndpoint
import io.kuicksilver.quic.QuicEndpointConfig
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.QuicServerConfig
import io.kuicksilver.quic.TransportError
import io.kuicksilver.quic.ZeroRttOutcome
import io.kuicksilver.quic.runtime.EndpointLoop
import io.kuicksilver.quic.runtime.LoopGroup
import io.kuicksilver.tls.EarlyDataState
import io.kuicksilver.tls.KeylogSink
import io.kuicksilver.tls.KslQuicCrypto
import io.kuicksilver.tls.QuicCrypto
import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.yield
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/** `QuicEndpoint.stats`, the connection listener and the logger (docs/guide/quic.md, "Observability"). */
@OptIn(ExperimentalKuicksilverApi::class, DelicateKuicksilverApi::class)
class ObservabilityTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private val serverAddr = InetSocketAddress("10.0.0.2", 2222)

    /** A server and [clients] client endpoints on one in-memory network, each built from the defaults plus the given blocks. */
    private class Endpoints(
        val server: QuicEndpoint,
        val clients: List<QuicEndpoint>,
    ) : AutoCloseable {
        override fun close() {
            for (c in clients) c.close()
            server.close()
        }
    }

    private suspend fun endpoints(
        crypto: QuicCrypto = NullCryptoProvider,
        clients: Int = 1,
        serverTls: io.kuicksilver.tls.TlsConfig = CoreFixtures.server(),
        serverEarlyData: Boolean = false,
        server: QuicEndpointConfig.Builder.() -> Unit = {},
        client: QuicEndpointConfig.Builder.() -> Unit = {},
    ): Endpoints {
        val net = MemoryNetwork()
        val s =
            QuicEndpoint.bind(
                serverAddr,
                QuicEndpointConfig
                    .Builder()
                    .apply {
                        this.server = QuicServerConfig.Builder(serverTls).apply { earlyData = serverEarlyData }.build()
                        this.crypto = crypto
                        io = { net.open(it) }
                        server()
                    }.build(),
            )
        val cs =
            List(clients) { i ->
                QuicEndpoint.bind(
                    InetSocketAddress("10.0.1.${i + 1}", 1000 + i),
                    QuicEndpointConfig
                        .Builder()
                        .apply {
                            this.crypto = crypto
                            io = { net.open(it) }
                            client()
                        }.build(),
                )
            }
        return Endpoints(s, cs)
    }

    private fun clientConfig(
        tls: io.kuicksilver.tls.TlsConfig = CoreFixtures.client(),
        early: EarlyDataState = EarlyDataState.Disabled,
    ) = QuicClientConfig.Builder(tls).apply { earlyData = early }.build()

    private suspend fun echo(
        c: QuicConnection,
        text: String,
    ): String {
        val s = c.openBidi()
        s.output.writeFully(text.encodeToByteArray())
        s.output.flushAndClose()
        val b = ByteArray(1024)
        var out = ""
        while (true) {
            val n = s.input.readAvailable(b, 0, b.size)
            if (n < 0) return out
            out += b.decodeToString(0, n)
        }
    }

    private suspend fun serveEcho(c: QuicConnection) {
        val s = c.acceptStream()
        val b = ByteArray(1024)
        while (true) {
            val n = s.input.readAvailable(b, 0, b.size)
            if (n < 0) break
            s.output.writeFully(b, 0, n)
        }
        s.output.flushAndClose()
    }

    /** Polls [cond] for up to five seconds: the loops publish their counters on their own threads. */
    private suspend fun eventually(cond: () -> Boolean) {
        withTimeout(5.seconds) { while (!cond()) delay(10) }
    }

    @Test fun statsCountAHandshakeOnBothSides(): Unit =
        runBlocking {
            endpoints().use { e ->
                withTimeout(20.seconds) {
                    val accepted = async { e.server.accept().also { serveEcho(it) } }
                    val c = e.clients[0].connect(e.server.localAddress, clientConfig())
                    assertEquals("hello", echo(c, "hello"))
                    accepted.await()
                    val s = e.server.stats
                    assertEquals(1, s.connectionsActive, "$s")
                    assertEquals(1, s.connectionsAccepted, "$s")
                    assertEquals(1, s.handshakesCompleted, "$s")
                    assertTrue(s.datagramsReceived > 0 && s.datagramsSent > 0, "$s")
                    val cs = e.clients[0].stats
                    assertEquals(1, cs.connectionsActive, "$cs")
                    assertEquals(0, cs.connectionsAccepted, "a client accepts nothing: $cs")
                    assertEquals(1, cs.handshakesCompleted, "$cs")
                    assertTrue(cs.datagramsSent >= 1 && cs.datagramsReceived >= 1, "$cs")
                    c.close(0, "done")
                    eventually { e.clients[0].stats.connectionsActive == 0L }
                    assertEquals(0, e.clients[0].stats.handshakesFailedOther, "a closed connection whose handshake completed is no failure")
                }
            }
        }

    @Test fun statsCountAcceptQueueRefusals(): Unit =
        runBlocking {
            endpoints(clients = 2, server = { acceptQueue = 1 }).use { e ->
                withTimeout(20.seconds) {
                    e.clients[0].connect(e.server.localAddress, clientConfig()) // waits in the accept queue, never accepted
                    // connect returns when the client's handshake is complete; the server queues the connection only once the
                    // client's Finished arrives, so the second client must not start before (its Initial would be admitted, and
                    // its connection refused only after its handshake completed: seen in the Windows JVM run)
                    eventually { e.server.stats.connectionsAccepted == 1L }
                    val lost =
                        assertFailsWith<QuicException.ConnectionLost.TransportClosed> {
                            e.clients[1].connect(e.server.localAddress, clientConfig())
                        }
                    assertEquals(TransportError.CONNECTION_REFUSED, lost.code)
                    eventually { e.clients[1].stats.connectionsActive == 0L }
                    assertEquals(1, e.server.stats.connectionsRefusedAcceptQueue, "${e.server.stats}")
                    assertEquals(1, e.clients[1].stats.handshakesFailedOther, "${e.clients[1].stats}")
                }
            }
        }

    @Test fun statsCountAdmissionAndLimitRefusals(): Unit =
        runBlocking {
            var n = 0
            val admission =
                ConnectionAdmission {
                    if (n++ ==
                        0
                    ) {
                        AdmissionDecision.Close(TransportError.CONNECTION_REFUSED)
                    } else {
                        AdmissionDecision.Allow
                    }
                }
            endpoints(clients = 3, server = {
                this.admission = admission
                maxConnections = 1
            }).use { e ->
                withTimeout(20.seconds) {
                    assertFailsWith<QuicException.ConnectionLost.TransportClosed> {
                        e.clients[0].connect(
                            e.server.localAddress,
                            clientConfig(),
                        )
                    }
                    e.clients[1].connect(e.server.localAddress, clientConfig())
                    val third = async { runCatching { e.clients[2].connect(e.server.localAddress, clientConfig()) } }
                    eventually { e.server.stats.connectionsRefusedLimits > 0 } // maxConnections = 1: dropped silently
                    third.cancel()
                    val s = e.server.stats
                    assertEquals(1, s.connectionsRefusedAdmission, "$s")
                    assertTrue(s.initialsDropped >= s.connectionsRefusedLimits, "$s")
                }
            }
        }

    @Test fun aTlsFailureCountsAsATlsHandshakeFailure(): Unit =
        runBlocking {
            endpoints(crypto = KslQuicCrypto).use { e ->
                withTimeout(20.seconds) {
                    val lost =
                        assertFailsWith<QuicException.ConnectionLost.TransportClosed> {
                            e.clients[0].connect(e.server.localAddress, clientConfig(CoreFixtures.client(name = "other.test")))
                        }
                    assertTrue(lost.code in 0x100L..0x1ffL, "a TLS alert: $lost")
                    eventually { e.clients[0].stats.handshakesFailedTls == 1L }
                    eventually { e.server.stats.handshakesFailedTls == 1L } // the peer's alert
                    assertEquals(0, e.server.stats.handshakesCompleted)
                }
            }
        }

    @Test fun zeroRttCountsOfferedAndAccepted(): Unit =
        runBlocking {
            val heard = ArrayList<ZeroRttOutcome>()
            val listener =
                object : ConnectionListener {
                    override fun onZeroRtt(
                        connection: ConnectionInfo,
                        outcome: ZeroRttOutcome,
                    ) {
                        heard += outcome
                    }
                }
            endpoints(crypto = KslQuicCrypto, serverEarlyData = true, client = { this.listener = listener }).use { e ->
                withTimeout(20.seconds) {
                    val server = async { repeat(2) { serveEcho(e.server.accept()) } }
                    val first = e.clients[0].connect(e.server.localAddress, clientConfig(early = EarlyDataState.Allowed))
                    assertEquals("one", echo(first, "one"))
                    val sessions = (e.clients[0] as EndpointLoop).sessions
                    while (sessions.size() == 0) yield()
                    first.close()
                    val second = e.clients[0].connectEarly(e.server.localAddress, clientConfig(early = EarlyDataState.Allowed))
                    assertEquals("two", echo(second, "two"))
                    second.awaitHandshake()
                    server.await()
                    val cs = e.clients[0].stats
                    assertEquals(1, cs.zeroRttOffered, "$cs")
                    assertEquals(1, cs.zeroRttAccepted, "$cs")
                    assertEquals(0, cs.zeroRttRejected, "$cs")
                    assertEquals(1, e.server.stats.zeroRttAccepted, "${e.server.stats}")
                    assertEquals(listOf(ZeroRttOutcome.Accepted), heard)
                }
            }
        }

    @Test fun groupStatsSumEveryLoop(): Unit =
        runBlocking {
            val net = MemoryNetwork()
            val other = InetSocketAddress("10.0.0.3", 2222)
            val config =
                QuicEndpointConfig
                    .Builder()
                    .apply {
                        server = QuicServerConfig.Builder(CoreFixtures.server()).build()
                        crypto = NullCryptoProvider
                        loops = 2
                    }.build()
            val group = LoopGroup.create(config, listOf(net.open(serverAddr), net.open(other)))
            val clients =
                List(2) { i ->
                    val io = net.open(InetSocketAddress("10.0.1.${i + 1}", 1000))
                    QuicEndpoint.bind(
                        io.localAddress,
                        QuicEndpointConfig
                            .Builder()
                            .apply {
                                crypto = NullCryptoProvider
                                this.io = { io }
                            }.build(),
                    )
                }
            try {
                withTimeout(20.seconds) {
                    clients[0].connect(serverAddr, clientConfig())
                    clients[1].connect(other, clientConfig())
                    eventually { group.stats.connectionsAccepted == 2L }
                    val s = group.stats
                    assertEquals(2, s.handshakesCompleted, "$s")
                    assertEquals(2, s.connectionsActive, "$s")
                    assertEquals(2, s.connectionsCreated, "$s")
                    assertEquals(1, group.statsForTest()[0].connectionsCreated, "one per loop")
                }
            } finally {
                for (c in clients) c.close()
                group.close()
            }
        }

    /** Records every callback as one line, in order. */
    private class Recorder : ConnectionListener {
        private val lines = Lines()
        val events: List<String> get() = lines.all
        private val infos = HashSet<ConnectionInfo>() // the loop's thread only

        override fun onOpened(connection: ConnectionInfo) {
            infos += connection
            lines += "opened ${connection.role}"
        }

        override fun onHandshakeCompleted(connection: ConnectionInfo) {
            lines += "handshake"
        }

        override fun onClosed(
            connection: ConnectionInfo,
            reason: QuicException.ConnectionLost,
        ) {
            assertTrue(connection in infos, "one ConnectionInfo per connection")
            lines += "closed ${reason.message}"
        }
    }

    @Test fun theListenerHearsTheLifecycleInOrder(): Unit =
        runBlocking {
            val server = Recorder()
            val client = Recorder()
            endpoints(server = { listener = server }, client = { listener = client }).use { e ->
                withTimeout(20.seconds) {
                    val accepted = async { e.server.accept() }
                    val c = e.clients[0].connect(e.server.localAddress, clientConfig())
                    val s = accepted.await()
                    c.close(7, "bye")
                    val reason = s.closed.await()
                    val closed = assertIs<QuicException.ConnectionLost.ApplicationClosed>(reason)
                    assertEquals(7, closed.code)
                    eventually { client.events.size == 3 && server.events.size == 3 }
                    assertEquals("opened Client", client.events[0])
                    assertEquals("handshake", client.events[1])
                    assertTrue(client.events[2].startsWith("closed application closed by Local: code 7"), "${client.events}")
                    assertEquals("opened Server", server.events[0])
                    assertEquals("handshake", server.events[1])
                    assertTrue(server.events[2].startsWith("closed application closed by Peer: code 7"), "${server.events}")
                }
            }
        }

    @Test fun aThrowingListenerIsCountedAndTheConnectionLives(): Unit =
        runBlocking {
            val throwing =
                object : ConnectionListener {
                    override fun onOpened(connection: ConnectionInfo): Unit = throw IllegalStateException("listener bug")

                    override fun onHandshakeCompleted(connection: ConnectionInfo): Unit = throw IllegalStateException("listener bug")
                }
            val warnings = Lines()
            val logger =
                object : KuicksilverLogger {
                    override fun isEnabled(level: LogLevel) = level >= LogLevel.Warn

                    override fun log(
                        level: LogLevel,
                        message: String,
                        cause: Throwable?,
                    ) {
                        warnings += message
                    }
                }
            endpoints(server = {
                listener = throwing
                this.logger = logger
            }).use { e ->
                withTimeout(20.seconds) {
                    val accepted = async { e.server.accept().also { serveEcho(it) } }
                    val c = e.clients[0].connect(e.server.localAddress, clientConfig())
                    assertEquals("still works", echo(c, "still works"))
                    accepted.await()
                    assertEquals(2, e.server.stats.listenerFailures)
                    assertTrue(warnings.all.any { "onOpened" in it }, "${warnings.all}")
                }
            }
        }

    @Test fun debugLoggingOfAHandshakeLogsNoSecret(): Unit =
        runBlocking {
            // threat model: keys, traffic secrets, tickets and tokens never reach a log, even at debug level. The keylog sink sees
            // every secret of both sides; none of them (nor the session ticket the client stores) may appear in a logged line
            val secrets = Lines()
            val keylog = KeylogSink { line -> secrets += line.split(' ').last().lowercase() }
            val lines = Lines()
            val logger =
                object : KuicksilverLogger {
                    override fun isEnabled(level: LogLevel) = true

                    override fun log(
                        level: LogLevel,
                        message: String,
                        cause: Throwable?,
                    ) {
                        lines += "$message ${cause ?: ""}"
                    }
                }
            endpoints(
                crypto = KslQuicCrypto,
                serverTls = CoreFixtures.server { this.keylog = keylog },
                serverEarlyData = true,
                server = { this.logger = logger },
                client = { this.logger = logger },
            ).use { e ->
                withTimeout(20.seconds) {
                    val accepted = async { repeat(2) { e.server.accept().also { serveEcho(it) } } }
                    val tls = CoreFixtures.client { this.keylog = keylog }
                    val first = e.clients[0].connect(e.server.localAddress, clientConfig(tls, EarlyDataState.Allowed))
                    assertEquals("secret?", echo(first, "secret?"))
                    val sessions = (e.clients[0] as EndpointLoop).sessions
                    while (sessions.size() == 0) yield()
                    first.close(0, "done")
                    val second = e.clients[0].connectEarly(e.server.localAddress, clientConfig(tls, EarlyDataState.Allowed))
                    assertEquals("again", echo(second, "again"))
                    accepted.await()
                    second.close(0, "done")
                    eventually { e.clients[0].stats.connectionsActive == 0L }
                }
            }
            val logged = lines.all.joinToString("\n").lowercase()
            assertTrue("handshake complete" in logged, "debug logging is on: $logged")
            assertTrue("0-rtt accepted" in logged, "the resumed connection is logged too: $logged")
            val all = secrets.all
            assertTrue(all.size >= 8, "the keylog saw the secrets of both sides: ${all.size}")
            for (s in all) assertTrue(s.length >= 32 && s !in logged, "a secret reached the log")
        }

    /** Lines appended from any thread (the keylog sink runs inside TLS on either loop). */
    @OptIn(kotlin.concurrent.atomics.ExperimentalAtomicApi::class)
    private class Lines {
        private val ref = kotlin.concurrent.atomics.AtomicReference<List<String>>(emptyList())
        val all: List<String> get() = ref.load()

        operator fun plusAssign(line: String) {
            while (true) {
                val old = ref.load()
                if (ref.compareAndSet(old, old + line)) return
            }
        }
    }
}
