// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import io.ktor.client.HttpClient
import io.ktor.client.plugins.websocket.DefaultClientWebSocketSession
import io.ktor.client.plugins.websocket.WebSockets
import io.ktor.client.plugins.websocket.webSocket
import io.ktor.client.request.get
import io.ktor.client.request.prepareGet
import io.ktor.client.statement.bodyAsChannel
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpProtocolVersion
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.server.application.install
import io.ktor.server.request.httpVersion
import io.ktor.server.response.respondBytesWriter
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.readAvailable
import io.ktor.utils.io.writeFully
import io.ktor.websocket.CloseReason
import io.ktor.websocket.Frame
import io.ktor.websocket.close
import io.ktor.websocket.readBytes
import io.ktor.websocket.readReason
import io.ktor.websocket.readText
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.DatagramIo
import io.kuicksilver.quic.KuicksilverLogger
import io.kuicksilver.quic.LogLevel
import io.kuicksilver.quic.MigrationEvent
import io.kuicksilver.quic.MigrationRefusal
import io.kuicksilver.quic.MigrationRefusedException
import io.kuicksilver.quic.NetworkMigrator
import io.kuicksilver.quic.PacketBatch
import io.kuicksilver.quic.QuicEndpointConfig
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.TimeoutKind
import io.kuicksilver.quic.quicConfig
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.onCompletion
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.concurrent.Volatile
import kotlin.concurrent.atomics.AtomicInt
import kotlin.concurrent.atomics.AtomicReference
import kotlin.concurrent.atomics.ExperimentalAtomicApi
import kotlin.concurrent.atomics.incrementAndFetch
import kotlin.concurrent.atomics.update
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue
import kotlin.test.fail
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds
import io.ktor.server.websocket.WebSockets as ServerWebSockets
import io.ktor.server.websocket.webSocketRaw as serverWebSocketRaw

/**
 * `http3 { connectionMigration }` (U.4a, RFC 9000 section 9): pooled HTTP/3 connections follow a network source. The
 * "networks" are a test flow of numbers; a new network is a new loopback socket, and the network the connection leaves
 * goes deaf ([CuttableIo] under the engine's endpoint), as a Wi-Fi interface does when the device walks away from it.
 */
@OptIn(ExperimentalKuicksilverApi::class, ExperimentalAtomicApi::class, kotlinx.coroutines.ExperimentalCoroutinesApi::class)
class ClientMigrationTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    /** The engine endpoint's socket; once [gone], nothing it sends leaves and nothing it receives arrives. */
    private class CuttableIo(
        private val d: DatagramIo,
    ) : DatagramIo by d {
        @Volatile var gone = false

        override suspend fun send(batch: PacketBatch): Int = if (gone) batch.count else d.send(batch)

        override fun trySend(batch: PacketBatch): Int = if (gone) batch.count else d.trySend(batch)

        override suspend fun receive(into: PacketBatch): Int {
            while (true) {
                val before = into.count
                val n = d.receive(into)
                if (!gone) return n
                into.count = before // dropped: the interface is gone
            }
        }
    }

    /** Every line of the engine's logger, with the message of its cause. */
    private class Lines : KuicksilverLogger {
        val lines = AtomicReference(emptyList<Pair<LogLevel, String>>())

        override fun isEnabled(level: LogLevel): Boolean = true

        override fun log(
            level: LogLevel,
            message: String,
            cause: Throwable?,
        ) {
            lines.update { it + (level to "$message ${cause?.message}") }
        }
    }

    /** What the listener heard. */
    private class Heard(
        val onMigrated: () -> Unit = {},
    ) : KuicksilverEventListener() {
        val migrations = Channel<Pair<String, MigrationEvent<*>>>(Channel.UNLIMITED)
        val fallbacks = Channel<Throwable>(Channel.UNLIMITED)

        override fun connectionMigrated(
            origin: String,
            event: MigrationEvent<*>,
        ) {
            if (event is MigrationEvent.Migrated) onMigrated()
            migrations.trySend(origin to event)
        }

        override fun fallback(
            request: io.ktor.client.request.HttpRequestData,
            cause: Throwable,
        ) {
            fallbacks.trySend(cause)
        }
    }

    /** The test's network source and the migrators the hook made. */
    private class Networks(
        /** Opening a socket on network 2 and up throws this instead (a socket the platform refuses). */
        val openFailure: Exception? = null,
    ) {
        val current = MutableStateFlow<Int?>(1)
        val made = Channel<NetworkMigrator<Int>>(Channel.UNLIMITED)
        val opened = AtomicReference(emptyList<DatagramIo>())
        val sourceStopped = AtomicInt(0)

        /** A hook over [current]; each new network is a new loopback socket. */
        val hook =
            Http3ConnectionMigration { c, scope ->
                NetworkMigrator(
                    c,
                    current.onCompletion { sourceStopped.incrementAndFetch() },
                    { n ->
                        if (n > 1) openFailure?.let { throw it }
                        DatagramIo.open(InetSocketAddress("127.0.0.1", 0)).also { io -> opened.update { it + io } }
                    },
                    scope,
                ).also { made.trySend(it) }
            }
    }

    /** A server whose `/big` (HTTP/3) sends [MIB_2] bytes, completes [atTwo], waits for [resume] and sends the rest of 8 MiB. */
    private class Gates {
        val atTwo = CompletableDeferred<Unit>()
        val resume = CompletableDeferred<Unit>()
        val held = CompletableDeferred<Unit>()
        val release = CompletableDeferred<Unit>()
    }

    private suspend fun server(
        g: Gates,
        allowMigration: Boolean = true,
    ) = testServer(configure = { if (!allowMigration) quic = quicConfig { this.allowMigration = false } }) {
        routing {
            get("/big") {
                call.respondBytesWriter {
                    val chunk = ByteArray(64 * 1024) { 7 }
                    var sent = 0
                    while (sent < MIB_8) {
                        if (sent == MIB_2 && call.request.httpVersion == "HTTP/3") {
                            g.atTwo.complete(Unit)
                            g.resume.await()
                        }
                        writeFully(chunk)
                        sent += chunk.size
                    }
                }
            }
            get("/small") { call.respondText(call.request.httpVersion) }
            // over HTTP/3 the answer waits for [Gates.release]; over HTTP/1.1 (the fallback) it comes at once
            get("/hold") {
                if (call.request.httpVersion == "HTTP/3") {
                    g.held.complete(Unit)
                    g.release.await()
                }
                call.respondText(call.request.httpVersion)
            }
        }
    }

    /** HTTP/3 first, HTTP/1.1 only after it failed; the engine's endpoint socket is [cut]. */
    private fun client(
        cut: CompletableDeferred<CuttableIo>,
        listener: KuicksilverEventListener,
        migration: Http3ConnectionMigration?,
        maxIdle: Duration = 10.seconds,
        engineIdle: Duration? = null,
        log: KuicksilverLogger? = null,
        block: io.ktor.client.HttpClientConfig<KuicksilverEngineConfig>.() -> Unit = {},
    ): HttpClient =
        testClient(Http3DiscoveryMode.Preferred, block = block, engine = {
            log?.let { logger = it }
            quic = quicConfig { maxIdleTimeout = maxIdle }
            eventListener = listener
            engineIdle?.let { idleTimeout = it }
            http3 {
                hardDelay = Duration.INFINITE
                connectionMigration = migration
                endpoint =
                    QuicEndpointConfig
                        .Builder()
                        .apply { io = { local -> CuttableIo(DatagramIo.open(local)).also { cut.complete(it) } } }
                        .build()
            }
        })

    /** Reads [ch] to its end; a channel closed with a cause throws it (ktor's -1 alone does not tell). */
    private suspend fun drain(ch: ByteReadChannel): Long {
        val b = ByteArray(64 * 1024)
        var n = 0L
        while (true) {
            val r = ch.readAvailable(b, 0, b.size)
            if (r < 0) break
            n += r
        }
        ch.closedCause?.let { throw it }
        return n
    }

    private fun engineOf(c: HttpClient) = c.engine as KuicksilverEngine

    @Test fun downloadSurvivesNetworkSwitch() =
        h3Test {
            val g = Gates()
            val (server, port) = server(g)
            val cut = CompletableDeferred<CuttableIo>()
            val nets = Networks()
            // the old network goes away right after the switch, before the rest of the body is sent
            val heard = Heard(onMigrated = { cut.getCompleted().gone = true })
            try {
                client(cut, heard, nets.hook).use { c ->
                    coroutineScope {
                        val download =
                            async {
                                c.prepareGet("https://127.0.0.1:$port/big").execute { r ->
                                    assertEquals(HttpProtocolVersion.HTTP_3_0, r.version)
                                    drain(r.bodyAsChannel())
                                }
                            }
                        g.atTwo.await()
                        val migrator = withTimeout(10.seconds) { nets.made.receive() }
                        withTimeout(10.seconds) { migrator.network.first { it == 1 } } // following network 1
                        val conn =
                            engineOf(c)
                                .h3
                                .connectionsForTest()
                                .single()
                        val before = conn.quic.stats.currentPath
                        nets.current.value = 2
                        val (origin, e) = withTimeout(10.seconds) { heard.migrations.receive() }
                        assertEquals("https://127.0.0.1:$port", origin)
                        val m = assertIs<MigrationEvent.Migrated<*>>(e, "$e")
                        assertEquals(1 to 2, m.old to m.new)
                        g.resume.complete(Unit)
                        assertEquals(MIB_8.toLong(), withTimeout(30.seconds) { download.await() })
                        assertNotEquals(before, conn.quic.stats.currentPath)
                        assertTrue(heard.migrations.tryReceive().isFailure, "one migration only")
                        assertTrue(heard.fallbacks.tryReceive().isFailure, "no fallback to TCP")
                        assertEquals("HTTP/3", c.get("https://127.0.0.1:$port/small").bodyAsText(), "the same connection")
                    }
                }
            } finally {
                g.resume.complete(Unit)
                server.stop(100, 500)
            }
        }

    /** Without `connectionMigration` (0.2's behaviour) the connection dies with its network; a GET in flight falls back to HTTP/1.1. */
    @Test fun negative_noMigrationWithoutConfig() =
        h3Test {
            val g = Gates()
            val (server, port) = server(g)
            val cut = CompletableDeferred<CuttableIo>()
            val heard = Heard()
            try {
                client(cut, heard, migration = null, maxIdle = 1.seconds).use { c ->
                    coroutineScope {
                        // a download whose network goes away midway: the idle timeout ends the connection and the body fails
                        val download =
                            async {
                                runCatching {
                                    c.prepareGet("https://127.0.0.1:$port/big").execute { r ->
                                        assertEquals(HttpProtocolVersion.HTTP_3_0, r.version)
                                        drain(r.bodyAsChannel())
                                    }
                                }
                            }
                        g.atTwo.await()
                        cut.getCompleted().gone = true
                        g.resume.complete(Unit)
                        val failure = withTimeout(30.seconds) { download.await() }.exceptionOrNull()
                        assertTrue(
                            generateSequence(failure) { it.cause }.any { it is QuicException.ConnectionLost },
                            "the download must fail with the lost connection: $failure",
                        )
                    }
                    // the network is back; an idempotent GET in flight when it goes again is repeated over HTTP/1.1
                    cut.getCompleted().gone = false
                    assertEquals("HTTP/3", c.get("https://127.0.0.1:$port/small").bodyAsText())
                    coroutineScope {
                        val held = async { c.get("https://127.0.0.1:$port/hold") }
                        g.held.await()
                        cut.getCompleted().gone = true
                        // bounded by the 1 s idle timeout of the dead connection, not by anything longer
                        val r = withTimeout(15.seconds) { held.await() }
                        assertEquals(HttpProtocolVersion.HTTP_1_1, r.version)
                        assertEquals("HTTP/1.1", r.bodyAsText())
                        val cause = withTimeout(5.seconds) { heard.fallbacks.receive() }
                        assertTrue(generateSequence(cause) { it.cause }.any { it is QuicException.ConnectionLost }, "$cause")
                    }
                    assertTrue(heard.migrations.tryReceive().isFailure, "nothing migrates without the option")
                }
            } finally {
                g.resume.complete(Unit)
                g.release.complete(Unit)
                server.stop(100, 500)
            }
        }

    @Test fun migratorClosedWithConnection() =
        h3Test {
            val g = Gates()
            val (server, port) = server(g)
            val cut = CompletableDeferred<CuttableIo>()
            val nets = Networks()
            try {
                client(cut, Heard(), nets.hook, engineIdle = 1.seconds).use { c ->
                    assertEquals("HTTP/3", c.get("https://127.0.0.1:$port/small").bodyAsText())
                    val migrator = withTimeout(10.seconds) { nets.made.receive() }
                    withTimeout(10.seconds) { migrator.network.first { it == 1 } }
                    val conn =
                        engineOf(c)
                            .h3
                            .connectionsForTest()
                            .single()
                    // the engine's idle timeout closes the connection; its migrator stops with it
                    withTimeout(15.seconds) { conn.closed.await() }
                    awaitMigratorsGone(c, nets)
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /** Waits until the network source of the one migrator stopped and no migration job is left (a deadline names what did not happen). */
    private suspend fun awaitMigratorsGone(
        c: HttpClient,
        nets: Networks,
    ) {
        val left =
            withTimeoutOrNull(10.seconds) {
                while (nets.sourceStopped.load() == 0 || engineOf(c).migrationJob.children.any()) delay(10)
            }
        if (left == null) {
            fail("migrator not closed: source stopped ${nets.sourceStopped.load()}, jobs ${engineOf(c).migrationJob.children.count()}")
        }
        assertEquals(1, nets.sourceStopped.load())
    }

    /** A migrator of a live pooled connection is closed with the client (the cleanup cancels the migration jobs). */
    @Test fun migratorClosedWithClient() =
        h3Test {
            val g = Gates()
            val (server, port) = server(g)
            val cut = CompletableDeferred<CuttableIo>()
            val nets = Networks()
            try {
                val c = client(cut, Heard(), nets.hook)
                assertEquals("HTTP/3", c.get("https://127.0.0.1:$port/small").bodyAsText())
                val migrator = withTimeout(10.seconds) { nets.made.receive() }
                withTimeout(10.seconds) { migrator.network.first { it == 1 } }
                c.close()
                withTimeout(10.seconds) { engineOf(c).cleanup.join() }
                awaitMigratorsGone(c, nets)
            } finally {
                server.stop(100, 500)
            }
        }

    /** `closeHttp3Connections()` closes an idle connection after its GOAWAY, and its migrator with it. */
    @Test fun migratorClosedByCloseHttp3Connections() =
        h3Test {
            val g = Gates()
            val (server, port) = server(g)
            val cut = CompletableDeferred<CuttableIo>()
            val nets = Networks()
            try {
                client(cut, Heard(), nets.hook).use { c ->
                    assertEquals("HTTP/3", c.get("https://127.0.0.1:$port/small").bodyAsText())
                    val migrator = withTimeout(10.seconds) { nets.made.receive() }
                    withTimeout(10.seconds) { migrator.network.first { it == 1 } }
                    c.closeHttp3Connections()
                    awaitMigratorsGone(c, nets)
                }
            } finally {
                server.stop(100, 500)
            }
        }

    @Test fun negative_serverDisablesActiveMigration() =
        h3Test {
            val g = Gates()
            val (server, port) = server(g, allowMigration = false)
            val cut = CompletableDeferred<CuttableIo>()
            val nets = Networks()
            val heard = Heard()
            val log = Lines()
            try {
                client(cut, heard, nets.hook, log = log).use { c ->
                    assertEquals("HTTP/3", c.get("https://127.0.0.1:$port/small").bodyAsText())
                    val migrator = withTimeout(10.seconds) { nets.made.receive() }
                    withTimeout(10.seconds) { migrator.network.first { it == 1 } }
                    val conn =
                        engineOf(c)
                            .h3
                            .connectionsForTest()
                            .single()
                    val path = conn.quic.stats.currentPath
                    nets.current.value = 2
                    val (_, e) = withTimeout(10.seconds) { heard.migrations.receive() }
                    val failed = assertIs<MigrationEvent.Failed<*>>(e, "$e")
                    val refused = assertIs<MigrationRefusedException>(failed.cause)
                    assertEquals(MigrationRefusal.DisabledByPeer, refused.reason)
                    assertEquals(1, nets.opened.load().size, "one socket opened, closed again by the refused path")
                    // a refusal comes back on every network change and is no fault: Debug, not Info
                    assertEquals(
                        listOf(LogLevel.Debug),
                        log.lines
                            .load()
                            .filter { "did not migrate" in it.second }
                            .map { it.first },
                    )
                    // the connection stays where it was and keeps serving
                    assertEquals(path, conn.quic.stats.currentPath)
                    assertEquals("HTTP/3", c.get("https://127.0.0.1:$port/small").bodyAsText())
                    assertTrue(heard.fallbacks.tryReceive().isFailure, "no fallback")
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /** Any other failure (here a socket the platform refuses, also an IllegalStateException) is worth Info. */
    @Test fun otherMigrationFailureLoggedAtInfo() =
        h3Test {
            val g = Gates()
            val (server, port) = server(g)
            val cut = CompletableDeferred<CuttableIo>()
            val nets = Networks(openFailure = IllegalStateException("interface gone"))
            val heard = Heard()
            val log = Lines()
            try {
                client(cut, heard, nets.hook, log = log).use { c ->
                    assertEquals("HTTP/3", c.get("https://127.0.0.1:$port/small").bodyAsText())
                    val migrator = withTimeout(10.seconds) { nets.made.receive() }
                    withTimeout(10.seconds) { migrator.network.first { it == 1 } }
                    nets.current.value = 2
                    val (_, e) = withTimeout(10.seconds) { heard.migrations.receive() }
                    assertEquals("interface gone", assertIs<MigrationEvent.Failed<*>>(e, "$e").cause.message)
                    assertEquals(
                        listOf(LogLevel.Info),
                        log.lines
                            .load()
                            .filter { "did not migrate" in it.second }
                            .map { it.first },
                    )
                }
            } finally {
                server.stop(100, 500)
            }
        }

    @Test fun hookNotCalledWithoutHttp3() =
        h3Test {
            val g = Gates()
            val (server, port) = server(g)
            val nets = Networks()
            try {
                testClient(Http3DiscoveryMode.H1Only, engine = { http3 { connectionMigration = nets.hook } }).use { c ->
                    assertEquals("HTTP/1.1", c.get("https://127.0.0.1:$port/small").bodyAsText())
                    assertTrue(nets.made.tryReceive().isFailure, "TCP connections do not migrate")
                }
            } finally {
                server.stop(100, 500)
            }
        }

    @Test fun throwingHookLeavesConnectionAlone() =
        h3Test {
            val g = Gates()
            val (server, port) = server(g)
            val cut = CompletableDeferred<CuttableIo>()
            val log = Lines()
            try {
                testClient(Http3DiscoveryMode.H3Only, engine = {
                    logger = log
                    http3 { connectionMigration = Http3ConnectionMigration { _, _ -> error("no network source") } }
                }).use { c ->
                    assertEquals("HTTP/3", c.get("https://127.0.0.1:$port/small").bodyAsText())
                    withTimeout(10.seconds) {
                        while (log.lines.load().none { (level, line) -> level == LogLevel.Info && "no network source" in line }) delay(10)
                    }
                    assertEquals("HTTP/3", c.get("https://127.0.0.1:$port/small").bodyAsText())
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /**
     * The WebSocket server's side of the script, shared with the test: what it received, in order, and its gates. Its
     * route is a raw one, so pings, pongs and every fragment reach it as they came.
     */
    private class WsScript {
        /** Every message, ping, pong and Close the server received, in order. */
        val received = Channel<String>(Channel.UNLIMITED)
        val sessions = AtomicInt(0)
        val version = CompletableDeferred<String>()
        val portBefore = CompletableDeferred<Int>()
        val portAfter = CompletableDeferred<Int>()

        /**
         * The first [HALF] fragments of the client's large message reached the server, and the first half of the server's
         * reached the client (its pong to the ping that followed them came back).
         */
        val halves = CompletableDeferred<Unit>()
        val resume = CompletableDeferred<Unit>()
        val ended = CompletableDeferred<Unit>()
    }

    /** A message's bytes as the server reports them: its size and a sum over them. */
    private fun digest(b: ByteArray) = "${b.size}/${b.foldIndexed(0L) { i, acc, x -> acc * 31 + (x.toLong() and 0xff) + i }}"

    private suspend fun wsServer(
        s: WsScript,
        allowMigration: Boolean = true,
    ) = testServer(configure = { if (!allowMigration) quic = quicConfig { this.allowMigration = false } }) {
        install(ServerWebSockets)
        routing {
            get("/small") { call.respondText(call.request.httpVersion) }
            serverWebSocketRaw("/ws") {
                s.sessions.incrementAndFetch()
                s.version.complete(call.request.httpVersion)
                s.portBefore.complete(call.request.local.remotePort)
                var closing = false
                var first: Frame? = null
                val message = ArrayList<ByteArray>()
                try {
                    for (f in incoming) {
                        when (f) {
                            is Frame.Ping -> {
                                s.received.trySend("ping:${f.data.decodeToString()}")
                                outgoing.send(Frame.Pong(f.data))
                                outgoing.send(Frame.Text("ping:${f.data.decodeToString()}"))
                            }

                            is Frame.Pong -> {
                                val payload = f.data.decodeToString()
                                s.received.trySend("pong:$payload")
                                if (payload == MID) {
                                    // the client answered the ping that followed the first half of the server's large
                                    // message on the same stream, so it has that half; now the network may change
                                    s.halves.complete(Unit)
                                    s.resume.await()
                                    for (i in HALF until PARTS) outgoing.send(Frame.Binary(i == PARTS - 1, serverBig.part(i)))
                                } else {
                                    outgoing.send(Frame.Text("pong:$payload"))
                                }
                            }

                            is Frame.Close -> {
                                val r = f.readReason()
                                s.received.trySend("close:${r?.code}:${r?.message}")
                                if (!closing) outgoing.send(Frame.Close(CloseReason(CloseReason.Codes.NORMAL, "server bye")))
                                flush()
                                break
                            }

                            else -> {
                                if (first == null) first = f
                                message += f.data
                                if (!f.fin) {
                                    // half the client's large message is here: the server sends half of its own, then a
                                    // ping (a control frame may come between fragments, RFC 6455 section 5.4) whose pong
                                    // tells that the client has that half
                                    if (message.size == HALF) {
                                        for (i in 0 until HALF) outgoing.send(Frame.Binary(false, serverBig.part(i)))
                                        outgoing.send(Frame.Ping(MID.encodeToByteArray()))
                                    }
                                    continue
                                }
                                val bytes = message.fold(ByteArray(0)) { a, b -> a + b }
                                val parts = message.size
                                val text = first is Frame.Text
                                first = null
                                message.clear()
                                if (!text) {
                                    s.received.trySend("binary:${digest(bytes)}:$parts")
                                    outgoing.send(Frame.Binary(true, bytes))
                                    continue
                                }
                                val t = bytes.decodeToString()
                                s.received.trySend("text:$t:$parts")
                                when {
                                    t == "ping-me" -> {
                                        outgoing.send(Frame.Ping("s-ping".encodeToByteArray()))
                                    }

                                    t.startsWith("burst:") -> {
                                        repeat(t.removePrefix("burst:").toInt()) { outgoing.send(Frame.Text("s$it")) }
                                    }

                                    t == "where" -> {
                                        s.portAfter.complete(call.request.local.remotePort)
                                        outgoing.send(Frame.Text("here"))
                                    }

                                    t == "close-me" -> {
                                        closing = true
                                        outgoing.send(Frame.Close(CloseReason(4001, "server bye")))
                                    }

                                    else -> {
                                        outgoing.send(Frame.Text("e:$t"))
                                    }
                                }
                            }
                        }
                        flush()
                    }
                } finally {
                    s.ended.complete(Unit)
                }
            }
        }
    }

    /** The next frame within a deadline that names what was awaited. */
    private suspend fun DefaultClientWebSocketSession.next(what: String): Frame =
        withTimeoutOrNull(15.seconds) { incoming.receive() } ?: fail("no frame within 15 s, awaited $what")

    private suspend fun DefaultClientWebSocketSession.expectText(t: String) {
        val f = next(t)
        assertIs<Frame.Text>(f, "awaited $t, got $f")
        assertEquals(t, f.readText())
    }

    private suspend fun DefaultClientWebSocketSession.expectBinary(b: ByteArray) {
        val f = next("binary ${b.size}")
        assertIs<Frame.Binary>(f, "awaited binary ${b.size}, got $f")
        val got = f.readBytes()
        assertTrue(b.contentEquals(got), "binary of ${b.size} bytes: got ${got.size} bytes, different content")
    }

    /**
     * Messages [range] sent back to back (a text and a binary each, nothing awaited between them), then their echoes, which
     * must come in the order sent; [expected] gets what the server must have received.
     */
    private suspend fun DefaultClientWebSocketSession.exchange(
        range: IntRange,
        expected: MutableList<String>,
    ) {
        fun bin(i: Int) = ByteArray(1000 + i) { (it * 7 + i).toByte() }
        for (i in range) {
            send(Frame.Text("c$i"))
            send(Frame.Binary(true, bin(i)))
            expected += "text:c$i:1"
            expected += "binary:${digest(bin(i))}:1"
        }
        for (i in range) {
            expectText("e:c$i")
            expectBinary(bin(i))
        }
    }

    /**
     * RFC 9220 over RFC 9000 section 9: a WebSocket on a pooled HTTP/3 connection (one stream of it) carries on across a
     * network change, as a download does. Messages both ways before and after the switch, a large fragmented message
     * each way whose first half crossed the old network and whose rest crosses the new one, pings both ways: everything
     * arrives once and in order, in the same session (one WebSocket on the server, the same call, now seen from the
     * client's new address), then a clean Close with a code and reason each way.
     */
    @Test fun webSocketSurvivesNetworkSwitch() = webSocketAcrossNetworkSwitch(clientCloses = true)

    /** [webSocketSurvivesNetworkSwitch] with the server closing: its code and reason reach the client after the switch. */
    @Test fun webSocketSurvivesNetworkSwitchServerCloses() = webSocketAcrossNetworkSwitch(clientCloses = false)

    private fun webSocketAcrossNetworkSwitch(clientCloses: Boolean) =
        h3Test {
            val s = WsScript()
            val (server, port) = wsServer(s)
            val cut = CompletableDeferred<CuttableIo>()
            val nets = Networks()
            // the old network goes away right after the switch, before the rest of the large messages is sent
            val heard = Heard(onMigrated = { cut.getCompleted().gone = true })
            val expected = mutableListOf<String>()
            try {
                client(cut, heard, nets.hook) { install(WebSockets) }.use { c ->
                    // a WebSocket takes HTTP/3 on a connection whose SETTINGS allow Extended CONNECT (RFC 9220 section 3)
                    assertEquals("HTTP/3", c.get("https://127.0.0.1:$port/small").bodyAsText())
                    val migrator = withTimeout(10.seconds) { nets.made.receive() }
                    withTimeout(10.seconds) { migrator.network.first { it == 1 } } // following network 1
                    val conn =
                        engineOf(c)
                            .h3
                            .connectionsForTest()
                            .single()
                    val before = conn.quic.stats.currentPath
                    var reason: CloseReason? = null
                    c.webSocket("wss://127.0.0.1:$port/ws") {
                        assertEquals(HttpProtocolVersion.HTTP_3_0, call.response.version)
                        exchange(0..9, expected)
                        send(Frame.Ping("c-ping-1".encodeToByteArray()))
                        expected += "ping:c-ping-1"
                        expectText("ping:c-ping-1")

                        // a large message each way, cut in the middle by the network change
                        for (i in 0 until HALF) send(Frame.Binary(false, clientBig.part(i)))
                        withTimeout(10.seconds) { s.halves.await() } // both first halves crossed network 1
                        expected += "pong:$MID"
                        nets.current.value = 2
                        val (origin, e) = withTimeout(10.seconds) { heard.migrations.receive() }
                        assertEquals("https://127.0.0.1:$port", origin)
                        val m = assertIs<MigrationEvent.Migrated<*>>(e, "$e")
                        assertEquals(1 to 2, m.old to m.new)
                        s.resume.complete(Unit)
                        for (i in HALF until PARTS) send(Frame.Binary(i == PARTS - 1, clientBig.part(i)))
                        expected += "binary:${digest(clientBig)}:$PARTS"
                        expectBinary(serverBig)
                        expectBinary(clientBig)

                        // after the switch: messages both ways, pings both ways, a burst from the server
                        exchange(10..19, expected)
                        send(Frame.Ping("c-ping-2".encodeToByteArray()))
                        expected += "ping:c-ping-2"
                        expectText("ping:c-ping-2")
                        send(Frame.Text("ping-me"))
                        expected += "text:ping-me:1"
                        expected += "pong:s-ping" // the client's session answered the server's ping
                        expectText("pong:s-ping")
                        send(Frame.Text("burst:5"))
                        expected += "text:burst:5:1"
                        for (i in 0 until 5) expectText("s$i")
                        send(Frame.Text("where"))
                        expected += "text:where:1"
                        expectText("here")

                        if (clientCloses) {
                            close(CloseReason(4000, "client bye"))
                            expected += "close:4000:client bye"
                        } else {
                            send(Frame.Text("close-me"))
                            expected += "text:close-me:1"
                            expected += "close:4001:server bye" // the client's session answers with the server's Close
                        }
                        for (f in incoming) fail("no frame after the Close, got $f")
                        reason = withTimeout(10.seconds) { closeReason.await() }
                    }
                    if (clientCloses) {
                        assertEquals(CloseReason(4000, "client bye"), reason)
                    } else {
                        assertEquals(CloseReason(4001, "server bye"), reason)
                    }
                    withTimeout(10.seconds) { s.ended.await() }
                    val got = generateSequence { s.received.tryReceive().getOrNull() }.toList()
                    assertEquals(expected, got, "what the server received, in order")
                    assertEquals("HTTP/3", s.version.await())
                    assertEquals(1, s.sessions.load(), "one WebSocket session, no reconnect")
                    assertNotEquals(s.portBefore.await(), s.portAfter.await(), "the server sees the session from the new socket")
                    assertNotEquals(before, conn.quic.stats.currentPath)
                    assertTrue(
                        engineOf(c)
                            .h3
                            .connectionsForTest()
                            .single() === conn,
                        "the same connection",
                    )
                    assertTrue(heard.migrations.tryReceive().isFailure, "one migration only")
                    assertTrue(heard.fallbacks.tryReceive().isFailure, "no fallback to TCP")
                }
            } finally {
                s.resume.complete(Unit)
                server.stop(100, 500)
            }
        }

    /**
     * Without `connectionMigration` a WebSocket over HTTP/3 ends with its network: once the old path hears nothing, the
     * idle timeout (RFC 9000 section 10.1) ends the connection, and the session's `incoming` fails and its `closeReason` is
     * 1006 (RFC 6455 section 7.1.5: the connection closed without a Close frame) instead of waiting for ever. (Ktor's JVM
     * reader takes a failed input for its end, so `incoming` does not carry the transport's cause on every platform; the
     * connection's own end does.)
     */
    @Test fun negative_webSocketEndsWithItsNetworkWithoutMigration() = webSocketEndsWithItsNetwork(migration = false, allowMigration = true)

    /**
     * With `connectionMigration` but a server that sent `disable_active_migration` (RFC 9000 section 9: the client "MUST
     * NOT send packets ... from a different local address"), the switch is refused and the WebSocket ends with the old
     * network as without the option.
     */
    @Test fun negative_webSocketEndsWithItsNetworkWhenServerDisablesMigration() =
        webSocketEndsWithItsNetwork(migration = true, allowMigration = false)

    private fun webSocketEndsWithItsNetwork(
        migration: Boolean,
        allowMigration: Boolean,
    ) = h3Test {
        val s = WsScript()
        val (server, port) = wsServer(s, allowMigration)
        val cut = CompletableDeferred<CuttableIo>()
        val nets = Networks()
        val heard = Heard()
        try {
            client(cut, heard, if (migration) nets.hook else null, maxIdle = 1.seconds) { install(WebSockets) }.use { c ->
                assertEquals("HTTP/3", c.get("https://127.0.0.1:$port/small").bodyAsText())
                val conn =
                    engineOf(c)
                        .h3
                        .connectionsForTest()
                        .single()
                c.webSocket("wss://127.0.0.1:$port/ws") {
                    assertEquals(HttpProtocolVersion.HTTP_3_0, call.response.version)
                    send(Frame.Text("c0"))
                    expectText("e:c0")
                    if (migration) {
                        val migrator = withTimeout(10.seconds) { nets.made.receive() }
                        withTimeout(10.seconds) { migrator.network.first { it == 1 } }
                        nets.current.value = 2
                        val (_, e) = withTimeout(10.seconds) { heard.migrations.receive() }
                        val failed = assertIs<MigrationEvent.Failed<*>>(e, "$e")
                        assertEquals(MigrationRefusal.DisabledByPeer, assertIs<MigrationRefusedException>(failed.cause).reason)
                    }
                    cut.getCompleted().gone = true
                    send(Frame.Text("c1")) // lost with the network
                    // bounded by the 1 s idle timeout of the dead connection
                    val outcome = withTimeoutOrNull(15.seconds) { runCatching { incoming.receive() } } ?: fail("the session hangs")
                    val failure = outcome.exceptionOrNull() ?: fail("a frame arrived after the network went away: ${outcome.getOrNull()}")
                    assertTrue(failure !is CancellationException, "the session fails, it is not cancelled: $failure")
                    // RFC 6455 section 7.1.5: closed with no Close frame received, "such as could occur if the underlying
                    // transport connection is lost", the close code "is considered to be 1006"
                    val reason = withTimeoutOrNull(5.seconds) { closeReason.await() }
                    assertEquals(CLOSED_ABNORMALLY, reason?.code, "$reason")
                    // the transport's cause: the idle timeout (RFC 9000 section 10.1) of the connection the session ran on
                    val lost = withTimeoutOrNull(5.seconds) { conn.closed.await() } ?: fail("the connection is still open")
                    assertEquals(TimeoutKind.Idle, assertIs<QuicException.ConnectionLost.Timeout>(lost, "$lost").kind)
                }
                assertTrue(heard.fallbacks.tryReceive().isFailure, "a WebSocket is not repeated over TCP")
                if (!migration) assertTrue(heard.migrations.tryReceive().isFailure, "nothing migrates without the option")
            }
        } finally {
            server.stop(100, 500)
        }
    }

    private fun ByteArray.part(i: Int) = copyOfRange(i * PART, (i + 1) * PART)

    private companion object {
        const val MIB_2 = 2 * 1024 * 1024
        const val MIB_8 = 8 * 1024 * 1024

        /** RFC 6455 section 7.4.1: 1006, a connection closed without a Close frame (Ktor keeps its constant internal). */
        const val CLOSED_ABNORMALLY: Short = 1006

        /** The large WebSocket messages: [PARTS] fragments of [PART] bytes, [HALF] of them before the network change. */
        const val PART = 32 * 1024
        const val PARTS = 8
        const val HALF = PARTS / 2

        /** The payload of the server's ping between the halves of its large message. */
        const val MID = "mid"
        val clientBig = ByteArray(PARTS * PART) { (it * 31 + 7).toByte() }
        val serverBig = ByteArray(PARTS * PART) { (it * 17 + 3).toByte() }
    }
}
