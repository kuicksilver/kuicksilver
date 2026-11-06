// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import io.ktor.client.HttpClient
import io.ktor.client.request.get
import io.ktor.client.request.prepareGet
import io.ktor.client.statement.bodyAsChannel
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpProtocolVersion
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.server.request.httpVersion
import io.ktor.server.response.respondBytesWriter
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.readAvailable
import io.ktor.utils.io.writeFully
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
import io.kuicksilver.quic.quicConfig
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

/**
 * `http3 { connectionMigration }` (U.4a, RFC 9000 section 9): pooled HTTP/3 connections follow a network source. The
 * "networks" are a test flow of numbers; a new network is a new loopback socket, and the network the connection leaves
 * goes deaf ([CuttableIo] under the engine's endpoint), as a Wi-Fi interface does when the device walks away from it.
 */
@OptIn(ExperimentalKuicksilverApi::class, ExperimentalAtomicApi::class)
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
    ): HttpClient =
        testClient(Http3DiscoveryMode.Preferred, engine = {
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

    private companion object {
        const val MIB_2 = 2 * 1024 * 1024
        const val MIB_8 = 8 * 1024 * 1024
    }
}
