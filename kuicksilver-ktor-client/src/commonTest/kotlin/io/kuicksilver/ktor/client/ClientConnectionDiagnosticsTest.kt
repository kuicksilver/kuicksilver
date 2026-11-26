// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class, kotlin.concurrent.atomics.ExperimentalAtomicApi::class)

package io.kuicksilver.ktor.client

import io.ktor.client.network.sockets.ConnectTimeoutException
import io.ktor.client.plugins.HttpRequestTimeoutException
import io.ktor.client.plugins.HttpTimeout
import io.ktor.client.request.HttpRequestData
import io.ktor.client.request.get
import io.ktor.client.request.prepareGet
import io.ktor.client.statement.bodyAsChannel
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpProtocolVersion
import io.ktor.network.selector.SelectorManager
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.network.sockets.ServerSocket
import io.ktor.network.sockets.openReadChannel
import io.ktor.network.sockets.openWriteChannel
import io.ktor.server.response.respondBytesWriter
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.ktor.utils.io.readAvailable
import io.ktor.utils.io.readByteArray
import io.ktor.utils.io.writeFully
import io.kuicksilver.http3.Http3Endpoint
import io.kuicksilver.http3.Http3Headers
import io.kuicksilver.ktor.client.h1.TcpProgress
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.ConnectionInfo
import io.kuicksilver.quic.ConnectionListener
import io.kuicksilver.quic.QuicEndpointConfig
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.QuicServerConfig
import io.kuicksilver.quic.VersionProfile
import io.kuicksilver.quic.quicConfig
import io.kuicksilver.tls.TlsException
import io.kuicksilver.tls.TlsRole
import io.kuicksilver.tls.tlsConfig
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.IO
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeout
import kotlin.concurrent.atomics.AtomicReference
import kotlin.concurrent.atomics.update
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

/**
 * Which connection served a call and which transport a failure came from (docs/guide/ktor.md, "Which connection served
 * this call?" and "Why did this call fail?"): `ProtocolDiagnostics.connection`, `transport`, `connectFailures`,
 * `Throwable.kuicksilverDiagnostics` and the `connectFailed` event.
 */
class ClientConnectionDiagnosticsTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    /** What the listeners heard: the connection setups that failed, the failed calls with their diagnostics, the QUIC handles. */
    private class Heard : KuicksilverEventListener() {
        val connectFailures = AtomicReference(emptyList<ConnectFailure>())
        val failed = AtomicReference<Pair<Throwable, ProtocolDiagnostics?>?>(null)
        val tlsFailed = CompletableDeferred<Unit>()
        val handles = AtomicReference(emptyList<ConnectionInfo>())

        val quic =
            object : ConnectionListener {
                override fun onOpened(connection: ConnectionInfo) {
                    handles.update { it + connection }
                }
            }

        override fun connectFailed(
            request: HttpRequestData,
            failure: ConnectFailure,
        ) {
            connectFailures.update { it + failure }
            if (failure.stage == ConnectStage.TlsHandshake) tlsFailed.complete(Unit)
        }

        override fun callFailed(
            request: HttpRequestData,
            cause: Throwable,
        ) {
            failed.store(cause to request.attributes.getOrNull(KuicksilverDiagnosticsKey))
        }
    }

    private fun okServer(): io.ktor.server.application.Application.() -> Unit = { routing { get("/") { call.respondText("ok") } } }

    /**
     * A TCP listener on [port] that answers every ClientHello with a fatal `protocol_version` alert (70) and closes: what a
     * server that speaks TLS 1.2 at most answers a client that offers TLS 1.3 only (RFC 8446 section 4.2.1).
     */
    private suspend fun CoroutineScope.alertingTcp(
        selector: SelectorManager,
        port: Int,
    ): Pair<ServerSocket, Int> {
        val (listener, bound) = tcpOn(selector, port)
        launch {
            runCatching {
                while (true) {
                    val s = listener.accept()
                    launch {
                        runCatching {
                            val input = s.openReadChannel()
                            val output = s.openWriteChannel(autoFlush = true)
                            input.readAvailable(ByteArray(4096), 0, 4096) // the ClientHello, or its first part
                            output.writeFully(byteArrayOf(0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x46))
                            output.flush()
                        }
                        s.close()
                    }
                }
            }
        }
        return listener to bound
    }

    private fun assertProtocolVersionAlert(e: Throwable) {
        val alert = generateSequence(e) { it.cause }.filterIsInstance<TlsException.AlertReceived>().firstOrNull()
        assertEquals(70, alert?.code, "a protocol_version alert in $e")
    }

    @Test fun anHttp3ResponseCarriesItsQuicConnection() =
        h3Test {
            val (server, port) = testServer(module = okServer())
            val heard = Heard()
            try {
                testClient(Http3Discovery.Preferred, engine = {
                    observability { eventListener = heard }
                    http3 {
                        expert { raceHeadStart = RaceHeadStart.NoRace }
                    }
                    observability { connectionListener = heard.quic }
                }).use { c ->
                    val r = c.get("https://127.0.0.1:$port/")
                    assertEquals(HttpProtocolVersion.HTTP_3_0, r.version)
                    val d = assertNotNull(r.kuicksilverDiagnostics)
                    assertEquals(Transport.Quic, d.transport)
                    val q = assertIs<QuicConnectionSnapshot>(d.connection)
                    assertEquals(HttpProtocolVersion.HTTP_3_0, q.protocol)
                    assertFalse(q.reused, "the call's own new connection")
                    // the handle the connection listener heard: one connection, joined by identity and by its id
                    val handle = heard.handles.load().single()
                    assertEquals(handle.id, q.connectionId)
                    val path = assertNotNull(q.path)
                    assertTrue(path.active)
                    assertEquals(port, q.remoteAddress?.port)
                    assertNotNull(path.localConnectionId)
                    assertNotNull(path.remoteConnectionId)
                    assertTrue(q.smoothedRtt.isPositive(), "$q")
                    assertEquals(0, q.pathChanges)
                    // the version the handshake settled, the one the connection listener's handle reads too
                    assertSame(VersionProfile.V1, q.version)
                    assertSame(handle.version, q.version)
                    assertTrue(d.connectFailures.isEmpty(), "${d.connectFailures}")
                    // the snapshot's text names no connection ID
                    assertFalse(path.localConnectionId!! in q.toString(), "$q")
                    assertFalse(path.localConnectionId!! in d.toString(), "$d")
                    // the next call takes the same connection
                    val q2 = assertIs<QuicConnectionSnapshot>(c.get("https://127.0.0.1:$port/").kuicksilverDiagnostics?.connection)
                    assertTrue(q2.reused)
                    assertEquals(handle.id, q2.connectionId)
                }
            } finally {
                server.stop(100, 500)
            }
        }

    @Test fun aTcpResponseCarriesItsTcpConnection() =
        clientTest {
            val (server, port) = testServer(module = okServer())
            try {
                testClient(null).use { c ->
                    val r = c.get("https://127.0.0.1:$port/")
                    val d = assertNotNull(r.kuicksilverDiagnostics)
                    assertEquals(Transport.Tcp, d.transport)
                    val t = assertIs<TcpConnectionSnapshot>(d.connection)
                    assertEquals(r.version, t.protocol)
                    assertEquals(port, t.remoteAddress?.port)
                    assertNotNull(t.localAddress)
                    assertTrue(t.secure)
                    assertFalse(t.viaProxy)
                    assertFalse(t.reused)
                    assertEquals(if (r.version == HttpProtocolVersion.HTTP_2_0) "h2" else "http/1.1", t.alpn)
                    r.bodyAsText()
                    val t2 = assertIs<TcpConnectionSnapshot>(c.get("https://127.0.0.1:$port/").kuicksilverDiagnostics?.connection)
                    assertTrue(t2.reused, "the pooled connection")
                    assertEquals(t.localAddress, t2.localAddress)
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /** H3Only to a port whose UDP never answers: the QUIC handshake times out and the failure says QUIC, with the address. */
    @Test fun negative_aQuicHandshakeTimeoutFailsOverQuic() =
        clientTest {
            val selector = SelectorManager(Dispatchers.IO)
            val (udp, port) = udpOn(selector, 0)
            val heard = Heard()
            try {
                testClient(Http3Discovery.H3Only, engine = {
                    quicHandshakeTimeoutForTest = 300.milliseconds
                    observability { eventListener = heard }
                }).use { c ->
                    val e = assertFailsWith<QuicException.ConnectionLost.Timeout> { c.get("https://127.0.0.1:$port/") }
                    val d = assertNotNull(e.kuicksilverDiagnostics, "the exception carries the call's diagnostics")
                    assertEquals(Transport.Quic, d.transport)
                    assertEquals(HttpProtocolVersion.HTTP_3_0, d.protocol)
                    assertNull(d.connection, "no connection came up")
                    val f = d.connectFailures.single()
                    assertEquals(Transport.Quic, f.transport)
                    assertEquals(ConnectStage.QuicHandshake, f.stage)
                    assertEquals(port, f.address?.port)
                    assertEquals(QuicHandshakeProgress.NoPacketReceived, f.quicProgress, "nothing came back")
                    // the same failure (the exception thrown may be a copy coroutines made on the way, with this one's stack)
                    assertIs<QuicException.ConnectionLost.Timeout>(f.cause)
                    assertEquals(listOf(f), heard.connectFailures.load())
                    // the listener read the same diagnostics from the request in callFailed
                    val (cause, inCallback) = assertNotNull(heard.failed.load())
                    assertSame(d, cause.kuicksilverDiagnostics)
                    assertSame(d, inCallback)
                    assertTrue("failed over Quic" in d.toString(), "$d")
                }
            } finally {
                udp.close()
                selector.close()
            }
        }

    /** A TCP server that answers TLS 1.3 with a protocol_version alert: `connectFailed` says so, with the address. */
    @Test fun negative_aTlsAlertOverTcpIsReportedWithItsAddress() =
        clientTest {
            val selector = SelectorManager(Dispatchers.IO)
            val heard = Heard()
            try {
                coroutineScope {
                    val (listener, port) = alertingTcp(selector, 0)
                    testClient(null, engine = { observability { eventListener = heard } }).use { c ->
                        val e = assertFailsWith<Throwable> { c.get("https://127.0.0.1:$port/") }
                        assertProtocolVersionAlert(e)
                        val d = assertNotNull(e.kuicksilverDiagnostics)
                        assertEquals(Transport.Tcp, d.transport)
                        assertEquals(HttpProtocolVersion.HTTP_1_1, d.protocol)
                        assertNull(d.h3Failure)
                        val t = assertIs<TcpConnectionSnapshot>(d.connection, "the connection whose TLS failed")
                        assertNull(t.protocol, "no protocol agreed")
                        assertEquals(port, t.remoteAddress?.port)
                        val f = d.connectFailures.single()
                        assertEquals(ConnectStage.TlsHandshake, f.stage)
                        assertEquals(Transport.Tcp, f.transport)
                        assertEquals(port, f.address?.port)
                        assertProtocolVersionAlert(f.cause)
                        assertEquals(listOf(f), heard.connectFailures.load())
                    }
                    listener.close()
                }
            } finally {
                selector.close()
            }
        }

    /**
     * HTTP/3 first (UDP silent), then TCP, whose TLS fails: the thrown failure is TCP's, the diagnostics say TCP and carry
     * HTTP/3's failure and both setups.
     */
    @Test fun negative_bothTransportsFailedSaysTcpWithTheQuicFailure() =
        clientTest {
            val selector = SelectorManager(Dispatchers.IO)
            val heard = Heard()
            try {
                coroutineScope {
                    var alerting: ServerSocket? = null
                    val (udp, _, port) =
                        bindOnSamePort(
                            first = { p -> udpOn(selector, p) },
                            releaseFirst = { it.close() },
                            second = { p -> alertingTcp(selector, p).also { alerting = it.first } },
                            releaseSecond = { it.close() },
                        )
                    testClient(Http3Discovery.Preferred, engine = {
                        quicHandshakeTimeoutForTest = 300.milliseconds
                        observability { eventListener = heard }
                        http3 { expert { raceHeadStart = RaceHeadStart.NoRace } }
                    }).use { c ->
                        val e = assertFailsWith<Throwable> { c.get("https://127.0.0.1:$port/") }
                        assertProtocolVersionAlert(e)
                        val d = assertNotNull(e.kuicksilverDiagnostics)
                        assertEquals(Transport.Tcp, d.transport)
                        assertIs<QuicException.ConnectionLost.Timeout>(d.h3Failure)
                        assertEquals(FallbackReason.HandshakeTimeout, d.fallback)
                        assertTrue(d.raced)
                        assertIs<TcpConnectionSnapshot>(d.connection)
                        assertEquals(
                            listOf(ConnectStage.QuicHandshake, ConnectStage.TlsHandshake),
                            d.connectFailures.map { it.stage },
                        )
                        // HTTP/3's failure is in the thrown one too (suppressed), as before
                        assertTrue(e.suppressedExceptions.any { it === d.h3Failure }, "${e.suppressedExceptions}")
                        // the carrier's text: one line, transports, types and stages, no address or port
                        val carrier = e.suppressedExceptions.filterIsInstance<FailureDiagnostics>().single()
                        val text = carrier.toString()
                        assertFalse('\n' in text, text)
                        assertFalse("127.0.0.1" in text || "$port" in text, text)
                        assertTrue(
                            text.endsWith(
                                "kuicksilver: failed over TCP; HTTP/3 failed first: Timeout (HandshakeTimeout); " +
                                    "setups failed: QuicHandshake, TlsHandshake",
                            ),
                            text,
                        )
                    }
                    udp.close()
                    alerting?.close()
                }
            } finally {
                selector.close()
            }
        }

    /**
     * Attack: the TCP side of a race fails in TLS (and records its connection) before HTTP/3 wins: the call is HTTP/3's,
     * its connection the QUIC one, and the TCP failure stays listed.
     */
    @Test fun aTcpFailureOfALostRaceDoesNotBecomeTheConnection() =
        h3Test {
            val selector = SelectorManager(Dispatchers.IO)
            val heard = Heard()
            try {
                coroutineScope {
                    val scope = this
                    var alerting: ServerSocket? = null
                    val (h3, _, port) =
                        bindOnSamePort(
                            first = { p -> scope.h3Origin(port = p).let { it to it.localAddress.port } },
                            releaseFirst = { it.close() },
                            second = { p -> alertingTcp(selector, p).also { alerting = it.first } },
                            releaseSecond = { it.close() },
                        )
                    testClient(Http3Discovery.Preferred, engine = { observability { eventListener = heard } }).use { c ->
                        // the QUIC setup waits until the TCP side failed in TLS
                        (c.engine as KuicksilverEngine).h3.beforeSetupForTest = { withTimeout(10.seconds) { heard.tlsFailed.await() } }
                        val r = c.get("https://127.0.0.1:$port/")
                        assertEquals(HttpProtocolVersion.HTTP_3_0, r.version)
                        val d = assertNotNull(r.kuicksilverDiagnostics)
                        assertEquals(Transport.Quic, d.transport)
                        assertIs<QuicConnectionSnapshot>(d.connection)
                        assertEquals(listOf(ConnectStage.TlsHandshake), d.connectFailures.map { it.stage })
                    }
                    h3.close()
                    alerting?.close()
                }
            } finally {
                selector.close()
            }
        }

    /** Attack: concurrent calls on one HTTP/3 connection each get their own diagnostics, all naming that connection. */
    @Test fun concurrentCallsOnOneConnectionEachNameIt() =
        h3Test {
            val (server, port) = testServer(module = okServer())
            try {
                testClient(Http3Discovery.Preferred, engine = { http3 { expert { raceHeadStart = RaceHeadStart.NoRace } } }).use { c ->
                    val first = assertIs<QuicConnectionSnapshot>(c.get("https://127.0.0.1:$port/").kuicksilverDiagnostics?.connection)
                    val all =
                        coroutineScope {
                            List(8) { async { c.get("https://127.0.0.1:$port/").kuicksilverDiagnostics } }.awaitAll()
                        }
                    assertEquals(8, all.map { assertNotNull(it) }.toSet().size, "one object per call")
                    for (d in all) {
                        val q = assertIs<QuicConnectionSnapshot>(d!!.connection)
                        assertEquals(first.connectionId, q.connectionId)
                        assertTrue(q.reused)
                    }
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /** A TCP server that accepts and never answers: the TLS handshake runs into the connect timeout, reported at its address. */
    @Test fun negative_aTlsHandshakeThatNeverEndsIsATimeoutAtItsAddress() =
        clientTest {
            val selector = SelectorManager(Dispatchers.IO)
            val heard = Heard()
            try {
                coroutineScope {
                    val (listener, port) = tcpOn(selector, 0)
                    // kept open and silent until the end, then closed (the leak sentinel counts an accepted socket left open)
                    val sockets = AtomicReference(emptyList<io.ktor.network.sockets.Socket>())
                    val accepted = launch { runCatching { while (true) listener.accept().also { s -> sockets.update { it + s } } } }
                    testClient(null, engine = {
                        connectTimeout = 500.milliseconds
                        observability { eventListener = heard }
                    }).use { c ->
                        val e = assertFailsWith<ConnectTimeoutException> { c.get("https://127.0.0.1:$port/") }
                        val d = assertNotNull(e.kuicksilverDiagnostics)
                        assertEquals(Transport.Tcp, d.transport)
                        val f = d.connectFailures.single()
                        assertEquals(ConnectStage.TlsHandshake, f.stage)
                        assertEquals(port, f.address?.port)
                        assertIs<ConnectTimeoutException>(f.cause)
                        assertNull(f.quicProgress)
                        assertEquals(listOf(f), heard.connectFailures.load())
                    }
                    accepted.cancelAndJoin()
                    sockets.load().forEach { it.close() }
                    listener.close()
                }
            } finally {
                selector.close()
            }
        }

    /** A name lookup that never answers uses the whole connect timeout: one NameLookup failure, without an address. */
    @Test fun negative_aLookupThatNeverAnswersIsATimeoutWithoutAnAddress() =
        clientTest {
            testClient(null, engine = {
                connectTimeout = 300.milliseconds
                network { dns = Dns { awaitCancellation() } }
            }).use { c ->
                val e = assertFailsWith<ConnectTimeoutException> { c.get("https://never.test/") }
                val f = assertNotNull(e.kuicksilverDiagnostics).connectFailures.single()
                assertEquals(ConnectStage.NameLookup, f.stage)
                assertNull(f.address)
                assertIs<ConnectTimeoutException>(f.cause)
            }
        }

    /** The connect timeout ends a QUIC handshake that got no answer: QuicHandshake, NoPacketReceived, the timeout as cause. */
    @Test fun negative_aQuicConnectTimeoutWithoutAnswerSaysNoPacketReceived() =
        clientTest {
            val selector = SelectorManager(Dispatchers.IO)
            val (udp, port) = udpOn(selector, 0)
            try {
                testClient(Http3Discovery.H3Only, engine = {
                    connectTimeout = 500.milliseconds
                    quicHandshakeTimeoutForTest = 30.seconds
                }).use { c ->
                    val e = assertFailsWith<ConnectTimeoutException> { c.get("https://127.0.0.1:$port/") }
                    val d = assertNotNull(e.kuicksilverDiagnostics)
                    assertEquals(Transport.Quic, d.transport)
                    val f = d.connectFailures.single()
                    assertEquals(ConnectStage.QuicHandshake, f.stage)
                    assertEquals(port, f.address?.port)
                    assertEquals(QuicHandshakeProgress.NoPacketReceived, f.quicProgress)
                    assertIs<ConnectTimeoutException>(f.cause)
                }
            } finally {
                udp.close()
                selector.close()
            }
        }

    /** The server's first datagram arrives, then nothing: the connect timeout reports a handshake that started. */
    @Test fun negative_aQuicConnectTimeoutAfterAnAnswerSaysHandshakeStarted() =
        h3Test {
            coroutineScope {
                val ep = h3Origin()
                try {
                    udpRelay(ep.localAddress.port) { port, relay ->
                        relay.serverDatagramsLeft = 1
                        testClient(Http3Discovery.H3Only, engine = {
                            connectTimeout = 1.seconds
                            quicHandshakeTimeoutForTest = 30.seconds
                        }).use { c ->
                            val e = assertFailsWith<ConnectTimeoutException> { c.get("https://127.0.0.1:$port/") }
                            val f = assertNotNull(e.kuicksilverDiagnostics).connectFailures.single()
                            assertEquals(ConnectStage.QuicHandshake, f.stage)
                            assertEquals(QuicHandshakeProgress.HandshakeStarted, f.quicProgress)
                        }
                    }
                } finally {
                    ep.close()
                }
            }
        }

    /**
     * Ktor's request timeout cancels the call with its HttpRequestTimeoutException, the exception Ktor then throws: it
     * carries the diagnostics, with the connection in use, and `callFailed` has them too.
     */
    @Test fun aRequestTimeoutCarriesTheDiagnostics() =
        clientTest {
            val release = CompletableDeferred<Unit>()
            val (server, port) =
                testServer(module = {
                    routing {
                        get("/slow") {
                            release.await()
                            call.respondText("late")
                        }
                    }
                })
            val heard = Heard()
            try {
                testClient(null, engine = { observability { eventListener = heard } }) {
                    install(HttpTimeout) { requestTimeoutMillis = 300 }
                }.use { c ->
                    val e = assertFailsWith<HttpRequestTimeoutException> { c.get("https://127.0.0.1:$port/slow") }
                    val (cause, inCallback) = assertNotNull(heard.failed.load())
                    val d = assertNotNull(inCallback, "callFailed has the diagnostics")
                    assertEquals(Transport.Tcp, d.transport)
                    assertIs<TcpConnectionSnapshot>(d.connection)
                    assertIs<CancellationException>(cause)
                    val carried = generateSequence(cause as Throwable) { it.cause }.firstOrNull { it is HttpRequestTimeoutException }
                    assertSame(d, assertNotNull(carried, "the cancellation's cause").kuicksilverDiagnostics)
                    // the exception Ktor throws is that one
                    assertSame(carried, e)
                    assertSame(d, e.kuicksilverDiagnostics)
                }
            } finally {
                release.complete(Unit)
                server.stop(100, 500)
            }
        }

    /** A call the application cancels carries nothing on its exception; `callFailed` has its diagnostics. */
    @Test fun aCancelledCallHasItsDiagnosticsInCallFailedOnly() =
        clientTest {
            val reached = CompletableDeferred<Unit>()
            val release = CompletableDeferred<Unit>()
            val (server, port) =
                testServer(module = {
                    routing {
                        get("/slow") {
                            reached.complete(Unit)
                            release.await()
                            call.respondText("late")
                        }
                    }
                })
            val heard = Heard()
            try {
                testClient(null, engine = { observability { eventListener = heard } }).use { c ->
                    coroutineScope {
                        val call = async { c.get("https://127.0.0.1:$port/slow") }
                        withTimeout(10.seconds) { reached.await() }
                        call.cancel()
                        val e = assertFailsWith<CancellationException> { call.await() }
                        assertNull(e.kuicksilverDiagnostics)
                    }
                    val (cause, d) = withTimeout(10.seconds) { heardFailure(heard) }
                    assertIs<CancellationException>(cause)
                    assertEquals(Transport.Tcp, assertNotNull(d).transport)
                    assertTrue(cause.suppressedExceptions.none { it is FailureDiagnostics })
                }
            } finally {
                release.complete(Unit)
                server.stop(100, 500)
            }
        }

    private suspend fun heardFailure(heard: Heard): Pair<Throwable, ProtocolDiagnostics?> {
        while (true) {
            heard.failed.load()?.let { return it }
            kotlinx.coroutines.yield()
        }
    }

    /**
     * Attack on the lock-free `reused`: while a test holds the HTTP/3 pool's lock right after the request acquired its
     * connection, the request still completes (it takes the lock no more after acquiring, as before the diagnostics), and
     * `reused` stays right: one call on a new connection, every later one reused.
     */
    @Test fun anHttp3RequestTakesNoPoolLockAfterAcquiring() =
        h3Test {
            val (server, port) = testServer(module = okServer())
            try {
                testClient(Http3Discovery.H3Only).use { c ->
                    val first = assertIs<QuicConnectionSnapshot>(c.get("https://127.0.0.1:$port/").kuicksilverDiagnostics?.connection)
                    assertFalse(first.reused)
                    val engine = c.engine as KuicksilverEngine
                    coroutineScope {
                        val held = CompletableDeferred<Unit>()
                        val done = CompletableDeferred<Unit>()
                        engine.h3.afterAcquireForTest = {
                            launch {
                                engine.h3.withLockForTest {
                                    held.complete(Unit)
                                    done.await()
                                }
                            }
                            held.await()
                        }
                        try {
                            val r = withTimeout(10.seconds) { c.get("https://127.0.0.1:$port/") }
                            assertTrue(assertIs<QuicConnectionSnapshot>(r.kuicksilverDiagnostics?.connection).reused)
                        } finally {
                            engine.h3.afterAcquireForTest = null
                            done.complete(Unit)
                        }
                    }
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /** The route's only connection slot is taken: the connect timeout is spent waiting for it, and says PoolWait. */
    @Test fun negative_aConnectTimeoutWaitingForAPoolSlotSaysPoolWait() =
        clientTest {
            val reached = CompletableDeferred<Unit>()
            val release = CompletableDeferred<Unit>()
            val (server, port) =
                testServer(module = {
                    routing {
                        get("/slow") {
                            reached.complete(Unit)
                            release.await()
                            call.respondText("late")
                        }
                    }
                })
            try {
                testClient(null, engine = {
                    pool { maxConnectionsPerRoute = 1 }
                    connectTimeout = 500.milliseconds
                    http2 { enabled = false }
                }).use { c ->
                    coroutineScope {
                        val holder = async { c.get("https://127.0.0.1:$port/slow") }
                        withTimeout(10.seconds) { reached.await() }
                        val e = assertFailsWith<ConnectTimeoutException> { c.get("https://127.0.0.1:$port/slow") }
                        val f = assertNotNull(e.kuicksilverDiagnostics).connectFailures.single()
                        assertEquals(ConnectStage.PoolWait, f.stage)
                        assertNull(f.address)
                        release.complete(Unit)
                        holder.await()
                    }
                }
            } finally {
                release.complete(Unit)
                server.stop(100, 500)
            }
        }

    /**
     * Attack on how a QUIC failure finds its connection: two origins set up at once to one address, one whose certificate
     * matches (`server.test`) and one whose does not (`other.test`). The failure names the connection its own setup made,
     * the one the listener saw closed by the TLS failure, never the other origin's.
     */
    @Test fun twoSetupsToOneAddressEachNameTheirOwnConnection() =
        h3Test {
            val (server, port) = testServer(module = okServer())
            val heard = Heard()
            val closedByTls = AtomicReference(emptyList<String>())
            val quic =
                object : ConnectionListener {
                    override fun onClosed(
                        connection: ConnectionInfo,
                        reason: QuicException.ConnectionLost,
                    ) {
                        if (reason is QuicException.ConnectionLost.TransportClosed && reason.code in 0x100L..0x1ffL) {
                            closedByTls.update { it + connection.id }
                        }
                    }
                }
            try {
                testClient(Http3Discovery.H3Only, engine = {
                    observability {
                        eventListener = heard
                        connectionListener = quic
                    }
                    resolverForTest = { _, p ->
                        listOf(
                            io.kuicksilver.ktor.network
                                .TcpAddress(byteArrayOf(127, 0, 0, 1), p),
                        )
                    }
                }).use { c ->
                    coroutineScope {
                        val good = async { c.get("https://server.test:$port/") }
                        val bad = async { runCatching { c.get("https://other.test:$port/") }.exceptionOrNull() }
                        val ok = assertIs<QuicConnectionSnapshot>(good.await().kuicksilverDiagnostics?.connection)
                        val e = assertNotNull(bad.await(), "other.test does not match the certificate")
                        val f = assertNotNull(e.kuicksilverDiagnostics).connectFailures.single()
                        assertEquals(ConnectStage.QuicHandshake, f.stage)
                        assertEquals(QuicHandshakeProgress.HandshakeStarted, f.quicProgress)
                        val id = assertNotNull(f.connectionId)
                        assertTrue(id != ok.connectionId, "the failure names the other origin's connection")
                        withTimeout(10.seconds) { while (id !in closedByTls.load()) kotlinx.coroutines.yield() }
                    }
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /**
     * Attack on the carrier: two HTTP/3 calls on one connection, one waiting for its response, one reading its body, and
     * the connection ends under both. The failure of the first carries its own diagnostics; the second, which reads the
     * connection's one failure from its body, and the connection listener's `onClosed` reason see none of them.
     */
    @Test fun aConnectionFailureCarriesNoOtherCallsDiagnostics() =
        h3Test {
            val held = CompletableDeferred<Unit>()
            val streaming = CompletableDeferred<Unit>()
            val release = CompletableDeferred<Unit>()
            val (server, port) =
                testServer(module = {
                    routing {
                        get("/hold") {
                            held.complete(Unit)
                            release.await()
                            call.respondText("late")
                        }
                        get("/stream") {
                            call.respondBytesWriter {
                                writeFully(ByteArray(1024))
                                flush()
                                streaming.complete(Unit)
                                release.await()
                            }
                        }
                    }
                })
            val reasons = AtomicReference(emptyList<QuicException.ConnectionLost>())
            val quic =
                object : ConnectionListener {
                    override fun onClosed(
                        connection: ConnectionInfo,
                        reason: QuicException.ConnectionLost,
                    ) {
                        reasons.update { it + reason }
                    }
                }
            try {
                testClient(Http3Discovery.H3Only, engine = { observability { connectionListener = quic } }).use { c ->
                    coroutineScope {
                        // the body is read on only after the other call failed (and its diagnostics went wherever they went)
                        val aFailed = CompletableDeferred<Unit>()
                        val bodyRead = CompletableDeferred<Unit>() // the other call read the first bytes of its body
                        val body =
                            async {
                                c.prepareGet("https://127.0.0.1:$port/stream").execute { r ->
                                    val ch = r.bodyAsChannel()
                                    val b = ByteArray(4096)
                                    var got = 0
                                    while (got < 1024) {
                                        val n = ch.readAvailable(b, 0, b.size)
                                        check(n >= 0) { "the body ended after $got bytes: ${ch.closedCause}" }
                                        got += n
                                    }
                                    bodyRead.complete(Unit)
                                    aFailed.await()
                                    runCatching { while (ch.readAvailable(b, 0, b.size) >= 0) continue }.exceptionOrNull() ?: ch.closedCause
                                }
                            }
                        withTimeout(10.seconds) { bodyRead.await() }
                        val waiting = async { runCatching { c.get("https://127.0.0.1:$port/hold") }.exceptionOrNull() }
                        withTimeout(10.seconds) { held.await() }
                        val conn =
                            (c.engine as KuicksilverEngine)
                                .h3
                                .connectionsForTest()
                                .single()
                        conn.quic.close(0x101, "test kills the connection")
                        val aErr = assertNotNull(withTimeout(10.seconds) { waiting.await() }, "the waiting call failed")
                        val dA = assertNotNull(aErr.kuicksilverDiagnostics, "its own failure carries its diagnostics: $aErr")
                        assertEquals(Transport.Quic, dA.transport)
                        assertConnectionWideUntouched(dA, aErr, conn.closed.await(), conn.quic.closed.await())
                        aFailed.complete(Unit)
                        val bErr = assertNotNull(withTimeout(10.seconds) { body.await() }, "the body read failed")
                        assertNull(bErr.kuicksilverDiagnostics, "the body's failure is the connection's: $bErr")
                        // the attack needs the one instance: the body's failure is (or wraps) the one the other call got
                        val shared = generateSequence(bErr) { it.cause }.toList()
                        assertTrue(shared.any { it::class == aErr::class }, "$shared")
                        withTimeout(10.seconds) { while (reasons.load().isEmpty()) kotlinx.coroutines.yield() }
                        for (r in reasons.load()) {
                            assertNull(r.kuicksilverDiagnostics, "onClosed's reason")
                            assertTrue(r.suppressedExceptions.none { it is FailureDiagnostics }, "$r")
                        }
                    }
                }
            } finally {
                release.complete(Unit)
                server.stop(100, 500)
            }
        }

    /**
     * The carrier never goes onto a connection's shared failure: two calls failing with one connection-scoped instance
     * each throw their own copy (same type) carrying their own diagnostics, and the instance itself, which other streams
     * and the connection listener get, and any later copy of it, carry none. A per-call failure is carried as it is.
     */
    @Test fun negative_aSharedConnectionFailureNeverCarriesACallsDiagnostics() {
        val shared =
            listOf<Throwable>(
                QuicException.ConnectionLost.ApplicationClosed(0x101, "", io.kuicksilver.quic.Initiator.Local),
                io.kuicksilver.http3.Http3Exception
                    .Protocol(0x101, io.kuicksilver.quic.Initiator.Local, null),
            )
        for (x in shared) {
            val a = ProtocolDiagnostics().also { it.transport = Transport.Quic }
            val b = ProtocolDiagnostics().also { it.transport = Transport.Quic }
            // the pools record the connection's own end by identity when a call fails on it
            a.connectionWide(x)
            b.connectionWide(x)
            val ta = settleFailure(a, x)
            val tb = settleFailure(b, x)
            assertTrue(ta !== x && tb !== x && ta !== tb, "each call throws its own copy")
            assertEquals(x::class, ta::class)
            assertSame(a, ta.kuicksilverDiagnostics)
            assertSame(b, tb.kuicksilverDiagnostics)
            assertNull(x.kuicksilverDiagnostics, "the shared instance: $x")
            @OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)
            assertNull((x as kotlinx.coroutines.CopyableThrowable<*>).createCopy()?.kuicksilverDiagnostics, "a later copy of it")
        }
        // a setup's failure (engine calls only): copied where it can be, else carried, marked shared by a second call
        val timeout =
            io.ktor.client.network.sockets
                .ConnectTimeoutException("connect timeout", null)
        val sa = ProtocolDiagnostics().also { it.setupShared(timeout) }
        val sb = ProtocolDiagnostics().also { it.setupShared(timeout) }
        val ca = settleFailure(sa, timeout)
        val cb = settleFailure(sb, timeout)
        assertTrue(ca !== timeout && cb !== timeout && ca !== cb)
        assertSame(sa, ca.kuicksilverDiagnostics)
        assertSame(sb, cb.kuicksilverDiagnostics)
        val lookup = kotlinx.io.IOException("no such host")
        val la = ProtocolDiagnostics().also { it.setupShared(lookup) }
        assertSame(lookup, settleFailure(la, lookup), "no copy: the instance itself")
        assertSame(la, lookup.kuicksilverDiagnostics, "one call: its own")
        val lb = ProtocolDiagnostics().also { it.setupShared(lookup) }
        settleFailure(lb, lookup)
        assertNull(lookup.kuicksilverDiagnostics, "two calls: neither")
        val own = kotlinx.io.IOException("this call's own")
        val d = ProtocolDiagnostics()
        d.connectionWide(IllegalStateException("another instance"))
        assertSame(own, settleFailure(d, own), "only the recorded instances are copied, whatever the type")
        assertSame(d, own.kuicksilverDiagnostics)
    }

    /**
     * What a TCP connect timeout reports, by what the setup was doing: the addresses being connected to, the step on the
     * connected socket, the lookup; nothing once the connection is set up (a plain connection, after TLS: an HTTP/2
     * preface or a health PING are no step of the setup).
     */
    @Test fun aTcpConnectTimeoutReportsOnlyWhatTheSetupWasDoing() {
        val timeout = IllegalStateException("timeout")
        val a = InetSocketAddress("192.0.2.1", 443)
        assertEquals(emptyList<ConnectFailure>(), TcpProgress().timedOut(timeout), "nothing started")
        val lookup = TcpProgress().apply { stage = ConnectStage.NameLookup }
        assertEquals(listOf(ConnectStage.NameLookup to null), lookup.timedOut(timeout).map { it.stage to it.address })
        lookup.trying(a, proxy = false)
        assertEquals(listOf(ConnectStage.TcpConnect to a), lookup.timedOut(timeout).map { it.stage to it.address })
        val tls = TcpProgress().apply { connected(a, ConnectStage.TlsHandshake) }
        assertEquals(listOf(ConnectStage.TlsHandshake to a), tls.timedOut(timeout).map { it.stage to it.address })
        tls.stage = null // TLS done: what follows is no step of the setup
        assertEquals(emptyList<ConnectFailure>(), tls.timedOut(timeout))
        val plain = TcpProgress().apply { connected(a, null) }
        assertEquals(emptyList<ConnectFailure>(), plain.timedOut(timeout))
    }

    /**
     * The first call on a new HTTP/3 connection claims it as new even when it fails before its exchange: its failure's
     * snapshot says new, and the next call says reused.
     */
    @Test fun aCallFailingBeforeItsExchangeStillClaimsTheNewConnection() =
        h3Test {
            val (server, port) = testServer(module = okServer())
            try {
                testClient(Http3Discovery.H3Only).use { c ->
                    val engine = c.engine as KuicksilverEngine
                    engine.h3.afterAcquireForTest = {
                        engine.h3.afterAcquireForTest = null
                        throw IllegalStateException("fails after acquiring, before the exchange")
                    }
                    val e = assertFailsWith<IllegalStateException> { c.get("https://127.0.0.1:$port/") }
                    assertFalse(assertIs<QuicConnectionSnapshot>(e.kuicksilverDiagnostics?.connection).reused, "the new connection")
                    assertTrue(
                        assertIs<QuicConnectionSnapshot>(c.get("https://127.0.0.1:$port/").kuicksilverDiagnostics?.connection).reused,
                    )
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /**
     * The peer closes the HTTP/3 connection with H3_REQUEST_REJECTED (a RequestNotProcessed, which no type list of
     * connection errors named) while another call reads its body on it: the waiting call, out of repeats, throws its own
     * copy with its diagnostics; the body's failure, the connection's one instance, carries none.
     */
    @Test fun aRequestRejectedCloseCarriesNoOtherCallsDiagnostics() =
        h3Test {
            coroutineScope {
                val onThird = CompletableDeferred<Unit>()
                val streaming = CompletableDeferred<Unit>()
                val closeNow = CompletableDeferred<Unit>()
                val tls =
                    tlsConfig(TlsRole.Server) {
                        alpn = listOf(Http3Endpoint.H3)
                        identity = ClientFixtures.identity()
                    }
                val ep =
                    Http3Endpoint.bind(
                        InetSocketAddress("127.0.0.1", 0),
                        QuicEndpointConfig
                            .Builder()
                            .apply {
                                server =
                                    QuicServerConfig
                                        .Builder(tls)
                                        .build()
                            }.build(),
                    )
                val server =
                    launch {
                        var n = 0
                        while (true) {
                            val conn = ep.accept()
                            val index = ++n
                            launch {
                                runCatching {
                                    while (true) {
                                        val r = conn.acceptRequest()
                                        launch {
                                            runCatching {
                                                if (r.path == "/stream") {
                                                    val w = r.respond(200, Http3Headers(emptyList()))
                                                    w.output.writeFully(ByteArray(1024))
                                                    w.output.flush()
                                                    streaming.complete(Unit)
                                                    awaitCancellation()
                                                } else if (index < 3) {
                                                    conn.quic.close(0x10B, "rejected") // H3_REQUEST_REJECTED: the call repeats
                                                } else {
                                                    onThird.complete(Unit)
                                                    closeNow.await()
                                                    conn.quic.close(0x10B, "rejected")
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                val port = ep.localAddress.port
                try {
                    testClient(Http3Discovery.H3Only).use { c ->
                        val waiting = async { runCatching { c.get("https://127.0.0.1:$port/hold") }.exceptionOrNull() }
                        withTimeout(20.seconds) { onThird.await() } // its third connection, the last repeat
                        val aFailed = CompletableDeferred<Unit>()
                        val bodyRead = CompletableDeferred<Unit>() // the other call read the first bytes of its body
                        val body =
                            async {
                                c.prepareGet("https://127.0.0.1:$port/stream").execute { r ->
                                    val ch = r.bodyAsChannel()
                                    val b = ByteArray(4096)
                                    var got = 0
                                    while (got < 1024) {
                                        val n = ch.readAvailable(b, 0, b.size)
                                        check(n >= 0) { "the body ended after $got bytes: ${ch.closedCause}" }
                                        got += n
                                    }
                                    bodyRead.complete(Unit)
                                    aFailed.await()
                                    runCatching { while (ch.readAvailable(b, 0, b.size) >= 0) continue }.exceptionOrNull() ?: ch.closedCause
                                }
                            }
                        withTimeout(10.seconds) { bodyRead.await() }
                        val conn =
                            (c.engine as KuicksilverEngine)
                                .h3
                                .connectionsForTest()
                                .single()
                        closeNow.complete(Unit)
                        val aErr = assertNotNull(withTimeout(10.seconds) { waiting.await() })
                        val dA = assertNotNull(aErr.kuicksilverDiagnostics, "its own failure carries its diagnostics: $aErr")
                        assertEquals(3, dA.attempts)
                        val closed = conn.closed.await()
                        assertIs<io.kuicksilver.http3.Http3Exception.RequestNotProcessed>(closed, "the session's end: $closed")
                        assertConnectionWideUntouched(dA, aErr, closed, conn.quic.closed.await())
                        aFailed.complete(Unit)
                        val bErr = assertNotNull(withTimeout(10.seconds) { body.await() })
                        assertNull(bErr.kuicksilverDiagnostics, "the body's failure is the connection's: $bErr")
                    }
                } finally {
                    server.cancel()
                    ep.close()
                }
            }
        }

    /**
     * An HTTP/2 connection that drops under two calls: the one waiting for its response throws its own copy of the
     * connection's close, with its diagnostics; the one reading its body gets the connection's one instance, without them.
     */
    @Test fun anHttp2ConnectionDropCarriesOnlyTheFailingCallsDiagnostics() =
        clientTest {
            val streaming = CompletableDeferred<Unit>()
            tlsWithSilentUdp(listOf("h2"), silentUdp = false, handler = { _, _, input, output ->
                fun frame(
                    type: Int,
                    flags: Int,
                    stream: Int,
                    payload: ByteArray = ByteArray(0),
                ): ByteArray =
                    byteArrayOf(
                        (payload.size shr 16).toByte(),
                        (payload.size shr 8).toByte(),
                        payload.size.toByte(),
                        type.toByte(),
                        flags.toByte(),
                        (stream ushr 24).toByte(),
                        (stream shr 16).toByte(),
                        (stream shr 8).toByte(),
                        stream.toByte(),
                    ) + payload
                input.readByteArray(24) // the preface
                output.writeFully(frame(4, 0, 0))
                output.flush()
                var requests = 0
                while (true) {
                    val head = input.readByteArray(9)
                    val len = ((head[0].toInt() and 0xff) shl 16) or ((head[1].toInt() and 0xff) shl 8) or (head[2].toInt() and 0xff)
                    val type = head[3].toInt() and 0xff
                    val flags = head[4].toInt() and 0xff
                    val stream =
                        ((head[5].toInt() and 0x7f) shl 24) or ((head[6].toInt() and 0xff) shl 16) or
                            ((head[7].toInt() and 0xff) shl 8) or (head[8].toInt() and 0xff)
                    input.readByteArray(len)
                    if (type == 4 && flags and 1 == 0) {
                        output.writeFully(frame(4, 1, 0))
                        output.flush()
                    }
                    if (type == 1 && ++requests == 1) {
                        // the first: a response that keeps streaming
                        output.writeFully(frame(1, 0x4, stream, byteArrayOf(0x88.toByte())))
                        output.writeFully(frame(0, 0, stream, ByteArray(1024)))
                        output.flush()
                        streaming.complete(Unit)
                    } else if (type == 1) {
                        return@tlsWithSilentUdp // the second: the connection drops (the handler's end closes it)
                    }
                }
            }) { port ->
                testClient(null).use { c ->
                    coroutineScope {
                        val aFailed = CompletableDeferred<Unit>()
                        val bodyRead = CompletableDeferred<Unit>() // the other call read the first bytes of its body
                        val body =
                            async {
                                c.prepareGet("https://127.0.0.1:$port/stream").execute { r ->
                                    assertEquals(HttpProtocolVersion.HTTP_2_0, r.version)
                                    val ch = r.bodyAsChannel()
                                    val b = ByteArray(4096)
                                    var got = 0
                                    while (got < 1024) {
                                        val n = ch.readAvailable(b, 0, b.size)
                                        check(n >= 0) { "the body ended after $got bytes: ${ch.closedCause}" }
                                        got += n
                                    }
                                    bodyRead.complete(Unit)
                                    aFailed.await()
                                    runCatching { while (ch.readAvailable(b, 0, b.size) >= 0) continue }.exceptionOrNull() ?: ch.closedCause
                                }
                            }
                        withTimeout(10.seconds) { bodyRead.await() }
                        val conn =
                            (c.engine as KuicksilverEngine)
                                .h1
                                .h2
                                .connectionsForTest()
                                .single()
                        val aErr = assertNotNull(runCatching { c.get("https://127.0.0.1:$port/hold") }.exceptionOrNull())
                        val dA = assertNotNull(aErr.kuicksilverDiagnostics, "its own failure carries its diagnostics: $aErr")
                        assertEquals(Transport.Tcp, dA.transport)
                        assertEquals(HttpProtocolVersion.HTTP_2_0, dA.connection?.protocol)
                        assertConnectionWideUntouched(dA, aErr, assertNotNull(conn.client.closeCause, "the connection's end"))
                        aFailed.complete(Unit)
                        val bErr = assertNotNull(withTimeout(10.seconds) { body.await() })
                        assertNull(bErr.kuicksilverDiagnostics, "the body's failure is the connection's: $bErr")
                    }
                }
            }
        }

    /**
     * The connection's own end, the instances every call on it (and the listener) gets: the failing call's pool recorded each
     * of them (by identity), none carries a call's diagnostics, and the call threw something else, its own.
     */
    private fun assertConnectionWideUntouched(
        d: ProtocolDiagnostics,
        thrown: Throwable,
        vararg shared: Throwable,
    ) {
        for (x in shared) {
            assertTrue(d.isConnectionWide(x), "the pool recorded the connection's end: $x")
            assertTrue(x.suppressedExceptions.none { it is FailureDiagnostics }, "the shared instance carries a call's: $x")
            assertNull(x.kuicksilverDiagnostics, "$x")
            assertTrue(thrown !== x, "the call threw the shared instance $x")
        }
    }

    /**
     * H3Only to a name the resolver cannot answer: the setup's failure (a fresh IOException, which coroutines cannot copy)
     * still carries the call's diagnostics, over QUIC.
     */
    @Test fun negative_anH3OnlySetupFailureThatCannotBeCopiedCarriesTheDiagnostics() =
        clientTest {
            testClient(Http3Discovery.H3Only, engine = {
                network { dns = Dns { throw kotlinx.io.IOException("no such host") } }
            }).use { c ->
                val e = assertFailsWith<Throwable> { c.get("https://never.test/") }
                val d = assertNotNull(e.kuicksilverDiagnostics, "the call's diagnostics: $e")
                assertEquals(Transport.Quic, d.transport)
            }
        }

    /** One exception that ends two calls (a connection's failure, shared) names neither; a cancellation carries nothing. */
    @Test fun negative_aSharedOrCancellingExceptionCarriesNoDiagnostics() {
        val a = ProtocolDiagnostics()
        val b = ProtocolDiagnostics()
        val own = IllegalStateException("own")
        attachDiagnostics(own, a)
        attachDiagnostics(own, a) // the same call twice: still its own
        assertSame(a, own.kuicksilverDiagnostics)
        assertSame(a, RuntimeException("wrapper", own).kuicksilverDiagnostics, "found through the causes")
        val shared = kotlinx.io.IOException("shared")
        attachDiagnostics(shared, a)
        attachDiagnostics(shared, b)
        assertNull(shared.kuicksilverDiagnostics, "two calls failed with one exception: neither is named")
        val cancelled = CancellationException("cancelled")
        attachDiagnostics(cancelled, a)
        assertNull(cancelled.kuicksilverDiagnostics)
        assertTrue(cancelled.suppressedExceptions.isEmpty())
        assertNull(RuntimeException("never attached").kuicksilverDiagnostics)
    }
}
