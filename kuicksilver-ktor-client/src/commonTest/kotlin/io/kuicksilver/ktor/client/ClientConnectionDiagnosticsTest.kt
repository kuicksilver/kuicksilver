// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class, kotlin.concurrent.atomics.ExperimentalAtomicApi::class)

package io.kuicksilver.ktor.client

import io.ktor.client.request.HttpRequestData
import io.ktor.client.request.get
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpProtocolVersion
import io.ktor.network.selector.SelectorManager
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.network.sockets.ServerSocket
import io.ktor.network.sockets.openReadChannel
import io.ktor.network.sockets.openWriteChannel
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.ktor.utils.io.readAvailable
import io.ktor.utils.io.writeFully
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.ConnectionInfo
import io.kuicksilver.quic.ConnectionListener
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.quicConfig
import io.kuicksilver.tls.TlsException
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.IO
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
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
                testClient(Http3DiscoveryMode.Preferred, engine = {
                    eventListener = heard
                    http3 {
                        hardDelay = Duration.INFINITE
                        connectionListener = heard.quic
                    }
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
                    assertSame(handle, q.info)
                    val path = assertNotNull(q.path)
                    assertTrue(path.active)
                    assertEquals(port, q.remoteAddress?.port)
                    assertNotNull(path.localConnectionId)
                    assertNotNull(path.remoteConnectionId)
                    assertTrue(q.smoothedRtt.isPositive(), "$q")
                    assertEquals(0, q.pathChanges)
                    assertTrue(d.connectFailures.isEmpty(), "${d.connectFailures}")
                    // the snapshot's text names no connection ID
                    assertFalse(path.localConnectionId!! in q.toString(), "$q")
                    assertFalse(path.localConnectionId!! in d.toString(), "$d")
                    // the next call takes the same connection
                    val q2 = assertIs<QuicConnectionSnapshot>(c.get("https://127.0.0.1:$port/").kuicksilverDiagnostics?.connection)
                    assertTrue(q2.reused)
                    assertSame(handle, q2.info)
                }
            } finally {
                server.stop(100, 500)
            }
        }

    @Test fun aTcpResponseCarriesItsTcpConnection() =
        clientTest {
            val (server, port) = testServer(module = okServer())
            try {
                testClient(Http3DiscoveryMode.H1Only).use { c ->
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
                testClient(Http3DiscoveryMode.H3Only, engine = {
                    quic = quicConfig { handshakeTimeout = 300.milliseconds }
                    eventListener = heard
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
                    testClient(Http3DiscoveryMode.H1Only, engine = { eventListener = heard }).use { c ->
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
                    testClient(Http3DiscoveryMode.Preferred, engine = {
                        quic = quicConfig { handshakeTimeout = 300.milliseconds }
                        eventListener = heard
                        http3 { hardDelay = Duration.INFINITE }
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
                    testClient(Http3DiscoveryMode.Preferred, engine = { eventListener = heard }).use { c ->
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
                testClient(Http3DiscoveryMode.Preferred, engine = { http3 { hardDelay = Duration.INFINITE } }).use { c ->
                    val first = assertIs<QuicConnectionSnapshot>(c.get("https://127.0.0.1:$port/").kuicksilverDiagnostics?.connection)
                    val all =
                        coroutineScope {
                            List(8) { async { c.get("https://127.0.0.1:$port/").kuicksilverDiagnostics } }.awaitAll()
                        }
                    assertEquals(8, all.map { assertNotNull(it) }.toSet().size, "one object per call")
                    for (d in all) {
                        val q = assertIs<QuicConnectionSnapshot>(d!!.connection)
                        assertSame(first.info, q.info)
                        assertTrue(q.reused)
                    }
                }
            } finally {
                server.stop(100, 500)
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
