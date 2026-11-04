// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class, kotlin.concurrent.atomics.ExperimentalAtomicApi::class)

package io.kuicksilver.ktor.client

import io.ktor.client.engine.ProxyBuilder
import io.ktor.client.request.HttpRequestData
import io.ktor.client.request.get
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpProtocolVersion
import io.ktor.http.Url
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.ktor.utils.io.writeStringUtf8
import io.kuicksilver.http3.Http3Endpoint
import io.kuicksilver.http3.Http3ErrorCode
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.KuicksilverLogger
import io.kuicksilver.quic.LogLevel
import io.kuicksilver.quic.QuicEndpoint
import io.kuicksilver.quic.QuicEndpointConfig
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.QuicServerConfig
import io.kuicksilver.quic.quicConfig
import io.kuicksilver.tls.SpkiSha256
import io.kuicksilver.tls.TlsRole
import io.kuicksilver.tls.TrustConfig
import io.kuicksilver.tls.tlsConfig
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull
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
import kotlin.test.assertTrue
import kotlin.test.fail
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

/**
 * Per-call protocol diagnostics through the engine (docs/guide/ktor.md, "Why did this request not use HTTP/3?"): the
 * response attribute, the log line, and their agreement with the event listener. Races whose order matters use
 * `hardDelay = Duration.INFINITE` (HTTP/1.1 only once HTTP/3 failed) or hold the HTTP/3 setup, so no outcome depends on
 * which loopback connection is faster.
 */
class ClientDiagnosticsTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    /** The engine's diagnostic lines (`kuicksilver: ...`) at every level, with their level. */
    internal class DiagnosticLines(
        private val enabled: LogLevel = LogLevel.Debug,
    ) : KuicksilverLogger {
        private val taken = AtomicReference(emptyList<Pair<LogLevel, String>>())
        val lines: List<Pair<LogLevel, String>> get() = taken.load()

        override fun isEnabled(level: LogLevel): Boolean = level >= enabled

        override fun log(
            level: LogLevel,
            message: String,
            cause: Throwable?,
        ) {
            if (message.startsWith("kuicksilver: ")) taken.update { it + (level to message) }
        }
    }

    /** The reasons protocolSelected heard, and the alternatives marked broken. */
    private class Reasons : KuicksilverEventListener() {
        val selected = AtomicReference(emptyList<ProtocolReason>())
        val broken = CompletableDeferred<String>()
        val failed = AtomicReference<Pair<Throwable, ProtocolDiagnostics?>?>(null)

        override fun protocolSelected(
            request: HttpRequestData,
            protocol: HttpProtocolVersion,
            reason: ProtocolReason,
        ) {
            selected.update { it + reason }
        }

        override fun altSvcMarkedBroken(
            origin: String,
            alternative: String,
        ) {
            broken.complete(alternative)
        }

        override fun callFailed(
            request: HttpRequestData,
            cause: Throwable,
        ) {
            failed.store(cause to request.attributes.getOrNull(KuicksilverDiagnosticsKey))
        }
    }

    private fun okServer(): io.ktor.server.application.Application.() -> Unit = { routing { get("/") { call.respondText("ok") } } }

    @Test fun h3WinnerHasNoFallback() =
        h3Test {
            val (server, port) = testServer(module = okServer())
            val reasons = Reasons()
            try {
                testClient(Http3DiscoveryMode.Preferred, engine = {
                    http3 { hardDelay = Duration.INFINITE }
                    eventListener = reasons
                }).use { c ->
                    val r = c.get("https://127.0.0.1:$port/")
                    assertEquals("ok", r.bodyAsText())
                    val d = assertNotNull(r.kuicksilverDiagnostics)
                    assertEquals(HttpProtocolVersion.HTTP_3_0, d.protocol)
                    assertNull(d.fallback)
                    assertNull(d.h3Failure)
                    assertTrue(d.raced)
                    assertEquals(Duration.INFINITE, d.headStart)
                    assertEquals(AlternativeSource.Preferred, d.alternativeSource)
                    assertEquals("127.0.0.1:$port", d.alternative)
                    assertEquals(1, d.attempts)
                    // listenerAndAttributeAgree: the attribute's reason is the last one the listener heard
                    assertEquals(reasons.selected.load().last(), d.reason)
                    assertEquals(ProtocolReason.Race, d.reason)
                    // the next call uses the open connection
                    val d2 = assertNotNull(c.get("https://127.0.0.1:$port/").kuicksilverDiagnostics)
                    assertEquals(ProtocolReason.ExistingConnection, d2.reason)
                    assertEquals(HttpProtocolVersion.HTTP_3_0, d2.protocol)
                    assertFalse(d2.raced)
                    assertNull(d2.headStart)
                }
            } finally {
                server.stop(100, 500)
            }
        }

    @Test fun noAltSvcIsNoAlternative() =
        clientTest {
            val (server, port) = testServer(module = okServer())
            try {
                testClient(Http3DiscoveryMode.Auto).use { c ->
                    val d = assertNotNull(c.get("https://127.0.0.1:$port/").kuicksilverDiagnostics)
                    assertEquals(HttpProtocolVersion.HTTP_1_1, d.protocol)
                    assertEquals(FallbackReason.NoAlternative, d.fallback)
                    assertEquals(ProtocolReason.NoAlternative, d.reason)
                    assertNull(d.alternative)
                    assertNull(d.alternativeSource)
                    assertFalse(d.raced)
                }
            } finally {
                server.stop(100, 500)
            }
        }

    @Test fun httpIsNotSecure() =
        clientTest {
            val (server, port) = testServer(plain = true, module = okServer())
            try {
                testClient(Http3DiscoveryMode.Preferred).use { c ->
                    val d = assertNotNull(c.get("http://127.0.0.1:$port/").kuicksilverDiagnostics)
                    assertEquals(HttpProtocolVersion.HTTP_1_1, d.protocol)
                    assertEquals(FallbackReason.NotSecure, d.fallback)
                    assertNull(d.alternative)
                }
            } finally {
                server.stop(100, 500)
            }
        }

    @Test fun h1OnlyIsConfiguration() =
        clientTest {
            val (server, port) = testServer(module = okServer())
            try {
                testClient(Http3DiscoveryMode.H1Only).use { c ->
                    val d = assertNotNull(c.get("https://127.0.0.1:$port/").kuicksilverDiagnostics)
                    assertEquals(FallbackReason.Configuration, d.fallback)
                }
            } finally {
                server.stop(100, 500)
            }
        }

    @Test fun proxyIsProxy() =
        clientTest {
            val (server, port) = testServer(module = okServer())
            try {
                ClientProxyTest().tunnelProxy(port) { proxyPort, _ ->
                    testClient(Http3DiscoveryMode.Preferred, engine = { proxy = ProxyBuilder.http(Url("http://127.0.0.1:$proxyPort")) })
                        .use { c ->
                            val d = assertNotNull(c.get("https://127.0.0.1:$port/").kuicksilverDiagnostics)
                            assertEquals(HttpProtocolVersion.HTTP_1_1, d.protocol)
                            assertEquals(FallbackReason.Proxy, d.fallback)
                            assertEquals(ProtocolReason.Proxy, d.reason)
                        }
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /** Serves `ok` on every request of a connection until the client closes it. */
    private val serveOk: suspend CoroutineScope.(Int, io.ktor.utils.io.ByteReadChannel, io.ktor.utils.io.ByteWriteChannel) -> Unit =
        { _, input, output ->
            while (readRequest(input).isNotEmpty()) output.writeStringUtf8("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
        }

    /**
     * UDP silent, no confirmed QUIC: the 10 ms head start runs out long before the handshake timeout, so HTTP/1.1 wins
     * while HTTP/3 has not failed yet (H3NotReady). The setup that lost fails later and marks the alternative broken; the
     * next call says so, with the reason that marked it.
     */
    @Test fun silentUdpFirstNotReadyThenBroken() =
        clientTest {
            val reasons = Reasons()
            val log = DiagnosticLines(LogLevel.Info)
            tlsH1WithSilentUdp(handler = serveOk) { port ->
                testClient(Http3DiscoveryMode.Preferred, engine = {
                    quic = quicConfig { handshakeTimeout = 2.seconds }
                    eventListener = reasons
                    logger = log
                }).use { c ->
                    val d = assertNotNull(c.get("https://127.0.0.1:$port/").kuicksilverDiagnostics)
                    assertEquals(HttpProtocolVersion.HTTP_1_1, d.protocol)
                    assertEquals(FallbackReason.H3NotReady, d.fallback)
                    assertNull(d.h3Failure)
                    assertTrue(d.raced)
                    assertEquals(MIN_HEAD_START, d.headStart)
                    assertEquals(reasons.selected.load().last(), d.reason)
                    withTimeoutOrNull(30.seconds) { reasons.broken.await() } ?: fail("the alternative was not marked broken within 30 s")
                    val d2 = assertNotNull(c.get("https://127.0.0.1:$port/").kuicksilverDiagnostics)
                    assertEquals(FallbackReason.BrokenAlternative, d2.fallback)
                    assertEquals(ProtocolReason.BrokenAlternative, d2.reason)
                    assertNull(d2.h3Failure)
                    assertFalse(d2.raced)
                    val line = log.lines.last()
                    assertEquals(LogLevel.Info, line.first)
                    assertTrue("broken since: HandshakeTimeout" in line.second, line.second)
                    assertTrue(
                        line.second.startsWith("kuicksilver: GET https://127.0.0.1:$port/ -> HTTP/1.1 (fallback=BrokenAlternative"),
                        line.second,
                    )
                }
            }
        }

    /** HTTP/1.1 starts only once HTTP/3 failed: the handshake timeout is the reason, with the failure itself. */
    @Test fun udpTimeoutBeforeTcpIsHandshakeTimeout() =
        clientTest {
            tlsH1WithSilentUdp(handler = serveOk) { port ->
                testClient(Http3DiscoveryMode.Preferred, engine = {
                    quic = quicConfig { handshakeTimeout = 300.milliseconds }
                    http3 { hardDelay = Duration.INFINITE }
                }).use { c ->
                    val d = assertNotNull(c.get("https://127.0.0.1:$port/").kuicksilverDiagnostics)
                    assertEquals(HttpProtocolVersion.HTTP_1_1, d.protocol)
                    assertEquals(FallbackReason.HandshakeTimeout, d.fallback)
                    assertIs<QuicException.ConnectionLost.Timeout>(d.h3Failure)
                    assertTrue(d.raced)
                }
            }
        }

    /** An HTTP/1.1 server on the TCP side of a port, [udp] (bound on a free port, returning it) on its UDP side. */
    private suspend fun <U> h1And(
        udp: suspend () -> Pair<U, Int>,
        release: suspend (U) -> Unit,
    ): Triple<TestServer, U, Int> {
        val (u, server, port) =
            bindOnSamePort(first = udp, release = release) { p ->
                testServer(configure = { http3 = false }, port = p, module = okServer()).first
            }
        return Triple(server, u, port)
    }

    private fun serverTls(alpn: String) =
        tlsConfig(TlsRole.Server) {
            this.alpn = listOf(alpn)
            identity = ClientFixtures.identity()
        }

    /** An HTTP/1.1 server on the TCP side of a port and an HTTP/3 endpoint running [onConnection] per connection on its UDP side. */
    private suspend fun CoroutineScope.h1AndRawH3(
        onConnection: suspend CoroutineScope.(io.kuicksilver.http3.Http3Connection) -> Unit,
    ): Triple<TestServer, Http3Endpoint, Int> {
        val config = QuicEndpointConfig.Builder().apply { server = QuicServerConfig.Builder(serverTls(Http3Endpoint.H3)).build() }.build()
        val t = h1And({ Http3Endpoint.bind(InetSocketAddress("127.0.0.1", 0), config).let { it to it.localAddress.port } }, { it.close() })
        val ep = t.second
        launch {
            runCatching {
                while (true) {
                    val conn = ep.accept()
                    launch { runCatching { onConnection(conn) } }
                }
            }
        }
        return t
    }

    @Test fun wrongAlpnIsTlsFailure() =
        h3Test {
            coroutineScope {
                // a QUIC server that offers no h3: its TLS refuses the client's ALPN (RFC 7301 section 3.2, no_application_protocol)
                val config =
                    QuicEndpointConfig.Builder().apply { server = QuicServerConfig.Builder(serverTls("not-h3")).build() }.build()
                val (server, ep, port) =
                    h1And(
                        { QuicEndpoint.bind(InetSocketAddress("127.0.0.1", 0), config).let { it to it.localAddress.port } },
                        { it.close() },
                    )
                try {
                    testClient(Http3DiscoveryMode.Preferred, engine = { http3 { hardDelay = Duration.INFINITE } }).use { c ->
                        val d = assertNotNull(c.get("https://127.0.0.1:$port/").kuicksilverDiagnostics)
                        assertEquals(HttpProtocolVersion.HTTP_1_1, d.protocol)
                        assertEquals(FallbackReason.TlsFailure, d.fallback, "${d.h3Failure}")
                    }
                } finally {
                    ep.close()
                    server.stop(100, 500)
                    coroutineContext[kotlinx.coroutines.Job]?.children?.forEach { it.cancel() }
                }
            }
        }

    /** An HTTP/3 stream reset on a working connection: the GET goes again over HTTP/1.1, a second attempt. */
    @Test fun streamResetFallsBackAsStreamFailed() =
        h3Test {
            coroutineScope {
                val (server, ep, port) =
                    h1AndRawH3 { conn ->
                        while (true) conn.acceptRequest().reset(Http3ErrorCode.INTERNAL_ERROR)
                    }
                try {
                    testClient(Http3DiscoveryMode.Preferred, engine = { http3 { hardDelay = Duration.INFINITE } }).use { c ->
                        val r = c.get("https://127.0.0.1:$port/")
                        assertEquals("ok", r.bodyAsText())
                        val d = assertNotNull(r.kuicksilverDiagnostics)
                        assertEquals(HttpProtocolVersion.HTTP_1_1, d.protocol)
                        assertEquals(ProtocolReason.Fallback, d.reason)
                        assertEquals(FallbackReason.StreamFailed, d.fallback)
                        assertNotNull(d.h3Failure)
                        assertEquals(2, d.attempts)
                        assertTrue(d.raced)
                        assertFalse("marked broken" in d.toString(), "$d")
                    }
                } finally {
                    ep.close()
                    server.stop(100, 500)
                    coroutineContext[kotlinx.coroutines.Job]?.children?.forEach { it.cancel() }
                }
            }
        }

    /** The HTTP/3 setup never finishes: HTTP/1.1 wins after the 10 ms head start, and HTTP/3 was simply not ready. */
    @Test fun notReadyWhenTcpWins() =
        clientTest {
            val (server, port) = testServer(module = okServer())
            val hold = CompletableDeferred<Unit>()
            try {
                testClient(Http3DiscoveryMode.Preferred, engine = { http3 { hardDelay = 10.milliseconds } }).use { c ->
                    (c.engine as KuicksilverEngine).h3.beforeSetupForTest = { hold.await() }
                    val d = assertNotNull(c.get("https://127.0.0.1:$port/").kuicksilverDiagnostics)
                    assertEquals(HttpProtocolVersion.HTTP_1_1, d.protocol)
                    assertEquals(FallbackReason.H3NotReady, d.fallback)
                    assertNull(d.h3Failure)
                    assertTrue(d.raced)
                    assertEquals(10.milliseconds, d.headStart)
                    hold.cancel()
                }
            } finally {
                hold.cancel()
                server.stop(100, 500)
            }
        }

    /**
     * A call that fails has no response, so no diagnostics: the attribute is not on the request when callFailed is heard.
     * When both setups failed, the HTTP/1.1 failure is thrown with the HTTP/3 one in `suppressed`.
     */
    @Test fun diagnosticsOnFailedCallNotAttached() =
        h3Test {
            val (server, port) = testServer(module = okServer())
            val reasons = Reasons()
            try {
                val pinned = TrustConfig.Pinned(setOf(SpkiSha256(ByteArray(32))), base = ClientFixtures.trust)
                testClient(Http3DiscoveryMode.Preferred, engine = {
                    trust = pinned
                    http3 { hardDelay = Duration.INFINITE }
                    eventListener = reasons
                }).use { c ->
                    val e = assertFailsWith<Throwable> { c.get("https://127.0.0.1:$port/") }
                    val (cause, diagnostics) = assertNotNull(reasons.failed.load())
                    assertNull(diagnostics, "a failed call carries no diagnostics")
                    assertTrue(
                        generateSequence(cause) { it.cause }.any { it.suppressedExceptions.isNotEmpty() },
                        "the HTTP/3 failure is suppressed in the HTTP/1.1 one: $cause (thrown: $e)",
                    )
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /** The log line of a call carries neither its query nor its user info. */
    @Test fun negative_diagnosticsLogHasNoQueryThroughTheEngine() =
        clientTest {
            val (server, port) = testServer(module = okServer())
            val log = DiagnosticLines(LogLevel.Debug)
            try {
                testClient(Http3DiscoveryMode.Auto, engine = { logger = log }).use { c ->
                    c.get("https://127.0.0.1:$port/?token=secret")
                    val line = log.lines.single().second
                    assertEquals("kuicksilver: GET https://127.0.0.1:$port/ -> HTTP/1.1 (fallback=NoAlternative)", line)
                    assertFalse("secret" in line, line)
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /** `diagnosticsLogLevel = null` writes no line at all; an HTTP/3 call writes its line at Debug. */
    @Test fun logLevels() =
        h3Test {
            val (server, port) = testServer(module = okServer())
            val quiet = DiagnosticLines(LogLevel.Debug)
            val loud = DiagnosticLines(LogLevel.Debug)
            try {
                testClient(Http3DiscoveryMode.H1Only, engine = {
                    logger = quiet
                    http3 { diagnosticsLogLevel = null }
                }).use { c -> c.get("https://127.0.0.1:$port/") }
                assertEquals(emptyList(), quiet.lines)
                testClient(Http3DiscoveryMode.H3Only, engine = { logger = loud }).use { c -> c.get("https://127.0.0.1:$port/") }
                val (level, line) = loud.lines.single()
                assertEquals(LogLevel.Debug, level)
                assertEquals("kuicksilver: GET https://127.0.0.1:$port/ -> HTTP/3.0 (alt=127.0.0.1:$port via H3Only)", line)
            } finally {
                server.stop(100, 500)
            }
        }
}
