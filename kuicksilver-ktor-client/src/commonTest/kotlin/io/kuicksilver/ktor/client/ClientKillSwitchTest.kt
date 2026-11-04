// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class, kotlin.concurrent.atomics.ExperimentalAtomicApi::class)

package io.kuicksilver.ktor.client

import io.ktor.client.request.HttpRequestData
import io.ktor.client.request.get
import io.ktor.client.request.prepareGet
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpProtocolVersion
import io.ktor.http.Url
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.server.response.respondBytesWriter
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.ktor.utils.io.writeStringUtf8
import io.kuicksilver.http3.Http3Connection
import io.kuicksilver.http3.Http3Endpoint
import io.kuicksilver.http3.Http3Headers
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.KuicksilverLogger
import io.kuicksilver.quic.LogLevel
import io.kuicksilver.quic.QuicEndpointConfig
import io.kuicksilver.quic.QuicServerConfig
import io.kuicksilver.tls.TlsRole
import io.kuicksilver.tls.tlsConfig
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.concurrent.atomics.AtomicBoolean
import kotlin.concurrent.atomics.AtomicInt
import kotlin.concurrent.atomics.AtomicReference
import kotlin.concurrent.atomics.update
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.test.fail
import kotlin.time.Duration
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.seconds

/**
 * The client's HTTP/3 kill switch (`http3 { http3Allowed }`) and `HttpClient.closeHttp3Connections()` (docs/guide/ktor.md,
 * "Turning HTTP/3 off remotely"). Calls that must go over HTTP/3 use `hardDelay = Duration.INFINITE`, so HTTP/1.1 never
 * wins a race on a fast loopback.
 */
class ClientKillSwitchTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    /** Warnings of the engine logger, with their message. */
    private class Warnings : KuicksilverLogger {
        val lines = AtomicReference(emptyList<String>())

        override fun isEnabled(level: LogLevel): Boolean = level >= LogLevel.Warn

        override fun log(
            level: LogLevel,
            message: String,
            cause: Throwable?,
        ) {
            lines.update { it + message }
        }
    }

    private class Events : KuicksilverEventListener() {
        val reasons = AtomicReference(emptyList<ProtocolReason>())
        val altSvcUsed = AtomicInt(0)

        override fun protocolSelected(
            request: HttpRequestData,
            protocol: HttpProtocolVersion,
            reason: ProtocolReason,
        ) {
            reasons.update { it + reason }
        }

        override fun altSvcUsed(
            request: HttpRequestData,
            alternative: String,
        ) {
            altSvcUsed.addAndFetch(1)
        }
    }

    private val ok: io.ktor.server.application.Application.() -> Unit = { routing { get("/") { call.respondText("ok") } } }

    /** Switched off: the request goes over HTTP/1.1 for that reason, and the engine never even binds its UDP socket. */
    @Test fun disabledGoesOverTcpWithReason() =
        clientTest {
            val (server, port) = testServer(module = ok)
            val allowed = AtomicBoolean(false)
            val events = Events()
            try {
                testClient(Http3DiscoveryMode.Preferred, engine = {
                    http3 { http3Allowed = { allowed.load() } }
                    eventListener = events
                }).use { c ->
                    val r = c.get("https://127.0.0.1:$port/")
                    assertEquals("ok", r.bodyAsText())
                    assertEquals(HttpProtocolVersion.HTTP_1_1, r.version)
                    val d = assertNotNull(r.kuicksilverDiagnostics)
                    assertEquals(ProtocolReason.Http3Disabled, d.reason)
                    assertEquals(FallbackReason.Http3Disabled, d.fallback)
                    assertEquals(listOf(ProtocolReason.Http3Disabled), events.reasons.load())
                    assertFalse((c.engine as KuicksilverEngine).h3.endpointBoundForTest, "no UDP socket, so no datagram, while disabled")
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /** Alt-Svc is learned while HTTP/3 is off: switched on again, the next call goes straight to the alternative. */
    @Test fun reEnableUsesLearnedAltSvc() =
        h3Test {
            val (server, port) = testServer(module = ok)
            val allowed = AtomicBoolean(false)
            val events = Events()
            try {
                testClient(Http3DiscoveryMode.Auto, engine = {
                    http3 {
                        http3Allowed = { allowed.load() }
                        hardDelay = Duration.INFINITE
                    }
                    eventListener = events
                }).use { c ->
                    val url = "https://127.0.0.1:$port/"
                    repeat(2) { assertEquals(HttpProtocolVersion.HTTP_1_1, c.get(url).version) }
                    assertTrue((c.engine as KuicksilverEngine).altSvcSnapshot(Url(url)).isNotEmpty(), "Alt-Svc learned while disabled")
                    assertEquals(0, events.altSvcUsed.load())
                    allowed.store(true)
                    val r = c.get(url)
                    assertEquals(HttpProtocolVersion.HTTP_3_0, r.version)
                    assertEquals(AlternativeSource.AltSvc, r.kuicksilverDiagnostics?.alternativeSource)
                    assertEquals(1, events.altSvcUsed.load())
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /** An open HTTP/3 connection takes no new request while disabled; the request already on it finishes there. */
    @Test fun existingH3NotUsedWhileDisabled() =
        h3Test {
            val gate = CompletableDeferred<Unit>()
            val (server, port) =
                testServer {
                    routing {
                        get("/") { call.respondText("ok") }
                        get("/slow") {
                            call.respondBytesWriter {
                                writeStringUtf8("start")
                                flush()
                                gate.await()
                                writeStringUtf8("done")
                            }
                        }
                    }
                }
            val allowed = AtomicBoolean(true)
            try {
                testClient(Http3DiscoveryMode.Preferred, engine = {
                    http3 {
                        http3Allowed = { allowed.load() }
                        hardDelay = Duration.INFINITE
                    }
                }).use { c ->
                    val engine = c.engine as KuicksilverEngine
                    coroutineScope {
                        val head = CompletableDeferred<HttpProtocolVersion>()
                        val slow =
                            async {
                                c.prepareGet("https://127.0.0.1:$port/slow").execute { r ->
                                    head.complete(r.version)
                                    r.bodyAsText()
                                }
                            }
                        assertEquals(HttpProtocolVersion.HTTP_3_0, head.await())
                        allowed.store(false)
                        val r = c.get("https://127.0.0.1:$port/")
                        assertEquals(HttpProtocolVersion.HTTP_1_1, r.version)
                        assertEquals(ProtocolReason.Http3Disabled, r.kuicksilverDiagnostics?.reason)
                        assertTrue(engine.hasH3Connection(Url("https://127.0.0.1:$port/")), "the HTTP/3 connection stays open")
                        gate.complete(Unit)
                        assertEquals("startdone", slow.await())
                    }
                }
            } finally {
                gate.complete(Unit)
                server.stop(100, 500)
            }
        }

    /** H3Only promises never TCP: switched off, the call fails before any connection, TCP or UDP. */
    @Test fun negative_h3OnlyWhileDisabledFails() =
        clientTest {
            val served = AtomicInt(0)
            tlsH1WithSilentUdp(handler = { _, _, _ -> served.addAndFetch(1) }) { port ->
                testClient(Http3DiscoveryMode.H3Only, engine = { http3 { http3Allowed = { false } } }).use { c ->
                    val e = assertFailsWith<UnsupportedOperationException> { c.get("https://127.0.0.1:$port/") }
                    assertTrue("http3Allowed" in (e.message ?: ""), "${e.message}")
                    val engine = c.engine as KuicksilverEngine
                    assertFalse(engine.h3.endpointBoundForTest, "no UDP socket was bound")
                    assertEquals(0, engine.h1.pool.liveCount, "no TCP connection was made")
                }
            }
            assertEquals(0, served.load())
        }

    /** A switch that throws leaves HTTP/3 on (fail-open) and is reported once per 5 minutes, not per call. */
    @Test fun negative_throwingSwitchFallsOpenAndWarnsOnce() =
        h3Test {
            val (server, port) = testServer(module = ok)
            val warnings = Warnings()
            try {
                testClient(Http3DiscoveryMode.Preferred, engine = {
                    http3 {
                        http3Allowed = { throw IllegalStateException("remote config not loaded") }
                        hardDelay = Duration.INFINITE
                    }
                    logger = warnings
                }).use { c ->
                    (c.engine as KuicksilverEngine).http3SwitchWarning.clock = { 0L } // no time passes: one warning at most
                    repeat(10) { assertEquals(HttpProtocolVersion.HTTP_3_0, c.get("https://127.0.0.1:$port/").version) }
                }
                assertEquals(1, warnings.lines.load().count { "http3Allowed" in it }, "${warnings.lines.load()}")
            } finally {
                server.stop(100, 500)
            }
        }

    @Test fun switchWarningAtMostOncePerFiveMinutes() {
        var now = 0L
        val w = RateLimitedWarning(5.minutes) { now }
        assertTrue(w.tryAcquire())
        assertFalse(w.tryAcquire())
        now += 5.minutes.inWholeMilliseconds - 1
        assertFalse(w.tryAcquire())
        now += 1
        assertTrue(w.tryAcquire())
        assertFalse(w.tryAcquire())
    }

    /** A raw HTTP/3 server: `/slow` sends "start", then "done" once [gate] completes; the rest "ok". Keeps its connections. */
    private suspend fun CoroutineScope.recordingH3(
        gate: CompletableDeferred<Unit>,
        accepted: AtomicReference<List<Http3Connection>>,
    ): Http3Endpoint {
        val tls =
            tlsConfig(TlsRole.Server) {
                alpn = listOf(Http3Endpoint.H3)
                identity = ClientFixtures.identity()
            }
        val ep =
            Http3Endpoint.bind(
                InetSocketAddress("127.0.0.1", 0),
                QuicEndpointConfig.Builder().apply { server = QuicServerConfig.Builder(tls).build() }.build(),
            )
        launch {
            runCatching {
                while (true) {
                    val conn = ep.accept()
                    accepted.update { it + conn }
                    launch {
                        runCatching {
                            while (true) {
                                val r = conn.acceptRequest()
                                launch {
                                    runCatching {
                                        val w = r.respond(200, Http3Headers(emptyList()))
                                        if (r.path == "/slow") {
                                            w.output.writeStringUtf8("start")
                                            w.output.flush()
                                            gate.await()
                                            w.output.writeStringUtf8("done")
                                        } else {
                                            w.output.writeStringUtf8("ok")
                                        }
                                        w.finish()
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        return ep
    }

    /**
     * `closeHttp3Connections()` sends GOAWAY on every HTTP/3 connection and takes them out of the pool: the next call opens a
     * new connection, the call in flight finishes on the old one, which closes after it.
     */
    @Test fun closeHttp3ConnectionsSendsGoAway() =
        h3Test {
            coroutineScope {
                val gate = CompletableDeferred<Unit>()
                val accepted = AtomicReference(emptyList<Http3Connection>())
                val ep = recordingH3(gate, accepted)
                val port = ep.localAddress.port
                try {
                    testClient(Http3DiscoveryMode.H3Only).use { c ->
                        val head = CompletableDeferred<Unit>()
                        val slow =
                            async {
                                c.prepareGet("https://127.0.0.1:$port/slow").execute { r ->
                                    head.complete(Unit)
                                    r.bodyAsText()
                                }
                            }
                        head.await()
                        c.closeHttp3Connections()
                        val first = accepted.load().single()
                        withTimeoutOrNull(30.seconds) { first.goAwayReceived.first { it != null } }
                            ?: fail("the server got no GOAWAY within 30 s")
                        assertEquals(0L, first.goAwayReceived.value, "a client's GOAWAY carries push ID 0 (no server push)")
                        assertEquals("ok", c.get("https://127.0.0.1:$port/").bodyAsText())
                        assertEquals(2, accepted.load().size, "the next call opened a new connection")
                        assertFalse(first.closed.isCompleted, "the connection with a call in flight stays open")
                        gate.complete(Unit)
                        assertEquals("startdone", slow.await())
                        withTimeoutOrNull(30.seconds) { first.closed.await() }
                            ?: fail("the old connection did not close within 30 s after its last call")
                    }
                } finally {
                    gate.complete(Unit)
                    ep.close()
                    coroutineContext[kotlinx.coroutines.Job]?.children?.forEach { it.cancel() }
                }
            }
        }
}
