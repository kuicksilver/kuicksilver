// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import io.ktor.client.request.HttpRequestBuilder
import io.ktor.client.request.get
import io.ktor.client.request.post
import io.ktor.client.request.put
import io.ktor.client.request.setBody
import io.ktor.client.request.url
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpProtocolVersion
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.server.application.Application
import io.ktor.server.response.header
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import io.ktor.server.routing.put
import io.ktor.server.routing.routing
import io.ktor.utils.io.readAvailable
import io.kuicksilver.http3.Http3Endpoint
import io.kuicksilver.http3.Http3ErrorCode
import io.kuicksilver.http3.Http3Exception
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.AdmissionDecision
import io.kuicksilver.quic.ConnectionAdmission
import io.kuicksilver.quic.QuicEndpointConfig
import io.kuicksilver.quic.QuicServerConfig
import io.kuicksilver.quic.TransportError
import io.kuicksilver.quic.quicConfig
import io.kuicksilver.tls.SpkiSha256
import io.kuicksilver.tls.TlsException
import io.kuicksilver.tls.TlsIdentity
import io.kuicksilver.tls.TlsRole
import io.kuicksilver.tls.TrustConfig
import io.kuicksilver.tls.tlsConfig
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.IO
import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds
import kotlin.time.TimeSource

class ClientFallbackTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    /** Feature focus 4: Alt-Svc points at a UDP port where nobody answers. */
    @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
    @Test
    fun blockedUdpFallsBackAfterHardDelayAndMarksBroken() =
        clientTest {
            val markedBroken = CompletableDeferred<Pair<String, String>>()
            val listener =
                object : KuicksilverEventListener() {
                    override fun altSvcMarkedBroken(
                        origin: String,
                        alternative: String,
                    ) {
                        markedBroken.complete(origin to alternative)
                    }
                }
            val (server, port) =
                testServer(configure = { http3 = false }) {
                    routing {
                        get("/") {
                            call.response.header("Alt-Svc", "h3=\":${call.request.local.localPort}\"")
                            call.respondText("h1")
                        }
                    }
                }
            try {
                testClient(Http3DiscoveryMode.Auto, engine = {
                    quic = quicConfig { handshakeTimeout = 500.milliseconds }
                    eventListener = listener
                }).use { c ->
                    assertEquals("h1", c.get("https://127.0.0.1:$port/").bodyAsText()) // learns the alternative
                    val t0 = TimeSource.Monotonic.markNow()
                    val r = c.get("https://127.0.0.1:$port/")
                    assertEquals(HttpProtocolVersion.HTTP_1_1, r.version)
                    assertTrue(t0.elapsedNow() < 2.seconds, "${t0.elapsedNow()}")
                    val engine = c.engine as KuicksilverEngine
                    val origin = "https://127.0.0.1:$port"
                    val alt = "127.0.0.1:$port"
                    // h3 failed and h1 worked: the HTTP/3 attempt that lost the race marks the alternative once it fails
                    val marked =
                        kotlinx.coroutines.withTimeoutOrNull(30.seconds) { markedBroken.await() }
                            ?: kotlin.test.fail("$alt of $origin was not marked broken within 30 s")
                    assertEquals(origin to alt, marked)
                    assertTrue(engine.brokenAltSvc.isBroken(origin, alt))
                    assertEquals(HttpProtocolVersion.HTTP_1_1, c.get("https://127.0.0.1:$port/").version)
                }
            } finally {
                server.stop(100, 500)
            }
        }

    @Test fun negative_fallbackKeepsPins() =
        clientTest {
            val (server, port) =
                testServer(
                    configure = { http3 = false },
                ) { routing { get("/") { call.respondText("must not be reached") } } }
            try {
                val pinned = TrustConfig.Pinned(setOf(SpkiSha256(ByteArray(32))), base = ClientFixtures.trust)
                testClient(Http3DiscoveryMode.Preferred, engine = {
                    trust = pinned
                    connectTimeout = 1.seconds
                }).use { c ->
                    val e = assertFailsWith<Throwable> { c.get("https://127.0.0.1:$port/") }
                    assertTrue(
                        generateSequence(e) { it.cause }.any { it is TlsException },
                        "the HTTP/1.1 fallback must fail the same pin: $e",
                    )
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /** A raw HTTP/3 server endpoint on a free UDP port of 127.0.0.1. */
    private suspend fun h3Endpoint(admission: ConnectionAdmission = ConnectionAdmission.default()): Http3Endpoint {
        val tls =
            tlsConfig(TlsRole.Server) {
                alpn = listOf("h3")
                identity =
                    TlsIdentity.fromDer(listOf(TestCerts.server), TestCerts.serverKey.copyOf())
            }
        return Http3Endpoint.bind(
            InetSocketAddress("127.0.0.1", 0),
            QuicEndpointConfig
                .Builder()
                .apply {
                    this.server =
                        QuicServerConfig.Builder(tls).build()
                    this.admission = admission
                }.build(),
        )
    }

    /**
     * An HTTP/1.1 [testServer] (no HTTP/3 of its own) running [module] on the TCP side of a port and [h3] on its UDP side:
     * the UDP endpoint binds a free port first and the TCP server takes the same number, a new pair when that is taken.
     * A free TCP port says nothing about its UDP twin: binding UDP on the port the TCP server got failed with "Address
     * already in use" whenever another process held that UDP port.
     */
    private suspend fun h1AndH3(
        module: Application.() -> Unit,
        h3: suspend () -> Http3Endpoint,
    ): Triple<TestServer, Http3Endpoint, Int> {
        val (ep, server, port) =
            bindOnSamePort(
                first = { h3().let { it to it.localAddress.port } },
                release = { it.close() },
            ) { p -> testServer(configure = { http3 = false }, port = p, module = module).first }
        return Triple(server, ep, port)
    }

    /**
     * A raw HTTP/3 server on a free UDP port that fails every request after reading it (H3_INTERNAL_ERROR), except
     * [okPaths] (200): by resetting the stream, or with [closeConnection] by closing the whole connection.
     */
    private suspend fun CoroutineScope.failingH3(
        okPaths: Set<String> = emptySet(),
        closeConnection: Boolean = false,
    ): Http3Endpoint {
        val ep = h3Endpoint()
        launch {
            runCatching {
                while (true) {
                    val conn = ep.accept()
                    launch {
                        runCatching {
                            while (true) {
                                val r = conn.acceptRequest()
                                when {
                                    r.path in okPaths -> r.respond(200).finish()
                                    closeConnection -> conn.close(Http3ErrorCode.INTERNAL_ERROR, "failing")
                                    else -> r.reset(Http3ErrorCode.INTERNAL_ERROR)
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
     * A raw HTTP/3 server on a free UDP port that answers 200 to every request, except that while [refuseWith] holds a
     * code, its admission refuses each new client statelessly with an Initial CONNECTION_CLOSE carrying that code (as
     * `Drain`, a full accept queue or a stop do with CONNECTION_REFUSED, RFC 9000 section 5.2.2). Paths with their own
     * behaviour:
     * - `/goaway-close`: GOAWAY (both frames, RFC 9114 section 5.2), then, once [closeGate] completes (the test opens
     *   it when the client has seen the GOAWAY), the connection closes with H3_NO_ERROR while the request is unanswered,
     *   as a stopping server's grace period ends
     * - `/goaway-close-error`: the same with H3_INTERNAL_ERROR
     * - `/close-no-error`: the same close without a GOAWAY first
     * - `/reject`: the server starts refusing new clients, then resets the request with H3_REQUEST_REJECTED (not
     *   processed: the client repeats it on a new connection, which is refused)
     */
    @OptIn(kotlin.concurrent.atomics.ExperimentalAtomicApi::class)
    private suspend fun CoroutineScope.refusingH3(
        refuseWith: kotlin.concurrent.atomics.AtomicReference<Long?>,
        closeGate: CompletableDeferred<Unit>?,
    ): Http3Endpoint {
        val ep =
            h3Endpoint(
                ConnectionAdmission { refuseWith.load()?.let { AdmissionDecision.Close(it) } ?: AdmissionDecision.Allow },
            )
        launch {
            runCatching {
                while (true) {
                    val conn = ep.accept()
                    launch {
                        runCatching {
                            while (true) {
                                val r = conn.acceptRequest()
                                when (r.path) {
                                    "/goaway-close", "/goaway-close-error" -> {
                                        launch {
                                            conn.goAway()
                                            closeGate?.await()
                                            val code =
                                                if (r.path ==
                                                    "/goaway-close"
                                                ) {
                                                    Http3ErrorCode.NO_ERROR
                                                } else {
                                                    Http3ErrorCode.INTERNAL_ERROR
                                                }
                                            conn.close(code, "")
                                        }
                                    }

                                    "/close-no-error" -> {
                                        conn.close(Http3ErrorCode.NO_ERROR, "")
                                    }

                                    "/reject" -> {
                                        refuseWith.store(TransportError.CONNECTION_REFUSED)
                                        r.reset(Http3ErrorCode.REQUEST_REJECTED)
                                    }

                                    else -> {
                                        r.respond(200).finish()
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

    /** An HTTP/1.1 origin that announces its UDP twin as `h3` (RFC 7838) on every response, and [refusingH3] on that twin. */
    @OptIn(kotlin.concurrent.atomics.ExperimentalAtomicApi::class)
    private suspend fun CoroutineScope.originWithRefusingH3(
        refuseWith: kotlin.concurrent.atomics.AtomicReference<Long?>,
        closeGate: CompletableDeferred<Unit>? = null,
    ) = h1AndH3({
        routing {
            get("/{path?}") {
                call.response.header("Alt-Svc", "h3=\":${call.request.local.localPort}\"")
                call.respondText("h1")
            }
        }
    }) { refusingH3(refuseWith, closeGate) }

    /**
     * CONNECTION_REFUSED (a pod in `Drain`, with a full accept queue or stopping) is transient (RFC 9000 sections 5.2.2,
     * 10.2.3 and 20.1): each refused call falls back to HTTP/1.1 once with `fallback = Refused`, the alternative stays
     * cached and is never marked broken (RFC 7838 sections 2.2 and 3) however often the refusal repeats, and the first call
     * after the server takes clients again goes over HTTP/3. Before 0.3.0 the first refusal marked the alternative broken
     * for 5 minutes, doubling up to 2 days. `hardDelay = INFINITE`: HTTP/1.1 starts only once HTTP/3 failed, so the
     * winner of each race does not depend on timing.
     */
    @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class, kotlin.concurrent.atomics.ExperimentalAtomicApi::class)
    @Test
    fun connectionRefusedFallsBackWithoutMarkingBroken() =
        h3Test {
            kotlinx.coroutines.coroutineScope {
                val refuseWith = kotlin.concurrent.atomics.AtomicReference<Long?>(null)
                val (server, ep, port) = originWithRefusingH3(refuseWith)
                val marked = mutableListOf<String>()
                val listener =
                    object : KuicksilverEventListener() {
                        override fun altSvcMarkedBroken(
                            origin: String,
                            alternative: String,
                        ) {
                            marked += alternative
                        }
                    }
                val origin = "https://127.0.0.1:$port"
                // the losing HTTP/3 setup is settled (marked or not) in the background: each call waits for it
                val settled = kotlinx.coroutines.channels.Channel<Unit>(kotlinx.coroutines.channels.Channel.UNLIMITED)
                try {
                    testClient(Http3DiscoveryMode.Auto, engine = {
                        eventListener = listener
                        http3 { hardDelay = Duration.INFINITE }
                    }).use { c ->
                        val engine = c.engine as KuicksilverEngine
                        engine.raceLoserSettledForTest = { settled.trySend(Unit) }
                        assertEquals(FallbackReason.NoAlternative, c.get("$origin/").kuicksilverDiagnostics?.fallback) // learns h3
                        refuseWith.store(TransportError.CONNECTION_REFUSED)
                        // repeated refusals: every call tries HTTP/3 again and falls back once; nothing escalates
                        repeat(3) { i ->
                            val r = c.get("$origin/")
                            val d = assertNotNull(r.kuicksilverDiagnostics)
                            assertEquals(HttpProtocolVersion.HTTP_1_1, r.version, "call $i")
                            assertEquals(FallbackReason.Refused, d.fallback, "call $i: ${d.h3Failure}")
                            assertEquals(
                                TransportError.CONNECTION_REFUSED,
                                (d.h3Failure as? io.kuicksilver.quic.QuicException.ConnectionLost.TransportClosed)?.code,
                                "call $i: ${d.h3Failure}",
                            )
                            assertEquals("h1", r.bodyAsText())
                            kotlinx.coroutines.withTimeout(30.seconds) { settled.receive() }
                            assertFalse(engine.brokenAltSvc.isBroken(origin, "127.0.0.1:$port"), "call $i marked the alternative broken")
                            assertEquals(listOf(port), engine.altSvcSnapshot(io.ktor.http.Url("$origin/")).map { it.port })
                        }
                        // the server takes new clients again: the next call goes over HTTP/3, no broken mark held it back
                        refuseWith.store(null)
                        val back = c.get("$origin/")
                        assertEquals(HttpProtocolVersion.HTTP_3_0, back.version, "${back.kuicksilverDiagnostics}")
                        assertNull(back.kuicksilverDiagnostics?.fallback)
                        assertEquals(emptyList(), marked, "altSvcMarkedBroken")
                    }
                } finally {
                    ep.close()
                    server.stop(100, 500)
                    coroutineContext[kotlinx.coroutines.Job]?.children?.forEach { it.cancel() }
                }
            }
        }

    /** A client on [port]'s alternative, with an HTTP/3 connection open: learns `Alt-Svc`, then one call goes over HTTP/3. */
    @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
    private suspend fun h3Client(port: Int): io.ktor.client.HttpClient {
        val c = testClient(Http3DiscoveryMode.Auto, engine = { http3 { hardDelay = Duration.INFINITE } })
        c.get("https://127.0.0.1:$port/") // learns h3
        val r = c.get("https://127.0.0.1:$port/")
        assertEquals(HttpProtocolVersion.HTTP_3_0, r.version, "${r.kuicksilverDiagnostics}")
        return c
    }

    /**
     * Calls [path] (`/goaway-close` or `/goaway-close-error`) over an open HTTP/3 connection: the server sends GOAWAY, the
     * test waits until the client's connection has it, and only then lets the server close the connection under the
     * request. Then [check] with the call's diagnostics, whether the alternative is broken, and a next call to the origin.
     */
    @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class, kotlin.concurrent.atomics.ExperimentalAtomicApi::class)
    private fun goAwayThenClose(
        path: String,
        check: suspend (d: ProtocolDiagnostics, broken: Boolean, nextCall: suspend () -> io.ktor.client.statement.HttpResponse) -> Unit,
    ) = h3Test {
        kotlinx.coroutines.coroutineScope {
            val refuseWith = kotlin.concurrent.atomics.AtomicReference<Long?>(null)
            val closeGate = CompletableDeferred<Unit>()
            val (server, ep, port) = originWithRefusingH3(refuseWith, closeGate)
            val origin = "https://127.0.0.1:$port"
            try {
                h3Client(port).use { c ->
                    val engine = c.engine as KuicksilverEngine
                    val conn =
                        assertNotNull(
                            engine.h3.existing(
                                io.kuicksilver.ktor.client.h3
                                    .H3Target("127.0.0.1", "127.0.0.1", port),
                            ),
                        )
                    val call = async { c.get("$origin$path") }
                    kotlinx.coroutines.withTimeout(30.seconds) { conn.goAwayReceived.first { it != null } }
                    closeGate.complete(Unit)
                    val r = call.await()
                    val d = assertNotNull(r.kuicksilverDiagnostics)
                    assertEquals(HttpProtocolVersion.HTTP_1_1, r.version, "$d")
                    assertEquals("h1", r.bodyAsText())
                    check(d, engine.brokenAltSvc.isBroken(origin, "127.0.0.1:$port")) { c.get("$origin/") }
                }
            } finally {
                closeGate.complete(Unit)
                ep.close()
                server.stop(100, 500)
                coroutineContext[kotlinx.coroutines.Job]?.children?.forEach { it.cancel() }
            }
        }
    }

    /**
     * A stopping server sends GOAWAY and, once its grace period ends, closes what is left with H3_NO_ERROR (RFC 9114
     * section 5.2): an orderly close, not a failure of the alternative (RFC 7838 section 2.4). The request in flight below
     * the GOAWAY id falls back to HTTP/1.1, the alternative is not marked broken, and the next call goes over HTTP/3 on a
     * new connection.
     */
    @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
    @Test
    fun closeAfterGoAwayDoesNotMarkBroken() =
        goAwayThenClose("/goaway-close") { d, broken, nextCall ->
            assertFalse(d.markedBroken, "$d")
            assertFalse(broken)
            val next = nextCall()
            assertEquals(HttpProtocolVersion.HTTP_3_0, next.version, "${next.kuicksilverDiagnostics}")
        }

    /**
     * Regression for [closeAfterGoAwayDoesNotMarkBroken]: GOAWAY followed by a close with an error code
     * (H3_INTERNAL_ERROR) is no graceful shutdown (RFC 9114 section 5.2 asks for H3_NO_ERROR) and marks the alternative
     * broken; a server sends GOAWAY early for other reasons too (a cap on requests per connection).
     */
    @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
    @Test
    fun negative_errorCloseAfterGoAwayMarksBroken() =
        goAwayThenClose("/goaway-close-error") { d, broken, _ ->
            assertTrue(d.markedBroken, "$d")
            assertTrue(broken)
        }

    /**
     * Regression for [closeAfterGoAwayDoesNotMarkBroken]: the same H3_NO_ERROR close without a GOAWAY first is a
     * connection that failed under its request, and marks the alternative broken: the code alone does not tell, the GOAWAY
     * must come first (an unknown code also reads as H3_NO_ERROR, RFC 9114 section 9).
     */
    @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class, kotlin.concurrent.atomics.ExperimentalAtomicApi::class)
    @Test
    fun negative_closeWithoutGoAwayMarksBroken() =
        h3Test {
            kotlinx.coroutines.coroutineScope {
                val refuseWith = kotlin.concurrent.atomics.AtomicReference<Long?>(null)
                val (server, ep, port) = originWithRefusingH3(refuseWith)
                val origin = "https://127.0.0.1:$port"
                try {
                    h3Client(port).use { c ->
                        val engine = c.engine as KuicksilverEngine
                        val r = c.get("$origin/close-no-error")
                        val d = assertNotNull(r.kuicksilverDiagnostics)
                        assertEquals(HttpProtocolVersion.HTTP_1_1, r.version, "$d")
                        assertTrue(d.markedBroken, "$d")
                        assertTrue(engine.brokenAltSvc.isBroken(origin, "127.0.0.1:$port"))
                    }
                } finally {
                    ep.close()
                    server.stop(100, 500)
                    coroutineContext[kotlinx.coroutines.Job]?.children?.forEach { it.cancel() }
                }
            }
        }

    /**
     * The request's own fallback path: the server rejects the request unprocessed (H3_REQUEST_REJECTED, as for a GOAWAY,
     * RFC 9114 section 5.2), the engine repeats it on a new connection, and the server refuses that one with
     * CONNECTION_REFUSED. The call falls back with `fallback = Refused`, the alternative is not marked broken, and once
     * the server takes clients again the next call goes over HTTP/3.
     */
    @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class, kotlin.concurrent.atomics.ExperimentalAtomicApi::class)
    @Test
    fun refusedRetryAfterRejectionDoesNotMarkBroken() =
        h3Test {
            kotlinx.coroutines.coroutineScope {
                val refuseWith = kotlin.concurrent.atomics.AtomicReference<Long?>(null)
                val (server, ep, port) = originWithRefusingH3(refuseWith)
                val origin = "https://127.0.0.1:$port"
                try {
                    h3Client(port).use { c ->
                        val engine = c.engine as KuicksilverEngine
                        val r = c.get("$origin/reject")
                        val d = assertNotNull(r.kuicksilverDiagnostics)
                        assertEquals(HttpProtocolVersion.HTTP_1_1, r.version, "$d")
                        assertEquals(FallbackReason.Refused, d.fallback, "${d.h3Failure}")
                        assertFalse(d.raced, "the open connection served the call, the fallback came after it: $d")
                        assertEquals(2, d.attempts, "the rejected attempt and the HTTP/1.1 one: $d")
                        assertFalse(d.markedBroken, "$d")
                        assertFalse(engine.brokenAltSvc.isBroken(origin, "127.0.0.1:$port"))
                        refuseWith.store(null)
                        val next = c.get("$origin/")
                        assertEquals(HttpProtocolVersion.HTTP_3_0, next.version, "${next.kuicksilverDiagnostics}")
                    }
                } finally {
                    ep.close()
                    server.stop(100, 500)
                    coroutineContext[kotlinx.coroutines.Job]?.children?.forEach { it.cancel() }
                }
            }
        }

    /**
     * Regression for [connectionRefusedFallsBackWithoutMarkingBroken]: a setup the server closes with any other code
     * (PROTOCOL_VIOLATION here) is a real setup failure, and still marks the alternative broken (RFC 7838 section 2.4).
     */
    @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class, kotlin.concurrent.atomics.ExperimentalAtomicApi::class)
    @Test
    fun negative_otherSetupCloseStillMarksBroken() =
        h3Test {
            kotlinx.coroutines.coroutineScope {
                val refuseWith = kotlin.concurrent.atomics.AtomicReference<Long?>(null)
                val (server, ep, port) = originWithRefusingH3(refuseWith)
                val markedBroken = CompletableDeferred<String>()
                val listener =
                    object : KuicksilverEventListener() {
                        override fun altSvcMarkedBroken(
                            origin: String,
                            alternative: String,
                        ) {
                            markedBroken.complete(alternative)
                        }
                    }
                val origin = "https://127.0.0.1:$port"
                try {
                    testClient(Http3DiscoveryMode.Auto, engine = {
                        eventListener = listener
                        http3 { hardDelay = Duration.INFINITE }
                    }).use { c ->
                        val engine = c.engine as KuicksilverEngine
                        c.get("$origin/") // learns h3
                        refuseWith.store(TransportError.PROTOCOL_VIOLATION)
                        val r = c.get("$origin/")
                        assertEquals(HttpProtocolVersion.HTTP_1_1, r.version)
                        assertEquals(FallbackReason.Refused, r.kuicksilverDiagnostics?.fallback, "${r.kuicksilverDiagnostics?.h3Failure}")
                        val alt =
                            kotlinx.coroutines.withTimeoutOrNull(30.seconds) { markedBroken.await() }
                                ?: kotlin.test.fail("127.0.0.1:$port was not marked broken within 30 s")
                        assertEquals("127.0.0.1:$port", alt)
                        assertTrue(engine.brokenAltSvc.isBroken(origin, alt))
                        refuseWith.store(null)
                        val next = c.get("$origin/")
                        assertEquals(HttpProtocolVersion.HTTP_1_1, next.version)
                        assertEquals(FallbackReason.BrokenAlternative, next.kuicksilverDiagnostics?.fallback)
                    }
                } finally {
                    ep.close()
                    server.stop(100, 500)
                    coroutineContext[kotlinx.coroutines.Job]?.children?.forEach { it.cancel() }
                }
            }
        }

    /**
     * The HTTP/3 connection to 127.0.0.1:[port], once there is one: joins the setup a lost race left running (or returns
     * the open connection) instead of polling the pool. The budget leaves room for a loaded host.
     */
    private suspend fun KuicksilverEngine.awaitH3Connection(port: Int) {
        val target = io.ktor.http.Url("https://127.0.0.1:$port/")
        val request = HttpRequestBuilder().apply { url(target) }.build()
        kotlinx.coroutines.withTimeoutOrNull(30.seconds) {
            h3.connection(
                io.kuicksilver.ktor.client.h3
                    .H3Target(target.host, target.host, target.port),
                request,
            )
        } ?: kotlin.test.fail("no HTTP/3 connection to $target within 30 s")
        assertTrue(hasH3Connection(target), "the HTTP/3 connection to $target closed before the next request")
    }

    /** Both setups fail: the h1 failure of the race is the result; the engine does not open a second TCP connection. */
    @Test fun raceFailureMakesOneH1Attempt() =
        clientTest {
            var accepts = 0
            val selector =
                io.ktor.network.selector
                    .SelectorManager(kotlinx.coroutines.Dispatchers.IO)
            val listener =
                io.ktor.network.sockets
                    .aSocket(selector)
                    .tcp()
                    .bind("127.0.0.1", 0)
            val port = (listener.localAddress as InetSocketAddress).port
            kotlinx.coroutines.coroutineScope {
                val acceptor =
                    launch {
                        while (true) {
                            val s = listener.accept() // nobody listens on UDP; TCP accepts and closes at once
                            accepts++
                            s.close()
                        }
                    }
                try {
                    testClient(Http3DiscoveryMode.Auto, engine = {
                        http3 { quicHints = setOf(HostPort("127.0.0.1", port)) }
                        quic = quicConfig { handshakeTimeout = 500.milliseconds }
                    }).use { c ->
                        assertFailsWith<Throwable> { c.get("https://127.0.0.1:$port/") }
                    }
                    delay(200) // a second attempt, if any, would arrive right after the failure
                    assertEquals(1, accepts, "one h1 attempt: the race's")
                } finally {
                    acceptor.cancel()
                    listener.close()
                    selector.close()
                }
            }
        }

    /**
     * HTTP/3 failed at connection level while HTTP/1.1 served the request: the alternative is marked broken (RFC 7838 section 2.4).
     * Which setup wins the first race is up to the host: when HTTP/3 wins, that first request fails on it and HTTP/1.1
     * serves it, so the alternative is broken and no HTTP/3 connection is left to wait for (1 of 40 runs on the Windows VM).
     */
    @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class, kotlin.concurrent.atomics.ExperimentalAtomicApi::class)
    @Test
    fun h3FailureWithH1SuccessMarksBroken() =
        h3Test {
            kotlinx.coroutines.coroutineScope {
                val (server, ep, port) =
                    h1AndH3({ routing { get("/") { call.respondText("h1") } } }) { failingH3(closeConnection = true) }
                val winners = mutableListOf<HttpProtocolVersion>()
                val fallbacks = mutableListOf<Throwable>()
                val listener =
                    object : KuicksilverEventListener() {
                        override fun raceEnded(
                            request: io.ktor.client.request.HttpRequestData,
                            winner: HttpProtocolVersion,
                            headStart: kotlin.time.Duration,
                            h3Failure: Throwable?,
                        ) {
                            winners += winner
                        }

                        override fun fallback(
                            request: io.ktor.client.request.HttpRequestData,
                            cause: Throwable,
                        ) {
                            fallbacks += cause
                        }
                    }
                try {
                    testClient(Http3DiscoveryMode.Preferred, engine = { eventListener = listener }).use { c ->
                        assertEquals(HttpProtocolVersion.HTTP_1_1, c.get("https://127.0.0.1:$port/").version)
                        val engine = c.engine as KuicksilverEngine
                        if (winners.single() == HttpProtocolVersion.HTTP_1_1) {
                            // HTTP/1.1 won the race; the HTTP/3 setup outlives it and serves the next request, which fails on it
                            engine.awaitH3Connection(port)
                            // the wait joined (or found) the race's own setup; a loser cancelled with the race would have
                            // left the wait to start a setup of its own, which counts no waiter
                            assertEquals(1, engine.h3.setupWaitersForTest.load(), "the HTTP/3 setup that lost the race was not kept")
                            assertEquals(HttpProtocolVersion.HTTP_1_1, c.get("https://127.0.0.1:$port/").version)
                        }
                        assertEquals(1, fallbacks.size, "one request failed over HTTP/3 and went to HTTP/1.1: $fallbacks")
                        assertTrue(engine.brokenAltSvc.isBroken("https://127.0.0.1:$port", "127.0.0.1:$port"))
                    }
                } finally {
                    ep.close()
                    server.stop(100, 500)
                    coroutineContext[kotlinx.coroutines.Job]?.children?.forEach { it.cancel() }
                }
            }
        }

    /** A single stream reset on a working HTTP/3 connection falls back for that request but does not mark the alternative broken. */
    @Test fun streamErrorDoesNotMarkAlternativeBroken() =
        h3Test {
            kotlinx.coroutines.coroutineScope {
                val (server, ep, port) =
                    h1AndH3({ routing { get("/") { call.respondText("h1") } } }) { failingH3(okPaths = setOf("/warmup")) }
                try {
                    testClient(Http3DiscoveryMode.Preferred).use { c ->
                        val engine = c.engine as KuicksilverEngine
                        // the first request may be won by HTTP/1.1 outright; wait for the HTTP/3 connection the race left behind
                        c.get("https://127.0.0.1:$port/warmup")
                        engine.awaitH3Connection(port)
                        assertEquals(HttpProtocolVersion.HTTP_1_1, c.get("https://127.0.0.1:$port/").version)
                        assertTrue(
                            !engine.brokenAltSvc.isBroken("https://127.0.0.1:$port", "127.0.0.1:$port"),
                            "a stream reset is no broken alternative",
                        )
                    }
                } finally {
                    ep.close()
                    server.stop(100, 500)
                    coroutineContext[kotlinx.coroutines.Job]?.children?.forEach { it.cancel() }
                }
            }
        }

    @Test fun idempotentRetriedOnH1() =
        h3Test {
            var h1Calls = 0
            kotlinx.coroutines.coroutineScope {
                val (server, ep, port) =
                    h1AndH3({
                        routing {
                            get("/") {
                                h1Calls++
                                call.respondText("h1")
                            }
                        }
                    }) { failingH3() }
                try {
                    testClient(Http3DiscoveryMode.Preferred).use { c ->
                        val r = c.get("https://127.0.0.1:$port/")
                        assertEquals(HttpProtocolVersion.HTTP_1_1, r.version)
                        assertEquals(1, h1Calls)
                    }
                } finally {
                    ep.close()
                    server.stop(100, 500)
                    coroutineContext[kotlinx.coroutines.Job]?.children?.forEach { it.cancel() }
                }
            }
        }

    @Test fun nonIdempotentNotRetriedAfterHeadersSent() =
        h3Test {
            var h1Calls = 0
            kotlinx.coroutines.coroutineScope {
                val (server, ep, port) =
                    h1AndH3({
                        routing {
                            post("/") {
                                h1Calls++
                                call.respondText("h1")
                            }
                        }
                    }) { failingH3(okPaths = setOf("/warmup")) }
                try {
                    testClient(Http3DiscoveryMode.Preferred).use { c ->
                        // set up the HTTP/3 connection first (the first request may race to HTTP/1.1), so the POST goes over HTTP/3;
                        // the warm-up must succeed over HTTP/3: a fallback would mark the alternative broken and route the POST to HTTP/1.1
                        runCatching { c.get("https://127.0.0.1:$port/warmup") }
                        val engine = c.engine as KuicksilverEngine
                        engine.awaitH3Connection(port)
                        val e = assertFailsWith<Throwable> { c.post("https://127.0.0.1:$port/") { setBody("payment") } }
                        assertTrue(generateSequence(e) { it.cause }.any { it is Http3Exception.Protocol }, "$e")
                        assertEquals(0, h1Calls)
                    }
                } finally {
                    ep.close()
                    server.stop(100, 500)
                    coroutineContext[kotlinx.coroutines.Job]?.children?.forEach { it.cancel() }
                }
            }
        }

    /** A streamed body that HTTP/3 already consumed is not replayed on the HTTP/1.1 fallback: the failure surfaces instead. */
    @Test fun streamedBodyNotReplayedAfterMidUploadFailure() =
        h3Test {
            var h1Calls = 0
            kotlinx.coroutines.coroutineScope {
                val (server, ep, port) =
                    h1AndH3({
                        routing {
                            put("/") {
                                h1Calls++
                                call.respondText("h1")
                            }
                        }
                    }) {
                        // reads part of the body, then fails the stream
                        h3Endpoint().also { ep ->
                            launch {
                                runCatching {
                                    while (true) {
                                        val conn = ep.accept()
                                        launch {
                                            runCatching {
                                                while (true) {
                                                    val r = conn.acceptRequest()
                                                    if (r.path == "/warmup") {
                                                        launch { runCatching { r.respond(200).finish() } }
                                                        continue
                                                    }
                                                    launch {
                                                        runCatching {
                                                            val b = ByteArray(65_536)
                                                            var got = 0
                                                            while (got < b.size) {
                                                                val n = r.body.readAvailable(b, 0, b.size - got)
                                                                if (n < 0) break
                                                                got += n
                                                            }
                                                        }
                                                        r.reset(Http3ErrorCode.INTERNAL_ERROR)
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                try {
                    testClient(Http3DiscoveryMode.Preferred).use { c ->
                        runCatching { c.get("https://127.0.0.1:$port/warmup") }
                        val engine = c.engine as KuicksilverEngine
                        engine.awaitH3Connection(port)
                        val streamed =
                            object : io.ktor.http.content.OutgoingContent.ReadChannelContent() {
                                override fun readFrom() =
                                    io.ktor.utils.io.ByteReadChannel(
                                        ByteArray(1024 * 1024),
                                    )
                            }
                        val e = assertFailsWith<Throwable> { c.put("https://127.0.0.1:$port/") { setBody(streamed) } }
                        assertTrue(generateSequence(e) { it.cause }.any { it is Http3Exception }, "the HTTP/3 failure surfaces: $e")
                        assertEquals(0, h1Calls, "no HTTP/1.1 retry with a consumed body")
                    }
                } finally {
                    ep.close()
                    server.stop(100, 500)
                    coroutineContext[kotlinx.coroutines.Job]?.children?.forEach { it.cancel() }
                }
            }
        }
}
