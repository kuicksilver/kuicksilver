// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class, kotlin.concurrent.atomics.ExperimentalAtomicApi::class)

package io.kuicksilver.ktor.client

import io.ktor.client.HttpClient
import io.ktor.client.HttpClientConfig
import io.ktor.client.network.sockets.SocketTimeoutException
import io.ktor.client.plugins.HttpTimeout
import io.ktor.client.plugins.HttpTimeoutConfig
import io.ktor.client.plugins.sse.SSE
import io.ktor.client.plugins.sse.sse
import io.ktor.client.plugins.timeout
import io.ktor.client.plugins.websocket.WebSockets
import io.ktor.client.plugins.websocket.webSocket
import io.ktor.client.request.HttpRequestBuilder
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.request.url
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpProtocolVersion
import io.ktor.http.content.OutgoingContent
import io.ktor.server.request.receiveChannel
import io.ktor.server.response.respondBytesWriter
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import io.ktor.server.routing.routing
import io.ktor.sse.ServerSentEvent
import io.ktor.utils.io.ByteWriteChannel
import io.ktor.utils.io.discard
import io.ktor.utils.io.writeFully
import io.ktor.utils.io.writeStringUtf8
import io.ktor.websocket.Frame
import io.ktor.websocket.readText
import io.kuicksilver.ktor.client.h3.Stall
import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.nanoseconds
import kotlin.time.Duration.Companion.seconds
import io.ktor.server.application.install as serverInstall
import io.ktor.server.sse.SSE as ServerSSE
import io.ktor.server.sse.sse as serverSse
import io.ktor.server.websocket.WebSockets as ServerWebSockets
import io.ktor.server.websocket.webSocket as serverWebSocket

/**
 * `engine { socketTimeout }`: 10 s by default, the time without progress in either direction (OkHttp's read and write
 * timeouts), over HTTP/1.1, HTTP/2 and HTTP/3; `HttpTimeout`'s value wins; WebSockets, SSE and event streams are left
 * alone. Real time: a stall has to last, and a slow stream has to keep moving for longer than the timeout.
 */
private const val SLOW_STEPS = 30

class ClientSocketTimeoutTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    // wide margins on the real clock: a progressing stream moves every short / 20, a stall lasts short * 2
    private val short = 2.seconds

    /** The protocols a scenario runs over: HTTP/1.1, HTTP/2, and HTTP/3 where a QUIC server can run. */
    private enum class Proto { H1, H2, H3 }

    private suspend fun protos(): List<Proto> = listOf(Proto.H1, Proto.H2) + if (quicServerSupported()) listOf(Proto.H3) else emptyList()

    private suspend fun server(
        proto: Proto,
        routes: io.ktor.server.routing.Routing.() -> Unit,
    ) = testServer(configure = {
        http2 { enabled = proto == Proto.H2 }
        http3 { enabled = proto == Proto.H3 }
    }) {
        serverInstall(ServerSSE)
        serverInstall(ServerWebSockets)
        routing(routes)
    }

    private fun client(
        proto: Proto,
        socketTimeout: Duration? = short,
        block: HttpClientConfig<KuicksilverEngineConfig>.() -> Unit = {},
    ): HttpClient =
        testClient(if (proto == Proto.H3) Http3Discovery.H3Only else null, engine = {
            this.socketTimeout = socketTimeout
            if (proto == Proto.H1) http2 { enabled = false }
        }, block = block)

    private fun version(proto: Proto) =
        when (proto) {
            Proto.H1 -> HttpProtocolVersion.HTTP_1_1
            Proto.H2 -> HttpProtocolVersion.HTTP_2_0
            Proto.H3 -> HttpProtocolVersion.HTTP_3_0
        }

    private fun assertSocketTimeout(
        e: Throwable,
        what: String,
    ) {
        assertTrue(generateSequence(e) { it.cause }.any { it is SocketTimeoutException }, "$what: $e")
    }

    private suspend fun each(block: suspend (Proto, Int) -> Unit) {
        for (proto in protos()) {
            val (server, port) =
                server(proto) {
                    get("/stall-head") { awaitCancellation() }
                    get("/stall-body") {
                        call.respondBytesWriter {
                            writeStringUtf8("a")
                            flush()
                            awaitCancellation()
                        }
                    }
                    get("/slow") {
                        call.respondBytesWriter {
                            repeat(SLOW_STEPS) {
                                writeStringUtf8("x")
                                flush()
                                delay(short / 20)
                            }
                        }
                    }
                    get("/pause") {
                        delay(short * 2)
                        call.respondText("late")
                    }
                    get("/events") {
                        call.respondBytesWriter(contentType = ContentType.Text.EventStream) {
                            writeStringUtf8("data: a\n\n")
                            flush()
                            delay(short * 2)
                            writeStringUtf8("data: b\n\n")
                        }
                    }
                    serverSse("/sse") {
                        send(ServerSentEvent("a"))
                        delay(short * 2)
                        send(ServerSentEvent("b"))
                    }
                    serverWebSocket("/ws") {
                        val f = incoming.receive() as Frame.Text
                        delay(short * 2)
                        send(Frame.Text("late:" + f.readText()))
                    }
                    post("/sink") { awaitCancellation() }
                    post("/count") {
                        val ch = call.receiveChannel()
                        call.respondText("${ch.discard()}")
                    }
                }
            try {
                block(proto, port)
            } finally {
                server.stop(100, 500)
            }
        }
    }

    @Test fun theDefaultIsTenSeconds() {
        assertEquals(10.seconds, KuicksilverEngineConfig().socketTimeout)
    }

    @Test fun negative_aTimeoutBelowOneMillisecondIsRefused() {
        for (bad in listOf(Duration.ZERO, (-1).seconds, 500.nanoseconds)) {
            val e = assertFailsWith<IllegalArgumentException>("$bad") { HttpClient(Kuicksilver) { engine { socketTimeout = bad } }.close() }
            assertContains(e.message!!, "socketTimeout must be at least 1 ms or null")
        }
        HttpClient(Kuicksilver) { engine { socketTimeout = null } }.close()
    }

    /** A server that accepts and stays silent no longer holds a call forever: the default fails it, no `HttpTimeout` needed. */
    @Test fun negative_aSilentServerTimesOutBeforeTheHead() =
        clientTest {
            each { proto, port ->
                client(proto).use { c ->
                    assertSocketTimeout(assertFailsWith<Throwable> { c.get("https://127.0.0.1:$port/stall-head") }, "$proto")
                }
            }
        }

    @Test fun negative_aStalledResponseBodyTimesOut() =
        clientTest {
            each { proto, port ->
                client(proto).use { c ->
                    assertSocketTimeout(assertFailsWith<Throwable> { c.get("https://127.0.0.1:$port/stall-body").bodyAsText() }, "$proto")
                }
            }
        }

    /** A peer that stops reading stalls the upload (flow control, full socket buffers): the write side times out too. */
    @Test fun negative_aStalledUploadTimesOut() =
        clientTest {
            each { proto, port ->
                client(proto).use { c ->
                    val e =
                        assertFailsWith<Throwable> {
                            c.post("https://127.0.0.1:$port/sink") {
                                setBody(
                                    object : OutgoingContent.WriteChannelContent() {
                                        override suspend fun writeTo(channel: ByteWriteChannel) {
                                            val chunk = ByteArray(64 * 1024)
                                            repeat(4096) { channel.writeFully(chunk) } // 256 MiB: more than any buffer on the way
                                        }
                                    },
                                )
                            }
                        }
                    assertSocketTimeout(e, "$proto")
                }
            }
        }

    /**
     * HTTP/1.1, the order a loaded host can take: the expiry closes the connection under the stalled body, whose write then
     * fails with "connection closed"; that failure may be recorded before the exchange looks at it
     * ([io.kuicksilver.ktor.client.h1.H1Pool.exchangeFailedForTest] waits for the body's end there). The call still fails
     * with the socket timeout, not with the closed channel the timeout caused.
     */
    @Test fun negative_aStalledUploadTimesOutWhenItsBodyFailsFirst() =
        clientTest {
            each { proto, port ->
                if (proto != Proto.H1) return@each
                client(proto).use { c ->
                    var bodyFailure: Throwable? = null
                    (c.engine as KuicksilverEngine).h1.exchangeFailedForTest = { sender ->
                        if (sender != null) {
                            withTimeout(10.seconds) { sender.sent.await() }
                            bodyFailure = sender.failure
                        }
                    }
                    val e =
                        assertFailsWith<Throwable> {
                            c.post("https://127.0.0.1:$port/sink") {
                                setBody(
                                    object : OutgoingContent.WriteChannelContent() {
                                        override suspend fun writeTo(channel: ByteWriteChannel) {
                                            val chunk = ByteArray(64 * 1024)
                                            repeat(4096) { channel.writeFully(chunk) } // 256 MiB: more than any buffer on the way
                                        }
                                    },
                                )
                            }
                        }
                    assertNotNull(bodyFailure, "the body's write failed before the exchange looked: $e")
                    assertSocketTimeout(e, "$proto (the body failed with $bodyFailure)")
                }
            }
        }

    /** The timeout is inactivity: a download that keeps moving never trips it, though it takes 1.5 times as long. */
    @Test fun aSlowButProgressingDownloadNeverTimesOut() =
        clientTest {
            each { proto, port ->
                client(proto).use { c ->
                    val r = c.get("https://127.0.0.1:$port/slow")
                    assertEquals(version(proto), r.version)
                    assertEquals("x".repeat(SLOW_STEPS), r.bodyAsText())
                }
            }
        }

    @Test fun aSlowButProgressingUploadNeverTimesOut() =
        clientTest {
            each { proto, port ->
                client(proto).use { c ->
                    val r =
                        c.post("https://127.0.0.1:$port/count") {
                            setBody(
                                object : OutgoingContent.WriteChannelContent() {
                                    override suspend fun writeTo(channel: ByteWriteChannel) {
                                        repeat(SLOW_STEPS) {
                                            channel.writeFully(ByteArray(1024))
                                            channel.flush()
                                            delay(short / 20)
                                        }
                                    }
                                },
                            )
                        }
                    assertEquals("${SLOW_STEPS * 1024}", r.bodyAsText(), "$proto")
                }
            }
        }

    /** SSE (the plugin's sessions, and any `text/event-stream` body) is long-lived by nature: the default leaves it alone. */
    @Test fun eventStreamsAreLeftAlone() =
        clientTest {
            each { proto, port ->
                client(proto, block = { install(SSE) }).use { c ->
                    // Ktor's SSE plugin over HTTP/2 and HTTP/3 gets no events from this engine whatever the timeout (a separate
                    // bug, not the socket timeout's, which an SSE request never takes); the plain event stream below covers them
                    if (proto == Proto.H1) {
                        val got = ArrayList<String>()
                        c.sse("https://127.0.0.1:$port/sse") { incoming.collect { e -> e.data?.let { got += it } } }
                        assertEquals(listOf("a", "b"), got, "$proto")
                    }
                    val asked = c.get("https://127.0.0.1:$port/events") { header(HttpHeaders.Accept, "text/event-stream") }
                    assertEquals("data: a\n\ndata: b\n\n", asked.bodyAsText(), "$proto")
                }
            }
        }

    /**
     * L1: a server cannot turn the client's timeout off by answering an ordinary request with `text/event-stream`: only a
     * request that asked for an event stream is left alone.
     */
    @Test fun negative_anEventStreamNobodyAskedForKeepsTheTimeout() =
        clientTest {
            each { proto, port ->
                client(proto).use { c ->
                    assertSocketTimeout(assertFailsWith<Throwable> { c.get("https://127.0.0.1:$port/events").bodyAsText() }, "$proto")
                }
            }
        }

    /** An explicit `HttpTimeout` still applies to them: the application asked for it. */
    @Test fun negative_anExplicitHttpTimeoutStillAppliesToEventStreams() =
        clientTest {
            each { proto, port ->
                client(proto, socketTimeout = null, block = {
                    install(HttpTimeout) { socketTimeoutMillis = short.inWholeMilliseconds }
                }).use { c ->
                    assertSocketTimeout(assertFailsWith<Throwable> { c.get("https://127.0.0.1:$port/events").bodyAsText() }, "$proto")
                }
            }
        }

    /** A WebSocket session that is quiet for longer than the timeout is not cut (its pings are the session's own watch). */
    @Test fun webSocketSessionsAreLeftAlone() =
        clientTest {
            each { proto, port ->
                client(proto, block = { install(WebSockets) }).use { c ->
                    var answer = ""
                    c.webSocket("wss://127.0.0.1:$port/ws") {
                        send(Frame.Text("hi"))
                        answer = (incoming.receive() as Frame.Text).readText()
                    }
                    assertEquals("late:hi", answer, "$proto")
                }
            }
        }

    /** `HttpTimeout` wins in both directions: a longer value, `INFINITE_TIMEOUT_MS` per request, and a shorter one. */
    @Test fun httpTimeoutTakesPrecedence() =
        clientTest {
            each { proto, port ->
                client(proto, block = { install(HttpTimeout) { socketTimeoutMillis = 10_000 } }).use { c ->
                    assertEquals("late", c.get("https://127.0.0.1:$port/pause").bodyAsText(), "$proto: HttpTimeout's 10 s")
                }
                client(proto).use { c ->
                    assertSocketTimeout(assertFailsWith<Throwable> { c.get("https://127.0.0.1:$port/pause") }, "$proto: the default")
                    val r =
                        c.get("https://127.0.0.1:$port/pause") {
                            timeout { socketTimeoutMillis = HttpTimeoutConfig.INFINITE_TIMEOUT_MS }
                        }
                    assertEquals("late", r.bodyAsText(), "$proto: off for one request")
                }
                client(proto, socketTimeout = 10.seconds, block = {
                    install(HttpTimeout) { socketTimeoutMillis = short.inWholeMilliseconds }
                }).use { c ->
                    assertSocketTimeout(
                        assertFailsWith<Throwable> { c.get("https://127.0.0.1:$port/pause") },
                        "$proto: HttpTimeout's shorter",
                    )
                }
            }
        }

    /** `null` is off (ADR-0026 principle 6). */
    @Test fun nullTurnsItOff() =
        clientTest {
            each { proto, port ->
                client(proto, socketTimeout = null).use { c ->
                    assertEquals("late", c.get("https://127.0.0.1:$port/pause").bodyAsText(), "$proto")
                }
            }
        }

    /** What the engine applies to which request, without a connection. */
    @Test fun whichRequestsTakeTheDefault() {
        val config = KuicksilverEngineConfig()

        fun request(block: HttpRequestBuilder.() -> Unit = {}) =
            HttpRequestBuilder()
                .apply {
                    url("https://a.test/")
                    block()
                }.build()
        assertEquals(10_000L, request().socketTimeoutMillis(config))
        assertNull(request { setCapability(io.ktor.client.plugins.sse.SSECapability, Unit) }.socketTimeoutMillis(config))
        val accepts = request { header(HttpHeaders.Accept, "application/json, text/event-stream;q=0.9") }
        assertNull(accepts.bodySocketTimeoutMillis(config, "text/event-stream; charset=utf-8"))
        assertNull(accepts.bodySocketTimeoutMillis(config, "Text/Event-Stream"))
        assertNull(
            request { setCapability(io.ktor.client.plugins.sse.SSECapability, Unit) }.bodySocketTimeoutMillis(config, "text/event-stream"),
        )
        // not asked for: the server's choice of type changes nothing (L1)
        assertEquals(10_000L, request().bodySocketTimeoutMillis(config, "text/event-stream"))
        assertEquals(10_000L, request().bodySocketTimeoutMillis(config, "text/plain"))
        assertEquals(10_000L, request().bodySocketTimeoutMillis(config, null))
        assertEquals(
            300L,
            request {
                header(HttpHeaders.Accept, "text/event-stream")
                setCapability(io.ktor.client.plugins.HttpTimeoutCapability, HttpTimeoutConfig(socketTimeoutMillis = 300))
            }.bodySocketTimeoutMillis(config, "text/event-stream"),
        )
        assertNull(
            request {
                setCapability(
                    io.ktor.client.plugins.HttpTimeoutCapability,
                    HttpTimeoutConfig(socketTimeoutMillis = HttpTimeoutConfig.INFINITE_TIMEOUT_MS),
                )
            }.socketTimeoutMillis(config),
        )
        // HttpTimeout installed without a socket timeout (only a request timeout): the engine's default applies
        assertEquals(
            10_000L,
            request {
                setCapability(io.ktor.client.plugins.HttpTimeoutCapability, HttpTimeoutConfig(requestTimeoutMillis = 30_000))
            }.socketTimeoutMillis(config),
        )
        assertNull(request().socketTimeoutMillis(KuicksilverEngineConfig().apply { socketTimeout = null }))
    }

    /**
     * The wiring of the cause: a socket timeout that runs out as a stall is declared names it (the end-to-end behaviour, the
     * timer standing still during a stall, is ClientH3StallTest's aStallHoldsTheSocketTimeoutUntilThePathComesBack and
     * negative_aStallThatLastsFailsAtAbandonAfterNotAtTheSocketTimeout).
     */
    @Test fun aTimeoutDuringAStallCarriesTheStall(): Unit =
        runBlocking {
            val request = HttpRequestBuilder().apply { url("https://a.test/") }.build()
            val stall = Stall(2.seconds, 3, handshakeComplete = true)
            val e =
                assertFailsWith<SocketTimeoutException> {
                    withSocketInactivityTimeout(request, 50, Activity(), cause = { stall.exception(it) }) { awaitCancellation() }
                }
            assertIs<QuicStalledException>(e.cause)
            val plain =
                assertFailsWith<SocketTimeoutException> { withSocketInactivityTimeout(request, 50, Activity()) { awaitCancellation() } }
            assertIs<kotlinx.coroutines.CancellationException>(plain.cause)
        }
}
