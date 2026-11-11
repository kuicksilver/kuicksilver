// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class, io.kuicksilver.annotations.InternalKuicksilverApi::class)

package io.kuicksilver.ktor.server

import io.ktor.client.HttpClient
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsBytes
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpProtocolVersion
import io.ktor.http.HttpStatusCode
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.server.application.ApplicationCall
import io.ktor.server.engine.connector
import io.ktor.server.request.httpVersion
import io.ktor.server.request.receiveChannel
import io.ktor.server.request.receiveText
import io.ktor.server.response.respondBytes
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import io.ktor.server.routing.routing
import io.ktor.utils.io.readAvailable
import io.kuicksilver.http2.Http2Settings
import io.kuicksilver.ktor.client.Http3DiscoveryMode
import io.kuicksilver.native.KslLoader
import io.kuicksilver.tls.Certificate
import io.kuicksilver.tls.TrustConfig
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.withTimeout
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds
import io.kuicksilver.ktor.client.Kuicksilver as KuicksilverClient

/**
 * HTTP/2 in the server engine (RFC 9113; docs/guide/ktor.md, "HTTP/2 on the server"): ALPN `h2` on TLS connectors when
 * `http2` is set, Ktor calls per stream, the two-step GOAWAY at a stop, the deadlines, and requests no real client sends,
 * written by hand ([RawH2Client]): each malformed one is a stream error of type PROTOCOL_ERROR (section 8.1.1) and the
 * connection goes on.
 */
class ServerH2Test {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private fun client() =
        HttpClient(KuicksilverClient) {
            expectSuccess = false
            engine {
                trust = TrustConfig.AnchoredCa(listOf(Certificate(TestCerts.testCa)))
                http3 { discovery = Http3DiscoveryMode.H1Only } // the TCP path: HTTP/2 when the server offers it
            }
        }

    private suspend fun h2Server(
        configure: KuicksilverApplicationEngine.Configuration.() -> Unit = {},
        module: io.ktor.server.application.Application.() -> Unit,
    ): Pair<Server, Int> =
        tlsServer(
            configure = {
                http2 = true
                http3 = false
                configure()
            },
            module = module,
        )

    private val protocolError = 0x1L

    @Test fun servesH2WhenOffered() =
        serverTest {
            val opened = Channel<HttpProtocolVersion>(Channel.UNLIMITED)
            val (server, port) =
                h2Server(configure = {
                    eventListener =
                        object : KuicksilverServerEventListener() {
                            override fun connectionOpened(
                                protocol: HttpProtocolVersion,
                                remote: InetSocketAddress?,
                            ) {
                                opened.trySend(protocol)
                            }
                        }
                }) {
                    routing { get("/") { call.respondText("${call.request.httpVersion} ${call.request.local.scheme}") } }
                }
            try {
                client().use { c ->
                    val r = withTimeout(10.seconds) { c.get("https://127.0.0.1:$port/") }
                    assertEquals(HttpProtocolVersion.HTTP_2_0, r.version)
                    assertEquals("HTTP/2 https", r.bodyAsText())
                }
                assertEquals(HttpProtocolVersion.HTTP_2_0, withTimeout(5.seconds) { opened.receive() })
                RawH2Client.connect(port, listOf("h2", "http/1.1")).use { assertEquals("h2", it.alpn) }
            } finally {
                server.stop(100, 500)
            }
        }

    @Test fun h1ClientStillServed() =
        serverTest {
            val (server, port) = h2Server { routing { get("/") { call.respondText("v=${call.request.httpVersion}") } } }
            try {
                val resp = rawHttp(port, "GET / HTTP/1.1\r\nHost: server.test\r\nConnection: close\r\n\r\n")
                assertTrue(resp.startsWith("HTTP/1.1 200") && resp.endsWith("v=HTTP/1.1"), resp)
            } finally {
                server.stop(100, 500)
            }
        }

    /** 0.3.0: HTTP/2 is opt-in; without `http2` the ALPN of a TLS connector stays `http/1.1`, as in 0.2. */
    @Test fun disabledByDefaultOffersOnlyHttp11() =
        serverTest {
            val (server, port) = tlsServer(configure = { http3 = false }) { routing { get("/") { call.respondText("ok") } } }
            try {
                RawH2Client.connect(port, listOf("h2", "http/1.1")).use { assertEquals("http/1.1", it.alpn) }
                client().use { c ->
                    assertEquals(HttpProtocolVersion.HTTP_1_1, withTimeout(10.seconds) { c.get("https://127.0.0.1:$port/") }.version)
                }
            } finally {
                server.stop(100, 500)
            }
        }

    @Test fun routingParametersHeadersBodyRoundTrip() =
        serverTest {
            val (server, port) =
                h2Server {
                    routing {
                        post("/echo/{name}") {
                            val body = call.receiveText()
                            call.response.headers.append("X-Name", call.parameters["name"]!!)
                            call.respondText("${call.request.queryParameters["q"]}|${call.request.headers["X-In"]}|$body")
                        }
                    }
                }
            try {
                client().use { c ->
                    val r =
                        withTimeout(10.seconds) {
                            c.post("https://127.0.0.1:$port/echo/kq?q=1") {
                                header("X-In", "in")
                                setBody("hello")
                            }
                        }
                    assertEquals(HttpProtocolVersion.HTTP_2_0, r.version)
                    assertEquals("kq", r.headers["X-Name"])
                    assertEquals("1|in|hello", r.bodyAsText())
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /** An upload far larger than the server's windows goes through: credit follows the handler's reading (section 5.2). */
    @Test fun largeUploadThroughSmallWindows() =
        serverTest {
            val size = 8 shl 20
            val (server, port) =
                h2Server(configure = {
                    http2Settings =
                        Http2Settings(
                            initialStreamWindow = 65_536,
                            maxStreamWindow = 65_536,
                            initialConnectionWindow = 65_536,
                            maxConnectionWindow = 65_536,
                        )
                }) {
                    routing {
                        post("/") {
                            val ch = call.receiveChannel()
                            val buf = ByteArray(8192)
                            var n = 0L
                            var sum = 0L
                            while (true) {
                                val k = ch.readAvailable(buf, 0, buf.size)
                                if (k < 0) break
                                n += k
                                for (i in 0 until k) sum += buf[i]
                            }
                            call.respondText("$n $sum")
                        }
                    }
                }
            try {
                val payload = ByteArray(size) { (it % 251).toByte() }
                client().use { c ->
                    val r = withTimeout(30.seconds) { c.post("https://127.0.0.1:$port/") { setBody(payload) } }
                    assertEquals(HttpProtocolVersion.HTTP_2_0, r.version)
                    assertEquals("$size ${payload.sumOf { it.toLong() }}", r.bodyAsText())
                }
            } finally {
                server.stop(100, 500)
            }
        }

    @Test fun largeResponseAndHead() =
        serverTest {
            val content = ByteArray(1 shl 20) { (it % 7).toByte() }
            val (server, port) = h2Server { routing { get("/big") { call.respondBytes(content) } } }
            try {
                client().use { c ->
                    val r = withTimeout(20.seconds) { c.get("https://127.0.0.1:$port/big") }
                    assertContentEquals(content, r.bodyAsBytes())
                }
                // HEAD (RFC 9110 section 9.3.2): the fields a GET would have, no content (a DATA frame would make it malformed)
                RawH2Client.connect(port).use { raw ->
                    raw.preface()
                    raw.headers(1, RawH2Client.get("/big").map { if (it.first == ":method") ":method" to "HEAD" else it })
                    val h = assertNotNull(raw.await { it.stream == 1 })
                    assertEquals(RawFrame.HEADERS, h.type)
                    assertTrue(h.endStream, "a HEAD response ends with its HEADERS")
                }
            } finally {
                server.stop(100, 500)
            }
        }

    @Test fun altSvcOnH2Responses() =
        h3ServerTest {
            val (server, port) = tlsServer(configure = { http2 = true }) { routing { get("/") { call.respondText("ok") } } }
            try {
                client().use { c ->
                    val r = withTimeout(10.seconds) { c.get("https://127.0.0.1:$port/") }
                    assertEquals(HttpProtocolVersion.HTTP_2_0, r.version)
                    assertEquals("h3=\":$port\"; ma=86400", r.headers["Alt-Svc"])
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /**
     * RFC 9113 section 6.8: a stop sends GOAWAY with 2^31-1 and a PING, then (once the PING is answered) GOAWAY with the
     * last stream taken. The request in flight completes; a stream opened after the second GOAWAY gets no answer, and the
     * connection closes when the first is done.
     */
    @Test fun gracefulStopTwoPhaseGoAway() =
        serverTest {
            val release = CompletableDeferred<Unit>()
            val started = CompletableDeferred<Unit>()
            val (server, port) =
                h2Server {
                    routing {
                        get("/") {
                            started.complete(Unit)
                            release.await()
                            call.respondText("done")
                        }
                    }
                }
            RawH2Client.connect(port).use { raw ->
                coroutineScope {
                    raw.preface()
                    raw.headers(1, RawH2Client.get())
                    withTimeout(10.seconds) { started.await() }
                    val stop = async { server.stopSuspend(10_000, 15_000) }
                    val first = assertNotNull(raw.await { it.type == RawFrame.GOAWAY })
                    assertEquals(Int.MAX_VALUE, first.lastStreamId)
                    assertEquals(0L, first.errorCode)
                    val ping = assertNotNull(raw.await { it.type == RawFrame.PING && it.flags and 1 == 0 })
                    raw.write(RawH2Client.frame(RawFrame.PING, 1, 0, ping.payload))
                    val second = assertNotNull(raw.await { it.type == RawFrame.GOAWAY })
                    assertEquals(1, second.lastStreamId)
                    raw.headers(3, RawH2Client.get()) // after the GOAWAY: not processed
                    release.complete(Unit)
                    val rest = raw.readToEnd()
                    assertTrue(rest.any { it.stream == 1 && it.type == RawFrame.DATA && it.endStream }, "$rest")
                    assertTrue(rest.none { it.stream == 3 }, "$rest")
                    // the client closes, as a real one does after GOAWAY and the end of the stream: its close_notify ends
                    // the server's TLS close at once (without it the server waits up to 3 s for it, as on HTTP/1.1)
                    raw.close()
                    val t =
                        kotlin.time.TimeSource.Monotonic
                            .markNow()
                    withTimeout(15.seconds) { stop.await() }
                    assertTrue(t.elapsedNow() < 2.seconds, "the stop waited ${t.elapsedNow()} after the client closed")
                }
            }
        }

    /**
     * RFC 9110 section 10.1.1 over HTTP/2: the interim 100 goes out as the handler starts, before the client
     * sends it; then the final response.
     */
    @Test fun expectContinueGetsAnInterim100() =
        serverTest {
            val (server, port) = h2Server { routing { post("/") { call.respondText(call.receiveText()) } } }
            try {
                RawH2Client.connect(port).use { raw ->
                    raw.preface()
                    val post = listOf(":method" to "POST", ":scheme" to "https", ":authority" to "server.test", ":path" to "/")
                    raw.headers(1, post + ("expect" to "100-continue") + ("content-length" to "2"), endStream = false)
                    val interim = assertNotNull(raw.await { it.stream == 1 })
                    assertEquals(RawFrame.HEADERS, interim.type)
                    assertTrue(!interim.endStream, "an interim response never ends the stream")
                    raw.data(1, "hi".encodeToByteArray(), endStream = true)
                    val final = assertNotNull(raw.await { it.stream == 1 && it.type == RawFrame.HEADERS })
                    assertEquals(0x88.toByte(), final.payload[0], ":status 200 (static index 8)")
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /**
     * RFC 9110 section 10.1.1: "an immediate 100 (Continue) response" when the head determines no final status: it goes out
     * as the handler starts, while the handler still waits before it reads or answers. Before, it went out only when the
     * handler first read the body.
     */
    @Test fun expectContinueGets100BeforeTheHandlerReads() =
        serverTest {
            val answer = CompletableDeferred<Unit>()
            val (server, port) =
                h2Server {
                    routing {
                        post("/") {
                            answer.await()
                            call.respondText("no", status = HttpStatusCode.Forbidden)
                        }
                    }
                }
            try {
                RawH2Client.connect(port).use { raw ->
                    raw.preface()
                    val post = listOf(":method" to "POST", ":scheme" to "https", ":authority" to "server.test", ":path" to "/")
                    raw.headers(1, post + ("expect" to "100-continue") + ("content-length" to "2"), endStream = false)
                    val interim = assertNotNull(raw.await { it.stream == 1 && it.type == RawFrame.HEADERS })
                    assertTrue(!interim.endStream && !answer.isCompleted, "the interim 100 before the handler answered")
                    raw.data(1, "hi".encodeToByteArray(), endStream = true)
                    answer.complete(Unit)
                    val final = assertNotNull(raw.await { it.stream == 1 && it.type == RawFrame.HEADERS })
                    assertTrue(final.payload.isNotEmpty())
                }
            } finally {
                answer.complete(Unit)
                server.stop(100, 500)
            }
        }

    /**
     * A field section above our SETTINGS_MAX_HEADER_LIST_SIZE is answered 431 (RFC 9113 section 8.2, RFC 6585 section 5)
     * without reaching the application; a CONNECT is answered 501 (no tunnels). Both end with their HEADERS, no reset.
     */
    @Test fun negative_oversizedFieldSectionAndConnectAreAnswered() =
        serverTest {
            val handled = Channel<String>(Channel.UNLIMITED)
            val (server, port) =
                h2Server(configure = { http2Settings = Http2Settings(maxHeaderListSize = 1024) }) {
                    routing { get("/{...}") { handled.trySend(call.request.local.uri) } }
                }
            try {
                RawH2Client.connect(port).use { raw ->
                    raw.preface()
                    // above 1024 decoded, within the 2048 compressed bytes buffered for a block (beyond those: a connection error)
                    raw.headers(1, RawH2Client.get() + ("x-big" to "a".repeat(1500)))
                    val big = assertNotNull(raw.await { it.stream == 1 })
                    assertEquals(RawFrame.HEADERS, big.type)
                    assertTrue(big.endStream)
                    raw.headers(3, listOf(":method" to "CONNECT", ":authority" to "example.test:443"), endStream = false)
                    val connect = assertNotNull(raw.await { it.stream == 3 && it.type != RawFrame.WINDOW_UPDATE })
                    assertEquals(RawFrame.HEADERS, connect.type)
                    assertTrue(connect.endStream)
                    assertTrue(handled.tryReceive().isFailure, "neither reached the application")
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /**
     * RFC 9113 section 3.2: no h2c on a plain connector, `http2` or not: its preface (`PRI * HTTP/2.0`) is an HTTP/1.1
     * request line of version 2.0, which the server refuses with 505 and closes, as before.
     */
    @Test fun negative_h2cPrefaceOnPlainConnectorRejected() =
        serverTest {
            val server =
                kuicksilverServer(null, configure = {
                    http2 = true
                    connector {
                        host = "127.0.0.1"
                        port = 0
                    }
                }) { routing { get("/") { call.respondText("ok") } } }
            server.startSuspend(wait = false)
            try {
                val port =
                    server.engine
                        .resolvedConnectors()
                        .first()
                        .port
                val resp = rawHttp(port, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", tls = null)
                assertTrue(resp.startsWith("HTTP/1.1 505 "), resp)
            } finally {
                server.stop(100, 500)
            }
        }

    @Test fun negative_headerBlockSlowerThanTimeoutCloses() =
        serverTest {
            val (server, port) =
                h2Server(
                    configure = { requestHeaderTimeoutSeconds = 1 },
                ) { routing { get("/") { call.respondText("ok") } } }
            try {
                RawH2Client.connect(port).use { raw ->
                    raw.preface()
                    // the server's SETTINGS first: its acknowledgement must not land inside the field block (section 6.10)
                    assertNotNull(raw.await { it.type == RawFrame.SETTINGS && it.flags == 0 })
                    raw.headers(1, RawH2Client.get(), endHeaders = false) // no CONTINUATION ever follows
                    val frames = raw.readToEnd(within = 15.seconds)
                    val goAway = assertNotNull(frames.lastOrNull { it.type == RawFrame.GOAWAY }, "$frames")
                    assertEquals(0xbL, goAway.errorCode) // ENHANCE_YOUR_CALM
                }
            } finally {
                server.stop(100, 500)
            }
        }

    @Test fun negative_prefaceSlowerThanTimeoutCloses() =
        serverTest {
            val (server, port) =
                h2Server(
                    configure = { requestHeaderTimeoutSeconds = 1 },
                ) { routing { get("/") { call.respondText("ok") } } }
            try {
                RawH2Client.connect(port).use { raw ->
                    // the TLS handshake agreed on h2, then nothing: within the request-head deadline the server sends GOAWAY
                    // (RFC 9113 section 9.1; no stream taken) and closes
                    val frames = raw.readToEnd(within = 15.seconds)
                    val goAway = assertNotNull(frames.lastOrNull { it.type == RawFrame.GOAWAY }, "$frames")
                    assertEquals(0, goAway.lastStreamId)
                    assertEquals(0L, goAway.errorCode)
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /** A client's RST_STREAM cancels the handler (the request is no longer wanted, RFC 9113 section 8.1). */
    @Test fun streamCancelStopsHandler() =
        serverTest {
            val started = CompletableDeferred<Unit>()
            val cancelled = CompletableDeferred<Throwable>()
            val (server, port) =
                h2Server {
                    routing {
                        get("/") {
                            started.complete(Unit)
                            try {
                                awaitCancellation()
                            } catch (e: Throwable) {
                                cancelled.complete(e)
                                throw e
                            }
                        }
                    }
                }
            try {
                RawH2Client.connect(port).use { raw ->
                    raw.preface()
                    raw.headers(1, RawH2Client.get())
                    withTimeout(10.seconds) { started.await() }
                    raw.rstStream(1, 0x8) // CANCEL
                    withTimeout(10.seconds) { cancelled.await() }
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /** RFC 8441 is not offered: no SETTINGS_ENABLE_CONNECT_PROTOCOL, and `:protocol` makes the request malformed. */
    @Test fun negative_extendedConnectRefused() =
        serverTest {
            val (server, port) = h2Server { routing { get("/") { call.respondText("ok") } } }
            try {
                RawH2Client.connect(port).use { raw ->
                    raw.preface()
                    raw.headers(
                        1,
                        listOf(
                            ":method" to "CONNECT",
                            ":protocol" to "websocket",
                            ":scheme" to "https",
                            ":authority" to "server.test",
                            ":path" to "/",
                        ),
                    )
                    val rst = assertNotNull(raw.await { it.stream == 1 })
                    assertEquals(RawFrame.RST_STREAM, rst.type)
                    assertEquals(protocolError, rst.errorCode)
                    assertNull(assertNotNull(raw.serverSettings)[0x8], "SETTINGS_ENABLE_CONNECT_PROTOCOL is not sent")
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /** Each request is sent on its own stream of one connection; each must be reset with protocolError, then a GET works. */
    private suspend fun assertMalformed(vararg cases: Pair<String, suspend RawH2Client.(Int) -> Unit>) {
        val handled = Channel<String>(Channel.UNLIMITED)
        val (server, port) =
            h2Server {
                routing {
                    get("/{...}") {
                        handled.trySend(call.request.local.uri)
                        call.respondText("ok")
                    }
                    post("/{...}") {
                        handled.trySend(call.request.local.uri)
                        runCatching { call.receiveText() }
                        call.respondText("ok")
                    }
                }
            }
        try {
            RawH2Client.connect(port).use { raw ->
                raw.preface()
                var id = 1
                for ((what, send) in cases) {
                    raw.send(id)
                    val f = assertNotNull(raw.await { it.stream == id && it.type == RawFrame.RST_STREAM }, what)
                    assertEquals(protocolError, f.errorCode, what)
                    id += 2
                }
                raw.headers(id, RawH2Client.get("/fine"))
                val ok = assertNotNull(raw.await { it.stream == id && it.type == RawFrame.HEADERS }, "the connection goes on")
                assertEquals(0x88.toByte(), ok.payload[0], ":status 200 (static index 8)")
            }
        } finally {
            server.stop(100, 500)
        }
    }

    private fun fields(vararg extra: Pair<String, String>) = RawH2Client.get("/x") + extra.toList()

    /** RFC 9113 section 8.2: field names are lowercase; section 8.2.2: no connection-specific fields, `te` only `trailers`. */
    @Test fun negative_fieldRulesOfSection82() =
        serverTest {
            assertMalformed(
                "uppercase name" to { headers(it, fields("X-Upper" to "1")) },
                "connection" to { headers(it, fields("connection" to "keep-alive")) },
                "keep-alive" to { headers(it, fields("keep-alive" to "5")) },
                "proxy-connection" to { headers(it, fields("proxy-connection" to "close")) },
                "transfer-encoding" to { headers(it, fields("transfer-encoding" to "chunked")) },
                "upgrade" to { headers(it, fields("upgrade" to "websocket")) },
                "te other than trailers" to { headers(it, fields("te" to "gzip")) },
                "CR in a value" to { headers(it, fields("x-a" to "a\rb")) },
                "space in a name" to { headers(it, fields("x a" to "1")) },
            )
        }

    /** RFC 9113 section 8.3.1: request pseudo-header fields. */
    @Test fun negative_pseudoHeaderRulesOfSection83() =
        serverTest {
            val get = RawH2Client.get("/x")
            assertMalformed(
                "pseudo after regular" to { headers(it, listOf("x-a" to "1") + get) },
                "unknown pseudo" to { headers(it, get + (":foo" to "bar")) },
                "response pseudo in a request" to { headers(it, get + (":status" to "200")) },
                "duplicate :path" to { headers(it, get + (":path" to "/y")) },
                "no :method" to { headers(it, get.filter { f -> f.first != ":method" }) },
                "no :scheme" to { headers(it, get.filter { f -> f.first != ":scheme" }) },
                "no :path" to { headers(it, get.filter { f -> f.first != ":path" }) },
                "empty :path" to { headers(it, get.map { f -> if (f.first == ":path") ":path" to "" else f }) },
                "host differs from :authority" to { headers(it, get + ("host" to "other.test")) },
                "userinfo in :authority" to {
                    headers(
                        it,
                        get.map { f ->
                            if (f.first ==
                                ":authority"
                            ) {
                                f.first to "u@server.test"
                            } else {
                                f
                            }
                        },
                    )
                },
            )
        }

    /** RFC 9113 section 8.1.1: content that does not match content-length. */
    @Test fun negative_contentLengthMismatch() =
        serverTest {
            val post = listOf(":method" to "POST", ":scheme" to "https", ":authority" to "server.test", ":path" to "/x")
            assertMalformed(
                "less content" to {
                    headers(it, post + ("content-length" to "5"), endStream = false)
                    data(it, "abc".encodeToByteArray(), endStream = true)
                },
                "more content" to {
                    headers(it, post + ("content-length" to "2"), endStream = false)
                    data(it, "abc".encodeToByteArray(), endStream = true)
                },
                "content-length on a request ended by its HEADERS" to { headers(it, post + ("content-length" to "5")) },
                "invalid content-length" to { headers(it, post + ("content-length" to "x"), endStream = false) },
            )
        }

    /** A body that stops arriving fails the handler's read; the call is answered 408 (as on HTTP/1.1), the connection goes on. */
    @Test fun negative_requestBodyStallIs408() =
        serverTest {
            val statuses = Channel<Int?>(Channel.UNLIMITED)
            val (server, port) =
                h2Server(configure = {
                    connectionIdleTimeoutSeconds = 1
                    eventListener =
                        object : KuicksilverServerEventListener() {
                            override fun requestEnded(
                                protocol: HttpProtocolVersion,
                                call: ApplicationCall,
                                cause: Throwable?,
                            ) {
                                statuses.trySend(call.response.status()?.value)
                            }
                        }
                }) { routing { post("/") { call.respondText(call.receiveText()) } } }
            try {
                RawH2Client.connect(port).use { raw ->
                    raw.preface()
                    val post = listOf(":method" to "POST", ":scheme" to "https", ":authority" to "server.test", ":path" to "/")
                    raw.headers(1, post + ("content-length" to "10"), endStream = false)
                    raw.data(1, "abc".encodeToByteArray(), endStream = false)
                    assertEquals(408, withTimeout(15.seconds) { statuses.receive() })
                    val h = assertNotNull(raw.await { it.stream == 1 && it.type == RawFrame.HEADERS })
                    assertTrue(h.endStream || raw.await { it.stream == 1 && it.endStream } != null)
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /**
     * HTTP/2 connections count against the TCP connection limits like HTTP/1.1 ones (one socket each, from accept until it
     * is released): with `maxTcpConnectionsPerIp = 1` and an HTTP/2 connection open and served, a second client from the
     * same address is closed at accept, before its TLS handshake; once the first is closed the address is served again.
     */
    @Test fun negative_connectionLimitCountsH2() =
        serverTest {
            val (server, port) = h2TlsServer({ maxTcpConnectionsPerIp = 1 }) { routing { get("/") { call.respondText("ok") } } }
            try {
                RawH2Client.connect(port).use { raw ->
                    assertEquals("h2", raw.alpn)
                    raw.preface()
                    raw.headers(1, RawH2Client.get())
                    assertNotNull(raw.await(within = 15.seconds) { it.stream == 1 && it.endStream }, "the first request is answered")
                    val probe = KuicksilverServerProbe.snapshot(server.engine)
                    assertEquals(1L, probe["server.h2Connections"])
                    assertEquals(1L, probe["server.tcpConnections"])
                    assertTrue(
                        runCatching { RawH2Client.connect(port).close() }.isFailure,
                        "a second connection from 127.0.0.1 was accepted",
                    )
                    withTimeout(10.seconds) { server.engine.refusedPerIp.first { it == 1L } }
                }
                withTimeout(10.seconds) { server.engine.openTcpSockets.first { it == 0 } }
                RawH2Client.connect(port).use { raw ->
                    raw.preface()
                    raw.headers(1, RawH2Client.get())
                    assertNotNull(raw.await(within = 15.seconds) { it.stream == 1 && it.endStream }, "served again")
                }
            } finally {
                server.stop(100, 500)
            }
        }
}
