// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import io.ktor.client.call.body
import io.ktor.client.engine.HttpClientEngineCapability
import io.ktor.client.network.sockets.ConnectTimeoutException
import io.ktor.client.network.sockets.SocketTimeoutException
import io.ktor.client.plugins.HttpTimeout
import io.ktor.client.plugins.HttpTimeoutCapability
import io.ktor.client.plugins.sse.SSE
import io.ktor.client.plugins.sse.SSECapability
import io.ktor.client.plugins.sse.sse
import io.ktor.client.plugins.websocket.WebSocketCapability
import io.ktor.client.plugins.websocket.WebSockets
import io.ktor.client.plugins.websocket.webSocket
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.preparePost
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpProtocolVersion
import io.ktor.network.selector.SelectorManager
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.network.sockets.aSocket
import io.ktor.network.sockets.openReadChannel
import io.ktor.network.sockets.openWriteChannel
import io.ktor.server.application.install
import io.ktor.server.request.receiveChannel
import io.ktor.server.request.receiveText
import io.ktor.server.response.respond
import io.ktor.server.response.respondBytesWriter
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import io.ktor.server.routing.routing
import io.ktor.sse.ServerSentEvent
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.ByteWriteChannel
import io.ktor.utils.io.readByteArray
import io.ktor.utils.io.readUTF8Line
import io.ktor.utils.io.writeStringUtf8
import io.ktor.websocket.Frame
import io.ktor.websocket.readText
import io.kuicksilver.ktor.network.TcpAddress
import io.kuicksilver.native.KslLoader
import io.kuicksilver.tls.SpkiSha256
import io.kuicksilver.tls.TlsException
import io.kuicksilver.tls.TrustConfig
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds
import io.ktor.server.sse.SSE as ServerSSE
import io.ktor.server.sse.sse as serverSse
import io.ktor.server.websocket.WebSockets as ServerWebSockets
import io.ktor.server.websocket.webSocket as serverWebSocket

class ClientH1Test {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    /** Android's Network Security Configuration (`cleartextTrafficPermitted`) refuses `http://` before any connection, as OkHttp does. */
    @Test fun cleartextThePolicyRefusesNeverConnects() =
        clientTest {
            var served = 0
            val (server, port) = testServer(plain = true) { routing { get("/") { call.respondText("ok").also { served++ } } } }
            try {
                testClient().use { client ->
                    val engine = client.engine as KuicksilverEngine
                    engine.h1.cleartextPermitted = { host -> host != "127.0.0.1" }
                    val e = kotlin.test.assertFailsWith<kotlinx.io.IOException> { client.get("http://127.0.0.1:$port/") }
                    assertEquals("CLEARTEXT communication to 127.0.0.1 not permitted by network security policy", e.message)
                    assertEquals(0, served)
                    engine.h1.cleartextPermitted = { true }
                    assertEquals("ok", client.get("http://127.0.0.1:$port/").bodyAsText())
                }
            } finally {
                server.stop(100, 500)
            }
        }

    @Test fun getHttps() =
        clientTest {
            val (server, port) = testServer { routing { get("/") { call.respondText("ok") } } }
            try {
                testClient().use { c ->
                    val r = c.get("https://127.0.0.1:$port/")
                    assertEquals("ok", r.bodyAsText())
                    assertEquals(HttpProtocolVersion.HTTP_1_1, r.version)
                }
            } finally {
                server.stop(100, 500)
            }
        }

    @Test fun plainHttp() =
        clientTest {
            val (server, port) = testServer(plain = true) { routing { get("/") { call.respondText("plain") } } }
            try {
                testClient().use { c ->
                    assertEquals("plain", c.get("http://127.0.0.1:$port/").bodyAsText())
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /** Cleartext HTTP/1.1 to an IPv6 literal on every platform, Windows Native included. */
    @Test fun plainHttpToIpv6Literal() =
        clientTest {
            val (server, port) =
                runCatching { testServer(plain = true, host = "::1") { routing { get("/") { call.respondText("v6") } } } }
                    .getOrElse {
                        println("plainHttpToIpv6Literal skipped: needs an IPv6 loopback ($it)")
                        return@clientTest
                    }
            try {
                testClient().use { c -> assertEquals("v6", c.get("http://[::1]:$port/").bodyAsText()) }
            } finally {
                server.stop(100, 500)
            }
        }

    /**
     * The client connects to the address in the URL and nowhere else: a request to `[::ffff:127.0.0.1]` (where the test's
     * own listener closes every connection) does not reach the server on `::1`.
     *
     * The test owns `127.0.0.1` on the port too, with a listener that closes every connection: a port free on `::1` says
     * nothing about `127.0.0.1`, and an unrelated server there (bound to that number after the decoy, which macOS and
     * Linux let through) answered the request and failed the test as if the decoy had.
     */
    @Test fun negative_h1ToIpv6LiteralReachesThatAddressOnly() =
        clientTest {
            val selector = SelectorManager(Dispatchers.Default)
            try {
                runCatching { aSocket(selector).tcp().bind("::1", 0).close() }.onFailure {
                    println("negative_h1ToIpv6LiteralReachesThatAddressOnly skipped: needs an IPv6 loopback ($it)")
                    return@clientTest
                }
                var decoyServed = 0
                val (v4, decoy, port) =
                    bindOnSamePort(
                        first = { aSocket(selector).tcp().bind("127.0.0.1", 0).let { it to (it.localAddress as InetSocketAddress).port } },
                        release = { it.close() },
                    ) { p ->
                        testServer(plain = true, host = "::1", port = p) {
                            routing { get("/") { call.respondText("decoy").also { decoyServed++ } } }
                        }.first
                    }
                coroutineScope {
                    val closer = launch { while (true) v4.accept().close() }
                    try {
                        testClient().use { c ->
                            val r = runCatching { c.get("http://[::ffff:127.0.0.1]:$port/").bodyAsText() }
                            assertTrue(r.isFailure, "a request to [::ffff:127.0.0.1]:$port was answered: ${r.getOrNull()}")
                            assertEquals(0, decoyServed, "a request to [::ffff:127.0.0.1]:$port reached the server on [::1]")
                        }
                    } finally {
                        closer.cancel()
                        v4.close()
                        decoy.stop(100, 500)
                    }
                }
            } finally {
                selector.close()
            }
        }

    @Test fun postAndChunked() =
        clientTest {
            val (server, port) =
                testServer {
                    routing {
                        post("/echo") {
                            val t = call.receiveText()
                            call.respondBytesWriter {
                                writeStringUtf8(t)
                                flush()
                                writeStringUtf8(t)
                            }
                        }
                    }
                }
            try {
                testClient().use { c ->
                    assertEquals("abcabc", c.post("https://127.0.0.1:$port/echo") { setBody("abc") }.bodyAsText())
                }
            } finally {
                server.stop(100, 500)
            }
        }

    @Test fun keepAliveReusesConnection() =
        clientTest {
            val (server, port) = testServer { routing { get("/") { call.respondText("${call.request.local.remotePort}") } } }
            try {
                testClient().use { c ->
                    val a = c.get("https://127.0.0.1:$port/").bodyAsText()
                    val b = c.get("https://127.0.0.1:$port/").bodyAsText()
                    assertEquals(a, b)
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /**
     * HTTP/3 needs `https` (RFC 9114 section 3.1), so `H3Only` fails an `http://` request instead of sending it over
     * cleartext HTTP/1.1, which it did before (the mode promises HTTP/3 or a reported failure, never TCP).
     */
    @Test fun negative_h3OnlyRefusesHttpUrls() =
        clientTest {
            testClient(Http3DiscoveryMode.H3Only).use { c ->
                val e = assertFailsWith<UnsupportedOperationException> { c.get("http://127.0.0.1:1/") }
                assertTrue(e.message!!.contains("https"), e.message)
            }
        }

    @Test fun socketTimeoutMapsToKtor() =
        clientTest {
            val (server, port) =
                testServer {
                    routing {
                        get("/") {
                            delay(3_000)
                            call.respondText("late")
                        }
                    }
                }
            try {
                testClient(block = { install(HttpTimeout) { socketTimeoutMillis = 300 } }).use { c ->
                    assertFailsWith<SocketTimeoutException> { c.get("https://127.0.0.1:$port/") }
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /** Found by the vendored contract (HttpTimeoutTest.testSocketTimeoutRead): the socket timeout covers body reads too. */
    @Test fun socketTimeoutCoversTheBody() =
        clientTest {
            val (server, port) =
                testServer {
                    routing {
                        get("/") {
                            call.respondBytesWriter {
                                writeStringUtf8("a")
                                flush()
                                delay(3_000)
                                writeStringUtf8("b")
                            }
                        }
                    }
                }
            try {
                testClient(block = { install(HttpTimeout) { socketTimeoutMillis = 300 } }).use { c ->
                    assertFailsWith<kotlinx.io.IOException> { c.get("https://127.0.0.1:$port/").bodyAsText() }
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /** Found by the vendored server suite (testFlushingHeaders): the response is read while the request body still streams. */
    @Test fun responseHeadersBeforeTheRequestBodyEnds() =
        clientTest {
            val (server, port) =
                testServer(plain = true) {
                    routing {
                        post("/echo") {
                            val ch = call.receiveChannel()
                            call.respond(
                                object : io.ktor.http.content.OutgoingContent.ReadChannelContent() {
                                    override val contentLength: Long = 5

                                    override fun readFrom() = ch
                                },
                            )
                        }
                    }
                }
            try {
                testClient().use { c ->
                    val body =
                        io.ktor.utils.io
                            .ByteChannel(true)
                    c.preparePost("http://127.0.0.1:$port/echo") { setBody(body) }.execute { r ->
                        assertEquals(200, r.status.value) // before the body is complete
                        body.writeStringUtf8("hello")
                        body.flushAndClose()
                        assertEquals("hello", r.bodyAsText())
                    }
                }
            } finally {
                server.stop(100, 500)
            }
        }

    @Test fun connectTimeoutMapsToKtor() =
        clientTest {
            testClient(block = { install(HttpTimeout) { connectTimeoutMillis = 300 } }).use { c ->
                assertFailsWith<ConnectTimeoutException> { c.get("https://10.255.255.1:443/") }
            }
        }

    @Test fun wrongPinFails() =
        clientTest {
            val (server, port) = testServer { routing { get("/") { call.respondText("ok") } } }
            try {
                val pinned = TrustConfig.Pinned(setOf(SpkiSha256(ByteArray(32))), base = ClientFixtures.trust)
                testClient(engine = { trust = pinned }).use { c ->
                    val e = assertFailsWith<Throwable> { c.get("https://127.0.0.1:$port/") }
                    assertTrue(generateSequence(e) { it.cause }.any { it is TlsException }, "$e")
                }
            } finally {
                server.stop(100, 500)
            }
        }

    @Test fun sseOverH1() =
        clientTest {
            val (server, port) =
                testServer {
                    install(ServerSSE)
                    routing {
                        serverSse("/events") {
                            send(ServerSentEvent("hello"))
                            send(ServerSentEvent("world"))
                        }
                    }
                }
            try {
                testClient(block = { install(SSE) }).use { c ->
                    val got = ArrayList<String>()
                    c.sse("https://127.0.0.1:$port/events") { incoming.collect { e -> e.data?.let { got += it } } }
                    assertEquals(listOf("hello", "world"), got)
                }
            } finally {
                server.stop(100, 500)
            }
        }

    @Test fun webSocketOverH1() =
        clientTest {
            val (server, port) =
                testServer {
                    install(ServerWebSockets)
                    routing {
                        serverWebSocket("/ws") {
                            for (f in incoming) {
                                if (f is Frame.Text) {
                                    send(
                                        Frame.Text("echo:" + f.readText()),
                                    )
                                }
                            }
                        }
                    }
                }
            try {
                testClient(block = { install(WebSockets) }).use { c ->
                    c.webSocket("wss://127.0.0.1:$port/ws") {
                        send(Frame.Text("hi"))
                        assertEquals("echo:hi", (incoming.receive() as Frame.Text).readText())
                    }
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /** A 1xx is not the final response; the real one (and the next keep-alive one) stays in order. */
    @Test fun informationalResponsesAreSkipped() =
        clientTest {
            rawServer(
                "HTTP/1.1 103 Early Hints\r\nLink: </a.css>; rel=preload\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nfirst",
                "HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nsecond",
            ) { port ->
                testClient().use { c ->
                    val r1 = c.get("http://127.0.0.1:$port/1")
                    assertEquals(200, r1.status.value)
                    assertEquals("first", r1.bodyAsText())
                    assertEquals("second", c.get("http://127.0.0.1:$port/2").bodyAsText())
                }
            }
        }

    /** With `Expect: 100-continue`, the interim 100 Continue is skipped as well. */
    @Test fun continueResponseIsSkipped() =
        clientTest {
            rawServer(
                "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 201 Created\r\nContent-Length: 5\r\n\r\nfirst",
                "HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nsecond",
                bodyBytes = listOf(3, 0),
            ) { port ->
                testClient().use { c ->
                    val r1 =
                        c.post("http://127.0.0.1:$port/1") {
                            header(HttpHeaders.Expect, "100-continue")
                            setBody("abc")
                        }
                    assertEquals(201, r1.status.value)
                    assertEquals("first", r1.bodyAsText())
                    assertEquals("second", c.get("http://127.0.0.1:$port/2").bodyAsText())
                }
            }
        }

    /** Whether request bytes arrive on [input] within [millis] (the client sent the body without waiting). */
    private suspend fun bytesArriveWithin(
        input: ByteReadChannel,
        millis: Long,
    ): Boolean = withTimeoutOrNull(millis) { input.awaitContent() } == true

    /**
     * RFC 9110 section 10.1.1: with `Expect: 100-continue` the body waits for the server; a final status first (417 here)
     * is the response and the body is never sent, the connection (which promised a body) is not reused.
     */
    @Test fun expectContinueFinalStatusFirstSendsNoBody() =
        clientTest {
            var earlyBody: Boolean? = null
            var connections = 0
            rawServerPerConnection({ index, input, output ->
                connections++
                readHead(input)
                if (index == 0) {
                    earlyBody = bytesArriveWithin(input, 300)
                    output.writeStringUtf8("HTTP/1.1 417 Expectation Failed\r\nContent-Length: 0\r\n\r\n")
                } else {
                    output.writeStringUtf8("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                }
                input.readUTF8Line() // until the client closes
            }) { port ->
                testClient().use { c ->
                    val r =
                        c.post("http://127.0.0.1:$port/") {
                            header(HttpHeaders.Expect, "100-continue")
                            setBody("abc")
                        }
                    assertEquals(417, r.status.value)
                    assertEquals(false, earlyBody, "the body went out before the server answered")
                    assertEquals("ok", c.get("http://127.0.0.1:$port/next").bodyAsText())
                    assertEquals(2, connections, "the connection that promised a body is not reused")
                }
            }
        }

    /** With `Expect: 100-continue` the body goes out after the server's 100 Continue, not before. */
    @Test fun expectContinueBodyWaitsForContinue() =
        clientTest {
            for (streamed in listOf(false, true)) {
                var earlyBody: Boolean? = null
                var received: String? = null
                rawServer({ input, output ->
                    readHead(input)
                    earlyBody = bytesArriveWithin(input, 300)
                    output.writeStringUtf8("HTTP/1.1 100 Continue\r\n\r\n")
                    received = input.readByteArray(3).decodeToString()
                    output.writeStringUtf8("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                }) { port ->
                    testClient().use { c ->
                        val r =
                            c.post("http://127.0.0.1:$port/") {
                                header(HttpHeaders.Expect, "100-continue")
                                header(HttpHeaders.ContentLength, "3")
                                if (streamed) setBody(ByteReadChannel("abc")) else setBody("abc")
                            }
                        assertEquals(200, r.status.value)
                        assertEquals("ok", r.bodyAsText())
                        assertEquals(false, earlyBody, "streamed=$streamed: the body went out before 100 Continue")
                        assertEquals("abc", received)
                    }
                }
            }
        }

    /** A server that ignores `Expect: 100-continue` gets the body after a bounded wait (RFC 9110 section 10.1.1). */
    @Test fun expectContinueBodySentAfterTimeoutWithoutAnswer() =
        clientTest {
            var received: String? = null
            rawServer({ input, output ->
                readHead(input)
                received = input.readByteArray(3).decodeToString()
                output.writeStringUtf8("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
            }) { port ->
                testClient().use { c ->
                    val r =
                        c.post("http://127.0.0.1:$port/") {
                            header(HttpHeaders.Expect, "100-continue")
                            setBody("abc")
                        }
                    assertEquals("ok", r.bodyAsText())
                    assertEquals("abc", received)
                }
            }
        }

    /** One plain TCP connection driven by [handler]; [block] gets the port. */
    private suspend fun rawServer(
        handler: suspend (input: ByteReadChannel, output: ByteWriteChannel) -> Unit,
        block: suspend (Int) -> Unit,
    ) = rawServerPerConnection({ _, input, output ->
        handler(input, output)
        input.readUTF8Line() // until the client closes
    }, block)

    /** A pooled connection the server closed is replaced once for an idempotent request (RFC 9110 section 9.2.2). */
    @Test fun staleConnectionRetriedOnceForGet() =
        clientTest {
            var getsSeen = 0
            rawServerPerConnection({ index, input, output ->
                readHead(input)
                getsSeen++
                output.writeStringUtf8("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                if (index == 0) {
                    readHead(input) // the second request arrives on the pooled connection: close without answering
                    getsSeen++
                } else {
                    readHead(input)
                }
            }) { port ->
                testClient().use { c ->
                    assertEquals("ok", c.get("http://127.0.0.1:$port/1").bodyAsText())
                    assertEquals("ok", c.get("http://127.0.0.1:$port/2").bodyAsText())
                }
            }
            assertEquals(3, getsSeen, "the second GET went out on the stale connection and once more on a fresh one")
        }

    /** A POST that failed on a stale pooled connection may have been processed: it is never sent again (RFC 9112 section 9.3.1). */
    @Test fun negative_postNotRetriedOnStaleConnection() =
        clientTest {
            var postsSeen = 0
            rawServerPerConnection({ index, input, output ->
                val first = readHead(input)
                if (first.startsWith("POST")) postsSeen++
                if (index == 0) {
                    output.writeStringUtf8("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                    if (readHead(input).startsWith("POST")) postsSeen++ // the POST on the pooled connection: close without answering
                } else {
                    output.writeStringUtf8("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                    readHead(input)
                }
            }) { port ->
                testClient().use { c ->
                    assertEquals("ok", c.get("http://127.0.0.1:$port/").bodyAsText())
                    assertFailsWith<kotlinx.io.IOException> { c.post("http://127.0.0.1:$port/") { setBody("x") } }
                }
            }
            assertEquals(1, postsSeen, "the POST reached the stale connection only")
        }

    /** Reads a request head; returns its request line ("" at end of stream). */
    private suspend fun readHead(input: ByteReadChannel): String {
        val line = input.readUTF8Line() ?: return ""
        while (input.readUTF8Line()?.isNotEmpty() == true) Unit
        return line
    }

    /** A plain TCP listener that runs [handler] once per accepted connection, with the connection's index. */
    private suspend fun rawServerPerConnection(
        handler: suspend (index: Int, input: ByteReadChannel, output: ByteWriteChannel) -> Unit,
        block: suspend (Int) -> Unit,
    ) {
        val selector = SelectorManager(Dispatchers.Default)
        val listener = aSocket(selector).tcp().bind("127.0.0.1", 0)
        try {
            coroutineScope {
                val server =
                    launch {
                        var index = 0
                        while (true) {
                            val s = listener.accept()
                            val i = index++
                            launch { s.use { handler(i, it.openReadChannel(), it.openWriteChannel(autoFlush = true)) } }
                        }
                    }
                block((listener.localAddress as InetSocketAddress).port)
                server.cancel()
            }
        } finally {
            listener.close()
            selector.close()
        }
    }

    /** One plain TCP connection: per request, reads the head (and [bodyBytes]) and writes the canned [responses] in turn. */
    private suspend fun rawServer(
        vararg responses: String,
        bodyBytes: List<Int> = responses.map { 0 },
        block: suspend (Int) -> Unit,
    ) {
        val selector = SelectorManager(Dispatchers.Default)
        val listener = aSocket(selector).tcp().bind("127.0.0.1", 0)
        try {
            coroutineScope {
                val server =
                    launch {
                        listener.accept().use { s ->
                            val input = s.openReadChannel()
                            val output = s.openWriteChannel(autoFlush = true)
                            responses.forEachIndexed { i, r ->
                                while (input.readUTF8Line()?.isNotEmpty() == true) Unit
                                if (bodyBytes[i] > 0) input.readByteArray(bodyBytes[i])
                                output.writeStringUtf8(r)
                            }
                            input.readUTF8Line() // until the client closes
                        }
                    }
                block((listener.localAddress as InetSocketAddress).port)
                server.cancel()
            }
        } finally {
            listener.close()
            selector.close()
        }
    }

    /**
     * Happy Eyeballs (RFC 8305): the first address the name resolves to fails and the engine connects to the next one at
     * once, within one connection. The failing address is port 0 of `::1`: no socket can listen there, so the attempt
     * fails on every host whatever else runs on it (without IPv6 it fails as well, with "unreachable").
     */
    @Test fun h1FallsBackToSecondAddress() =
        clientTest {
            val (server, port) = testServer(plain = true) { routing { get("/") { call.respondText("second") } } }
            try {
                val asked = mutableListOf<Pair<String, Int>>()
                var acquired = 0
                testClient(engine = {
                    resolverForTest = { host, p ->
                        asked += host to p
                        listOf(TcpAddress(ByteArray(16).also { it[15] = 1 }, 0), TcpAddress(byteArrayOf(127, 0, 0, 1), p))
                    }
                    eventListener =
                        object : KuicksilverEventListener() {
                            override fun connectionAcquired(
                                request: io.ktor.client.request.HttpRequestData,
                                protocol: HttpProtocolVersion,
                                reused: Boolean,
                            ) {
                                acquired++
                            }
                        }
                }).use { c ->
                    val r = c.get("http://origin.test:$port/")
                    assertEquals(200, r.status.value)
                    assertEquals("second", r.bodyAsText())
                }
                assertEquals(listOf("origin.test" to port), asked)
                assertEquals(1, acquired)
            } finally {
                server.stop(100, 500)
            }
        }

    /** RFC 8305 section 8: the connection attempt delay is 10 ms..2 s, or infinite for one address after another. */
    @Test fun negative_connectionAttemptDelayOutOfRangeRefused() {
        for (bad in listOf(kotlin.time.Duration.ZERO, 9.milliseconds, 2001.milliseconds)) {
            assertFailsWith<IllegalArgumentException>("$bad") { testClient(engine = { connectionAttemptDelay = bad }).close() }
        }
        for (good in listOf(10.milliseconds, 2.seconds, kotlin.time.Duration.INFINITE)) {
            testClient(engine = { connectionAttemptDelay = good }).close()
        }
    }

    @Test fun engineNameAndCapabilities() {
        testClient().use { c ->
            val caps: Set<HttpClientEngineCapability<*>> = c.engine.supportedCapabilities
            assertTrue(HttpTimeoutCapability in caps && WebSocketCapability in caps && SSECapability in caps)
            assertTrue(c.engine.toString().contains("Kuicksilver") || c.engine::class.simpleName == "KuicksilverEngine")
        }
    }
}
