// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import io.ktor.client.plugins.HttpTimeout
import io.ktor.client.plugins.websocket.WebSockets
import io.ktor.client.plugins.websocket.webSocket
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.prepareGet
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsBytes
import io.ktor.client.statement.bodyAsChannel
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpProtocolVersion
import io.ktor.http.content.OutgoingContent
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.server.application.install
import io.ktor.server.request.receiveChannel
import io.ktor.server.request.uri
import io.ktor.server.response.header
import io.ktor.server.response.respondBytesWriter
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import io.ktor.server.routing.routing
import io.ktor.utils.io.ByteWriteChannel
import io.ktor.utils.io.discard
import io.ktor.utils.io.readAvailable
import io.ktor.utils.io.readByteArray
import io.ktor.utils.io.readRemaining
import io.ktor.utils.io.writeFully
import io.ktor.websocket.Frame
import io.ktor.websocket.readText
import io.kuicksilver.http3.Http3Endpoint
import io.kuicksilver.http3.Http3ErrorCode
import io.kuicksilver.http3.Http3Headers
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.QuicEndpointConfig
import io.kuicksilver.quic.QuicServerConfig
import io.kuicksilver.tls.SpkiSha256
import io.kuicksilver.tls.TlsIdentity
import io.kuicksilver.tls.TlsRole
import io.kuicksilver.tls.TrustConfig
import io.kuicksilver.tls.tlsConfig
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.yield
import kotlinx.io.readByteArray
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds
import io.ktor.server.websocket.WebSockets as ServerWebSockets
import io.ktor.server.websocket.webSocket as serverWebSocket

class ClientH3Test {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    @Test fun h3OnlyGet() =
        h3Test {
            val (server, port) = testServer { routing { get("/") { call.respondText("v=${call.request.local.version}") } } }
            try {
                testClient(Http3DiscoveryMode.H3Only).use { c ->
                    val r = c.get("https://127.0.0.1:$port/")
                    assertEquals(HttpProtocolVersion.HTTP_3_0, r.version)
                    assertEquals("v=HTTP/3", r.bodyAsText())
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /**
     * A URL without a path but with a query (`https://host?a=1`) goes out as `:path /?a=1`: RFC 9114 section 4.3.1 requires
     * "/" for an http(s) URI without a path, and the HTTP/3 layer refuses `?a=1` as malformed.
     */
    @Test fun queryWithoutPathSendsSlash() =
        h3Test {
            val (server, port) = testServer { routing { get("/") { call.respondText(call.request.uri) } } }
            try {
                testClient(Http3DiscoveryMode.H3Only).use { c ->
                    val r = c.get("https://127.0.0.1:$port?a=1")
                    assertEquals(HttpProtocolVersion.HTTP_3_0, r.version)
                    assertEquals("/?a=1", r.bodyAsText())
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /**
     * `quic { connectionIdLength }` alone sets the length of the engine's endpoint too, as the server engine does; the endpoint
     * kept its default of 8 and every HTTP/3 connect failed its check (docs review before 0.2.0). An endpoint-only change is
     * followed by the connections in the same way.
     */
    @Test fun h3WithAnotherConnectionIdLength() =
        h3Test {
            val (server, port) = testServer { routing { get("/") { call.respondText("v=${call.request.local.version}") } } }
            try {
                testClient(Http3DiscoveryMode.H3Only, engine = {
                    quic = io.kuicksilver.quic.quicConfig { connectionIdLength = 12 }
                }).use { c ->
                    assertEquals("v=HTTP/3", c.get("https://127.0.0.1:$port/").bodyAsText())
                }
                testClient(Http3DiscoveryMode.H3Only, engine = {
                    http3 { endpoint = io.kuicksilver.quic.quicEndpointConfig { connectionIdLength = 16 } }
                }).use { c ->
                    assertEquals("v=HTTP/3", c.get("https://127.0.0.1:$port/").bodyAsText())
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /** Two different explicit lengths cannot both hold: the engine refuses them when it is created, naming both. */
    @Test fun conflictingConnectionIdLengthsAreRefused() {
        val e =
            assertFailsWith<IllegalArgumentException> {
                testClient(Http3DiscoveryMode.H3Only, engine = {
                    quic = io.kuicksilver.quic.quicConfig { connectionIdLength = 12 }
                    http3 { endpoint = io.kuicksilver.quic.quicEndpointConfig { connectionIdLength = 16 } }
                }).close()
            }
        assertEquals(
            "quic.connectionIdLength (12) and http3.endpoint.connectionIdLength (16) differ: set one of them, the other follows",
            e.message,
        )
    }

    /**
     * HTTP/3 needs the server to be able to open three unidirectional streams (RFC 9114 section 6.2): an engine whose QUIC
     * settings grant fewer is refused when it is created, unless it never speaks HTTP/3.
     */
    @Test fun negative_fewerThanThreeUniStreamsAreRefused() {
        val e =
            assertFailsWith<IllegalArgumentException> {
                testClient(Http3DiscoveryMode.Preferred, engine = { quic = io.kuicksilver.quic.quicConfig { maxUniStreams = 2 } }).close()
            }
        assertTrue("RFC 9114 section 6.2" in e.message.orEmpty(), e.message)
        testClient(Http3DiscoveryMode.H1Only, engine = { quic = io.kuicksilver.quic.quicConfig { maxUniStreams = 2 } }).close()
    }

    /** The client's endpoint binds 0.0.0.0:0; that socket is dual-stack, so an IPv6 server is reachable over h3 (review of k7/macos-server). */
    @Test fun h3ToIpv6Loopback() =
        h3Test {
            val server =
                io.ktor.server.engine.embeddedServer(io.kuicksilver.ktor.server.Kuicksilver, configure = {
                    tlsConnector(ClientFixtures.identity()) {
                        host = "::1"
                        port = 0
                    }
                }) { routing { get("/") { call.respondText("v=${call.request.local.version}") } } }
            val started = runCatching { server.startSuspend(false) }
            if (started.isFailure) {
                println("h3ToIpv6Loopback skipped: needs an IPv6 loopback")
                return@h3Test
            }
            try {
                val port =
                    server.engine
                        .resolvedConnectors()
                        .first()
                        .port
                testClient(Http3DiscoveryMode.H3Only).use { c ->
                    val r = c.get("https://[::1]:$port/")
                    assertEquals(HttpProtocolVersion.HTTP_3_0, r.version)
                    assertEquals("v=HTTP/3", r.bodyAsText())
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /**
     * The same IPv6 server over HTTP/1.1 (TCP only). Ktor keeps the brackets in `Url.host` ("[::1]"); the JVM resolver accepts
     * them, Kotlin/Native's `getaddrinfo` does not (EAI_NONAME, reported as "POSIX error 0").
     *
     * Under Ktor 3.6.0's Kotlin/Native TCP sockets every IPv6 bind and connect went to `::` (docs/upstream/ktor-native-ipv6.md):
     * Linux and Apple route a connect to `::` to the local host, so this passed there by accident, and Windows refused it
     * with WSAEADDRNOTAVAIL (10049). The engines' own native TCP sockets carry the address on every platform.
     */
    @Test fun h1ToIpv6Loopback() =
        h3Test {
            val server =
                io.ktor.server.engine.embeddedServer(io.kuicksilver.ktor.server.Kuicksilver, configure = {
                    tlsConnector(ClientFixtures.identity()) {
                        host = "::1"
                        port = 0
                    }
                }) { routing { get("/") { call.respondText("v=${call.request.local.version}") } } }
            if (runCatching { server.startSuspend(false) }.isFailure) {
                println("h1ToIpv6Loopback skipped: needs an IPv6 loopback")
                return@h3Test
            }
            try {
                val port =
                    server.engine
                        .resolvedConnectors()
                        .first()
                        .port
                testClient(Http3DiscoveryMode.H1Only).use { c ->
                    val r = c.get("https://[::1]:$port/")
                    assertEquals(HttpProtocolVersion.HTTP_1_1, r.version)
                    assertEquals("v=HTTP/1.1", r.bodyAsText())
                }
            } finally {
                server.stop(100, 500)
            }
        }

    @Test fun chunkedAndH3BodiesReadWhole() =
        h3Test {
            val (server, port) =
                testServer {
                    routing { get("/big") { call.respondBytesWriter { repeat(100) { writeFully(ByteArray(30_000) { 1 }) } } } }
                }
            try {
                for (mode in listOf(Http3DiscoveryMode.H3Only, Http3DiscoveryMode.H1Only)) {
                    testClient(mode).use { c ->
                        assertEquals(3_000_000, c.get("https://127.0.0.1:$port/big").bodyAsBytes().size, "$mode")
                    }
                }
            } finally {
                server.stop(100, 500)
            }
        }

    @Test fun uploadStreamingBody() =
        h3Test {
            val (server, port) =
                testServer {
                    routing {
                        post("/count") {
                            val ch = call.receiveChannel()
                            var n = 0L
                            val b = ByteArray(65536)
                            while (true) {
                                val r = ch.readAvailable(b, 0, b.size)
                                if (r <
                                    0
                                ) {
                                    break
                                }
                                n += r
                            }
                            call.respondText("$n")
                        }
                    }
                }
            try {
                testClient(Http3DiscoveryMode.H3Only).use { c ->
                    val body =
                        object : OutgoingContent.WriteChannelContent() {
                            override suspend fun writeTo(channel: ByteWriteChannel) {
                                repeat(32) {
                                    channel.writeFully(ByteArray(65536))
                                    channel.flush()
                                }
                            }
                        }
                    assertEquals("${32 * 65536}", c.post("https://127.0.0.1:$port/count") { setBody(body) }.bodyAsText())
                }
            } finally {
                server.stop(100, 500)
            }
        }

    @Test fun headersRoundTripLowercase() =
        h3Test {
            val (server, port) =
                testServer {
                    routing {
                        get("/") {
                            call.response.header("X-Reply", "r")
                            call.respondText(call.request.headers["X-Test"] ?: "none")
                        }
                    }
                }
            try {
                testClient(Http3DiscoveryMode.H3Only).use { c ->
                    val r = c.get("https://127.0.0.1:$port/") { header("X-Test", "v") }
                    assertEquals("v", r.bodyAsText())
                    assertEquals("r", r.headers["X-Reply"])
                }
            } finally {
                server.stop(100, 500)
            }
        }

    @Test fun cancelledCallResetsStream() =
        h3Test {
            val serverFailed = CompletableDeferred<Throwable>()
            val (server, port) =
                testServer {
                    routing {
                        get("/endless") {
                            try {
                                call.respondBytesWriter {
                                    while (true) {
                                        writeFully(ByteArray(16_384))
                                        flush()
                                        delay(2)
                                    }
                                }
                            } catch (
                                e: Throwable,
                            ) {
                                serverFailed.complete(e)
                                throw e
                            }
                        }
                    }
                }
            try {
                testClient(Http3DiscoveryMode.H3Only).use { c ->
                    c.prepareGet("https://127.0.0.1:$port/endless").execute { r ->
                        val ch = r.bodyAsChannel()
                        ch.discard(100_000)
                    } // leave early: the call ends, the stream is reset
                    withTimeout(10.seconds) { serverFailed.await() }
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /** A hand-run HTTP/3 server: the first connection rejects every request (H3_REQUEST_REJECTED), the next ones answer 200. */
    @Test fun engineRetriesRequestNotProcessedOnNewConnection() =
        h3Test {
            val serverTls =
                tlsConfig(TlsRole.Server) {
                    alpn = listOf("h3")
                    identity =
                        TlsIdentity.fromDer(listOf(TestCerts.server), TestCerts.serverKey.copyOf())
                }
            val ep =
                Http3Endpoint.bind(
                    InetSocketAddress("127.0.0.1", 0),
                    QuicEndpointConfig
                        .Builder()
                        .apply {
                            this.server =
                                QuicServerConfig.Builder(serverTls).build()
                        }.build(),
                )
            var connections = 0
            coroutineScope {
                val serving =
                    launch {
                        while (true) {
                            val conn = ep.accept()
                            val reject = connections++ == 0
                            launch {
                                while (true) {
                                    val r =
                                        runCatching { conn.acceptRequest() }.getOrNull() ?: break
                                    if (reject) {
                                        r.reset(Http3ErrorCode.REQUEST_REJECTED)
                                    } else {
                                        launch {
                                            r.respond(200).apply {
                                                output.writeFully("ok".encodeToByteArray())
                                                finish()
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                try {
                    testClient(Http3DiscoveryMode.H3Only).use { c ->
                        val bodies =
                            (0 until 3)
                                .map {
                                    async {
                                        c
                                            .get(
                                                "https://127.0.0.1:${ep.localAddress.port}/",
                                            ).bodyAsText()
                                    }
                                }.awaitAll()
                        assertEquals(listOf("ok", "ok", "ok"), bodies)
                        assertEquals(2, connections)
                        // the server stops before the client closes: a finish() still running would fail on that close
                        serving.cancelAndJoin()
                    }
                } finally {
                    serving.cancel()
                    ep.close()
                }
            }
        }

    @Test fun preferredFallsBackToH1WhenNoUdpServer() =
        clientTest {
            val (server, port) = testServer(configure = { http3 = false }) { routing { get("/") { call.respondText("h1") } } }
            try {
                testClient(Http3DiscoveryMode.Preferred, engine = { connectTimeout = 2.seconds }).use { c ->
                    val r = c.get("https://127.0.0.1:$port/")
                    assertEquals(HttpProtocolVersion.HTTP_1_1, r.version)
                    assertEquals("h1", r.bodyAsText())
                }
            } finally {
                server.stop(100, 500)
            }
        }

    @Test fun h3OnlyFailsWithoutUdpServer() =
        clientTest {
            val (server, port) = testServer(configure = { http3 = false }) { routing { get("/") { call.respondText("h1") } } }
            try {
                testClient(Http3DiscoveryMode.H3Only, engine = { connectTimeout = 1.seconds }).use { c ->
                    assertFailsWith<Throwable> { c.get("https://127.0.0.1:$port/") }
                }
            } finally {
                server.stop(100, 500)
            }
        }

    @Test fun webSocketOverH3() =
        h3Test {
            val (server, port) =
                testServer {
                    install(ServerWebSockets)
                    routing {
                        serverWebSocket("/ws") {
                            for (f in incoming) {
                                if (f is Frame.Text) {
                                    send(
                                        Frame.Text("h3:" + f.readText()),
                                    )
                                }
                            }
                        }
                    }
                }
            try {
                testClient(Http3DiscoveryMode.H3Only, block = { install(WebSockets) }).use { c ->
                    c.webSocket("wss://127.0.0.1:$port/ws") {
                        send(Frame.Text("hi"))
                        assertEquals("h3:hi", (incoming.receive() as Frame.Text).readText())
                    }
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /** A cleanly closed WebSocket over h3 ends its stream with FIN, not a late RESET_STREAM that discards the Close reply. */
    @Test fun webSocketCleanCloseDoesNotResetStream() =
        h3Test {
            val serverTls =
                tlsConfig(TlsRole.Server) {
                    alpn = listOf("h3")
                    identity =
                        TlsIdentity.fromDer(listOf(TestCerts.server), TestCerts.serverKey.copyOf())
                }
            val ep =
                Http3Endpoint.bind(
                    InetSocketAddress("127.0.0.1", 0),
                    QuicEndpointConfig
                        .Builder()
                        .apply {
                            this.server =
                                QuicServerConfig.Builder(serverTls).build()
                        }.build(),
                    io.kuicksilver.http3.http3Settings { enableConnectProtocol = true },
                )
            val clientDone = CompletableDeferred<Unit>()
            coroutineScope {
                val served =
                    async {
                        val conn = ep.accept()
                        val s = conn.acceptRequest().acceptConnect()
                        s.output.writeFully(byteArrayOf(0x88.toByte(), 0x02, 0x03, 0xE8.toByte()))
                        s.output.flushAndClose() // Close(1000), then FIN
                        clientDone.await()
                        delay(300) // read only after the client's call is over: a reset by then would have discarded its Close
                        runCatching {
                            s.input
                                .readRemaining()
                                .readByteArray()
                                .size
                        }
                    }
                try {
                    testClient(Http3DiscoveryMode.H3Only, block = { install(WebSockets) }).use { c ->
                        c.webSocket("wss://127.0.0.1:${ep.localAddress.port}/ws") { for (f in incoming) Unit }
                        clientDone.complete(Unit)
                        val got = withTimeout(5.seconds) { served.await() }
                        assertTrue(got.isSuccess && got.getOrThrow() >= 6, "the server reads the client's Close reply and FIN, got $got")
                    }
                } finally {
                    served.cancel()
                    ep.close()
                }
            }
        }

    @Test fun h3UsesSameTrust() =
        h3Test {
            val (server, port) = testServer { routing { get("/") { call.respondText("ok") } } }
            try {
                val pinned = TrustConfig.Pinned(setOf(SpkiSha256(ByteArray(32))), base = ClientFixtures.trust)
                testClient(Http3DiscoveryMode.H3Only, engine = { trust = pinned }).use { c ->
                    assertFailsWith<Throwable> { c.get("https://127.0.0.1:$port/") }
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /** Found by the vendored contract (HttpTimeoutTest over h3): the body fails with the timeout, not a bare stream cancellation. */
    @Test fun requestTimeoutDuringTheBodyIsReportedAsSuch() =
        h3Test {
            val (server, port) =
                testServer {
                    routing {
                        get("/slow") {
                            call.respondBytesWriter {
                                writeFully(ByteArray(10))
                                flush()
                                delay(5_000)
                                writeFully(ByteArray(10))
                            }
                        }
                    }
                }
            try {
                testClient(Http3DiscoveryMode.H3Only, block = { install(HttpTimeout) { requestTimeoutMillis = 500 } }).use { c ->
                    val e =
                        assertFailsWith<Throwable> {
                            c
                                .prepareGet(
                                    "https://127.0.0.1:$port/slow",
                                ).execute { it.bodyAsChannel().readRemaining() }
                        }
                    assertTrue(
                        e is io.ktor.client.plugins.HttpRequestTimeoutException ||
                            e.cause is io.ktor.client.plugins.HttpRequestTimeoutException,
                        "got $e",
                    )
                }
                testClient(Http3DiscoveryMode.H3Only, block = { install(HttpTimeout) { socketTimeoutMillis = 500 } }).use { c ->
                    assertFailsWith<kotlinx.io.IOException> { c.get("https://127.0.0.1:$port/slow").bodyAsBytes() }
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /** Found by the vendored server suite (testAccessingQueryParameterWithoutValue): `?auto` reaches the server as sent. */
    @Test fun queryParameterWithoutValue() =
        h3Test {
            val (server, port) =
                testServer {
                    routing {
                        get(
                            "/",
                        ) { call.respondText("${call.request.uri}|${call.request.queryParameters["auto"]}") }
                    }
                }
            try {
                for (mode in listOf(Http3DiscoveryMode.H3Only, Http3DiscoveryMode.H1Only)) {
                    testClient(mode).use { c ->
                        assertEquals("/?auto|", c.get("https://127.0.0.1:$port/?auto").bodyAsText(), "$mode")
                    }
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /**
     * A response whose connection ends before its FIN fails the body, it does not look complete: `bodyAsText` throws, a
     * streamed `bodyAsChannel()` fails once the bytes that arrived are read, and the engine's own channel (`rawContent`)
     * throws from `readAvailable` instead of answering -1, which the interop client took for the end of a truncated download
     * (0.2.0 release gate).
     */
    @OptIn(io.ktor.utils.io.InternalAPI::class)
    @Test
    fun truncatedH3ResponseFailsTheBody() =
        h3Test {
            coroutineScope {
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
                // one gate per request, in the order the requests are made: the origin ends the connection once the gate opens
                val gates = Channel<CompletableDeferred<Unit>>(Channel.UNLIMITED)
                val serving =
                    launch {
                        while (true) {
                            val conn = ep.accept()
                            launch {
                                runCatching {
                                    val r = conn.acceptRequest()
                                    val w = r.respond(200, Http3Headers.of("content-length" to "2000"))
                                    w.output.writeFully(ByteArray(1000) { 1 })
                                    w.output.flush()
                                    gates.receive().await()
                                    conn.close(Http3ErrorCode.INTERNAL_ERROR, "gone")
                                }
                            }
                        }
                    }
                try {
                    testClient(Http3DiscoveryMode.H3Only).use { c ->
                        val url = "https://127.0.0.1:${ep.localAddress.port}/"
                        val gate1 = CompletableDeferred<Unit>().also { gates.send(it) }
                        var readFailed = false
                        c.prepareGet(url).execute { r ->
                            assertEquals(HttpProtocolVersion.HTTP_3_0, r.version)
                            val ch = r.bodyAsChannel()
                            assertEquals(1000, ch.readByteArray(1000).size)
                            gate1.complete(Unit)
                            assertFailsWith<Throwable> { withTimeout(10.seconds) { ch.readRemaining() } }
                            readFailed = true
                        }
                        assertTrue(readFailed, "the streamed body failed after its first 1000 bytes")
                        // the engine's channel as the application sees it: readAvailable throws the cause, never -1
                        val gate2 = CompletableDeferred<Unit>().also { gates.send(it) }
                        readFailed = false
                        c.prepareGet(url).execute { r ->
                            assertEquals(200, r.status.value)
                            val raw = r.rawContent
                            val buf = ByteArray(1000)
                            var got = 0
                            while (got < 1000) {
                                val n = raw.readAvailable(buf, got, 1000 - got)
                                assertTrue(n > 0, "the first 1000 bytes arrive before the connection ends")
                                got += n
                            }
                            gate2.complete(Unit)
                            // the end is known before the application reads on: a read that was not waiting must fail too, not see -1
                            withTimeout(10.seconds) { while (raw.closedCause == null) yield() }
                            assertFailsWith<Throwable> { while (raw.readAvailable(buf, 0, buf.size) >= 0) Unit }
                            readFailed = true
                        }
                        assertTrue(readFailed, "the engine's channel failed after its first 1000 bytes")
                        // the whole body at once: the connection ends right after the first bytes
                        CompletableDeferred<Unit>().also { it.complete(Unit) }.also { gates.send(it) }
                        assertFailsWith<Throwable> { withTimeout(10.seconds) { c.get(url).bodyAsText() } }
                    }
                } finally {
                    serving.cancel()
                    ep.close()
                }
            }
        }
}
