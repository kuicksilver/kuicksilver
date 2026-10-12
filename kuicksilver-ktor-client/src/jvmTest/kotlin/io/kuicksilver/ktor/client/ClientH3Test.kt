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
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeout
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
        clientTest {
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

    /** The client's endpoint binds 0.0.0.0:0; that socket is dual-stack, so an IPv6 server is reachable over h3 (review of k7/macos-server). */
    @Test fun h3ToIpv6Loopback() =
        clientTest {
            val server =
                io.ktor.server.engine.embeddedServer(io.kuicksilver.ktor.server.Kuicksilver, configure = {
                    tlsConnector(ClientFixtures.identity()) {
                        host = "::1"
                        port = 0
                    }
                }) { routing { get("/") { call.respondText("v=${call.request.local.version}") } } }
            val started = runCatching { server.startSuspend(false) }
            org.junit.jupiter.api.Assumptions.assumeTrue(started.isSuccess, "needs an IPv6 loopback")
            try {
                val port = server.engine.resolvedConnectors().first().port
                testClient(Http3DiscoveryMode.H3Only).use { c ->
                    val r = c.get("https://[::1]:$port/")
                    assertEquals(HttpProtocolVersion.HTTP_3_0, r.version)
                    assertEquals("v=HTTP/3", r.bodyAsText())
                }
            } finally {
                server.stop(100, 500)
            }
        }

    @Test fun chunkedAndH3BodiesReadWhole() =
        clientTest {
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
        clientTest {
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
        clientTest {
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
        clientTest {
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
        clientTest {
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
        clientTest {
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
        clientTest {
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
        clientTest {
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

    /** Found by the vendored Ktor client contract tests: every closed client left its UDP receive loop parked on Dispatchers.IO. */
    @Test fun closingTheClientReleasesItsUdpSocket() =
        clientTest {
            fun receivers() =
                Thread.getAllStackTraces().values.count { st ->
                    st.any {
                        it.className.startsWith("io.kuicksilver.quic.NioDatagramIo") &&
                            it.methodName.startsWith("receive")
                    }
                }
            val (server, port) = testServer { routing { get("/") { call.respondText("ok") } } }
            try {
                testClient(Http3DiscoveryMode.H3Only).use { c -> assertEquals("ok", c.get("https://127.0.0.1:$port/").bodyAsText()) }
                delay(300)
                val baseline = receivers()
                repeat(6) {
                    testClient(Http3DiscoveryMode.H3Only).use { c ->
                        assertEquals("ok", c.get("https://127.0.0.1:$port/").bodyAsText())
                    }
                }
                var now = receivers()
                var waited = 0
                while (now > baseline && waited < 3000) {
                    delay(100)
                    waited += 100
                    now = receivers()
                }
                assertTrue(now <= baseline, "UDP receive loops: $baseline before, $now after six closed clients")
            } finally {
                server.stop(100, 500)
            }
        }

    /** Found by the vendored contract (HttpTimeoutTest over h3): the body fails with the timeout, not a bare stream cancellation. */
    @Test fun requestTimeoutDuringTheBodyIsReportedAsSuch() =
        clientTest {
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
        clientTest {
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
}
