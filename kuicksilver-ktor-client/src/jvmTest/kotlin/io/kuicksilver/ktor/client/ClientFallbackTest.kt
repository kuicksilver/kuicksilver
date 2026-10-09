// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import io.ktor.client.request.get
import io.ktor.client.request.post
import io.ktor.client.request.put
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpProtocolVersion
import io.ktor.network.sockets.InetSocketAddress
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
import io.kuicksilver.quic.QuicEndpointConfig
import io.kuicksilver.quic.QuicServerConfig
import io.kuicksilver.quic.quicConfig
import io.kuicksilver.tls.SpkiSha256
import io.kuicksilver.tls.TlsException
import io.kuicksilver.tls.TlsIdentity
import io.kuicksilver.tls.TlsRole
import io.kuicksilver.tls.TrustConfig
import io.kuicksilver.tls.tlsConfig
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds
import kotlin.time.TimeSource

class ClientFallbackTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    /** Feature focus 4: Alt-Svc points at a UDP port where nobody answers. */
    @Test fun blockedUdpFallsBackAfterHardDelayAndMarksBroken() =
        clientTest {
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
                testClient(Http3DiscoveryMode.Auto, engine = { quic = quicConfig { handshakeTimeout = 500.milliseconds } }).use { c ->
                    assertEquals("h1", c.get("https://127.0.0.1:$port/").bodyAsText()) // learns the alternative
                    val t0 = TimeSource.Monotonic.markNow()
                    val r = c.get("https://127.0.0.1:$port/")
                    assertEquals(HttpProtocolVersion.HTTP_1_1, r.version)
                    assertTrue(t0.elapsedNow() < 2.seconds, "${t0.elapsedNow()}")
                    val engine = c.engine as KuicksilverEngine
                    val origin = "https://127.0.0.1:$port"
                    val alt = "127.0.0.1:$port"
                    // h3 failed and h1 worked
                    kotlinx.coroutines.withTimeout(5.seconds) { while (!engine.brokenAltSvc.isBroken(origin, alt)) delay(50) }
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

    /** A raw HTTP/3 server on the UDP side of [port] that fails every request after reading it (H3_INTERNAL_ERROR). */
    private suspend fun CoroutineScope.failingH3(port: Int): Http3Endpoint {
        val tls =
            tlsConfig(TlsRole.Server) {
                alpn = listOf("h3")
                identity =
                    TlsIdentity.fromDer(listOf(TestCerts.server), TestCerts.serverKey.copyOf())
            }
        val ep =
            Http3Endpoint.bind(
                InetSocketAddress("127.0.0.1", port),
                QuicEndpointConfig
                    .Builder()
                    .apply {
                        this.server =
                            QuicServerConfig.Builder(tls).build()
                    }.build(),
            )
        launch {
            runCatching {
                while (true) {
                    val conn = ep.accept()
                    launch {
                        runCatching {
                            while (true) {
                                conn.acceptRequest().reset(Http3ErrorCode.INTERNAL_ERROR)
                            }
                        }
                    }
                }
            }
        }
        return ep
    }

    @Test fun idempotentRetriedOnH1() =
        clientTest {
            var h1Calls = 0
            val (server, port) =
                testServer(configure = { http3 = false }) {
                    routing {
                        get("/") {
                            h1Calls++
                            call.respondText("h1")
                        }
                    }
                }
            kotlinx.coroutines.coroutineScope {
                val ep = failingH3(port)
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
        clientTest {
            var h1Calls = 0
            val (server, port) =
                testServer(configure = { http3 = false }) {
                    routing {
                        post("/") {
                            h1Calls++
                            call.respondText("h1")
                        }
                    }
                }
            kotlinx.coroutines.coroutineScope {
                val ep = failingH3(port)
                try {
                    testClient(Http3DiscoveryMode.Preferred).use { c ->
                        // set up the HTTP/3 connection first (the first request may race to HTTP/1.1), so the POST goes over HTTP/3
                        runCatching { c.get("https://127.0.0.1:$port/warmup") }
                        val engine = c.engine as KuicksilverEngine
                        kotlinx.coroutines.withTimeout(
                            5.seconds,
                        ) { while (!engine.hasH3Connection(io.ktor.http.Url("https://127.0.0.1:$port/"))) delay(20) }
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
        clientTest {
            var h1Calls = 0
            val (server, port) =
                testServer(configure = { http3 = false }) {
                    routing {
                        put("/") {
                            h1Calls++
                            call.respondText("h1")
                        }
                    }
                }
            kotlinx.coroutines.coroutineScope {
                val tls =
                    tlsConfig(TlsRole.Server) {
                        alpn = listOf("h3")
                        identity =
                            TlsIdentity.fromDer(listOf(TestCerts.server), TestCerts.serverKey.copyOf())
                    }
                val ep =
                    Http3Endpoint.bind(
                        InetSocketAddress("127.0.0.1", port),
                        QuicEndpointConfig
                            .Builder()
                            .apply {
                                this.server =
                                    QuicServerConfig.Builder(tls).build()
                            }.build(),
                    )
                launch {
                    runCatching {
                        while (true) {
                            val conn = ep.accept()
                            launch {
                                runCatching {
                                    while (true) {
                                        val r = conn.acceptRequest()
                                        launch {
                                            runCatching {
                                                val b = ByteArray(65_536)
                                                var got = 0
                                                while (got <
                                                    b.size
                                                ) {
                                                    val n = r.body.readAvailable(b, 0, b.size - got)
                                                    if (n <
                                                        0
                                                    ) {
                                                        break
                                                    }
                                                    got += n
                                                }
                                            }
                                            ; r.reset(Http3ErrorCode.INTERNAL_ERROR)
                                        }
                                    }
                                }
                            }
                        }
                    }
                } // reads part of the body, then fails the stream
                try {
                    testClient(Http3DiscoveryMode.Preferred).use { c ->
                        runCatching { c.get("https://127.0.0.1:$port/warmup") }
                        val engine = c.engine as KuicksilverEngine
                        kotlinx.coroutines.withTimeout(
                            5.seconds,
                        ) { while (!engine.hasH3Connection(io.ktor.http.Url("https://127.0.0.1:$port/"))) delay(20) }
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
