// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server

import io.ktor.network.sockets.InetSocketAddress
import io.ktor.server.request.httpVersion
import io.ktor.server.request.receive
import io.ktor.server.response.header
import io.ktor.server.response.respondBytes
import io.ktor.server.response.respondBytesWriter
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import io.ktor.server.routing.routing
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.readAvailable
import io.ktor.utils.io.writeFully
import io.kuicksilver.http3.Http3Connection
import io.kuicksilver.http3.Http3Endpoint
import io.kuicksilver.http3.Http3Request
import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.io.readByteArray
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

internal suspend fun ByteReadChannel.readFullBody(): ByteArray {
    val out = kotlinx.io.Buffer()
    val b = ByteArray(16384)
    while (true) {
        val n = readAvailable(b, 0, b.size)
        if (n <
            0
        ) {
            break
        }
        out.write(b, 0, n)
    }
    closedCause?.let { throw it }
    return out.readByteArray()
}

/** HTTP/3 on the TLS connector's port, checked with the kuicksilver-http3 client. */
class ServerH3Test {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private suspend fun <T> h3(
        port: Int,
        block: suspend (Http3Connection) -> T,
    ): T {
        val ep = Http3Endpoint.bind(InetSocketAddress("127.0.0.1", 0))
        try {
            val c = ep.connect(InetSocketAddress("127.0.0.1", port), ServerFixtures.clientTls(alpn = listOf("h3")))
            try {
                return block(c)
            } finally {
                c.close()
            }
        } finally {
            ep.close()
        }
    }

    private fun get(path: String = "/") = Http3Request("GET", authority = "server.test", path = path)

    @Test fun getOverH3() =
        serverTest {
            val (server, port) =
                tlsServer {
                    routing {
                        get(
                            "/",
                        ) {
                            call.respondText(
                                "${call.request.httpVersion} ${call.request.local.scheme} ${call.request.local.method.value}",
                            )
                        }
                    }
                }
            try {
                h3(port) { c ->
                    val r = c.request(get())
                    assertEquals(200, r.status)
                    assertEquals("HTTP/3 https GET", r.body.readFullBody().decodeToString())
                    assertTrue(r.headers["content-type"]!!.startsWith("text/plain"))
                }
            } finally {
                server.stop(100, 500)
            }
        }

    @Test fun postEchoLargeBody() =
        serverTest {
            val payload = ByteArray(4 shl 20) { (it * 31).toByte() }
            val (server, port) = tlsServer { routing { post("/echo") { call.respondBytes(call.receive<ByteArray>()) } } }
            try {
                h3(port) { c ->
                    val r = c.request(Http3Request("POST", authority = "server.test", path = "/echo", body = ByteReadChannel(payload)))
                    assertContentEquals(payload, r.body.readFullBody())
                }
            } finally {
                server.stop(100, 500)
            }
        }

    @Test fun unknownLengthBodyOverH3HasNoTransferEncoding() =
        serverTest {
            val (server, port) =
                tlsServer {
                    routing {
                        get(
                            "/",
                        ) { call.respondBytesWriter { repeat(100) { writeFully(ByteArray(30_000) { 7 }) } } }
                    }
                }
            try {
                h3(port) { c ->
                    val r = c.request(get())
                    assertNull(r.headers["transfer-encoding"])
                    assertNull(r.headers["connection"])
                    assertEquals(3_000_000, r.body.readFullBody().size)
                }
            } finally {
                server.stop(100, 500)
            }
        }

    @Test fun altSvcOnH1Responses() =
        serverTest {
            val (server, port) = tlsServer { routing { get("/") { call.respondText("ok") } } }
            try {
                val resp = rawHttp(port, "GET / HTTP/1.1\r\nHost: server.test\r\nConnection: close\r\n\r\n")
                assertTrue(resp.contains("Alt-Svc: h3=\":$port\"; ma=86400"), resp)
            } finally {
                server.stop(100, 500)
            }
        }

    @Test fun altSvcDisabled() =
        serverTest {
            val (server, port) = tlsServer(configure = { altSvc = false }) { routing { get("/") { call.respondText("ok") } } }
            try {
                val resp = rawHttp(port, "GET / HTTP/1.1\r\nHost: server.test\r\nConnection: close\r\n\r\n")
                assertTrue(!resp.contains("Alt-Svc"), resp)
            } finally {
                server.stop(100, 500)
            }
        }

    @Test fun appAltSvcNotOverwritten() =
        serverTest {
            val (server, port) =
                tlsServer {
                    routing {
                        get("/") {
                            call.response.header("Alt-Svc", "clear")
                            call.respondText("ok")
                        }
                    }
                }
            try {
                val resp = rawHttp(port, "GET / HTTP/1.1\r\nHost: server.test\r\nConnection: close\r\n\r\n")
                assertTrue(resp.contains("Alt-Svc: clear") && !resp.contains("h3="), resp)
            } finally {
                server.stop(100, 500)
            }
        }

    @Test fun hundredRequestsOneConnection() =
        serverTest {
            val (server, port) = tlsServer { routing { get("/{n}") { call.respondText("n=${call.parameters["n"]}") } } }
            try {
                h3(port) { c ->
                    val bodies =
                        coroutineScope {
                            (0 until 100)
                                .map { i ->
                                    async {
                                        c
                                            .request(get("/$i"))
                                            .body
                                            .readFullBody()
                                            .decodeToString()
                                    }
                                }.awaitAll()
                        }
                    assertEquals(
                        (
                            0 until
                                100
                        ).map { "n=$it" },
                        bodies,
                    )
                }
            } finally {
                server.stop(100, 500)
            }
        }

    @Test fun h3ResponseHeadersAreLowercase() =
        serverTest {
            val (server, port) =
                tlsServer {
                    routing {
                        get("/") {
                            call.response.header("X-Custom-Header", "v")
                            call.respondText("ok")
                        }
                    }
                }
            try {
                h3(port) { c -> assertEquals("v", c.request(get()).headers["x-custom-header"]) }
            } finally {
                server.stop(100, 500)
            }
        }

    /** `stop(grace, timeout)` is honoured for HTTP/3 too — in-flight calls finish, the client sees GOAWAY. */
    @Test fun stopWaitsForInFlightH3Call() =
        serverTest {
            val (server, port) =
                tlsServer {
                    routing {
                        get("/slow") {
                            kotlinx.coroutines.delay(1500)
                            call.respondText("done")
                        }
                    }
                }
            val ep = Http3Endpoint.bind(InetSocketAddress("127.0.0.1", 0))
            try {
                val c = ep.connect(InetSocketAddress("127.0.0.1", port), ServerFixtures.clientTls(alpn = listOf("h3")))
                try {
                    coroutineScope {
                        val response = async { c.request(get("/slow")) }
                        kotlinx.coroutines.delay(300)
                        val t0 =
                            kotlin.time.TimeSource.Monotonic
                                .markNow()
                        server.stopSuspend(5000, 10000)
                        val stopTook = t0.elapsedNow()
                        val r = response.await()
                        assertEquals(200, r.status)
                        assertEquals("done", r.body.readFullBody().decodeToString())
                        assertTrue(stopTook < 4.seconds && stopTook > 500.milliseconds, "stop waited for the call: $stopTook")
                        assertEquals(
                            true,
                            kotlinx.coroutines.withTimeoutOrNull(3.seconds) {
                                while (c.goAwayReceived.value ==
                                    null
                                ) {
                                    kotlinx.coroutines.delay(20)
                                }
                                true
                            },
                            "the client received GOAWAY",
                        )
                    }
                } finally {
                    c.close()
                }
            } finally {
                ep.close()
                runCatching { server.stop(100, 500) }
            }
        }

    /** GOAWAY reaches every connection at once, not one per 2×RTT; the in-flight calls all finish within the grace period. */
    @Test fun stopSendsGoAwayToAllConnectionsAtOnce() =
        serverTest {
            val arrived =
                java.util.concurrent.atomic
                    .AtomicInteger()
            val (server, port) =
                tlsServer {
                    routing {
                        get("/slow") {
                            arrived.incrementAndGet()
                            kotlinx.coroutines.delay(600)
                            call.respondText("done")
                        }
                    }
                }
            val ep = Http3Endpoint.bind(InetSocketAddress("127.0.0.1", 0))
            val conns = ArrayList<Http3Connection>()
            try {
                repeat(50) { conns += ep.connect(InetSocketAddress("127.0.0.1", port), ServerFixtures.clientTls(alpn = listOf("h3"))) }
                coroutineScope {
                    val responses =
                        conns.map { c ->
                            async {
                                c.request(get("/slow")).let { r ->
                                    r.status to
                                        r.body.readFullBody().decodeToString()
                                }
                            }
                        }
                    kotlinx.coroutines.withTimeout(5.seconds) { while (arrived.get() < 50) kotlinx.coroutines.delay(10) }
                    val t0 =
                        kotlin.time.TimeSource.Monotonic
                            .markNow()
                    val stop = async(kotlinx.coroutines.Dispatchers.IO) { server.stop(1000, 3000) }
                    kotlinx.coroutines.withTimeout(
                        5.seconds,
                    ) { while (conns.any { it.goAwayReceived.value == null }) kotlinx.coroutines.delay(5) }
                    val allSawGoAway = t0.elapsedNow()
                    assertEquals(List(50) { 200 to "done" }, responses.awaitAll())
                    stop.await()
                    assertTrue(allSawGoAway < 400.milliseconds, "every client saw GOAWAY after $allSawGoAway")
                }
            } finally {
                conns.forEach { it.close() }
                ep.close()
                runCatching { server.stop(100, 500) }
            }
        }

    /** Split `cookie` fields are one header for the application (RFC 9114 section 4.2.1). */
    @Test fun cookieCrumbsAreJoined() =
        serverTest {
            val (server, port) =
                tlsServer {
                    routing { get("/") { call.respondText("${call.request.headers["Cookie"]}|${call.request.cookies["b"]}") } }
                }
            try {
                h3(port) { c ->
                    val r =
                        c.request(
                            Http3Request(
                                "GET",
                                authority = "server.test",
                                path = "/",
                                headers =
                                    io.kuicksilver.http3.Http3Headers
                                        .of("cookie" to "a=1", "cookie" to "b=2"),
                            ),
                        )
                    assertEquals("a=1; b=2|2", r.body.readFullBody().decodeToString())
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /** Ktor allows optional whitespace around a header value; HTTP/3 does not carry it. The value is trimmed instead of hanging the stream. */
    @Test fun headerWithTrailingSpaceDoesNotHang() =
        serverTest {
            val (server, port) =
                tlsServer {
                    routing {
                        get("/") {
                            call.response.header("X-A", "v ")
                            call.respondText("ok")
                        }
                    }
                }
            try {
                h3(port) { c ->
                    val r = kotlinx.coroutines.withTimeout(5.seconds) { c.request(get()) }
                    assertEquals(200, r.status)
                    assertEquals("v", r.headers["x-a"])
                    assertEquals("ok", r.body.readFullBody().decodeToString())
                }
            } finally {
                server.stop(100, 500)
            }
        }
}
