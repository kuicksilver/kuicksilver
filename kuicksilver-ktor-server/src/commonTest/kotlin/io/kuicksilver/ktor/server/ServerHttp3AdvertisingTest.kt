// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server

import io.ktor.network.selector.SelectorManager
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.network.sockets.openReadChannel
import io.ktor.network.sockets.openWriteChannel
import io.ktor.server.response.header
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.LineEnding
import io.ktor.utils.io.readByteArray
import io.ktor.utils.io.readLine
import io.ktor.utils.io.writeStringUtf8
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.http3.Http3Connection
import io.kuicksilver.http3.Http3Endpoint
import io.kuicksilver.http3.http3Request
import io.kuicksilver.ktor.network.tls
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.TransportError
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.withTimeout
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.time.Duration.Companion.seconds

/**
 * `KuicksilverApplicationEngine.http3Advertising` (docs/guide/ktor.md, "Turning HTTP/3 off remotely"): `Alt-Svc` per response
 * (RFC 7838 section 3 `clear`), GOAWAY to live HTTP/3 connections (RFC 9114 section 5.2) and new QUIC connections refused with
 * CONNECTION_REFUSED (RFC 9000 section 10.2.3) under `Drain`. Every wait is on an event (a response, GOAWAY, a refusal) under a
 * deadline that names it; nothing sleeps.
 */
@OptIn(ExperimentalKuicksilverApi::class)
class ServerHttp3AdvertisingTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private val h3Tls get() = ServerFixtures.clientTls(alpn = listOf("h3"))

    private fun get(path: String = "/") = http3Request("GET", "server.test", path)

    /** A TLS HTTP/1.1 connection kept alive across [steps]: each sends a GET of `/`, reads its response in full, then runs. */
    private suspend fun keepAlive(
        port: Int,
        vararg steps: suspend () -> Unit,
    ): List<String> {
        val selector = SelectorManager(Dispatchers.Default)
        try {
            val tcp =
                io.kuicksilver.ktor.network
                    .connectTcp(selector, InetSocketAddress("127.0.0.1", port))
            val socket = tcp.tls(ServerFixtures.clientTls())
            try {
                val w = socket.openWriteChannel(autoFlush = true)
                val r = socket.openReadChannel()
                return steps.map { step ->
                    w.writeStringUtf8("GET / HTTP/1.1\r\nHost: server.test\r\n\r\n")
                    w.flush()
                    withTimeout(10.seconds) { readResponseHead(r) }.also { step() }
                }
            } finally {
                socket.close()
            }
        } finally {
            selector.close()
        }
    }

    /** One response's head (its body, of Content-Length bytes, is read and dropped). */
    private suspend fun readResponseHead(r: ByteReadChannel): String {
        val head = StringBuilder()
        var length = 0
        while (true) {
            val line = r.readLine(LineEnding.Lenient) ?: error("the connection closed in a response head: $head")
            if (line.isEmpty()) break
            head.append(line).append("\r\n")
            if (line.startsWith("Content-Length:", ignoreCase = true)) length = line.substringAfter(':').trim().toInt()
        }
        r.readByteArray(length)
        return head.toString()
    }

    private fun Server.advertising(mode: Http3Advertising) {
        engine.http3Advertising = mode
    }

    private suspend fun h1(port: Int): String = rawHttp(port, "GET / HTTP/1.1\r\nHost: server.test\r\nConnection: close\r\n\r\n")

    private suspend fun awaitGoAway(c: Http3Connection) =
        withTimeout(10.seconds) { c.goAwayReceived.first { it != null } } ?: error("no GOAWAY")

    /** `On` advertises h3; `Clear` and `Drain` say `Alt-Svc: clear`, read for each response, on one keep-alive connection. */
    @Test fun clearSendsAltSvcClearOnTheSameConnection() =
        h3ServerTest {
            val (server, port) = tlsServer { routing { get("/") { call.respondText("ok") } } }
            try {
                assertEquals(Http3Advertising.On, server.engine.http3Advertising)
                val heads =
                    keepAlive(
                        port,
                        { server.advertising(Http3Advertising.Clear) },
                        { server.advertising(Http3Advertising.Drain) },
                        { server.advertising(Http3Advertising.On) },
                        {},
                    )
                assertEquals(
                    listOf("h3=\":$port\"; ma=86400", "clear", "clear", "h3=\":$port\"; ma=86400"),
                    heads.map { h -> h.lines().single { it.startsWith("Alt-Svc:") }.substringAfter(": ") },
                    heads.toString(),
                )
            } finally {
                server.stop(100, 500)
            }
        }

    /** `Drain` sends GOAWAY to every live HTTP/3 connection, idle or busy; the request in flight still completes with 200. */
    @Test fun drainGoAwaysLiveConnectionsAndTheirRequestsFinish() =
        h3ServerTest {
            val arrived = CompletableDeferred<Unit>()
            val release = CompletableDeferred<Unit>()
            val (server, port) =
                tlsServer {
                    routing {
                        get("/slow") {
                            arrived.complete(Unit)
                            release.await()
                            call.respondText("done")
                        }
                    }
                }
            val ep = Http3Endpoint.bind(InetSocketAddress("127.0.0.1", 0))
            try {
                val busy = ep.connect(InetSocketAddress("127.0.0.1", port), h3Tls)
                val idle = ep.connect(InetSocketAddress("127.0.0.1", port), h3Tls)
                coroutineScope {
                    val response = async { busy.request(get("/slow")).let { it.status to it.body.readFullBody().decodeToString() } }
                    withTimeout(10.seconds) { arrived.await() }
                    server.advertising(Http3Advertising.Drain)
                    awaitGoAway(busy)
                    awaitGoAway(idle)
                    release.complete(Unit)
                    assertEquals(200 to "done", withTimeout(10.seconds) { response.await() }, "the request in flight finished")
                }
                busy.close()
                idle.close()
            } finally {
                ep.close()
                server.stop(100, 500)
            }
        }

    /**
     * A connection the accept loop took just before `Drain` was set, but had not registered yet, still gets GOAWAY: the switch
     * is flipped from the accept hook, between `accept()` and the registration, and the hook waits until the switch's own
     * GOAWAY round has taken its list of live connections, so only the accept loop's own check can reach this one.
     */
    @Test fun drainReachesAConnectionAcceptedJustBefore() =
        h3ServerTest {
            val (s, port) =
                tlsServer { routing { get("/") { call.respondText("ok") } } }.also { (srv, _) ->
                    srv.engine.afterH3AcceptForTest = {
                        srv.advertising(Http3Advertising.Drain)
                        withTimeout(10.seconds) { srv.engine.drainRoundForTest!!.join() }
                    }
                }
            val ep = Http3Endpoint.bind(InetSocketAddress("127.0.0.1", 0))
            try {
                val c = ep.connect(InetSocketAddress("127.0.0.1", port), h3Tls)
                awaitGoAway(c)
                c.close()
            } finally {
                ep.close()
                s.stop(100, 500)
            }
        }

    /** Under `Drain` a new QUIC client is refused at its first Initial with CONNECTION_REFUSED; HTTP/1.1 goes on, saying `clear`. */
    @Test fun drainRefusesNewQuic() =
        h3ServerTest {
            val (server, port) = tlsServer { routing { get("/") { call.respondText("ok") } } }
            val ep = Http3Endpoint.bind(InetSocketAddress("127.0.0.1", 0))
            try {
                server.advertising(Http3Advertising.Drain)
                val refused =
                    withTimeout(10.seconds) {
                        assertFailsWith<QuicException.ConnectionLost.TransportClosed> {
                            ep.connect(InetSocketAddress("127.0.0.1", port), h3Tls)
                        }
                    }
                assertEquals(TransportError.CONNECTION_REFUSED, refused.code)
                val resp = h1(port)
                assertEquals(true, resp.endsWith("ok") && resp.contains("Alt-Svc: clear\r\n"), resp)
            } finally {
                ep.close()
                server.stop(100, 500)
            }
        }

    /** `Clear` leaves HTTP/3 serving: a client that still holds the old Alt-Svc connects and is answered. */
    @Test fun clearKeepsServingHttp3() =
        h3ServerTest {
            val (server, port) = tlsServer { routing { get("/") { call.respondText("ok") } } }
            val ep = Http3Endpoint.bind(InetSocketAddress("127.0.0.1", 0))
            try {
                server.advertising(Http3Advertising.Clear)
                val c = ep.connect(InetSocketAddress("127.0.0.1", port), h3Tls)
                val r = c.request(get())
                assertEquals(200 to "ok", r.status to r.body.readFullBody().decodeToString())
                assertNull(c.goAwayReceived.value, "Clear sends no GOAWAY")
                c.close()
            } finally {
                ep.close()
                server.stop(100, 500)
            }
        }

    /** From `Drain` back to `On`: new QUIC clients are accepted and served, and HTTP/1.1 advertises h3 again. */
    @Test fun backToOnAdvertisesAndAcceptsAgain() =
        h3ServerTest {
            val (server, port) = tlsServer { routing { get("/") { call.respondText("ok") } } }
            val ep = Http3Endpoint.bind(InetSocketAddress("127.0.0.1", 0))
            try {
                server.advertising(Http3Advertising.Drain)
                withTimeout(10.seconds) {
                    assertFailsWith<QuicException.ConnectionLost.TransportClosed> {
                        ep.connect(
                            InetSocketAddress("127.0.0.1", port),
                            h3Tls,
                        )
                    }
                }
                server.advertising(Http3Advertising.On)
                val c = withTimeout(10.seconds) { ep.connect(InetSocketAddress("127.0.0.1", port), h3Tls) }
                val r = c.request(get())
                assertEquals(200 to "ok", r.status to r.body.readFullBody().decodeToString())
                c.close()
                val resp = h1(port)
                assertEquals(true, resp.contains("Alt-Svc: h3=\":$port\"; ma=86400\r\n"), resp)
            } finally {
                ep.close()
                server.stop(100, 500)
            }
        }

    /**
     * `altSvc = false` sends no Alt-Svc in any mode (the switch decides what is advertised only when advertising is on), while
     * `Drain` still stops HTTP/3 itself: new QUIC clients are refused.
     */
    @Test fun altSvcOffSendsNoHeaderInAnyMode() =
        h3ServerTest {
            val (server, port) = tlsServer(configure = { altSvc = false }) { routing { get("/") { call.respondText("ok") } } }
            val ep = Http3Endpoint.bind(InetSocketAddress("127.0.0.1", 0))
            try {
                for (mode in Http3Advertising.entries) {
                    server.advertising(mode)
                    val resp = h1(port)
                    assertEquals(true, resp.endsWith("ok") && !resp.contains("Alt-Svc"), "$mode: $resp")
                }
                server.advertising(Http3Advertising.Drain)
                withTimeout(10.seconds) {
                    assertFailsWith<QuicException.ConnectionLost.TransportClosed> {
                        ep.connect(
                            InetSocketAddress("127.0.0.1", port),
                            h3Tls,
                        )
                    }
                }
            } finally {
                ep.close()
                server.stop(100, 500)
            }
        }

    /** An `Alt-Svc` the application set is sent as it is in every mode; the engine adds none next to it. */
    @Test fun negative_appAltSvcNotOverridden() =
        h3ServerTest {
            val (server, port) =
                tlsServer {
                    routing {
                        get("/") {
                            call.response.header("Alt-Svc", "h3=\"alt.example:443\"")
                            call.respondText("ok")
                        }
                    }
                }
            try {
                for (mode in Http3Advertising.entries) {
                    server.advertising(mode)
                    val resp = h1(port)
                    assertEquals(
                        listOf("Alt-Svc: h3=\"alt.example:443\""),
                        resp.lines().filter { it.startsWith("Alt-Svc", ignoreCase = true) },
                        "$mode: $resp",
                    )
                }
            } finally {
                server.stop(100, 500)
            }
        }
}
