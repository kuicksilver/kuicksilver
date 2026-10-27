// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)

package io.kuicksilver.ktor.server

import io.ktor.network.sockets.InetSocketAddress
import io.ktor.server.response.respondText
import io.ktor.server.routing.route
import io.ktor.server.routing.routing
import io.ktor.utils.io.copyTo
import io.ktor.utils.io.readBuffer
import io.ktor.utils.io.writeFully
import io.kuicksilver.http3.Http3Connection
import io.kuicksilver.http3.Http3Endpoint
import io.kuicksilver.http3.Http3Exception
import io.kuicksilver.http3.Http3Headers
import io.kuicksilver.http3.http3Request
import io.kuicksilver.http3.http3Settings
import io.kuicksilver.http3.webTransport
import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.flow.filterNotNull
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.withTimeout
import kotlinx.io.readString
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/** WebTransport sessions through Ktor routing: `webTransport("/path") { session -> }`. */
class ServerWebTransportTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private val wt =
        http3Settings {
            enableConnectProtocol = true
            webTransport = true
        }

    private fun wtReq(
        path: String = "/wt",
        origin: String? = "https://server.test",
    ) = http3Request("CONNECT", "server.test", path) {
        headers = Http3Headers(listOfNotNull(origin?.let { "origin" to it }))
    }

    private suspend fun <T> h3(
        port: Int,
        block: suspend (Http3Connection) -> T,
    ): T {
        val ep = Http3Endpoint.bind(InetSocketAddress("127.0.0.1", 0))
        try {
            val c = ep.connect(InetSocketAddress("127.0.0.1", port), ServerFixtures.clientTls(alpn = listOf("h3")), settings = wt)
            try {
                return block(c)
            } finally {
                c.close()
            }
        } finally {
            ep.close()
        }
    }

    @Test fun echoRoute() =
        h3ServerTest {
            val (server, port) =
                tlsServer({ webTransport = true }) {
                    routing {
                        webTransport("/wt") { session ->
                            val st = session.acceptBidi()
                            st.input.copyTo(st.output)
                            st.output.flushAndClose()
                            session.sendDatagram(session.receiveDatagram())
                            session.closed.await()
                        }
                    }
                }
            try {
                h3(port) { c ->
                    val session = c.webTransport(wtReq())
                    val st = session.openBidi()
                    st.output.writeFully("ping".encodeToByteArray())
                    st.output.flushAndClose()
                    assertEquals("ping", withTimeout(5.seconds) { st.input.readBuffer().readString() })
                    session.trySendDatagram(byteArrayOf(1, 2, 3))
                    assertContentEquals(byteArrayOf(1, 2, 3), withTimeout(5.seconds) { session.receiveDatagram() })
                    session.close(0, "done")
                }
            } finally {
                server.stopSuspend(100, 1000)
            }
        }

    @Test fun unknownPathIs404() =
        h3ServerTest {
            val (server, port) = tlsServer({ webTransport = true }) { routing { webTransport("/wt") { } } }
            try {
                h3(port) { c ->
                    assertEquals(404, assertFailsWith<Http3Exception.ConnectRejected> { c.webTransport(wtReq("/other")) }.status)
                }
            } finally {
                server.stopSuspend(100, 1000)
            }
        }

    @Test fun negative_foreignOriginIs403() =
        h3ServerTest {
            val ran = CompletableDeferred<Unit>()
            val (server, port) = tlsServer({ webTransport = true }) { routing { webTransport("/wt") { ran.complete(Unit) } } }
            try {
                h3(port) { c ->
                    val e = assertFailsWith<Http3Exception.ConnectRejected> { c.webTransport(wtReq(origin = "https://evil.test")) }
                    assertEquals(403, e.status)
                }
                assertFalse(ran.isCompleted)
            } finally {
                server.stopSuspend(100, 1000)
            }
        }

    /** A client without Origin (no browser) is not checked by the default; a browser always sends one. */
    @Test fun noOriginIsAccepted() =
        h3ServerTest {
            val (server, port) = tlsServer({ webTransport = true }) { routing { webTransport("/wt") { } } }
            try {
                h3(port) { c -> withTimeout(5.seconds) { c.webTransport(wtReq(origin = null)).closed.await() } }
            } finally {
                server.stopSuspend(100, 1000)
            }
        }

    @Test fun handlerReturnClosesSession() =
        h3ServerTest {
            val (server, port) = tlsServer({ webTransport = true }) { routing { webTransport("/wt") { } } }
            try {
                h3(port) { c ->
                    val info = withTimeout(5.seconds) { c.webTransport(wtReq()).closed.await() }
                    assertEquals(0L, info.code)
                    assertEquals(null, info.cause)
                }
            } finally {
                server.stopSuspend(100, 1000)
            }
        }

    @Test fun handlerExceptionClosesWithError() =
        h3ServerTest {
            var calls = 0
            val log = CapturedLog()
            val (server, port) =
                tlsServer({ webTransport = true }, log = log) {
                    routing { webTransport("/wt") { if (calls++ == 0) throw IllegalStateException("boom") } }
                }
            try {
                h3(port) { c ->
                    val info = withTimeout(5.seconds) { c.webTransport(wtReq()).closed.await() }
                    assertEquals(WEB_TRANSPORT_HANDLER_FAILED, info.code)
                    assertEquals("", info.reason) // the exception's message stays on the server
                }
                // the server lives on and serves the next session
                h3(port) { c -> assertEquals(0L, withTimeout(5.seconds) { c.webTransport(wtReq()).closed.await() }.code) }
                // the failure reaches the application log (an error with the handler's exception), not the test output
                log.assertLogged("ERROR", "CONNECT - /wt", "boom")
            } finally {
                server.stopSuspend(100, 1000)
            }
        }

    @Test fun protocolNegotiatedByRoute() =
        h3ServerTest {
            val (server, port) =
                tlsServer({ webTransport = true }) {
                    routing { webTransport("/wt", protocols = listOf("v2", "v1")) { it.closed.await() } }
                }
            try {
                h3(port) { c ->
                    val s = c.webTransport(wtReq(), protocols = listOf("v1", "v2"))
                    assertEquals("v2", s.protocol) // the server's preference
                    s.close()
                }
            } finally {
                server.stopSuspend(100, 1000)
            }
        }

    @Test fun webTransportOffByDefault() =
        h3ServerTest {
            val (server, port) = tlsServer { routing { webTransport("/wt") { } } }
            try {
                h3(port) { c ->
                    val ps = withTimeout(5.seconds) { c.peerSettings.filterNotNull().first() }
                    assertFalse(ps.webTransport)
                    assertFailsWith<Http3Exception.Settings> { c.webTransport(wtReq()) }
                    // the token as a plain Extended CONNECT is answered as before
                    assertEquals(501, assertFailsWith<Http3Exception.ConnectRejected> { c.connect(wtReq(), "webtransport-h3") }.status)
                }
            } finally {
                server.stopSuspend(100, 1000)
            }
        }

    @Test fun h1RequestNeverMatchesWebTransportRoute() =
        h3ServerTest {
            val ran = CompletableDeferred<Unit>()
            val (server, port) = tlsServer({ webTransport = true }) { routing { webTransport("/wt") { ran.complete(Unit) } } }
            try {
                val resp = rawHttp(port, "GET /wt HTTP/1.1\r\nHost: server.test\r\nConnection: close\r\n\r\n")
                // Ktor's answer when the path matches a route of another method (the route is a CONNECT route)
                assertEquals("HTTP/1.1 405 Method Not Allowed", resp.lineSequence().first().trim())
                assertFalse(ran.isCompleted)
            } finally {
                server.stopSuspend(100, 1000)
            }
        }

    /** The opaque origin `null` (a sandboxed page) and other schemes are refused by the default check. */
    @Test fun negative_opaqueOriginIs403() =
        h3ServerTest {
            val (server, port) = tlsServer({ webTransport = true }) { routing { webTransport("/wt") { } } }
            try {
                h3(port) { c ->
                    for (origin in listOf("null", "file://server.test", "chrome-extension://server.test")) {
                        val e = assertFailsWith<Http3Exception.ConnectRejected>(origin) { c.webTransport(wtReq(origin = origin)) }
                        assertEquals(403, e.status, origin)
                    }
                }
            } finally {
                server.stopSuspend(100, 1000)
            }
        }

    /** Another route that answers the WebTransport CONNECT with a 2xx would fake a session: it is turned into 501. */
    @Test fun negative_plainRouteCannotFakeASession() =
        h3ServerTest {
            val (server, port) =
                tlsServer({ webTransport = true }) {
                    routing { route("/wt") { handle { call.respondText("not a session") } } }
                }
            try {
                h3(port) { c -> assertEquals(501, assertFailsWith<Http3Exception.ConnectRejected> { c.webTransport(wtReq()) }.status) }
            } finally {
                server.stopSuspend(100, 1000)
            }
        }
}
