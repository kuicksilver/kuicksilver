// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server

import io.ktor.http.HttpProtocolVersion
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.server.application.ApplicationCall
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.http3.Http3Endpoint
import io.kuicksilver.http3.http3Request
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.ConnectionInfo
import io.kuicksilver.quic.ConnectionListener
import io.kuicksilver.quic.KuicksilverLogger
import io.kuicksilver.quic.LogLevel
import io.kuicksilver.quic.QlogSink
import io.kuicksilver.quic.QlogTrace
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.TransportError
import io.kuicksilver.tls.TlsRole
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.withTimeout
import kotlin.concurrent.atomics.AtomicReference
import kotlin.concurrent.atomics.ExperimentalAtomicApi
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds
import kotlin.time.TimeSource

/** The server engine's event listener, logger and qlog wiring, and `stop(grace)` on the QUIC side. */
@OptIn(ExperimentalKuicksilverApi::class, ExperimentalAtomicApi::class)
class ServerObservabilityTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    /** Lines appended from any thread. */
    private class Lines {
        private val ref = AtomicReference<List<String>>(emptyList())
        val all: List<String> get() = ref.load()

        operator fun plusAssign(line: String) {
            while (true) {
                val old = ref.load()
                if (ref.compareAndSet(old, old + line)) return
            }
        }
    }

    private fun get(path: String = "/") = http3Request("GET", "server.test", path)

    private suspend fun eventually(cond: () -> Boolean) = withTimeout(5.seconds) { while (!cond()) delay(10) }

    @Test fun stopRefusesNewHttp3ClientsWhileInFlightCallsFinish() =
        h3ServerTest {
            val arrived = CompletableDeferred<Unit>()
            val (server, port) =
                tlsServer {
                    routing {
                        get("/slow") {
                            arrived.complete(Unit)
                            delay(2000)
                            call.respondText("done")
                        }
                    }
                }
            val ep = Http3Endpoint.bind(InetSocketAddress("127.0.0.1", 0))
            try {
                val c = ep.connect(InetSocketAddress("127.0.0.1", port), ServerFixtures.clientTls(alpn = listOf("h3")))
                coroutineScope {
                    val response = async { c.request(get("/slow")).let { it.status to it.body.readFullBody().decodeToString() } }
                    arrived.await()
                    val t0 = TimeSource.Monotonic.markNow()
                    val stop = async(Dispatchers.Default) { server.stop(5000, 10000) }
                    // a new client is refused at its first Initial (CONNECTION_REFUSED), long before the slow call ends
                    var refused: QuicException.ConnectionLost.TransportClosed? = null
                    withTimeout(1500) {
                        while (refused == null) {
                            val late = Http3Endpoint.bind(InetSocketAddress("127.0.0.1", 0))
                            try {
                                late.connect(InetSocketAddress("127.0.0.1", port), ServerFixtures.clientTls(alpn = listOf("h3"))).close()
                                delay(20) // the stop has not reached the endpoint yet
                            } catch (e: QuicException.ConnectionLost.TransportClosed) {
                                refused = e
                            } finally {
                                late.close()
                            }
                        }
                    }
                    assertEquals(TransportError.CONNECTION_REFUSED, refused!!.code)
                    assertTrue(t0.elapsedNow() < 1500.milliseconds, "refused promptly")
                    assertEquals(200 to "done", response.await(), "the in-flight call finished in the grace period")
                    stop.await()
                }
                c.close()
            } finally {
                ep.close()
                runCatching { server.stop(100, 500) }
            }
        }

    /** At the grace deadline what is left closes with H3_NO_ERROR (RFC 9114 section 5.2), not QUIC application code 0. */
    @Test fun stopAtTheGraceDeadlineClosesWithH3NoError() =
        h3ServerTest {
            val arrived = CompletableDeferred<Unit>()
            val (server, port) =
                tlsServer {
                    routing {
                        get("/forever") {
                            arrived.complete(Unit)
                            delay(60_000)
                            call.respondText("late")
                        }
                    }
                }
            val ep = Http3Endpoint.bind(InetSocketAddress("127.0.0.1", 0))
            try {
                val c = ep.connect(InetSocketAddress("127.0.0.1", port), ServerFixtures.clientTls(alpn = listOf("h3")))
                coroutineScope {
                    val call = async { runCatching { c.request(get("/forever")).body.readFullBody() } }
                    arrived.await()
                    val t0 = TimeSource.Monotonic.markNow()
                    server.stop(300, 3000)
                    assertTrue(t0.elapsedNow() < 3000.milliseconds, "stop returned within timeoutMillis: ${t0.elapsedNow()}")
                    val closed = withTimeout(5.seconds) { c.quic.closed.await() }
                    val app = closed as QuicException.ConnectionLost.ApplicationClosed
                    assertEquals(io.kuicksilver.http3.Http3ErrorCode.NO_ERROR, app.code, "$closed")
                    assertTrue(call.await().isFailure, "the call still running at the deadline did not complete")
                }
            } finally {
                ep.close()
                runCatching { server.stop(100, 500) }
            }
        }

    /**
     * A connection whose handshake completes after the stop began (RFC 9114 section 5.2) is still served: it gets GOAWAY at
     * once, and the stop ends when it is idle instead of waiting out the whole grace period.
     */
    @Test fun aConnectionAcceptedDuringStopGetsGoAwayAndTheStopEndsEarly() =
        h3ServerTest {
            val (server, port) = tlsServer { routing { get("/") { call.respondText("ok") } } }
            val gate = CompletableDeferred<Unit>()
            val held = CompletableDeferred<Unit>()
            server.engine.afterH3AcceptForTest = {
                held.complete(Unit)
                gate.await()
            }
            val ep = Http3Endpoint.bind(InetSocketAddress("127.0.0.1", 0))
            try {
                val c = ep.connect(InetSocketAddress("127.0.0.1", port), ServerFixtures.clientTls(alpn = listOf("h3")))
                withTimeout(5.seconds) { held.await() } // accepted by QUIC, not yet served by the engine
                coroutineScope {
                    val t0 = TimeSource.Monotonic.markNow()
                    val stop = async(Dispatchers.Default) { server.stop(20_000, 30_000) }
                    eventually { server.engine.h3ListenersForProbe.all { it.stopping } }
                    gate.complete(Unit)
                    withTimeout(5.seconds) { c.goAwayReceived.first { it != null } }
                    withTimeout(10.seconds) { stop.await() }
                    assertTrue(t0.elapsedNow() < 10.seconds, "the stop ended once the connection was idle: ${t0.elapsedNow()}")
                    val app = c.quic.closed.await() as QuicException.ConnectionLost.ApplicationClosed
                    assertEquals(io.kuicksilver.http3.Http3ErrorCode.NO_ERROR, app.code, "$app")
                }
            } finally {
                gate.complete(Unit)
                ep.close()
                runCatching { server.stop(100, 500) }
            }
        }

    private class Recorder : KuicksilverServerEventListener() {
        val lines = Lines()

        override fun connectionOpened(
            protocol: HttpProtocolVersion,
            remote: InetSocketAddress?,
        ) {
            lines += "opened $protocol ${remote != null}"
        }

        override fun connectionClosed(
            protocol: HttpProtocolVersion,
            remote: InetSocketAddress?,
        ) {
            lines += "closed $protocol"
        }

        override fun requestStarted(
            protocol: HttpProtocolVersion,
            call: ApplicationCall,
        ) {
            lines += "started $protocol ${call.request.local.uri}"
        }

        override fun requestEnded(
            protocol: HttpProtocolVersion,
            call: ApplicationCall,
            cause: Throwable?,
        ) {
            lines += "ended $protocol ${call.response.status()?.value} ${cause == null}"
        }
    }

    @Test fun theEventListenerHearsHttp1AndHttp3() =
        h3ServerTest {
            val events = Recorder()
            val (server, port) = tlsServer({ eventListener = events }) { routing { get("/") { call.respondText("ok") } } }
            try {
                val raw = rawHttp(port, "GET /?h1 HTTP/1.1\r\nHost: server.test\r\nConnection: close\r\n\r\n")
                assertTrue(raw.startsWith("HTTP/1.1 200"), raw)
                val ep = Http3Endpoint.bind(InetSocketAddress("127.0.0.1", 0))
                try {
                    val c = ep.connect(InetSocketAddress("127.0.0.1", port), ServerFixtures.clientTls(alpn = listOf("h3")))
                    val r = c.request(get("/?h3"))
                    assertEquals("ok", r.body.readFullBody().decodeToString())
                    c.close()
                } finally {
                    ep.close()
                }
                eventually { events.lines.all.size >= 8 }
                val e = events.lines.all
                assertEquals(
                    listOf("opened HTTP/1.1 true", "started HTTP/1.1 /?h1", "ended HTTP/1.1 200 true", "closed HTTP/1.1"),
                    e.filter { "HTTP/1.1" in it },
                )
                assertEquals(
                    listOf("opened HTTP/3.0 true", "started HTTP/3.0 /?h3", "ended HTTP/3.0 200 true", "closed HTTP/3.0"),
                    e.filter { "HTTP/3.0" in it },
                )
            } finally {
                server.stop(100, 500)
            }
        }

    @Test fun anEventListenerThrowingCancellationNeverStopsServing() =
        h3ServerTest {
            // not suspending callbacks: a CancellationException out of one is the listener's bug; HTTP/3 accepting goes on
            val throwing =
                object : KuicksilverServerEventListener() {
                    private fun bug(): Nothing = throw kotlinx.coroutines.CancellationException("listener bug")

                    override fun connectionOpened(
                        protocol: HttpProtocolVersion,
                        remote: InetSocketAddress?,
                    ): Unit = bug()

                    override fun connectionClosed(
                        protocol: HttpProtocolVersion,
                        remote: InetSocketAddress?,
                    ): Unit = bug()

                    override fun requestStarted(
                        protocol: HttpProtocolVersion,
                        call: ApplicationCall,
                    ): Unit = bug()

                    override fun requestEnded(
                        protocol: HttpProtocolVersion,
                        call: ApplicationCall,
                        cause: Throwable?,
                    ): Unit = bug()
                }
            val (server, port) = tlsServer({ eventListener = throwing }) { routing { get("/") { call.respondText("ok") } } }
            try {
                repeat(2) {
                    val raw = rawHttp(port, "GET / HTTP/1.1\r\nHost: server.test\r\nConnection: close\r\n\r\n")
                    assertTrue(raw.startsWith("HTTP/1.1 200"), raw)
                }
                repeat(2) {
                    val ep = Http3Endpoint.bind(InetSocketAddress("127.0.0.1", 0))
                    try {
                        withTimeout(10.seconds) {
                            val c = ep.connect(InetSocketAddress("127.0.0.1", port), ServerFixtures.clientTls(alpn = listOf("h3")))
                            assertEquals(
                                "ok",
                                c
                                    .request(get())
                                    .body
                                    .readFullBody()
                                    .decodeToString(),
                            )
                            c.close()
                        }
                    } finally {
                        ep.close()
                    }
                }
            } finally {
                server.stop(100, 500)
            }
        }

    @Test fun loggerQlogAndConnectionListenerReachTheHttp3Endpoint() =
        h3ServerTest {
            val lines = Lines()
            val logger =
                object : KuicksilverLogger {
                    override fun isEnabled(level: LogLevel) = true

                    override fun log(
                        level: LogLevel,
                        message: String,
                        cause: Throwable?,
                    ) {
                        lines += message
                    }
                }
            val traces = Lines()
            val qlog =
                object : QlogSink {
                    override fun open(
                        odcidHex: String,
                        role: TlsRole,
                    ): QlogTrace? {
                        traces += "$odcidHex $role"
                        return null
                    }
                }
            val opened = Lines()
            val listener =
                object : ConnectionListener {
                    override fun onOpened(connection: ConnectionInfo) {
                        opened += connection.id
                    }
                }
            val (server, port) =
                tlsServer({
                    this.logger = logger
                    this.qlog = qlog
                    connectionListener = listener
                }) { routing { get("/") { call.respondText("ok") } } }
            try {
                val ep = Http3Endpoint.bind(InetSocketAddress("127.0.0.1", 0))
                try {
                    val c = ep.connect(InetSocketAddress("127.0.0.1", port), ServerFixtures.clientTls(alpn = listOf("h3")))
                    assertEquals(
                        "ok",
                        c
                            .request(get())
                            .body
                            .readFullBody()
                            .decodeToString(),
                    )
                    c.close()
                } finally {
                    ep.close()
                }
                eventually { lines.all.any { "handshake complete" in it } }
                assertEquals(1, opened.all.size)
                assertEquals(listOf("${opened.all[0]} Server"), traces.all)
            } finally {
                server.stop(100, 500)
            }
        }
}
