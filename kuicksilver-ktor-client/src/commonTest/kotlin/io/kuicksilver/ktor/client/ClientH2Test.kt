// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(InternalKuicksilverApi::class, ExperimentalKuicksilverApi::class)

package io.kuicksilver.ktor.client

import io.ktor.client.plugins.HttpTimeout
import io.ktor.client.plugins.websocket.WebSockets
import io.ktor.client.plugins.websocket.webSocket
import io.ktor.client.request.HttpRequestData
import io.ktor.client.request.get
import io.ktor.client.request.post
import io.ktor.client.request.prepareGet
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsChannel
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpProtocolVersion
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.readAvailable
import io.ktor.utils.io.readBuffer
import io.ktor.utils.io.readByteArray
import io.ktor.utils.io.writeFully
import io.ktor.utils.io.writeStringUtf8
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.annotations.InternalKuicksilverApi
import io.kuicksilver.http2.Http2ErrorCode
import io.kuicksilver.http2.Http2Settings
import io.kuicksilver.http2.runtime.Http2Exception
import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeout
import kotlinx.io.readByteArray
import kotlin.concurrent.atomics.AtomicInt
import kotlin.concurrent.atomics.ExperimentalAtomicApi
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

/**
 * HTTP/2 on the TCP path (RFC 9113; docs/guide/ktor.md, "HTTP/2"): ALPN `h2`, one multiplexed connection per route, the
 * protocol race's TCP side, repeats of requests the server did not process, HTTP_1_1_REQUIRED, deadlines. The server is
 * our HTTP/2 runtime over a TLS listener on loopback (tlsH2WithSilentUdp), answering as each test needs.
 */
@OptIn(ExperimentalAtomicApi::class)
class ClientH2Test {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private suspend fun ok(
        r: io.kuicksilver.http2.runtime.H2ServerStream,
        text: String = "h2",
    ) {
        r.respond(200, listOf("content-type" to "text/plain"))
        r.sendBody(ByteReadChannel(text.encodeToByteArray()))
    }

    private fun engine(c: io.ktor.client.HttpClient) = c.engine as KuicksilverEngine

    @Test fun negotiatesH2AndMultiplexes() =
        clientTest {
            tlsH2WithSilentUdp(onRequest = { _, r -> ok(r, r.path) }) { port, log ->
                testClient().use { c ->
                    val responses = coroutineScope { (1..50).map { i -> async { c.get("https://127.0.0.1:$port/$i") } }.awaitAll() }
                    for ((i, r) in responses.withIndex()) {
                        assertEquals(HttpProtocolVersion.HTTP_2_0, r.version)
                        assertEquals("/${i + 1}", r.bodyAsText())
                        assertEquals(HttpProtocolVersion.HTTP_2_0, r.kuicksilverDiagnostics!!.protocol)
                    }
                    // ten requests went out before the first connection existed; those that opened a TCP connection of their
                    // own closed it and used the first (or a second, when the first was full): at most one stays
                    assertEquals(1, engine(c).h1.h2.connectionCount)
                    val accepted = log.acceptCount
                    repeat(accepted - 1) { withTimeout(10.seconds) { log.ended.receive() } }
                    assertTrue(log.protocols.all { it == "h2" })
                }
            }
        }

    /**
     * RFC 9113 section 9.1: clients SHOULD NOT open more than one HTTP/2 connection to an origin. Ten requests that start
     * together toward a new origin open one TLS connection: while one connect is in flight the others wait for it (Go's
     * dialCall), and use it once it turned out to be HTTP/2.
     */
    @Test fun concurrentFirstRequestsOpenOneConnection() =
        clientTest {
            tlsH2WithSilentUdp(onRequest = { _, r -> ok(r) }) { port, log ->
                testClient().use { c ->
                    val all = coroutineScope { (1..10).map { async { c.get("https://127.0.0.1:$port/").bodyAsText() } }.awaitAll() }
                    assertEquals(List(10) { "h2" }, all)
                    assertEquals(1, log.acceptCount)
                }
            }
        }

    /**
     * The gap between "no HTTP/2 connection to reuse" and "may I dial": a connection that another request registered in
     * that gap must be used, not a second one dialled. The hook holds the second request there until the first call is
     * done (its connection is in the pool by then).
     */
    @Test fun aConnectionRegisteredWhileWaitingForAPermitIsUsed() =
        clientTest {
            tlsH2WithSilentUdp(onRequest = { _, r -> ok(r) }) { port, log ->
                testClient().use { c ->
                    val firstDone = CompletableDeferred<Unit>()
                    val arrivals = AtomicInt(0)
                    engine(c).h1.beforeDialForTest = { if (arrivals.addAndFetch(1) > 1) firstDone.await() }
                    coroutineScope {
                        val a = async { c.get("https://127.0.0.1:$port/").bodyAsText().also { firstDone.complete(Unit) } }
                        val b = async { c.get("https://127.0.0.1:$port/").bodyAsText().also { firstDone.complete(Unit) } }
                        assertEquals(listOf("h2", "h2"), listOf(a.await(), b.await()))
                    }
                    assertEquals(1, log.acceptCount)
                }
            }
        }

    /** The wait is for HTTP/2 only: once the first connect turned out HTTP/1.1, the others connect in parallel as before. */
    @Test fun concurrentFirstRequestsToAnH1ServerStillComplete() =
        clientTest {
            tlsH1WithSilentUdp(silentUdp = false, handler = { _, input, output ->
                while (true) {
                    if (readRequest(input).isEmpty()) break
                    output.writeStringUtf8("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nh1")
                }
            }) { port ->
                testClient().use { c ->
                    val all = coroutineScope { (1..10).map { async { c.get("https://127.0.0.1:$port/").bodyAsText() } }.awaitAll() }
                    assertEquals(List(10) { "h1" }, all)
                }
            }
        }

    @Test fun sequentialRequestsReuseOneConnection() =
        clientTest {
            tlsH2WithSilentUdp(onRequest = { _, r -> ok(r) }) { port, log ->
                val listener = EventRecorder()
                testClient(engine = { eventListener = listener }).use { c ->
                    repeat(3) { assertEquals("h2", c.get("https://127.0.0.1:$port/").bodyAsText()) }
                    assertEquals(1, log.acceptCount)
                    assertEquals(listOf(false, true, true), listener.acquired.map { it.second })
                    assertTrue(listener.acquired.all { it.first == HttpProtocolVersion.HTTP_2_0 })
                    // protocolSelected follows the connection and names its real protocol, before connectionAcquired
                    assertEquals(HttpProtocolVersion.HTTP_2_0, listener.selected.first())
                    assertTrue(listener.order.indexOf("protocolSelected") < listener.order.indexOf("connectionAcquired"))
                }
            }
        }

    @Test fun serverWithoutH2StaysOnH1() =
        clientTest {
            tlsH1WithSilentUdp(silentUdp = false, handler = { _, input, output ->
                readRequest(input)
                output.writeStringUtf8("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nh1")
                runCatching { input.readBuffer() } // the client closes first: closing here could cut the response short
            }) { port ->
                testClient().use { c ->
                    val r = c.get("https://127.0.0.1:$port/")
                    assertEquals(HttpProtocolVersion.HTTP_1_1, r.version)
                    assertEquals("h1", r.bodyAsText())
                }
            }
        }

    /** `http2 { enabled = false }` offers only `http/1.1`: a server that prefers h2 picks HTTP/1.1, as in 0.2. */
    @Test fun disabledOffersOnlyHttp11() =
        clientTest {
            tlsH2WithSilentUdp(onRequest = { _, r -> ok(r) }, h1 = { _, input, output ->
                readRequest(input)
                output.writeStringUtf8("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nh1")
                runCatching { input.readBuffer() } // the client closes first: closing here could cut the response short
            }) { port, log ->
                testClient(engine = { http2 { enabled = false } }).use { c ->
                    assertEquals(HttpProtocolVersion.HTTP_1_1, c.get("https://127.0.0.1:$port/").version)
                    assertEquals(listOf<String?>("http/1.1"), log.protocols)
                }
            }
        }

    /**
     * A client that allows TLS 1.2 offers h2 too (RFC 9113 section 9.2): a TLS 1.2 renegotiation, which section 9.2.1 makes a
     * connection error, is reported by the TLS layer and fails the connection with PROTOCOL_ERROR (H2InteropTest, against a
     * TLS 1.2 server). Here the server has TLS 1.3 and picks h2.
     */
    @Test fun tls12AllowedStillOffersH2() =
        clientTest {
            tlsH2WithSilentUdp(onRequest = { _, r -> ok(r) }) { port, log ->
                testClient(engine = { tls = { versions = io.kuicksilver.tls.TlsVersions.Tls12And13 } }).use { c ->
                    assertEquals(HttpProtocolVersion.HTTP_2_0, c.get("https://127.0.0.1:$port/").version)
                    assertEquals(listOf<String?>("h2"), log.protocols)
                }
            }
        }

    /**
     * A connection reused after a quiet spell is checked first (Chromium's PING on a session "at risk of loss"): a PING
     * that is not answered within its bound retires the connection, and the request, which never went out on it, takes a
     * new connection instead of hanging on a dead one.
     */
    @Test fun negative_silentIdleConnectionIsRetiredByAHealthPing() =
        clientTest {
            tlsWithSilentUdp(listOf("h2"), silentUdp = false, handler = { index, _, input, output ->
                rawH2Server(input, output, answerOnce = index == 0)
            }) { port ->
                testClient(engine = { connectTimeout = 2.seconds }).use { c ->
                    val e = engine(c)
                    e.h1.h2HealthAfterIdleMillis = 0 // every reuse is checked
                    assertEquals(200, c.get("https://127.0.0.1:$port/").status.value)
                    // connection 0 now answers nothing: the health PING fails, connection 1 serves the request
                    assertEquals(200, c.get("https://127.0.0.1:$port/").status.value)
                }
            }
        }

    /**
     * A failed health PING on a connection that still carries a call (a long poll) does not cut that call: the connection
     * gets GOAWAY (no new streams) and the new request goes to a new connection, while the running stream finishes.
     */
    @Test fun failedHealthPingSparesStreamsInFlight() =
        clientTest {
            val finishFirst = CompletableDeferred<Unit>()
            tlsWithSilentUdp(listOf("h2"), silentUdp = false, handler = { index, _, input, output ->
                rawH2Server(input, output, answerOnce = index == 0, finishFirst = finishFirst.takeIf { index == 0 })
            }) { port ->
                testClient(engine = { connectTimeout = 2.seconds }).use { c ->
                    engine(c).h1.h2HealthAfterIdleMillis = 0
                    c.prepareGet("https://127.0.0.1:$port/poll").execute { poll ->
                        assertEquals(200, poll.status.value)
                        // connection 0 answers no PING now: the next request goes elsewhere...
                        assertEquals(200, c.get("https://127.0.0.1:$port/").status.value)
                        // ...and the long poll on connection 0 still ends normally
                        finishFirst.complete(Unit)
                        assertEquals("done", poll.bodyAsText())
                    }
                }
            }
        }

    /**
     * A burst of requests onto a connection that is due for a health check shares one PING: forty checks of their own
     * overflowed the core's sixteen outstanding PINGs, the dropped ones never got an answer, and a healthy connection was
     * aborted under the burst.
     */
    @Test fun healthCheckBurstSharesOnePing() =
        clientTest {
            tlsH2WithSilentUdp(onRequest = { _, r -> ok(r) }) { port, log ->
                testClient(engine = { connectTimeout = 3.seconds }).use { c ->
                    engine(c).h1.h2HealthAfterIdleMillis = 0 // every reuse is checked
                    assertEquals("h2", c.get("https://127.0.0.1:$port/").bodyAsText())
                    val all = coroutineScope { (1..40).map { async { c.get("https://127.0.0.1:$port/").bodyAsText() } }.awaitAll() }
                    assertEquals(List(40) { "h2" }, all)
                    assertEquals(1, log.acceptCount, "the healthy connection served the burst")
                }
            }
        }

    /** The kill switch for HTTP/3 does not turn HTTP/2 off. */
    @Test fun http3SwitchedOffStillUsesH2() =
        clientTest {
            tlsH2WithSilentUdp(onRequest = { _, r -> ok(r) }) { port, _ ->
                testClient(Http3DiscoveryMode.Preferred, engine = { http3 { http3Allowed = { false } } }).use { c ->
                    val r = c.get("https://127.0.0.1:$port/")
                    assertEquals(HttpProtocolVersion.HTTP_2_0, r.version)
                    assertEquals(FallbackReason.Http3Disabled, r.kuicksilverDiagnostics!!.fallback)
                }
            }
        }

    @Test fun raceTcpSideIsH2() =
        clientTest {
            tlsH2WithSilentUdp(silentUdp = true, onRequest = { _, r -> ok(r) }) { port, _ ->
                val listener = EventRecorder()
                testClient(Http3DiscoveryMode.Preferred, engine = {
                    eventListener = listener
                    http3 { hardDelay = 10.milliseconds }
                })
                    .use { c ->
                        val r = c.get("https://127.0.0.1:$port/")
                        assertEquals(HttpProtocolVersion.HTTP_2_0, r.version)
                        assertEquals(listOf(HttpProtocolVersion.HTTP_2_0), listener.raceWinners)
                        val d = r.kuicksilverDiagnostics!!
                        assertEquals(HttpProtocolVersion.HTTP_2_0, d.protocol)
                        assertEquals(FallbackReason.H3NotReady, d.fallback)
                        assertTrue(d.raced)
                    }
            }
        }

    @Test fun secondConnectionAtMaxConcurrentStreams() =
        clientTest {
            val arrived = kotlinx.coroutines.channels.Channel<Unit>(kotlinx.coroutines.channels.Channel.UNLIMITED)
            val gate = CompletableDeferred<Unit>()
            tlsH2WithSilentUdp(settings = Http2Settings(maxConcurrentStreams = 2), onRequest = { _, r ->
                arrived.send(Unit)
                gate.await()
                ok(r)
            }) { port, log ->
                testClient().use { c ->
                    coroutineScope {
                        val calls = (1..5).map { async { c.get("https://127.0.0.1:$port/").bodyAsText() } }
                        repeat(5) { withTimeout(10.seconds) { arrived.receive() } }
                        // two streams each: three connections for five requests, never more
                        assertEquals(3, engine(c).h1.h2.connectionCount)
                        assertTrue(log.acceptCount <= 5)
                        gate.complete(Unit)
                        assertEquals(List(5) { "h2" }, calls.awaitAll())
                    }
                }
            }
        }

    @Test fun waitsForAFreeStreamAtTheRouteLimit() =
        clientTest {
            val arrived = kotlinx.coroutines.channels.Channel<Unit>(kotlinx.coroutines.channels.Channel.UNLIMITED)
            val gate = CompletableDeferred<Unit>()
            tlsH2WithSilentUdp(settings = Http2Settings(maxConcurrentStreams = 1), onRequest = { _, r ->
                arrived.send(Unit)
                gate.await()
                ok(r)
            }) { port, log ->
                testClient(engine = { maxConnectionsPerRoute = 1 }).use { c ->
                    coroutineScope {
                        val first = async { c.get("https://127.0.0.1:$port/").bodyAsText() }
                        withTimeout(10.seconds) { arrived.receive() }
                        // the only connection is full and the route has no room for another: the second waits for the stream
                        val second = async { c.get("https://127.0.0.1:$port/").bodyAsText() }
                        gate.complete(Unit)
                        assertEquals("h2", first.await())
                        assertEquals("h2", second.await())
                        assertEquals(1, log.acceptCount)
                    }
                }
            }
        }

    @Test fun refusedStreamRetried() =
        clientTest {
            val n = AtomicInt(0)
            tlsH2WithSilentUdp(onRequest = { _, r ->
                if (n.addAndFetch(1) == 1) r.reset(Http2ErrorCode.REFUSED_STREAM) else ok(r)
            }) { port, _ ->
                val listener = EventRecorder()
                testClient(engine = { eventListener = listener }).use { c ->
                    val r = c.post("https://127.0.0.1:$port/") { setBody("payload") }
                    assertEquals("h2", r.bodyAsText())
                    // RFC 9113 section 8.7: REFUSED_STREAM means nothing was processed, so even a POST goes again
                    assertEquals(2, r.kuicksilverDiagnostics!!.attempts)
                    assertEquals(1, listener.retries.size)
                }
            }
        }

    /**
     * A repeat must not wait for its own first attempt: the refused stream is released before the request goes again, so
     * with one stream and one connection allowed the repeat takes that stream (not a connect timeout).
     */
    @Test fun refusedStreamRepeatAtTheRouteLimit() =
        clientTest {
            val n = AtomicInt(0)
            tlsH2WithSilentUdp(settings = Http2Settings(maxConcurrentStreams = 1), onRequest = { _, r ->
                if (n.addAndFetch(1) == 1) r.reset(Http2ErrorCode.REFUSED_STREAM) else ok(r)
            }) { port, log ->
                testClient(engine = {
                    maxConnectionsPerRoute = 1
                    connectTimeout = 3.seconds
                }).use { c ->
                    assertEquals("h2", c.post("https://127.0.0.1:$port/") { setBody("payload") }.bodyAsText())
                    assertEquals(1, log.acceptCount)
                }
            }
        }

    /**
     * A GOAWAY at the route limit: the connection's refused stream is released at once, so the drained connection closes,
     * gives its slot back, and the repeat opens the route's one new connection.
     */
    @Test fun goAwayRepeatAtTheRouteLimit() =
        clientTest {
            val conns =
                kotlinx.coroutines.channels.Channel<io.kuicksilver.http2.runtime.H2ServerConnection>(
                    kotlinx.coroutines.channels.Channel.UNLIMITED,
                )
            tlsH2WithSilentUdp(onConnection = { _, c -> conns.send(c) }, onRequest = { index, r ->
                if (index == 0) {
                    conns.receive().goAway(Http2ErrorCode.NO_ERROR)
                    r.reset(Http2ErrorCode.REFUSED_STREAM)
                } else {
                    ok(r)
                }
            }) { port, log ->
                testClient(engine = {
                    maxConnectionsPerRoute = 1
                    connectTimeout = 3.seconds
                }).use { c ->
                    assertEquals("h2", c.post("https://127.0.0.1:$port/") { setBody("payload") }.bodyAsText())
                    assertEquals(2, log.acceptCount)
                }
            }
        }

    @Test fun nonIdempotentNotRetriedWhenProcessed() =
        clientTest {
            val n = AtomicInt(0)
            tlsH2WithSilentUdp(onRequest = { _, r ->
                n.addAndFetch(1)
                r.reset(Http2ErrorCode.INTERNAL_ERROR)
            }) { port, _ ->
                testClient().use { c ->
                    val e = assertFailsWith<Http2Exception.StreamReset> { c.post("https://127.0.0.1:$port/") { setBody("x") } }
                    assertEquals(Http2ErrorCode.INTERNAL_ERROR, e.code)
                    assertEquals(1, n.load())
                }
            }
        }

    @Test fun goAwayMovesNewRequestsToANewConnection() =
        clientTest {
            val conns =
                kotlinx.coroutines.channels.Channel<io.kuicksilver.http2.runtime.H2ServerConnection>(
                    kotlinx.coroutines.channels.Channel.UNLIMITED,
                )
            tlsH2WithSilentUdp(onConnection = { _, conn -> conns.send(conn) }, onRequest = { _, r -> ok(r) }) { port, log ->
                testClient().use { c ->
                    assertEquals("h2", c.get("https://127.0.0.1:$port/").bodyAsText())
                    // the server goes away (RFC 9113 section 6.8): the client closes the drained connection...
                    conns.receive().shutdown()
                    assertEquals(0, withTimeout(10.seconds) { log.ended.receive() })
                    // ...and the next request opens a new one
                    assertEquals("h2", c.get("https://127.0.0.1:$port/").bodyAsText())
                    assertEquals(2, log.acceptCount)
                }
            }
        }

    @Test fun negative_http11RequiredFallsBackAndMarks() =
        clientTest {
            tlsH2WithSilentUdp(onRequest = { _, r -> r.reset(Http2ErrorCode.HTTP_1_1_REQUIRED) }, h1 = { _, input, output ->
                while (true) {
                    if (readRequest(input).isEmpty()) break
                    output.writeStringUtf8("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nh1")
                }
            }) { port, log ->
                testClient().use { c ->
                    val r = c.get("https://127.0.0.1:$port/")
                    assertEquals(HttpProtocolVersion.HTTP_1_1, r.version)
                    assertEquals("h1", r.bodyAsText())
                    val d = r.kuicksilverDiagnostics!!
                    assertEquals(FallbackReason.H2Refused, d.fallback)
                    assertEquals(2, d.attempts)
                    // the route is marked: the next request offers only http/1.1 and goes there at once
                    val r2 = c.get("https://127.0.0.1:$port/")
                    assertEquals(HttpProtocolVersion.HTTP_1_1, r2.version)
                    assertEquals(FallbackReason.H2Refused, r2.kuicksilverDiagnostics!!.fallback)
                    assertEquals(1, r2.kuicksilverDiagnostics!!.attempts)
                    assertEquals(listOf<String?>("h2", "http/1.1"), log.protocols.take(2))
                }
            }
        }

    /**
     * RST_STREAM(HTTP_1_1_REQUIRED) on a POST's own stream: the server may have processed it, so it is not sent again over
     * HTTP/1.1 (RFC 9110 section 9.2.2; owner decision). The call fails with an error that says so, the route is marked,
     * and the next POST goes straight over HTTP/1.1 and succeeds.
     */
    @Test fun negative_http11RequiredOnTheStreamDoesNotRepeatAPost() =
        clientTest {
            val h2Requests = AtomicInt(0)
            val h1Requests = AtomicInt(0)
            tlsH2WithSilentUdp(onRequest = { _, r ->
                h2Requests.addAndFetch(1)
                r.reset(Http2ErrorCode.HTTP_1_1_REQUIRED)
            }, h1 = { _, input, output ->
                while (true) {
                    if (readRequest(input).isEmpty()) break
                    h1Requests.addAndFetch(1)
                    output.writeStringUtf8("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nh1")
                }
            }) { port, _ ->
                testClient().use { c ->
                    val e = assertFailsWith<Http11RequiredException> { c.post("https://127.0.0.1:$port/") { setBody("once") } }
                    assertTrue("HTTP/1.1" in e.message!!)
                    assertEquals(1, h2Requests.load())
                    assertEquals(0, h1Requests.load(), "the POST must not be repeated over HTTP/1.1: $e")
                    val r = c.post("https://127.0.0.1:$port/") { setBody("again") }
                    assertEquals(HttpProtocolVersion.HTTP_1_1, r.version)
                    assertEquals("h1", r.bodyAsText())
                    assertEquals(1, h2Requests.load())
                }
            }
        }

    /** HTTP_1_1_REQUIRED on the whole connection (its GOAWAY) does the same as on the stream (RFC 9113 section 7). */
    @Test fun http11RequiredOnTheConnection() =
        clientTest {
            val conns =
                kotlinx.coroutines.channels.Channel<io.kuicksilver.http2.runtime.H2ServerConnection>(
                    kotlinx.coroutines.channels.Channel.UNLIMITED,
                )
            tlsH2WithSilentUdp(onConnection = { _, c -> conns.send(c) }, onRequest = { _, _ ->
                conns.receive().goAway(Http2ErrorCode.HTTP_1_1_REQUIRED)
                kotlinx.coroutines.awaitCancellation()
            }, h1 = { _, input, output ->
                while (true) {
                    if (readRequest(input).isEmpty()) break
                    output.writeStringUtf8("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nh1")
                }
            }) { port, _ ->
                testClient().use { c ->
                    val r = c.get("https://127.0.0.1:$port/")
                    assertEquals(HttpProtocolVersion.HTTP_1_1, r.version)
                    assertEquals(FallbackReason.H2Refused, r.kuicksilverDiagnostics!!.fallback)
                }
            }
        }

    /**
     * A GOAWAY with HTTP_1_1_REQUIRED whose last stream is this POST's: the server may have processed it (RFC 9113 section
     * 8.7, RFC 9110 section 9.2.2), so it is not sent again; the call fails and the route is marked (the next request goes
     * over HTTP/1.1).
     */
    @Test fun negative_http11RequiredGoAwayDoesNotRepeatAProcessedPost() =
        clientTest {
            val h2Posts = AtomicInt(0)
            val h1Requests = AtomicInt(0)
            val conns =
                kotlinx.coroutines.channels.Channel<io.kuicksilver.http2.runtime.H2ServerConnection>(
                    kotlinx.coroutines.channels.Channel.UNLIMITED,
                )
            tlsH2WithSilentUdp(onConnection = { _, c -> conns.send(c) }, onRequest = { _, r ->
                h2Posts.addAndFetch(1) // processed
                conns.receive().goAway(Http2ErrorCode.HTTP_1_1_REQUIRED)
                kotlinx.coroutines.awaitCancellation()
            }, h1 = { _, input, output ->
                while (true) {
                    if (readRequest(input).isEmpty()) break
                    h1Requests.addAndFetch(1)
                    output.writeStringUtf8("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nh1")
                }
            }) { port, _ ->
                testClient().use { c ->
                    // the same typed error as on the stream (owner decision): the route is HTTP/1.1 now, the call may be repeated
                    assertFailsWith<Http11RequiredException> { c.post("https://127.0.0.1:$port/") { setBody("once") } }
                    assertEquals(1, h2Posts.load())
                    assertEquals(0, h1Requests.load(), "the POST must not be repeated over HTTP/1.1")
                    val r = c.get("https://127.0.0.1:$port/")
                    assertEquals(HttpProtocolVersion.HTTP_1_1, r.version)
                    assertEquals(FallbackReason.H2Refused, r.kuicksilverDiagnostics!!.fallback)
                }
            }
        }

    /** A GOAWAY with HTTP_1_1_REQUIRED before any request: the connection is unusable at once, and HTTP/1.1 serves the call. */
    @Test fun http11RequiredBeforeTheFirstRequest() =
        clientTest {
            tlsH2WithSilentUdp(onConnection = {
                _,
                c,
                ->
                c.goAway(Http2ErrorCode.HTTP_1_1_REQUIRED)
            }, onRequest = { _, r -> ok(r) }, h1 = { _, input, output ->
                while (true) {
                    if (readRequest(input).isEmpty()) break
                    output.writeStringUtf8("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nh1")
                }
            }) { port, _ ->
                testClient().use { c ->
                    val r = c.get("https://127.0.0.1:$port/")
                    assertEquals(HttpProtocolVersion.HTTP_1_1, r.version)
                    assertEquals("h1", r.bodyAsText())
                    assertEquals(FallbackReason.H2Refused, r.kuicksilverDiagnostics!!.fallback)
                }
            }
        }

    /**
     * A server that sends GOAWAY (last stream 0) on every new connection: the call fails after at most three connections
     * (one, when the GOAWAY arrives with the server's SETTINGS; else the two repeats of a request not processed), never a
     * connection storm within the connect timeout.
     */
    @Test fun negative_newConnectionThatTakesNoRequestFailsTheCall() =
        clientTest {
            tlsH2WithSilentUdp(onConnection = { _, c -> c.goAway(Http2ErrorCode.NO_ERROR) }, onRequest = { _, r -> ok(r) }) { port, log ->
                testClient().use { c ->
                    assertFailsWith<kotlinx.io.IOException> { c.get("https://127.0.0.1:$port/") }
                    assertTrue(log.acceptCount in 1..3, "connections: ${log.acceptCount}")
                }
            }
        }

    @Test fun negative_noServerSettingsWithinConnectTimeoutFails() =
        clientTest {
            // the server negotiates h2 and then says nothing: its preface must arrive within the connect timeout (RFC 9113
            // section 3.4)
            tlsWithSilentUdp(listOf("h2"), silentUdp = false, handler = { _, _, input, _ ->
                runCatching { input.readBuffer() }
            }) { port ->
                testClient(engine = { connectTimeout = 500.milliseconds }).use { c ->
                    assertFailsWith<io.ktor.client.network.sockets.ConnectTimeoutException> { c.get("https://127.0.0.1:$port/") }
                    assertEquals(0, engine(c).h1.pool.liveCount)
                }
            }
        }

    /**
     * The wait for the server's SETTINGS gets what the connect timeout left after TCP and TLS, not the whole timeout again:
     * a server whose TLS handshake takes 3 s (it accepts late) and that then never sends its SETTINGS fails a call with a
     * 4 s connect timeout at about 4 s (bound: 5.5 s), not at about 7 s.
     */
    @Test fun negative_settingsWaitGetsWhatTheConnectTimeoutLeft() =
        clientTest {
            val accept = CompletableDeferred<Unit>()
            tlsWithSilentUdp(listOf("h2"), silentUdp = false, acceptAfter = accept, handler = { _, _, input, _ ->
                runCatching { input.readBuffer() }
            }) { port ->
                testClient(engine = { connectTimeout = 4.seconds }).use { c ->
                    val started =
                        kotlin.time.TimeSource.Monotonic
                            .markNow()
                    kotlinx.coroutines.coroutineScope {
                        // the slow TLS step: the server takes the connection 3 s late (a stand-in for a slow handshake)
                        launch {
                            kotlinx.coroutines.delay(3_000)
                            accept.complete(Unit)
                        }
                        assertFailsWith<io.ktor.client.network.sockets.ConnectTimeoutException> { c.get("https://127.0.0.1:$port/") }
                    }
                    val took = started.elapsedNow()
                    assertTrue(took < 5_500.milliseconds, "failed after $took: the SETTINGS wait got the whole connect timeout again")
                }
            }
        }

    /**
     * The request's HEADERS went out before the server's preface, which never came: a request whose content had started
     * does not fail as a connect timeout (`HttpRequestRetry` takes that for a request that never left and may send a POST
     * again), but with the connection's end (SETTINGS_TIMEOUT); one without content does (the existing test above).
     */
    @Test fun negative_noServerSettingsAfterTheBodyStartedIsNotAConnectTimeout() =
        clientTest {
            tlsWithSilentUdp(listOf("h2"), silentUdp = false, handler = { _, _, input, _ ->
                runCatching { input.readBuffer() }
            }) { port ->
                testClient(engine = { connectTimeout = 500.milliseconds }).use { c ->
                    val e = assertFailsWith<Http2Exception.ConnectionClosed> { c.post("https://127.0.0.1:$port/") { setBody("payload") } }
                    assertEquals(Http2ErrorCode.SETTINGS_TIMEOUT, e.code)
                }
            }
        }

    /**
     * A server that sends its SETTINGS only after the first request arrived, with SETTINGS_MAX_CONCURRENT_STREAMS = 2, and
     * resets with PROTOCOL_ERROR any stream above it (RFC 9113 section 5.1.2 lets it): ten calls started together all succeed
     * on the route's one connection. Before the SETTINGS only the first request goes out; the others wait for them instead of opening
     * streams under the initial "unlimited" or connections of their own.
     */
    @Test fun burstBeforeTheServerSettingsStaysWithinTheirLimit() =
        clientTest {
            val calls = 10
            val violations = AtomicInt(0)
            val connections = AtomicInt(0)
            tlsWithSilentUdp(listOf("h2"), silentUdp = false, handler = { _, _, input, output ->
                connections.addAndFetch(1)
                strictH2Server(input, output, limit = 2, total = calls) { violations.addAndFetch(1) }
            }) { port ->
                // one connection per route, so that the server sees every request (a second connection would also be fine,
                // but its server could not tell the last request it gets)
                testClient(engine = { maxConnectionsPerRoute = 1 }).use { c ->
                    val bodies =
                        coroutineScope {
                            (1..calls)
                                .map { i ->
                                    async { c.get("https://127.0.0.1:$port/$i").bodyAsText() }
                                }.awaitAll()
                        }
                    assertEquals(List(calls) { "" }, bodies)
                    assertEquals(0, violations.load(), "streams above the server's limit")
                    assertEquals(1, connections.load(), "connections")
                }
            }
        }

    /**
     * A raw HTTP/2 server: no SETTINGS until the first HEADERS arrived, then SETTINGS_MAX_CONCURRENT_STREAMS = [limit]. It
     * answers (`:status 200`, END_STREAM) once [limit] streams are open, or all that are open once [total] requests came; a
     * HEADERS above the limit is reset with PROTOCOL_ERROR and reported to [onViolation], and so is a second request that
     * came before the client acknowledged the SETTINGS (sent before the client knew the limit).
     */
    private suspend fun strictH2Server(
        input: io.ktor.utils.io.ByteReadChannel,
        output: io.ktor.utils.io.ByteWriteChannel,
        limit: Int,
        total: Int,
        onViolation: () -> Unit,
    ) {
        fun frame(
            type: Int,
            flags: Int,
            stream: Int,
            payload: ByteArray = ByteArray(0),
        ): ByteArray =
            byteArrayOf(
                (payload.size shr 16).toByte(),
                (payload.size shr 8).toByte(),
                payload.size.toByte(),
                type.toByte(),
                flags.toByte(),
                (stream ushr 24).toByte(),
                (stream shr 16).toByte(),
                (stream shr 8).toByte(),
                stream.toByte(),
            ) + payload
        runCatching {
            input.readByteArray(24) // the client preface
            var settingsSent = false
            var ackOwed = false
            var acked = false // the client acknowledged our SETTINGS: it knows the limit from here on
            val open = ArrayList<Int>()
            var seen = 0
            while (true) {
                val head = input.readByteArray(9)
                val len = ((head[0].toInt() and 0xff) shl 16) or ((head[1].toInt() and 0xff) shl 8) or (head[2].toInt() and 0xff)
                val type = head[3].toInt() and 0xff
                val flags = head[4].toInt() and 0xff
                val stream =
                    ((head[5].toInt() and 0x7f) shl 24) or ((head[6].toInt() and 0xff) shl 16) or
                        ((head[7].toInt() and 0xff) shl 8) or (head[8].toInt() and 0xff)
                input.readByteArray(len)
                when {
                    type == 4 && flags and 1 == 0 -> {
                        if (settingsSent) output.writeFully(frame(4, 1, 0)) else ackOwed = true
                    }

                    type == 4 -> {
                        acked = true
                    }

                    type == 1 -> {
                        seen++
                        // a client writes our SETTINGS' acknowledgement before any field block it queues after them: a
                        // second request before it went out before the client knew the limit
                        if (!acked && seen > 1) onViolation()
                        if (!settingsSent) {
                            settingsSent = true
                            output.writeFully(frame(4, 0, 0, byteArrayOf(0, 3, 0, 0, 0, limit.toByte())))
                            if (ackOwed) output.writeFully(frame(4, 1, 0))
                        }
                        if (open.size >= limit) {
                            onViolation()
                            output.writeFully(frame(3, 0, stream, byteArrayOf(0, 0, 0, 1))) // RST_STREAM PROTOCOL_ERROR
                        } else {
                            open += stream
                        }
                        if (open.size == limit || seen == total) {
                            for (id in open) output.writeFully(frame(1, 0x5, id, byteArrayOf(0x88.toByte())))
                            open.clear()
                        }
                    }
                }
                output.flush()
            }
        }
    }

    @Test fun requestBodyRespectsPeerWindow() =
        clientTest {
            val size = 1 shl 20
            tlsH2WithSilentUdp(
                settings = Http2Settings(initialStreamWindow = 16_384, maxStreamWindow = 16_384, initialConnectionWindow = 65_535),
                onRequest = { _, r ->
                    val got = r.body.readBuffer().readByteArray()
                    ok(r, got.size.toString())
                },
            ) { port, _ ->
                testClient().use { c ->
                    val r = c.post("https://127.0.0.1:$port/") { setBody(ByteArray(size) { it.toByte() }) }
                    assertEquals(size.toString(), r.bodyAsText())
                }
            }
        }

    @Test fun largeResponseIsComplete() =
        clientTest {
            val size = 8 shl 20
            tlsH2WithSilentUdp(onRequest = { _, r ->
                r.respond(200, listOf("content-length" to size.toString()))
                r.sendBody(ByteReadChannel(ByteArray(size) { (it % 251).toByte() }))
            }) { port, _ ->
                testClient().use { c ->
                    val body =
                        c
                            .get("https://127.0.0.1:$port/")
                            .bodyAsChannel()
                            .readBuffer()
                            .readByteArray()
                    assertEquals(size, body.size)
                    assertContentEquals(ByteArray(size) { (it % 251).toByte() }, body)
                }
            }
        }

    @Test fun cancelSendsRstStreamCancel() =
        clientTest {
            val reset = CompletableDeferred<Http2ErrorCode>()
            tlsH2WithSilentUdp(onRequest = { _, r ->
                r.respond(200)
                val e = runCatching { r.sendBody(ByteReadChannel(ByteArray(64 shl 20))) }.exceptionOrNull()
                reset.complete((e as? Http2Exception.StreamReset)?.code ?: Http2ErrorCode.NO_ERROR)
            }) { port, _ ->
                testClient().use { c ->
                    c.prepareGet("https://127.0.0.1:$port/").execute { resp ->
                        val ch = resp.bodyAsChannel()
                        val buf = ByteArray(1024)
                        ch.readAvailable(buf, 0, buf.size)
                        // the application leaves the body: the call ends and the stream is reset (RFC 9113 section 8.1)
                    }
                    assertEquals(Http2ErrorCode.CANCEL, withTimeout(10.seconds) { reset.await() })
                }
            }
        }

    @Test fun webSocketGoesOverH1Only() =
        clientTest {
            tlsH2WithSilentUdp(onRequest = { _, r -> ok(r) }, h1 = { _, input, _ -> readRequest(input) }) { port, log ->
                testClient(block = { install(WebSockets) }).use { c ->
                    runCatching { c.webSocket("wss://127.0.0.1:$port/ws") {} }
                    // RFC 8441 is not supported: a WebSocket offers http/1.1 only, so this server's h2 preference is not used
                    assertEquals("http/1.1", withTimeout(10.seconds) { log.accepted.receive() })
                    assertEquals(listOf<String?>("http/1.1"), log.protocols)
                }
            }
        }

    /** A request whose body upgrades the connection (not a WebSocket) needs HTTP/1.1: it offers only http/1.1 (RFC 9113 section 8.6). */
    @Test fun protocolUpgradeBodyGoesOverH1Only() =
        clientTest {
            tlsH2WithSilentUdp(onRequest = { _, r -> ok(r) }, h1 = { _, input, _ -> readRequest(input) }) { port, log ->
                testClient().use { c ->
                    runCatching {
                        withTimeout(10.seconds) {
                            c.post("https://127.0.0.1:$port/upgrade") {
                                setBody(
                                    object : io.ktor.http.content.OutgoingContent.ProtocolUpgrade() {
                                        override suspend fun upgrade(
                                            input: io.ktor.utils.io.ByteReadChannel,
                                            output: io.ktor.utils.io.ByteWriteChannel,
                                            engineContext: kotlin.coroutines.CoroutineContext,
                                            userContext: kotlin.coroutines.CoroutineContext,
                                        ): kotlinx.coroutines.Job = kotlinx.coroutines.Job().also { it.complete() }
                                    },
                                )
                            }
                        }
                    }
                    // the server logs a connection when its TLS handshake is done: wait for that, not for the call's outcome
                    assertEquals("http/1.1", withTimeout(10.seconds) { log.accepted.receive() })
                    assertEquals(listOf<String?>("http/1.1"), log.protocols)
                }
            }
        }

    @Test fun throughConnectProxyIsH2() =
        clientTest {
            tlsH2WithSilentUdp(onRequest = { _, r -> ok(r) }) { port, _ ->
                ClientProxyTest().tunnelProxy(port) { proxyPort, head ->
                    testClient(
                        engine = {
                            proxy =
                                io.ktor.client.engine.ProxyBuilder
                                    .http(io.ktor.http.Url("http://127.0.0.1:$proxyPort"))
                        },
                    ).use { c ->
                        val r = c.get("https://127.0.0.1:$port/")
                        // ALPN is inside the TLS session with the origin: the tunnel carries HTTP/2
                        assertEquals(HttpProtocolVersion.HTTP_2_0, r.version)
                        assertEquals(FallbackReason.Proxy, r.kuicksilverDiagnostics!!.fallback)
                        assertTrue(head().first().startsWith("CONNECT 127.0.0.1:$port"))
                    }
                }
            }
        }

    @Test fun socketTimeoutOnAStalledResponse() =
        clientTest {
            tlsH2WithSilentUdp(onRequest = { _, r ->
                r.respond(200)
                kotlinx.coroutines.awaitCancellation()
            }) { port, _ ->
                testClient(block = { install(HttpTimeout) { socketTimeoutMillis = 300 } }).use { c ->
                    assertFailsWith<io.ktor.client.network.sockets.SocketTimeoutException> {
                        c.get("https://127.0.0.1:$port/").bodyAsText()
                    }
                    // the connection outlives one stalled stream
                    assertEquals(1, engine(c).h1.h2.connectionCount)
                }
            }
        }

    /** Events of interest, in order. */
    private class EventRecorder : KuicksilverEventListener() {
        val order = ArrayList<String>()
        val acquired = ArrayList<Pair<HttpProtocolVersion, Boolean>>()
        val selected = ArrayList<HttpProtocolVersion>()
        val raceWinners = ArrayList<HttpProtocolVersion>()
        val retries = ArrayList<Throwable>()

        private val lock =
            io.kuicksilver.ktor.client.h1
                .SpinLock()

        private fun add(s: String) = lock.withLock { order += s }

        override fun protocolSelected(
            request: HttpRequestData,
            protocol: HttpProtocolVersion,
            reason: ProtocolReason,
        ) {
            add("protocolSelected")
            synchronizedAdd { selected += protocol }
        }

        override fun connectionAcquired(
            request: HttpRequestData,
            protocol: HttpProtocolVersion,
            reused: Boolean,
        ) {
            add("connectionAcquired")
            synchronizedAdd { acquired += protocol to reused }
        }

        override fun raceEnded(
            request: HttpRequestData,
            winner: HttpProtocolVersion,
            headStart: kotlin.time.Duration,
            h3Failure: Throwable?,
        ) {
            synchronizedAdd { raceWinners += winner }
        }

        override fun retry(
            request: HttpRequestData,
            attempt: Int,
            cause: Throwable,
        ) {
            synchronizedAdd { retries += cause }
        }

        private fun synchronizedAdd(block: () -> Unit) = lock.withLock { block() }
    }
}
