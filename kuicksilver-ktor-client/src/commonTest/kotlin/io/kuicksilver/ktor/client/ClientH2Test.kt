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
import io.ktor.utils.io.readRemaining
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
                runCatching { input.readRemaining() } // the client closes first: closing here could cut the response short
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
                runCatching { input.readRemaining() } // the client closes first: closing here could cut the response short
            }) { port, log ->
                testClient(engine = { http2 { enabled = false } }).use { c ->
                    assertEquals(HttpProtocolVersion.HTTP_1_1, c.get("https://127.0.0.1:$port/").version)
                    assertEquals(listOf<String?>("http/1.1"), log.protocols)
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
                runCatching { input.readRemaining() }
            }) { port ->
                testClient(engine = { connectTimeout = 500.milliseconds }).use { c ->
                    assertFailsWith<io.ktor.client.network.sockets.ConnectTimeoutException> { c.get("https://127.0.0.1:$port/") }
                    assertEquals(0, engine(c).h1.pool.liveCount)
                }
            }
        }

    @Test fun requestBodyRespectsPeerWindow() =
        clientTest {
            val size = 1 shl 20
            tlsH2WithSilentUdp(
                settings = Http2Settings(initialStreamWindow = 16_384, maxStreamWindow = 16_384, initialConnectionWindow = 65_535),
                onRequest = { _, r ->
                    val got = r.body.readRemaining().readByteArray()
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
                            .readRemaining()
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
