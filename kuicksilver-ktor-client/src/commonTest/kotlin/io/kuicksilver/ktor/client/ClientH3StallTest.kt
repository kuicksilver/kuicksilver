// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import io.ktor.client.HttpClient
import io.ktor.client.plugins.websocket.WebSockets
import io.ktor.client.plugins.websocket.webSocket
import io.ktor.client.request.get
import io.ktor.client.request.post
import io.ktor.client.request.prepareGet
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsChannel
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpProtocolVersion
import io.ktor.server.application.install
import io.ktor.server.response.respondBytes
import io.ktor.server.response.respondBytesWriter
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import io.ktor.server.routing.routing
import io.ktor.utils.io.readAvailable
import io.ktor.utils.io.readBuffer
import io.ktor.utils.io.writeStringUtf8
import io.ktor.websocket.Frame
import io.ktor.websocket.readText
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.QuicEndpointConfig
import io.kuicksilver.quic.quicConfig
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.withTimeout
import kotlinx.io.readByteArray
import kotlin.concurrent.atomics.AtomicInt
import kotlin.concurrent.atomics.ExperimentalAtomicApi
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue
import kotlin.test.fail
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.seconds
import kotlin.time.TimeSource
import io.ktor.server.websocket.WebSockets as ServerWebSockets
import io.ktor.server.websocket.webSocket as serverWebSocket

/**
 * Stall detection (`http3 { stallDetection }`; docs/guide/ktor.md, "Stalled HTTP/3 connections"): a network that cuts UDP
 * flows. The engine's endpoint socket is a [FaultyIo] that drops everything, in both directions, after a number of
 * datagrams once armed. The QUIC idle timeout is 15 s here: without the detection every stalled call takes that long.
 */
@OptIn(ExperimentalKuicksilverApi::class, ExperimentalAtomicApi::class)
class ClientH3StallTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private class Heard : KuicksilverEventListener() {
        val fallbacks = Channel<Throwable>(Channel.UNLIMITED)
        val marked = AtomicInt(0)

        override fun fallback(
            request: io.ktor.client.request.HttpRequestData,
            cause: Throwable,
        ) {
            fallbacks.trySend(cause)
        }

        override fun altSvcMarkedBroken(
            origin: String,
            alternative: String,
        ) {
            marked.addAndFetch(1)
        }
    }

    private class Server(
        val port: Int,
        val partialGate: CompletableDeferred<Unit>,
        val gets: AtomicInt,
        val partials: AtomicInt,
        val posts: AtomicInt,
        val fullSent: CompletableDeferred<Unit>,
        val stop: suspend () -> Unit,
    )

    /** [idle]: the server's QUIC idle timeout (the client's PINGs must come at least every half of it). */
    private suspend fun server(idle: Duration? = null): Server {
        val gate = CompletableDeferred<Unit>()
        val gets = AtomicInt(0)
        val partials = AtomicInt(0)
        val posts = AtomicInt(0)
        val fullSent = CompletableDeferred<Unit>()
        val (s, port) =
            testServer(configure = { idle?.let { quic = quicConfig { maxIdleTimeout = it } } }) {
                install(ServerWebSockets)
                routing {
                    // an echo WebSocket (over HTTP/3 with Extended CONNECT once a connection allows it, RFC 9220)
                    serverWebSocket("/ws") {
                        for (f in incoming) if (f is Frame.Text) outgoing.send(Frame.Text(f.readText()))
                    }
                    // a large response, sent at once
                    get("/big") {
                        call.respondBytes(ByteArray(BIG) { 7 }, ContentType.Application.OctetStream)
                    }
                    // a whole response, sent at once
                    get("/full") {
                        call.respondText("firstrest")
                        fullSent.complete(Unit)
                    }
                    // the server holds the request for 6 s, then answers (three times its own 2 s idle timeout in one test)
                    get("/hold") {
                        delay(6.seconds)
                        call.respondText("held")
                    }
                    get("/") {
                        gets.addAndFetch(1)
                        call.respondText(call.request.local.version)
                    }
                    post("/") {
                        posts.addAndFetch(1)
                        call.respondText("posted")
                    }
                    // a slow server: it thinks for 3 s (the stall threshold is 500 ms) before it answers
                    get("/slow") {
                        delay(3.seconds)
                        call.respondText("slow")
                    }
                    // an idle long-lived response: headers and a first event, then nothing for 3 s, then the rest
                    get("/events") {
                        call.respondBytesWriter(ContentType.Text.EventStream) {
                            writeStringUtf8("a")
                            flush()
                            delay(3.seconds)
                            writeStringUtf8("b")
                        }
                    }
                    // a response under way when the path is cut
                    get("/partial") {
                        partials.addAndFetch(1)
                        call.respondBytesWriter(ContentType.Application.OctetStream) {
                            writeStringUtf8("first")
                            flush()
                            gate.await()
                            writeStringUtf8("rest")
                        }
                    }
                }
            }
        return Server(port, gate, gets, partials, posts, fullSent) {
            gate.complete(Unit)
            s.stop(100, 500)
        }
    }

    /** Auto mode, HTTP/3 first once its alternative is known (`hardDelay = INFINITE`): every test starts on a warm HTTP/3 connection. */
    private fun client(
        ios: FaultyIos,
        heard: Heard,
        detection: Boolean = true,
        idle: Duration = 15.seconds,
        hardDelay: Duration? = Duration.INFINITE,
        minSilence: Duration = 500.milliseconds,
        abandonAfter: Duration = 2.seconds,
        // windows that take a whole 4 MiB response before the application reads any of it
        windows: Boolean = false,
        block: io.ktor.client.HttpClientConfig<KuicksilverEngineConfig>.() -> Unit = {},
    ): HttpClient =
        testClient(Http3DiscoveryMode.Auto, engine = {
            quic =
                quicConfig {
                    maxIdleTimeout = idle
                    if (windows) {
                        initialStreamWindow = 8L * 1024 * 1024
                        maxStreamWindow = 8L * 1024 * 1024
                        initialConnectionWindow = 16L * 1024 * 1024
                        maxConnectionWindow = 16L * 1024 * 1024
                    }
                }
            eventListener = heard
            http3 {
                this.hardDelay = hardDelay
                stallDetection = detection
                stallMinSilence = minSilence
                stallAbandonAfter = abandonAfter
                endpoint =
                    QuicEndpointConfig
                        .Builder()
                        .apply { io = { local -> ios.open(local) } }
                        .build()
            }
        }, block = block)

    /** The first call learns the server's Alt-Svc over TCP, the second sets up and uses HTTP/3. */
    private suspend fun warm(
        c: HttpClient,
        url: String,
    ) {
        assertNotEquals(HttpProtocolVersion.HTTP_3_0, c.get(url).version)
        assertEquals(HttpProtocolVersion.HTTP_3_0, c.get(url).version)
    }

    private fun engineOf(c: HttpClient) = c.engine as KuicksilverEngine

    private fun Throwable.stall(): QuicStalledException? =
        generateSequence(this) { it.cause }.filterIsInstance<QuicStalledException>().firstOrNull()

    /**
     * Case 2 of the field report: the handshake completed and the connection carried a request, then the flow is cut both
     * ways. The next GET is never acknowledged; the PTOs go unanswered and the call goes over TCP within a few seconds, the
     * alternative marked broken; the next call goes straight to TCP.
     */
    @Test fun stalledGetRetriesOverTcpAndMarksBroken() =
        h3Test {
            val s = server()
            val ios = FaultyIos()
            val heard = Heard()
            try {
                client(ios, heard).use { c ->
                    val url = "https://127.0.0.1:${s.port}/"
                    warm(c, url)
                    ios.cut()
                    val t0 = TimeSource.Monotonic.markNow()
                    val r = c.get(url)
                    val took = t0.elapsedNow()
                    assertNotEquals(HttpProtocolVersion.HTTP_3_0, r.version)
                    assertTrue(took < 6.seconds, "fell back after $took")
                    val d = assertNotNull(r.kuicksilverDiagnostics)
                    assertEquals(FallbackReason.QuicStalled, d.fallback, "$d")
                    assertNotNull(d.h3Failure?.stall(), "${d.h3Failure}")
                    assertNotNull(
                        heard.fallbacks
                            .tryReceive()
                            .getOrNull()
                            ?.stall(),
                    )
                    assertEquals(1, heard.marked.load())
                    val engine = engineOf(c)
                    assertTrue(engine.brokenAltSvc.isBroken("https://127.0.0.1:${s.port}", "127.0.0.1:${s.port}"))
                    assertTrue(engine.h3.connectionsForTest().isEmpty(), "the stalled connection left the pool")
                    val t1 = TimeSource.Monotonic.markNow()
                    assertNotEquals(HttpProtocolVersion.HTTP_3_0, c.get(url).version)
                    assertTrue(t1.elapsedNow() < 2.seconds, "the next call goes straight to TCP: ${t1.elapsedNow()}")
                }
            } finally {
                s.stop()
            }
        }

    /**
     * The flow is cut after a few more datagrams each way: the request may get through and be acknowledged, and its response
     * lost, or part of it arrive. With nothing in flight no PTO would ever fire; the detector's PING makes the dead path show.
     * Either the call went over TCP (no response yet) or, once the response head was in, the body read failed with the
     * stall: fast in both cases, never at the 15 s idle timeout, and never repeated after a response began.
     */
    @Test fun pathCutAfterAFewDatagramsFailsOverFast() =
        h3Test {
            for (n in listOf(1, 2, 3)) {
                val s = server()
                val ios = FaultyIos()
                val heard = Heard()
                try {
                    client(ios, heard).use { c ->
                        val url = "https://127.0.0.1:${s.port}/"
                        warm(c, url)
                        val before = s.gets.load()
                        ios.cut(n)
                        val t0 = TimeSource.Monotonic.markNow()
                        val outcome = runCatching { c.get(url) }
                        val took = t0.elapsedNow()
                        assertTrue(took < 6.seconds, "n=$n: took $took")
                        val r = outcome.getOrNull()
                        if (r != null) {
                            assertNotEquals(HttpProtocolVersion.HTTP_3_0, r.version, "n=$n")
                            assertEquals(FallbackReason.QuicStalled, r.kuicksilverDiagnostics?.fallback, "n=$n")
                        } else {
                            val e = outcome.exceptionOrNull()!!
                            assertNotNull(e.stall(), "n=$n: the failure names the stall: $e")
                            assertEquals(before + 1, s.gets.load(), "n=$n: a response had begun, so no repeat over TCP")
                        }
                        assertEquals(1, heard.marked.load(), "n=$n")
                    }
                } finally {
                    s.stop()
                }
            }
        }

    /**
     * RFC 9110 section 9.2.2: a POST is not repeated. The path stays cut past `stallAbandonAfter` (2 s here): the POST
     * fails with the stall, not at the 15 s idle timeout.
     */
    @Test fun nonIdempotentRequestFailsFastWithoutRetry() =
        h3Test {
            val s = server()
            val ios = FaultyIos()
            val heard = Heard()
            try {
                client(ios, heard).use { c ->
                    val url = "https://127.0.0.1:${s.port}/"
                    warm(c, url)
                    ios.cut()
                    val t0 = TimeSource.Monotonic.markNow()
                    val e = assertFailsWith<Throwable> { c.post(url) { setBody("x") } }
                    val took = t0.elapsedNow()
                    val stall = assertNotNull(e.stall(), "the failure names the stall: $e")
                    assertTrue(took < 6.seconds, "failed after $took")
                    // what the detector saw: the thresholds were met (3 PTOs, 500 ms), not wall-clock bounds
                    assertTrue(stall.probeTimeouts in 3..64, "${stall.probeTimeouts}")
                    assertTrue(stall.silence.inWholeMilliseconds in 500L..60_000L, "${stall.silence}")
                    assertTrue(stall.message!!.contains("stalled"), stall.message)
                    assertNull(heard.fallbacks.tryReceive().getOrNull(), "no fallback")
                    assertEquals(0, s.posts.load(), "the POST never went over TCP")
                    assertEquals(1, heard.marked.load(), "the alternative is marked broken all the same")
                }
            } finally {
                s.stop()
            }
        }

    /** A response under way when the path is cut: the body read fails with the stall, and the request is not repeated. */
    @Test fun partialResponseFailsFastWithoutRetry() =
        h3Test {
            val s = server()
            val ios = FaultyIos()
            val heard = Heard()
            try {
                client(ios, heard).use { c ->
                    val url = "https://127.0.0.1:${s.port}/"
                    warm(c, url)
                    c.prepareGet("${url}partial").execute { r ->
                        assertEquals(HttpProtocolVersion.HTTP_3_0, r.version)
                        val ch = r.bodyAsChannel()
                        val first = ByteArray(5)
                        var got = 0
                        while (got < 5) {
                            val n = ch.readAvailable(first, got, 5 - got)
                            if (n < 0) fail("the body ended after $got bytes")
                            got += n
                        }
                        assertEquals("first", first.decodeToString())
                        ios.cut()
                        val t0 = TimeSource.Monotonic.markNow()
                        val e = assertFailsWith<Throwable> { ch.readBuffer() }
                        val took = t0.elapsedNow()
                        assertNotNull(e.stall(), "the failure names the stall: $e")
                        assertTrue(took < 6.seconds, "failed after $took")
                    }
                    assertEquals(1, s.partials.load(), "not repeated")
                    assertNull(heard.fallbacks.tryReceive().getOrNull(), "no fallback")
                }
            } finally {
                s.stop()
            }
        }

    /** Attack: a server that thinks for 3 s acknowledges the request meanwhile; that is no stall (no PTO, PINGs answered). */
    @Test fun slowServerIsNoStall() =
        h3Test {
            val s = server()
            val ios = FaultyIos()
            val heard = Heard()
            try {
                client(ios, heard).use { c ->
                    val url = "https://127.0.0.1:${s.port}/"
                    warm(c, url)
                    val conn = engineOf(c).h3.connectionsForTest().single()
                    val sent = conn.quic.stats.packetsSent
                    val r = c.get("${url}slow")
                    assertEquals(HttpProtocolVersion.HTTP_3_0, r.version)
                    assertEquals("slow", r.bodyAsText())
                    assertNull(heard.fallbacks.tryReceive().getOrNull())
                    assertEquals(0, heard.marked.load())
                    assertSame(conn, engineOf(c).h3.connectionsForTest().single(), "the same connection")
                    // the request, its acknowledgements, and the liveness PINGs of the 3 s wait (0.25 s, 0.5 s, 1 s, 2 s)
                    assertTrue(conn.quic.stats.packetsSent - sent >= 4, "${conn.quic.stats.packetsSent - sent}")
                }
            } finally {
                s.stop()
            }
        }

    /** Attack: an idle long-lived response (a server-sent event stream between events) is not killed. */
    @Test fun idleLongLivedResponseIsNoStall() =
        h3Test {
            val s = server()
            val ios = FaultyIos()
            val heard = Heard()
            try {
                client(ios, heard).use { c ->
                    val url = "https://127.0.0.1:${s.port}/"
                    warm(c, url)
                    val r = c.get("${url}events")
                    assertEquals(HttpProtocolVersion.HTTP_3_0, r.version)
                    assertEquals("ab", r.bodyAsText())
                    assertNull(heard.fallbacks.tryReceive().getOrNull())
                    assertEquals(0, heard.marked.load())
                }
            } finally {
                s.stop()
            }
        }

    /**
     * UDP dropped from the start, on a network where QUIC was never seen working: the race (RFC 8305 section 5) already
     * starts TCP after 10 ms and the call does not wait for the QUIC handshake (point 1 of the field report).
     */
    @Test fun udpDroppedFromTheStartLosesTheRaceAtOnce() =
        h3Test {
            val s = server()
            val ios = FaultyIos()
            val heard = Heard()
            try {
                client(ios, heard, hardDelay = null).use { c ->
                    val url = "https://127.0.0.1:${s.port}/"
                    assertNotEquals(HttpProtocolVersion.HTTP_3_0, c.get(url).version) // learns the alternative
                    ios.cut()
                    // the endpoint is bound at the first HTTP/3 attempt: its socket drops everything from its first datagram
                    val t0 = TimeSource.Monotonic.markNow()
                    val r = c.get(url)
                    assertNotEquals(HttpProtocolVersion.HTTP_3_0, r.version)
                    assertTrue(t0.elapsedNow() < 2.seconds, "${t0.elapsedNow()}")
                }
            } finally {
                s.stop()
            }
        }

    /** Attack: several requests on the stalled connection mark the alternative broken once (one backoff step per stall). */
    @Test fun concurrentRequestsMarkBrokenOnce() =
        h3Test {
            val s = server()
            val ios = FaultyIos()
            val heard = Heard()
            try {
                client(ios, heard).use { c ->
                    val url = "https://127.0.0.1:${s.port}/"
                    warm(c, url)
                    ios.cut()
                    val versions = coroutineScope { (1..4).map { async { c.get(url).version } }.awaitAll() }
                    assertTrue(versions.none { it == HttpProtocolVersion.HTTP_3_0 }, "$versions")
                    assertEquals(1, heard.marked.load())
                }
            } finally {
                s.stop()
            }
        }

    /** Negative control: with `stallDetection = false` the stalled call waits for the QUIC idle timeout (3 s here), as before 0.3.0. */
    @Test fun negative_offWaitsForTheIdleTimeout() =
        h3Test {
            val s = server()
            val ios = FaultyIos()
            val heard = Heard()
            try {
                client(ios, heard, detection = false, idle = 3.seconds).use { c ->
                    val url = "https://127.0.0.1:${s.port}/"
                    warm(c, url)
                    ios.cut()
                    val t0 = TimeSource.Monotonic.markNow()
                    val r = c.get(url)
                    assertNotEquals(HttpProtocolVersion.HTTP_3_0, r.version)
                    assertTrue(t0.elapsedNow() >= 2.seconds, "${t0.elapsedNow()}")
                    assertEquals(FallbackReason.Http3Error, r.kuicksilverDiagnostics?.fallback)
                }
            } finally {
                s.stop()
            }
        }

    /**
     * Review finding 1: a response that arrived whole (its FIN) needs the network no more. While the application reads it
     * slowly the watch is over (no wake-up, no PING), and when the path is cut and another request stalls the
     * connection, nothing holds the drained connection: it is closed at once, and the rest of the first body is still read.
     */
    @Test fun aResponseThatArrivedWholeSurvivesAStall() =
        h3Test {
            val s = server()
            val ios = FaultyIos()
            val heard = Heard()
            try {
                client(ios, heard).use { c ->
                    val url = "https://127.0.0.1:${s.port}/"
                    warm(c, url)
                    val engine = engineOf(c)
                    val conn = engine.h3.connectionsForTest().single()
                    val arrived = CompletableDeferred<Unit>()
                    engine.h3.receivedForTest = { arrived.complete(Unit) }
                    c.prepareGet("${url}full").execute { r ->
                        assertEquals(HttpProtocolVersion.HTTP_3_0, r.version)
                        val ch = r.bodyAsChannel()
                        val first = ByteArray(5)
                        var got = 0
                        while (got < 5) {
                            val n = ch.readAvailable(first, got, 5 - got)
                            if (n < 0) fail("the body ended after $got bytes")
                            got += n
                        }
                        assertEquals("first", first.decodeToString())
                        withTimeout(10.seconds) { arrived.await() }
                        withTimeout(10.seconds) { engine.h3.stallWatchLoopsForTest.first { it == 0 } } // the watch is over
                        val polls = engine.h3.stallPollsForTest.load()
                        delay(1.seconds) // a slow reader
                        assertEquals(polls, engine.h3.stallPollsForTest.load(), "the whole response arrived: nothing to watch")
                        ios.cut()
                        assertNotEquals(HttpProtocolVersion.HTTP_3_0, c.get(url).version, "the other request stalls and goes over TCP")
                        // abandoned at once (stallAbandonAfter is 2 s): nothing on it needs the network any more
                        withTimeout(1.seconds) { conn.quic.closed.await() }
                        assertEquals("rest", ch.readBuffer().readByteArray().decodeToString())
                    }
                }
            } finally {
                s.stop()
            }
        }

    /**
     * Review finding 2: a stall drains the connection. A POST (not repeatable) waits on it, and a 3 s outage (a handover
     * between radio networks) ends before `stallAbandonAfter` (8 s here): the POST completes over HTTP/3.
     */
    @Test fun nonRepeatableRequestSurvivesAShortOutage() =
        h3Test {
            val s = server()
            val ios = FaultyIos()
            val heard = Heard()
            try {
                client(ios, heard, abandonAfter = 8.seconds).use { c ->
                    val url = "https://127.0.0.1:${s.port}/"
                    warm(c, url)
                    val engine = engineOf(c)
                    val conn = engine.h3.connectionsForTest().single()
                    val stalled = CompletableDeferred<Unit>()
                    engine.h3.stalledForTest = { stalled.complete(Unit) }
                    ios.cut()
                    val t0 = TimeSource.Monotonic.markNow()
                    coroutineScope {
                        val post = async { c.post(url) { setBody("x") } }
                        withTimeout(10.seconds) { stalled.await() }
                        delay(3.seconds - t0.elapsedNow()) // the outage lasts 3 s
                        ios.heal()
                        val r = post.await()
                        assertEquals(HttpProtocolVersion.HTTP_3_0, r.version)
                        assertEquals("posted", r.bodyAsText())
                    }
                    assertEquals(1, s.posts.load())
                    assertEquals(1, heard.marked.load(), "the stall marked the alternative broken all the same")
                    // review finding 2 (second round): the drained connection that recovered is closed once its last request is
                    // over, not left to its idle timeout, and its monitor ends with it
                    withTimeout(5.seconds) { conn.quic.closed.await() }
                    withTimeout(5.seconds) { engine.h3.stallMonitorsForTest.first { it == 0 } }
                }
            } finally {
                s.stop()
            }
        }

    /** Review finding 9: the RTT grows by 700 ms after the handshake (an ACK delayed that long): no stall at the default 2 s. */
    @Test fun aLongerRttAfterTheHandshakeIsNoStall() =
        h3Test {
            val s = server()
            val ios = FaultyIos()
            val heard = Heard()
            try {
                client(ios, heard, minSilence = 2.seconds).use { c ->
                    val url = "https://127.0.0.1:${s.port}/"
                    warm(c, url)
                    ios.delayReceived(700.milliseconds)
                    val r = c.get(url)
                    assertEquals(HttpProtocolVersion.HTTP_3_0, r.version)
                    assertNull(heard.fallbacks.tryReceive().getOrNull())
                    assertEquals(0, heard.marked.load())
                }
            } finally {
                s.stop()
            }
        }

    /**
     * Review finding 5: the server's idle timeout is 2 s and it holds the request for 6 s. The watched connection's PINGs
     * come at most every half of the idle timeout in force (1 s), so the connection outlives the wait (RFC 9114
     * section 5.1); PINGs that doubled to 2 s and more let the server's idle timeout end it.
     */
    @Test fun pingsComeWithinHalfThePeersIdleTimeout() =
        h3Test {
            val s = server(idle = 2.seconds)
            val ios = FaultyIos()
            val heard = Heard()
            try {
                client(ios, heard).use { c ->
                    val url = "https://127.0.0.1:${s.port}/"
                    warm(c, url)
                    val r = c.get("${url}hold")
                    assertEquals(HttpProtocolVersion.HTTP_3_0, r.version, "${r.kuicksilverDiagnostics}")
                    assertEquals("held", r.bodyAsText())
                }
            } finally {
                s.stop()
            }
        }

    /** Review finding 6: with no request on the connection the monitor neither wakes up nor sends a PING. */
    @Test fun noWatcherMeansNoPollsAndNoPings() =
        h3Test {
            val s = server()
            val ios = FaultyIos()
            val heard = Heard()
            try {
                client(ios, heard).use { c ->
                    val url = "https://127.0.0.1:${s.port}/"
                    warm(c, url)
                    val engine = engineOf(c)
                    val conn = engine.h3.connectionsForTest().single()
                    withTimeout(10.seconds) { engine.h3.stallWatchLoopsForTest.first { it == 0 } } // the finished watch's loop ended
                    val polls = engine.h3.stallPollsForTest.load()
                    val pings = engine.h3.stallPingsForTest.load()
                    delay(2.seconds)
                    assertEquals(polls, engine.h3.stallPollsForTest.load(), "no wake-up without a watcher")
                    // the monitor's own PINGs: the connection's other packets (ACKs, the server's tickets) are no PING of ours
                    assertEquals(pings, engine.h3.stallPingsForTest.load(), "no PING without a watcher")
                    assertTrue(!conn.quic.closed.isCompleted)
                }
            } finally {
                s.stop()
            }
        }

    /**
     * Review finding 6: a watched quiet connection sleeps until its next PING is due instead of polling every 62 ms:
     * a 3 s idle response costs a handful of wake-ups (48 at the poll interval).
     */
    @Test fun aQuietWatchedConnectionWakesUpOnlyForItsPings() =
        h3Test {
            val s = server()
            val ios = FaultyIos()
            val heard = Heard()
            try {
                client(ios, heard).use { c ->
                    val url = "https://127.0.0.1:${s.port}/"
                    warm(c, url)
                    val engine = engineOf(c)
                    val polls = engine.h3.stallPollsForTest.load()
                    assertEquals("ab", c.get("${url}events").bodyAsText())
                    val woke = engine.h3.stallPollsForTest.load() - polls
                    assertTrue(woke <= 24, "$woke wake-ups in 3 s")
                }
            } finally {
                s.stop()
            }
        }

    /**
     * Review finding 8: a POST looked the connection up just before it stalled (held between the lookup and the count).
     * It was not sent, so it goes over TCP instead of onto the stalled connection.
     */
    @Test fun aRequestHandedTheConnectionAsItStallsGoesOverTcp() =
        h3Test {
            val s = server()
            val ios = FaultyIos()
            val heard = Heard()
            try {
                client(ios, heard).use { c ->
                    val url = "https://127.0.0.1:${s.port}/"
                    warm(c, url)
                    val engine = engineOf(c)
                    val stalled = CompletableDeferred<Unit>()
                    val held = CompletableDeferred<Unit>()
                    engine.h3.stalledForTest = { stalled.complete(Unit) }
                    engine.h3.beforeCountForTest = {
                        if (held.complete(Unit)) stalled.await() // the first caller (the POST) waits for the stall
                    }
                    ios.cut()
                    coroutineScope {
                        val post = async { c.post(url) { setBody("x") } }
                        withTimeout(10.seconds) { held.await() }
                        val get = async { c.get(url) } // runs into the dead path and stalls the connection
                        val t0 = TimeSource.Monotonic.markNow()
                        val r = post.await()
                        assertNotEquals(HttpProtocolVersion.HTTP_3_0, r.version)
                        assertEquals("posted", r.bodyAsText())
                        assertTrue(t0.elapsedNow() < 6.seconds, "${t0.elapsedNow()}")
                        assertNotEquals(HttpProtocolVersion.HTTP_3_0, get.await().version)
                    }
                    assertEquals(1, s.posts.load())
                }
            } finally {
                s.stop()
            }
        }

    /**
     * Review finding 1 (second round): on a network that lets each new connection carry one exchange and then cuts its
     * flow, the backoff must rise at every stall. A connection that stalls never lets it walk down, however many exchanges
     * it carried first; only one that ends without a stall does.
     */
    @Test fun aConnectionThatStallsAfterAnExchangeNeverLowersTheBackoff() =
        h3Test {
            val s = server()
            val ios = FaultyIos()
            val heard = Heard()
            try {
                client(ios, heard).use { c ->
                    val url = "https://127.0.0.1:${s.port}/"
                    val origin = "https://127.0.0.1:${s.port}"
                    val alt = "127.0.0.1:${s.port}"
                    val engine = engineOf(c)
                    assertNotEquals(HttpProtocolVersion.HTTP_3_0, c.get(url).version) // learns the alternative
                    for (round in 0..2) {
                        // a new connection carries one whole exchange...
                        assertEquals(HttpProtocolVersion.HTTP_3_0, c.get(url).version, "round $round")
                        // ...and then its flow is cut
                        ios.cut()
                        assertNotEquals(HttpProtocolVersion.HTTP_3_0, c.get(url).version, "round $round")
                        withTimeout(10.seconds) { engine.h3.stallMonitorsForTest.first { it == 0 } } // that connection is over
                        assertEquals(round, engine.altSvcLevelForTest(origin, alt), "round $round")
                        ios.heal()
                        engine.expireAltSvcMarkForTest(origin, alt) // the backoff passed
                    }
                }
            } finally {
                s.stop()
            }
        }

    /**
     * Review finding 3 (second round): a 4 MiB response arrived whole (the windows let it in) while the application read
     * only its first bytes; most of it is still behind the body channel. The watch ends at the stream's "Data Recvd" all
     * the same, so a stall of the connection (another request into the cut path) leaves the body alone, and it is read
     * to its end afterwards.
     */
    @Test fun aLargeResponseThatArrivedWholeSurvivesAStallWithASlowReader() =
        h3Test {
            val s = server()
            val ios = FaultyIos()
            val heard = Heard()
            try {
                client(ios, heard, windows = true).use { c ->
                    val url = "https://127.0.0.1:${s.port}/"
                    warm(c, url)
                    val engine = engineOf(c)
                    val conn = engine.h3.connectionsForTest().single()
                    val arrived = CompletableDeferred<Unit>()
                    engine.h3.receivedForTest = { arrived.complete(Unit) }
                    c.prepareGet("${url}big").execute { r ->
                        assertEquals(HttpProtocolVersion.HTTP_3_0, r.version)
                        val ch = r.bodyAsChannel()
                        val first = ByteArray(16)
                        var got = 0
                        while (got < first.size) {
                            val n = ch.readAvailable(first, got, first.size - got)
                            if (n < 0) fail("the body ended after $got bytes")
                            got += n
                        }
                        withTimeout(20.seconds) { arrived.await() }
                        ios.cut()
                        assertNotEquals(HttpProtocolVersion.HTTP_3_0, c.get(url).version, "the other request stalls and goes over TCP")
                        withTimeout(1.seconds) { conn.quic.closed.await() } // nothing on it needs the network: closed at once
                        assertEquals(BIG - first.size, ch.readBuffer().readByteArray().size, "the rest of the body is read")
                    }
                }
            } finally {
                s.stop()
            }
        }

    /**
     * Review round 3, item 2: an unwatched WebSocket over HTTP/3 shares the connection with a POST when the path is cut and
     * comes back. The stall drains the connection; the POST finishes over it, and its end does not close the connection
     * under the WebSocket, which goes on. The connection closes at its last release, when the WebSocket ends.
     */
    @Test fun aWebSocketOutlivesAStallThatRecovered() =
        h3Test {
            val s = server()
            val ios = FaultyIos()
            val heard = Heard()
            try {
                client(ios, heard, abandonAfter = 8.seconds, block = { install(WebSockets) }).use { c ->
                    val url = "https://127.0.0.1:${s.port}/"
                    warm(c, url)
                    val engine = engineOf(c)
                    val conn = engine.h3.connectionsForTest().single()
                    val stalled = CompletableDeferred<Unit>()
                    engine.h3.stalledForTest = { stalled.complete(Unit) }
                    val open = CompletableDeferred<Unit>()
                    val goOn = CompletableDeferred<Unit>()
                    coroutineScope {
                        val ws =
                            async {
                                c.webSocket("wss://127.0.0.1:${s.port}/ws") {
                                    assertEquals(HttpProtocolVersion.HTTP_3_0, call.response.version, "over the HTTP/3 connection")
                                    send(Frame.Text("a"))
                                    assertEquals("a", (incoming.receive() as Frame.Text).readText())
                                    open.complete(Unit)
                                    goOn.await()
                                    send(Frame.Text("b"))
                                    assertEquals("b", (incoming.receive() as Frame.Text).readText(), "the WebSocket goes on")
                                }
                            }
                        withTimeout(10.seconds) { open.await() }
                        ios.cut()
                        val t0 = TimeSource.Monotonic.markNow()
                        val post = async { c.post(url) { setBody("x") } }
                        withTimeout(10.seconds) { stalled.await() }
                        delay(2.seconds - t0.elapsedNow()) // a 2 s outage
                        ios.heal()
                        assertEquals(HttpProtocolVersion.HTTP_3_0, post.await().version)
                        withTimeout(10.seconds) { engine.h3.stallWatchLoopsForTest.first { it == 0 } } // the last watcher left
                        assertTrue(!conn.quic.closed.isCompleted, "the WebSocket still holds the drained connection")
                        goOn.complete(Unit)
                        withTimeout(10.seconds) { ws.await() }
                    }
                    withTimeout(5.seconds) { conn.quic.closed.await() } // its last release closed it
                }
            } finally {
                s.stop()
            }
        }

    /**
     * Review round 3, item 3: a stall's backoff walks down end to end. After a stall (level 0), a new connection carries a
     * whole exchange and the client closes it in order: the mark goes.
     */
    @Test fun aConnectionClosedInOrderWithoutAStallLowersTheBackoff() =
        h3Test {
            val s = server()
            val ios = FaultyIos()
            val heard = Heard()
            try {
                client(ios, heard).use { c ->
                    val url = "https://127.0.0.1:${s.port}/"
                    val origin = "https://127.0.0.1:${s.port}"
                    val alt = "127.0.0.1:${s.port}"
                    val engine = engineOf(c)
                    warm(c, url)
                    ios.cut()
                    assertNotEquals(HttpProtocolVersion.HTTP_3_0, c.get(url).version)
                    withTimeout(10.seconds) { engine.h3.stallMonitorsForTest.first { it == 0 } }
                    assertEquals(0, engine.altSvcLevelForTest(origin, alt))
                    ios.heal()
                    engine.expireAltSvcMarkForTest(origin, alt)
                    assertEquals(HttpProtocolVersion.HTTP_3_0, c.get(url).version) // a new connection, one whole exchange
                    val ended = CompletableDeferred<Boolean>()
                    val decayed = CompletableDeferred<Unit>()
                    engine.h3.stallMonitorEndedForTest = { ended.complete(it) }
                    engine.stallDecayedForTest = { decayed.complete(Unit) }
                    engine.h3.dropConnectionsForTest().forEach { it.close() } // closed in order by the client
                    assertEquals(true, withTimeout(10.seconds) { ended.await() })
                    withTimeout(10.seconds) { decayed.await() }
                    assertEquals(-1, engine.altSvcLevelForTest(origin, alt), "the mark at level 0 went")
                }
            } finally {
                s.stop()
            }
        }

    /**
     * Review round 3, item 4: a connection that never stalled but died by its idle timeout (2 s here) proves nothing
     * about the path: the backoff stays.
     */
    @Test fun negative_aConnectionThatDiedByIdleTimeoutDoesNotLowerTheBackoff() =
        h3Test {
            val s = server()
            val ios = FaultyIos()
            val heard = Heard()
            try {
                client(ios, heard, idle = 2.seconds).use { c ->
                    val url = "https://127.0.0.1:${s.port}/"
                    val origin = "https://127.0.0.1:${s.port}"
                    val alt = "127.0.0.1:${s.port}"
                    val engine = engineOf(c)
                    warm(c, url)
                    ios.cut()
                    assertNotEquals(HttpProtocolVersion.HTTP_3_0, c.get(url).version)
                    withTimeout(10.seconds) { engine.h3.stallMonitorsForTest.first { it == 0 } }
                    ios.heal()
                    engine.expireAltSvcMarkForTest(origin, alt)
                    assertEquals(HttpProtocolVersion.HTTP_3_0, c.get(url).version) // a new connection, one whole exchange
                    val conn = engine.h3.connectionsForTest().single()
                    val ended = CompletableDeferred<Boolean>()
                    engine.h3.stallMonitorEndedForTest = { ended.complete(it) }
                    ios.cut() // nothing more arrives: the connection dies by its idle timeout, no request watches it
                    val end = withTimeout(10.seconds) { conn.quic.closed.await() }
                    assertTrue(end is io.kuicksilver.quic.QuicException.ConnectionLost.Timeout, "$end")
                    assertEquals(false, withTimeout(10.seconds) { ended.await() })
                    assertEquals(0, engine.altSvcLevelForTest(origin, alt), "the backoff stays")
                }
            } finally {
                s.stop()
            }
        }

    @Test fun negative_stallThresholdsOutOfRangeAreRefused() {
        assertFailsWith<IllegalArgumentException> {
            testClient(Http3DiscoveryMode.Auto, engine = { http3 { stallProbeTimeouts = 0 } }).close()
        }
        assertFailsWith<IllegalArgumentException> {
            testClient(Http3DiscoveryMode.Auto, engine = { http3 { stallProbeTimeouts = 11 } }).close()
        }
        assertFailsWith<IllegalArgumentException> {
            testClient(Http3DiscoveryMode.Auto, engine = { http3 { stallMinSilence = 99.milliseconds } }).close()
        }
        assertFailsWith<IllegalArgumentException> {
            testClient(Http3DiscoveryMode.Auto, engine = { http3 { stallMinSilence = 61.seconds } }).close()
        }
        assertFailsWith<IllegalArgumentException> {
            testClient(Http3DiscoveryMode.Auto, engine = { http3 { stallAbandonAfter = 99.milliseconds } }).close()
        }
        assertFailsWith<IllegalArgumentException> {
            testClient(Http3DiscoveryMode.Auto, engine = { http3 { stallAbandonAfter = 11.minutes } }).close()
        }
    }
}

/** The large response of [ClientH3StallTest]: 4 MiB. */
private const val BIG = 4 * 1024 * 1024
