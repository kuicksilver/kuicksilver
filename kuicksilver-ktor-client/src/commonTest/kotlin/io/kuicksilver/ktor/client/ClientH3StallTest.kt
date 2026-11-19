// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import io.ktor.client.HttpClient
import io.ktor.client.request.get
import io.ktor.client.request.post
import io.ktor.client.request.prepareGet
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsChannel
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpProtocolVersion
import io.ktor.server.response.respondBytesWriter
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import io.ktor.server.routing.routing
import io.ktor.utils.io.readAvailable
import io.ktor.utils.io.readBuffer
import io.ktor.utils.io.writeStringUtf8
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.DatagramIo
import io.kuicksilver.quic.PacketBatch
import io.kuicksilver.quic.QuicEndpointConfig
import io.kuicksilver.quic.quicConfig
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlin.concurrent.atomics.AtomicInt
import kotlin.concurrent.atomics.AtomicReference
import kotlin.concurrent.atomics.ExperimentalAtomicApi
import kotlin.concurrent.atomics.update
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
import kotlin.time.Duration.Companion.seconds
import kotlin.time.TimeSource

/**
 * Stall detection (`http3 { stallDetection }`; docs/guide/ktor.md, "Stalled HTTP/3 connections"): a network that cuts UDP
 * flows. The engine's endpoint socket is a [FaultyIo] that drops everything, in both directions, after a number of
 * datagrams once armed. The QUIC idle timeout is 15 s here: without the detection every stalled call takes that long.
 */
@OptIn(ExperimentalKuicksilverApi::class, ExperimentalAtomicApi::class)
class ClientH3StallTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    /** The engine endpoints' sockets: once [cut], [n] more datagrams pass each way, then nothing. */
    private class FaultyIo(
        private val d: DatagramIo,
    ) : DatagramIo by d {
        private val sendLeft = AtomicInt(Int.MAX_VALUE)
        private val receiveLeft = AtomicInt(Int.MAX_VALUE)

        fun cut(n: Int) {
            sendLeft.store(n)
            receiveLeft.store(n)
        }

        private fun pass(
            left: AtomicInt,
            count: Int,
        ): Boolean {
            while (true) {
                val l = left.load()
                if (l == Int.MAX_VALUE) return true
                if (l < count) {
                    left.store(0)
                    return false
                }
                if (left.compareAndSet(l, l - count)) return true
            }
        }

        override suspend fun send(batch: PacketBatch): Int = if (pass(sendLeft, batch.count)) d.send(batch) else batch.count

        override fun trySend(batch: PacketBatch): Int = if (pass(sendLeft, batch.count)) d.trySend(batch) else batch.count

        override suspend fun receive(into: PacketBatch): Int {
            while (true) {
                val before = into.count
                val n = d.receive(into)
                if (n <= 0 || pass(receiveLeft, n)) return n
                into.count = before // dropped on the way
            }
        }
    }

    private class Ios {
        val opened = AtomicReference(emptyList<FaultyIo>())

        /** Applies to the sockets opened so far and to those opened later (an endpoint bound at the first HTTP/3 attempt). */
        @kotlin.concurrent.Volatile var cutAt: Int? = null

        fun cut(n: Int = 0) {
            cutAt = n
            opened.load().forEach { it.cut(n) }
        }

        suspend fun open(local: io.ktor.network.sockets.InetSocketAddress): DatagramIo =
            FaultyIo(DatagramIo.open(local)).also { f ->
                cutAt?.let { f.cut(it) }
                opened.update { it + f }
            }
    }

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
        val stop: suspend () -> Unit,
    )

    private suspend fun server(): Server {
        val gate = CompletableDeferred<Unit>()
        val gets = AtomicInt(0)
        val partials = AtomicInt(0)
        val posts = AtomicInt(0)
        val (s, port) =
            testServer {
                routing {
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
        return Server(port, gate, gets, partials, posts) {
            gate.complete(Unit)
            s.stop(100, 500)
        }
    }

    /** Auto mode, HTTP/3 first once its alternative is known (`hardDelay = INFINITE`): every test starts on a warm HTTP/3 connection. */
    private fun client(
        ios: Ios,
        heard: Heard,
        detection: Boolean = true,
        idle: Duration = 15.seconds,
        hardDelay: Duration? = Duration.INFINITE,
    ): HttpClient =
        testClient(Http3DiscoveryMode.Auto, engine = {
            quic = quicConfig { maxIdleTimeout = idle }
            eventListener = heard
            http3 {
                this.hardDelay = hardDelay
                stallDetection = detection
                stallMinSilence = 500.milliseconds
                endpoint =
                    QuicEndpointConfig
                        .Builder()
                        .apply { io = { local -> ios.open(local) } }
                        .build()
            }
        })

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
            val ios = Ios()
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
                    assertNotNull(heard.fallbacks.tryReceive().getOrNull()?.stall())
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
                val ios = Ios()
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

    /** RFC 9110 section 9.2.2: a POST is not repeated; it fails at once with the stall, not at the 15 s idle timeout. */
    @Test fun nonIdempotentRequestFailsFastWithoutRetry() =
        h3Test {
            val s = server()
            val ios = Ios()
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
            val ios = Ios()
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
            val ios = Ios()
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
            val ios = Ios()
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
            val ios = Ios()
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
            val ios = Ios()
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
            val ios = Ios()
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
    }
}
