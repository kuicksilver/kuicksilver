// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalKuicksilverApi::class, ExperimentalAtomicApi::class)

package io.kuicksilver.ktor.client

import io.ktor.client.network.sockets.ConnectTimeoutException
import io.ktor.client.plugins.HttpRequestTimeoutException
import io.ktor.client.plugins.HttpTimeout
import io.ktor.client.plugins.timeout
import io.ktor.client.request.HttpRequestBuilder
import io.ktor.client.request.get
import io.ktor.client.request.url
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpProtocolVersion
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.http3.beforeTransportClosedForTest
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.quicConfig
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeout
import kotlin.concurrent.atomics.AtomicInt
import kotlin.concurrent.atomics.ExperimentalAtomicApi
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

/** Connection limits, queueing and idle cleanup of the engine against a real server. */
class ClientPoolTest {
    /**
     * A server engine that permits [streams] request streams, below the 100 of RFC 9114 section 6.1 that the engine holds
     * a server to (the test seam lets it start), so a few requests exhaust the client's stream credit.
     */
    @OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)
    private suspend fun fewStreamsServer(
        streams: Long,
        module: io.ktor.server.application.Application.() -> Unit,
    ): Pair<TestServer, Int> =
        testServer(
            configure = {
                allowFewerBidiStreamsForTest = true
                http3 { quic { maxBidiStreams = streams } }
            },
            module = module,
        )

    @BeforeTest fun load() = KslLoader.ensureLoaded()

    /** Requests in the server handler at once, and the most seen; [gate] opens once [limit] are inside. */
    private class Concurrency(
        val limit: Int,
    ) {
        val inside = AtomicInt(0)
        val most = AtomicInt(0)
        val gate = CompletableDeferred<Unit>()
        val ports = HashSet<Int>()

        suspend fun enter(port: Int) {
            val n = inside.addAndFetch(1)
            while (true) {
                val m = most.load()
                if (n <= m || most.compareAndSet(m, n)) break
            }
            synchronizedAdd(port)
            if (n >= limit) gate.complete(Unit)
            gate.await()
            inside.addAndFetch(-1)
        }

        private val lock = AtomicInt(0)

        private fun synchronizedAdd(port: Int) {
            while (!lock.compareAndSet(0, 1)) {
                // a few nanoseconds
            }
            ports += port
            lock.store(0)
        }
    }

    /** Polls [condition] until it holds; [withTimeout] bounds the wait, the short delay is only the polling step. */
    private suspend fun eventually(condition: suspend () -> Boolean) =
        withTimeout(10.seconds) {
            while (!condition()) delay(10)
        }

    @Test fun perRouteLimitHoldsAndEveryRequestCompletes() =
        clientTest {
            val c = Concurrency(limit = 3)
            val (server, port) =
                testServer(plain = true) {
                    routing {
                        get("/") {
                            c.enter(call.request.local.remotePort)
                            call.respondText("ok")
                        }
                    }
                }
            try {
                testClient(engine = { pool { maxConnectionsPerRoute = 3 } }).use { client ->
                    val bodies =
                        coroutineScope {
                            (0 until 24)
                                .map {
                                    async(
                                        Dispatchers.Default,
                                    ) { client.get("http://127.0.0.1:$port/").bodyAsText() }
                                }.awaitAll()
                        }
                    assertEquals(List(24) { "ok" }, bodies)
                    assertEquals(3, c.most.load(), "the server saw at most 3 requests at once, and 3 did come at once")
                    assertTrue(c.ports.size <= 3, "at most 3 sockets ever: ${c.ports}")
                    val pool = (client.engine as KuicksilverEngine).h1.pool
                    assertTrue(pool.liveCount <= 3)
                    assertEquals(0, pool.waiterCount)
                }
            } finally {
                server.stop(100, 500)
            }
        }

    @Test fun totalLimitHoldsAcrossRoutes() =
        clientTest {
            val c = Concurrency(limit = 2)
            val module: io.ktor.server.application.Application.() -> Unit = {
                routing {
                    get("/") {
                        c.enter(call.request.local.remotePort)
                        call.respondText("ok")
                    }
                }
            }
            val (a, portA) = testServer(plain = true, module = module)
            val (b, portB) = testServer(plain = true, module = module)
            try {
                testClient(engine = {
                    pool { maxConnections = 2 }
                    pool { maxConnectionsPerRoute = 2 }
                }).use { client ->
                    val bodies =
                        coroutineScope {
                            (0 until 20)
                                .map { i ->
                                    async(Dispatchers.Default) {
                                        client.get("http://127.0.0.1:${if (i % 2 == 0) portA else portB}/").bodyAsText()
                                    }
                                }.awaitAll()
                        }
                    assertEquals(20, bodies.count { it == "ok" })
                    assertEquals(2, c.most.load())
                    assertTrue((client.engine as KuicksilverEngine).h1.pool.liveCount <= 2)
                }
            } finally {
                a.stop(100, 500)
                b.stop(100, 500)
            }
        }

    /** Waiting for a free connection counts against the connect timeout, as in the CIO engine. */
    @Test fun waitingBeyondTheConnectTimeoutFails() =
        clientTest {
            val release = CompletableDeferred<Unit>()
            val (server, port) =
                testServer(plain = true) {
                    routing {
                        get("/slow") {
                            release.await()
                            call.respondText("slow")
                        }
                        get("/") { call.respondText("ok") }
                    }
                }
            try {
                testClient(engine = { pool { maxConnectionsPerRoute = 1 } }) { install(HttpTimeout) }.use { client ->
                    val pool = (client.engine as KuicksilverEngine).h1.pool
                    coroutineScope {
                        val slow = async { client.get("http://127.0.0.1:$port/slow").bodyAsText() }
                        eventually { pool.liveCount == 1 }
                        assertFailsWith<ConnectTimeoutException> {
                            client.get("http://127.0.0.1:$port/") { timeout { connectTimeoutMillis = 200 } }
                        }
                        assertEquals(0, pool.waiterCount, "the timed-out waiter left the queue")
                        release.complete(Unit)
                        assertEquals("slow", slow.await())
                    }
                    assertEquals("ok", client.get("http://127.0.0.1:$port/").bodyAsText())
                    assertEquals(1, pool.liveCount, "one connection, reused; nothing was counted twice")
                }
            } finally {
                server.stop(100, 500)
            }
        }

    @Test fun idleConnectionsAreClosedAfterTheIdleTimeout() =
        clientTest {
            val (server, port) = testServer(plain = true) { routing { get("/") { call.respondText("ok") } } }
            try {
                testClient(engine = { pool { idleTimeout = 200.milliseconds } }).use { client ->
                    val pool = (client.engine as KuicksilverEngine).h1.pool
                    assertEquals("ok", client.get("http://127.0.0.1:$port/").bodyAsText())
                    eventually { pool.liveCount == 0 }
                    assertEquals(0, pool.routeCount, "the route left the map with its last connection")
                    assertEquals("ok", client.get("http://127.0.0.1:$port/").bodyAsText())
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /** The peer allows 2 streams: 12 requests share the one connection, waiting for MAX_STREAMS credit instead of failing. */
    @Test fun h3RequestsQueueOnExhaustedMaxStreams() =
        h3Test {
            val c = Concurrency(limit = 2)
            val (server, port) =
                fewStreamsServer(2) {
                    routing {
                        get("/") {
                            c.enter(call.request.local.remotePort)
                            call.respondText("ok")
                        }
                    }
                }
            try {
                testClient(Http3Discovery.H3Only).use { client ->
                    val responses =
                        coroutineScope {
                            (0 until 12).map { async(Dispatchers.Default) { client.get("https://127.0.0.1:$port/") } }.awaitAll()
                        }
                    assertTrue(responses.all { it.version == HttpProtocolVersion.HTTP_3_0 && it.bodyAsText() == "ok" })
                    assertEquals(2, c.most.load(), "never more requests at once than the peer's stream limit")
                    assertEquals(1, (client.engine as KuicksilverEngine).h3.connectionsForTest().size, "one QUIC connection")
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /** A request queued for stream credit is bounded by the request timeout, and leaving the queue costs no credit. */
    @Test fun h3QueuedRequestTimesOutAsRequestTimeout() =
        h3Test {
            val release = CompletableDeferred<Unit>()
            val entered = CompletableDeferred<Unit>()
            val (server, port) =
                fewStreamsServer(1) {
                    routing {
                        get("/slow") {
                            entered.complete(Unit)
                            release.await()
                            call.respondText("slow")
                        }
                        get("/") { call.respondText("ok") }
                    }
                }
            try {
                testClient(Http3Discovery.H3Only) { install(HttpTimeout) }.use { client ->
                    assertEquals("ok", client.get("https://127.0.0.1:$port/").bodyAsText()) // connected, SETTINGS in
                    coroutineScope {
                        val slow = async { client.get("https://127.0.0.1:$port/slow").bodyAsText() }
                        entered.await() // the slow request holds the one stream
                        assertFailsWith<HttpRequestTimeoutException> {
                            client.get("https://127.0.0.1:$port/") { timeout { requestTimeoutMillis = 300 } }
                        }
                        release.complete(Unit)
                        assertEquals("slow", slow.await())
                    }
                    assertEquals("ok", client.get("https://127.0.0.1:$port/").bodyAsText())
                    assertEquals(1, (client.engine as KuicksilverEngine).h3.connectionsForTest().size)
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /** The call setting up a shared HTTP/3 connection is cancelled: the calls waiting for that setup start their own (H3Only: no fallback). */
    @Test fun aCancelledSetupLeavesTheWaitingCallsToSetUpAgain() =
        h3Test {
            val (server, port) = testServer { routing { get("/") { call.respondText("ok") } } }
            try {
                testClient(Http3Discovery.H3Only).use { client ->
                    val engine = client.engine as KuicksilverEngine
                    val inSetup = CompletableDeferred<Unit>()
                    val setups = AtomicInt(0)
                    engine.h3.beforeSetupForTest = {
                        if (setups.addAndFetch(1) == 1) {
                            inSetup.complete(Unit)
                            CompletableDeferred<Unit>().await() // the first setup hangs until its caller is cancelled
                        }
                    }
                    coroutineScope {
                        val first = async { client.get("https://127.0.0.1:$port/").bodyAsText() }
                        inSetup.await()
                        val second = async { client.get("https://127.0.0.1:$port/").bodyAsText() }
                        eventually { engine.h3.setupWaitersForTest.load() == 1 } // the second call waits for the first's setup
                        first.cancel()
                        assertEquals("ok", withTimeout(10.seconds) { second.await() })
                    }
                    assertEquals(2, setups.load(), "the waiting call set up its own connection")
                }
            } finally {
                server.stop(100, 500)
            }
        }

    @Test fun idleH3ConnectionIsClosedAndForgotten() =
        h3Test {
            val (server, port) = testServer { routing { get("/") { call.respondText("ok") } } }
            try {
                testClient(Http3Discovery.H3Only, engine = { pool { idleTimeout = 200.milliseconds } }).use { client ->
                    val engine = client.engine as KuicksilverEngine
                    assertEquals("ok", client.get("https://127.0.0.1:$port/").bodyAsText())
                    val conn = engine.h3.connectionsForTest().single()
                    eventually { engine.h3.entryCountForTest() == 0 }
                    withTimeout(5.seconds) { conn.closed.await() }
                    assertEquals("ok", client.get("https://127.0.0.1:$port/").bodyAsText()) // a new connection
                }
            } finally {
                server.stop(100, 500)
            }
        }

    @Test fun h3ConnectionPastItsLifetimeIsReplaced() =
        h3Test {
            val (server, port) = testServer { routing { get("/") { call.respondText("ok") } } }
            try {
                testClient(Http3Discovery.H3Only, engine = { pool { maxConnectionLifetime = 200.milliseconds } }).use { client ->
                    val engine = client.engine as KuicksilverEngine
                    assertEquals("ok", client.get("https://127.0.0.1:$port/").bodyAsText())
                    val first = engine.h3.connectionsForTest().single()
                    eventually {
                        client.get("https://127.0.0.1:$port/").bodyAsText()
                        engine.h3.connectionsForTest().singleOrNull() !== first
                    }
                    withTimeout(5.seconds) { first.closed.await() } // retired, closed once its requests were done
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /**
     * A connection whose QUIC transport ended is not handed out again, also before its HTTP/3 session took note (the
     * session learns of the end in a coroutine of its own): the next request opens a new connection instead of failing on
     * the dead one. Seen as the flake of `ClientMigrationTest.negative_noMigrationWithoutConfig`, whose GET right after a
     * lost connection went to HTTP/1.1.
     */
    @Test fun negative_connectionWhoseTransportEndedIsNotReused() =
        h3Test {
            val (server, port) = testServer { routing { get("/") { call.respondText("ok") } } }
            try {
                testClient(Http3Discovery.H3Only).use { client ->
                    val engine = client.engine as KuicksilverEngine
                    repeat(ROUNDS) { round ->
                        assertEquals("ok", client.get("https://127.0.0.1:$port/").bodyAsText())
                        val conn = engine.h3.connectionsForTest().single()
                        conn.quic.close()
                        withTimeout(5.seconds) { conn.quic.closed.await() }
                        // at once: the session may not have taken note yet
                        val next = runCatching { client.get("https://127.0.0.1:$port/").bodyAsText() }
                        assertEquals("ok", next.getOrElse { throw AssertionError("round $round: the request after the end failed", it) })
                        assertTrue(engine.h3.connectionsForTest().single() !== conn, "round $round: a new connection")
                    }
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /**
     * The same when the transport ends between the connection's lookup and its count in `acquire` (the pool's re-check
     * before a request is handed the connection): the request goes to a new connection. In that step a pool hook closes
     * the transport while a session hook holds the HTTP/3 session's own end handling back, so every round has the
     * transport gone and the connection's `closed` not yet complete when the re-check runs.
     */
    @Test fun negative_connectionWhoseTransportEndsBeforeItIsCountedIsNotUsed() =
        h3Test {
            val (server, port) = testServer { routing { get("/") { call.respondText("ok") } } }
            try {
                testClient(Http3Discovery.H3Only).use { client ->
                    val engine = client.engine as KuicksilverEngine
                    var probed = 0
                    repeat(HELD_ROUNDS) { round ->
                        assertEquals("ok", client.get("https://127.0.0.1:$port/").bodyAsText())
                        val conn = engine.h3.connectionsForTest().single()
                        val sessionHeld = CompletableDeferred<Unit>()
                        conn.beforeTransportClosedForTest = { sessionHeld.await() }
                        engine.h3.beforeCountForTest = { c ->
                            if (c === conn) {
                                conn.quic.close()
                                withTimeout(5.seconds) { conn.quic.closed.await() }
                                if (!conn.closed.isCompleted) probed++
                            }
                        }
                        try {
                            val next = runCatching { client.get("https://127.0.0.1:$port/").bodyAsText() }
                            assertEquals("ok", next.getOrElse { throw AssertionError("round $round: the request failed", it) })
                        } finally {
                            engine.h3.beforeCountForTest = null
                            sessionHeld.complete(Unit)
                        }
                        assertTrue(engine.h3.connectionsForTest().single() !== conn, "round $round: a new connection")
                        withTimeout(5.seconds) { conn.closed.await() } // the session took note once let go
                    }
                    assertEquals(HELD_ROUNDS, probed, "every round had the transport gone and `closed` not complete")
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /**
     * The race's HTTP/1.1 side takes the route's idle connection as its caller is cancelled (HTTP/3 won the race meanwhile):
     * the connection goes back to the pool, idle, instead of staying out of it, open, with nobody to close it (the leak
     * sentinel's tcp.socket and ksl.ssl in matrix steps 54 and 72). The pool's wait for a connection watches the route's
     * HTTP/2 state (an https route may use HTTP/2), and a cancellation that reaches that wait's scope as it takes the
     * connection made the scope throw and drop it; here the caller is cancelled as it starts to obtain the connection, so
     * the scope always ends cancelled with the connection taken.
     */
    @Test fun negative_anIdleConnectionTakenAsTheCallerIsCancelledGoesBackToThePool() =
        clientTest {
            val (server, port) = testServer(configure = { http3 { enabled = false } }) { routing { get("/") { call.respondText("ok") } } }
            try {
                testClient(null).use { client ->
                    val h1 = (client.engine as KuicksilverEngine).h1
                    val url = "https://127.0.0.1:$port/"
                    assertEquals(HttpProtocolVersion.HTTP_1_1, client.get(url).also { assertEquals("ok", it.bodyAsText()) }.version)
                    assertEquals(1, h1.pool.idleCount, "the first request's connection is idle in the pool")
                    val data = HttpRequestBuilder().apply { url(url) }.build()
                    try {
                        coroutineScope {
                            var caller: Job? = null
                            h1.obtainBudgetForTest = { caller!!.cancel() }
                            caller =
                                launch(start = CoroutineStart.LAZY) {
                                    h1.open(data)
                                    error("the caller is cancelled before it gets the connection")
                                }
                            caller.start()
                            caller.join()
                        }
                    } finally {
                        h1.obtainBudgetForTest = null
                    }
                    assertEquals(1, h1.pool.liveCount, "one connection")
                    assertEquals(1, h1.pool.idleCount, "the connection the cancelled caller took is idle in the pool again")
                    assertEquals("ok", client.get(url).bodyAsText()) // and serves the next request
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /**
     * A QUIC attempt whose connect returned as its caller is cancelled (the race lost, the connect timeout) closes the
     * connection it made: the attempt's context ends cancelled, nobody receives the connection, and it stayed open until
     * the engine closed.
     */
    @Test fun negative_aQuicConnectionMadeAsItsAttemptIsCancelledIsClosed() =
        h3Test {
            val (server, port) = testServer { routing { get("/") { call.respondText("ok") } } }
            try {
                testClient(Http3Discovery.H3Only).use { client ->
                    val h3 = (client.engine as KuicksilverEngine).h3
                    val made = CompletableDeferred<io.kuicksilver.http3.Http3Connection>()
                    h3.attemptConnectedForTest = { c ->
                        made.complete(c)
                        kotlinx.coroutines.awaitCancellation() // the attempt is cancelled before its context ends
                    }
                    val conn =
                        try {
                            coroutineScope {
                                val call = launch { client.get("https://127.0.0.1:$port/") }
                                val c = made.await()
                                call.cancel()
                                call.join()
                                c
                            }
                        } finally {
                            h3.attemptConnectedForTest = null
                        }
                    withTimeout(10.seconds) { conn.quic.closed.await() }
                    assertTrue(h3.connectionsForTest().none { it === conn }, "the connection is not in the pool")
                    assertEquals("ok", client.get("https://127.0.0.1:$port/").bodyAsText())
                }
            } finally {
                server.stop(100, 500)
            }
        }

    private companion object {
        /** Rounds of [negative_connectionWhoseTransportEndedIsNotReused]: the window it probes is a few dispatches long. */
        const val ROUNDS = 30

        /** Rounds of [negative_connectionWhoseTransportEndsBeforeItIsCountedIsNotUsed]: each one probes the window. */
        const val HELD_ROUNDS = 5
    }
}
