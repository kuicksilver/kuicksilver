// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalKuicksilverApi::class, ExperimentalAtomicApi::class)

package io.kuicksilver.ktor.client

import io.ktor.client.network.sockets.ConnectTimeoutException
import io.ktor.client.plugins.HttpRequestTimeoutException
import io.ktor.client.plugins.HttpTimeout
import io.ktor.client.plugins.timeout
import io.ktor.client.request.get
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpProtocolVersion
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.quicConfig
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
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
                testClient(engine = { maxConnectionsPerRoute = 3 }).use { client ->
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
                    maxConnectionsCount = 2
                    maxConnectionsPerRoute = 2
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
                testClient(engine = { maxConnectionsPerRoute = 1 }) { install(HttpTimeout) }.use { client ->
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
                testClient(engine = { idleTimeout = 200.milliseconds }).use { client ->
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
                testServer(configure = { quic = quicConfig { maxBidiStreams = 2 } }) {
                    routing {
                        get("/") {
                            c.enter(call.request.local.remotePort)
                            call.respondText("ok")
                        }
                    }
                }
            try {
                testClient(Http3DiscoveryMode.H3Only).use { client ->
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
                testServer(configure = { quic = quicConfig { maxBidiStreams = 1 } }) {
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
                testClient(Http3DiscoveryMode.H3Only) { install(HttpTimeout) }.use { client ->
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
                testClient(Http3DiscoveryMode.H3Only).use { client ->
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
                testClient(Http3DiscoveryMode.H3Only, engine = { idleTimeout = 200.milliseconds }).use { client ->
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
                testClient(Http3DiscoveryMode.H3Only, engine = { maxConnectionLifetime = 200.milliseconds }).use { client ->
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
}
