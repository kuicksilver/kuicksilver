// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class, io.kuicksilver.annotations.InternalKuicksilverApi::class)

package io.kuicksilver.ktor.client

import io.ktor.client.HttpClient
import io.ktor.client.plugins.websocket.WebSockets
import io.ktor.client.plugins.websocket.webSocket
import io.ktor.client.request.get
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpProtocolVersion
import io.ktor.server.application.install
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.ktor.server.websocket.webSocket
import io.ktor.websocket.close
import io.kuicksilver.ktor.client.dns.SvcbRecord
import io.kuicksilver.ktor.network.TcpAddress
import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.job
import kotlinx.coroutines.yield
import kotlin.concurrent.Volatile
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.fail
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds
import kotlin.time.TimeSource

/**
 * What a request got as its connect timeout fires is kept: HTTPS records read then, the upgrade decided from them, a
 * connection obtained, the WebSocket's addresses, an HTTP/3 connection made. The timeout lands on another thread after the
 * step returned, before the timeout's scope completed; before, the request failed or went on without what it had. Each
 * hook is the engine's (per instance) and holds the step's thread until the connect timeout cancelled it; a run whose step
 * did not end before the timeout (a cold JVM) is repeated with the timeout doubled.
 */
class ClientConnectDeadlineRaceTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    @Volatile private var reached = false

    private suspend fun hold() {
        if (reached) return // once per run
        yield() // returns through a resumption, as the step does; throws once the deadline fired
        reached = true
        val job = currentCoroutineContext().job
        val giveUp = TimeSource.Monotonic.markNow() + 30.seconds
        while (!job.isCancelled && giveUp.hasNotPassedNow()) Thread.onSpinWait() // the connect timeout fires meanwhile
    }

    private fun race(attempt: suspend (connectTimeoutMillis: Long) -> Unit) =
        clientTest {
            var millis = 500L
            repeat(5) {
                reached = false
                val outcome = runCatching { attempt(millis) }
                if (reached) {
                    outcome.getOrThrow()
                    return@clientTest
                }
                millis *= 2
            }
            fail("no run reached the race")
        }

    private fun engine(c: HttpClient) = c.engine as KuicksilverEngine

    private fun rec(
        owner: String,
        port: Int?,
        vararg alpn: String,
    ) = SvcbRecord(1, ".", alpn.toList(), false, port, emptyList(), emptyList(), 300, owner)

    /** RFC 9460 section 9.5: an upgrade decided from records read as the connect timeout fires is the 307. */
    @Test fun negative_anUpgradeDecidedAsTheConnectTimeoutFiresIsThe307() =
        race { millis ->
            Tripwire().use { origin ->
                testClient(Http3DiscoveryMode.Auto, engine = {
                    resolverForTest = { _, p -> listOf(TcpAddress(byteArrayOf(127, 0, 0, 1), p)) }
                    connectTimeout = millis.milliseconds
                    http3 { httpsRecords = HttpsRecordsForTest { n -> listOf(rec(n, null, "h2")) } }
                }, block = { followRedirects = false }).use { c ->
                    engine(c).httpsResolvedForTest = { hold() }
                    // before: not upgraded, the request went to the plain origin
                    assertEquals(307, c.get("http://server.test:${origin.port}/").status.value)
                    assertEquals(0, origin.hits.get(), "the plain origin was not asked")
                }
            }
        }

    /** HTTPS records read as the connect timeout fires are the resolution: the request goes to the endpoint they name. */
    @Test fun negative_recordsReadAsTheConnectTimeoutFiresAreTheResolution() =
        race { millis ->
            val (server, port) = testServer(configure = { http3 = false }) { routing { get("/") { call.respondText("ok") } } }
            try {
                Tripwire().use { origin ->
                    testClient(Http3DiscoveryMode.Auto, engine = {
                        resolverForTest = { _, p -> listOf(TcpAddress(byteArrayOf(127, 0, 0, 1), p)) }
                        connectTimeout = millis.milliseconds
                        // the origin's own port is a tripwire; the record's endpoint is the server
                        http3 { httpsRecords = HttpsRecordsForTest { n -> listOf(rec(n, port, "http/1.1")) } }
                    }).use { c ->
                        engine(c).httpsResolvedForTest = { hold() }
                        assertEquals("ok", c.get("https://server.test:${origin.port}/").bodyAsText())
                        assertEquals(0, origin.hits.get(), "the origin's own port was not tried")
                    }
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /** An HTTP/1.1 connection obtained as the connect timeout fires is the request's, not a ConnectTimeoutException. */
    @Test fun negative_aConnectionObtainedAsTheConnectTimeoutFiresIsUsed() =
        race { millis ->
            val (server, port) = testServer(plain = true) { routing { get("/") { call.respondText("ok") } } }
            try {
                testClient(engine = { connectTimeout = millis.milliseconds }).use { c ->
                    engine(c).h1.obtainedForTest = { hold() }
                    assertEquals("ok", c.get("http://127.0.0.1:$port/").bodyAsText())
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /**
     * A WebSocket's addresses resolved as the connect timeout fires are its addresses: it goes on to the connection the pool
     * holds, not a ConnectTimeoutException. That connection is an earlier request's HTTP/2 connection, whose server allows
     * Extended CONNECT (RFC 8441): taken at once, it needs nothing of the timeout, all of which the resolution used. An
     * HTTP/1.1 WebSocket would not do: its route (`ws://`) never holds an idle connection, so it dials, and a dial within
     * the 1 ms left succeeded only where loopback connects that fast (macOS, not Linux or Windows).
     */
    @Test fun negative_aWebSocketsAddressesResolvedAsTheConnectTimeoutFiresAreUsed() =
        race { millis ->
            val (server, port) =
                testServer(configure = {
                    http2 = true
                    http3 = false
                }) {
                    install(io.ktor.server.websocket.WebSockets)
                    routing {
                        get("/") { call.respondText("ok") }
                        webSocket("/ws") { close() }
                    }
                }
            try {
                testClient(engine = {
                    connectTimeout = millis.milliseconds
                    resolverForTest = { _, p -> listOf(TcpAddress(byteArrayOf(127, 0, 0, 1), p)) }
                }, block = { install(WebSockets) }).use { c ->
                    // an HTTP/2 connection in the pool, its SETTINGS (Extended CONNECT allowed) received
                    assertEquals(HttpProtocolVersion.HTTP_2_0, c.get("https://server.test:$port/").version)
                    engine(c).h1.remoteHostsForTest = { hold() }
                    c.webSocket("wss://server.test:$port/ws") {
                        assertEquals(HttpProtocolVersion.HTTP_2_0, call.response.version, "on the pooled HTTP/2 connection")
                    }
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /** An HTTP/3 connection the race made as the connect timeout fires is the connection, not closed and failed. */
    @Test fun negative_anH3ConnectionMadeAsTheConnectTimeoutFiresIsUsed() =
        race { millis ->
            if (!quicServerSupported()) {
                reached = true
                return@race
            }
            val (server, port) = testServer { routing { get("/") { call.respondText("v=${call.request.local.version}") } } }
            try {
                testClient(Http3DiscoveryMode.H3Only, engine = { connectTimeout = millis.milliseconds }).use { c ->
                    engine(c).h3.setupMadeForTest = { hold() }
                    val r = c.get("https://127.0.0.1:$port/")
                    assertEquals(HttpProtocolVersion.HTTP_3_0, r.version)
                }
            } finally {
                server.stop(100, 500)
            }
        }
}
